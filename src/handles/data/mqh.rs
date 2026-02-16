use anyhow::{Result, bail};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use dirs::state_dir;

const MQ_HELP_TEXT: &str = r#"
RESOURCE SHELL - MQ HANDLE
=========================

USAGE:
  mq://queue-name.VERB(arguments)

DESCRIPTION:
  The MQ (Message Queue) handle provides a simple file-based message queue
  system. It allows you to create queues, put messages in them, get messages
  from them, and manage queue state. Messages are processed in FIFO (First In,
  First Out) order. Atomic file operations ensure message integrity during
  concurrent access.

QUEUE URL FORMAT:
  mq://queue-name

  Queue names are automatically sanitized to be filesystem-safe:
  • Unsafe characters replaced with underscores
  • Names limited to 120 characters
  • Path traversal attempts neutralized

VERBS:
  create          Create a new message queue (idempotent)
  put             Add a message to the queue
  get             Retrieve and remove the oldest message (FIFO)
  len             Return the number of messages in the queue
  peek            View the oldest message without removing it
  purge           Remove all messages from the queue (idempotent)

EXAMPLES:

  Create a queue:
    mq://myqueue.create

  Put message using data argument:
    mq://testqueue.put(data="hello")

  Put message from stdin:
    echo "hello-stdin" | mq://stdinqueue.put

  Put binary data from stdin:
    printf "\x00\x01\x02\xff\xfe" | mq://binary.put

  Get message from queue:
    mq://testqueue.get

  Get from empty queue (returns exit code 2):
    mq://emptyqueue.get

  FIFO ordering example:
    # Put messages in order
    mq://fifotest.put(data="one")
    mq://fifotest.put(data="two")
    mq://fifotest.put(data="three")
    
    # Get messages (same order)
    mq://fifotest.get    # Returns: one
    mq://fifotest.get    # Returns: two
    mq://fifotest.get    # Returns: three
    mq://fifotest.get    # Exit code 2 (empty)

  Check queue length:
    mq://testqueue.len

  Queue length tracking:
    mq://len-test.len                    # Returns: 0
    mq://len-test.put(data="one")
    mq://len-test.put(data="two")
    mq://len-test.put(data="three")
    mq://len-test.len                    # Returns: 3

  Peek at next message:
    mq://demo.peek

  Peek without consuming:
    mq://demo.put(data="one")
    mq://demo.put(data="two")
    mq://demo.peek       # Returns: one
    mq://demo.peek       # Returns: one (still there)
    mq://demo.len        # Returns: 2
    mq://demo.get        # Returns: one (consumed)
    mq://demo.peek       # Returns: two (now first)

  Purge all messages:
    mq://purge-test.purge

  Complete purge example:
    mq://purge-test.put(data="message1")
    mq://purge-test.put(data="message2")
    mq://purge-test.put(data="message3")
    mq://purge-test.len         # Returns: 3
    mq://purge-test.purge
    mq://purge-test.len         # Returns: 0
    mq://purge-test.get         # Exit code 2

  Queue name sanitization:
    # These all refer to the same sanitized queue
    mq://deploy/../strange name!!.put(data="weird")
    mq://deploy/../strange name!!.len      # Returns: 1
    mq://deploy/../strange name!!.get      # Returns: weird

  Multi-line messages:
    mq://multiline.put(data="line1\nline2\nline3")
    mq://multiline.get          # Returns all lines

  Binary data handling:
    printf "\x00\x01\x02\xff\xfe" | mq://binary.put
    mq://binary.get             # Returns binary data

  Pipeline integration:
    # Generate data and queue it
    date | mq://timestamps.put
    
    # Process queued messages
    mq://timestamps.get | awk '{print $1}'

  Batch message processing:
    # Queue multiple messages
    for i in {1..10}; do
      echo "Message $i" | mq://batch.put
    done
    
    # Process all messages
    while mq://batch.get; do
      echo "Processed"
    done

  Task queue pattern:
    # Producer: Add tasks to queue
    mq://tasks.create
    mq://tasks.put(data="process file1.txt")
    mq://tasks.put(data="process file2.txt")
    mq://tasks.put(data="process file3.txt")
    
    # Consumer: Process tasks
    while mq://tasks.get; do
      echo "Processing task"
    done

  Job scheduling:
    # Schedule jobs
    for job in job1 job2 job3; do
      echo "$job" | mq://jobs.put
    done
    
    # Check pending jobs
    mq://jobs.len
    
    # Preview next job
    mq://jobs.peek
    
    # Execute jobs
    while job=$(mq://jobs.get); do
      process_job "$job"
    done

  Message buffering:
    # Buffer incoming messages
    while read -r line; do
      echo "$line" | mq://buffer.put
    done
    
    # Process buffered messages later
    while message=$(mq://buffer.get); do
      echo "Processing: $message"
    done

  Rate limiting:
    # Queue requests
    for i in {1..1000}; do
      echo "Request $i" | mq://requests.put
    done
    
    # Process at controlled rate
    while request=$(mq://requests.get); do
      process_request "$request"
      sleep 0.1  # Rate limit to 10/sec
    done

  Log aggregation:
    # Collect logs from multiple sources
    app1_log | mq://logs.put &
    app2_log | mq://logs.put &
    app3_log | mq://logs.put &
    
    # Process aggregated logs
    while log=$(mq://logs.get); do
      process_log "$log"
    done

  Batch processing:
    # Accumulate items
    find /data -name "*.txt" | while read file; do
      echo "$file" | mq://batch.put
    done
    
    # Check batch size
    batch_size=$(mq://batch.len)
    echo "Processing $batch_size items"
    
    # Process batch
    while item=$(mq://batch.get); do
      process_item "$item"
    done

  Dead letter queue pattern:
    # Try processing with fallback
    while message=$(mq://primary.get); do
      if ! process "$message"; then
        echo "$message" | mq://failed.put
      fi
    done
    
    # Review failed messages
    mq://failed.len
    mq://failed.peek

  Priority simulation (multiple queues):
    # High priority queue
    mq://high-priority.put(data="urgent task")
    
    # Low priority queue
    mq://low-priority.put(data="normal task")
    
    # Process high priority first
    mq://high-priority.get || mq://low-priority.get

  Workflow coordination:
    # Step 1: Initial processing
    for item in items; do
      echo "$item" | mq://step1.put
    done
    
    # Step 2: Intermediate processing
    while item=$(mq://step1.get); do
      processed=$(process_step1 "$item")
      echo "$processed" | mq://step2.put
    done
    
    # Step 3: Final processing
    while item=$(mq://step2.get); do
      final=$(process_step2 "$item")
      echo "Completed: $final"
    done

CREATE ARGUMENTS:
  None - creates queue directory structure

PUT ARGUMENTS:
  data=TEXT              Message content (optional, can use stdin instead)

  If data argument provided: Uses argument value
  If no data argument: Reads from stdin

GET ARGUMENTS:
  None - retrieves and removes oldest message

LEN ARGUMENTS:
  None - returns count of messages in queue

PEEK ARGUMENTS:
  None - views oldest message without removing

PURGE ARGUMENTS:
  None - removes all messages from queue

QUEUE NAMING:
  Queue names are sanitized for filesystem safety:

  Original:              Sanitized:
  myqueue               myqueue (no change)
  my-queue              my-queue (no change)
  deploy/../hack        deploy___hack
  strange name!!        strange_name__
  very$special@queue    very_special_queue

  Rules:
  • Alphanumeric characters allowed: a-z, A-Z, 0-9
  • Hyphens and underscores allowed: -, _
  • Dots allowed: .
  • All other characters replaced with underscore: _
  • Path traversal attempts (../) sanitized
  • Maximum length: 120 characters

DATA HANDLING:

  Using data argument:
    mq://queue.put(data="message content")
    mq://queue.put(data="multi\nline\nmessage")

  Using stdin:
    echo "message" | mq://queue.put
    cat file.txt | mq://queue.put
    command-output | mq://queue.put

  Binary data preservation:
    • All bytes preserved exactly
    • No encoding or escaping applied
    • Newlines and tabs preserved
    • Binary data supported via stdin
    • No extra formatting added to output

  Message integrity:
    • Exact content preservation
    • No trailing newlines added
    • No whitespace trimming
    • Binary-safe operations

FIFO ORDERING:
  Messages are processed in First In, First Out order:

  1. First message put → First message get
  2. Second message put → Second message get
  3. Third message put → Third message get

  Example:
    mq://tasks.put(data="task1")     # Position 1
    mq://tasks.put(data="task2")     # Position 2
    mq://tasks.put(data="task3")     # Position 3
    
    mq://tasks.get    # Returns: task1 (was first)
    mq://tasks.get    # Returns: task2 (was second)
    mq://tasks.get    # Returns: task3 (was third)

IDEMPOTENT OPERATIONS:
  Some operations are safe to call multiple times:

  create:
    • Calling create multiple times is safe
    • Does nothing if queue already exists
    • No errors or warnings

  purge:
    • Calling purge multiple times is safe
    • Does nothing if queue already empty
    • No errors or warnings

OUTPUT FORMATS:

  create success:
    (no output, exit code 0)

  put success:
    (no output, exit code 0)

  get success:
    message content
    (exit code 0)

  get from empty queue:
    (no output, exit code 2)

  len output:
    3
    (number of messages, exit code 0)

  peek success:
    message content
    (exit code 0)

  peek from empty queue:
    (no output, exit code 2)

  purge success:
    (no output, exit code 0)

EXIT CODES:
  0                      Success
  2                      Empty queue (for get and peek operations)
  1                      General error (invalid verb, filesystem error)

ERROR HANDLING:

  Empty queue (get):
    $ mq://empty.get
    (no output, exit code 2)

  Empty queue (peek):
    $ mq://empty.peek
    (no output, exit code 2)

  Unknown verb:
    $ mq://queue.unknown
    Error: Unknown verb: unknown
    (exit code 1)

  Filesystem errors:
    $ mq://queue.create
    Error: Failed to create queue directory: Permission denied
    (exit code 1)

CONCURRENCY:
  Atomic file operations ensure message integrity:

  • Messages written to temporary files first
  • Atomic move to final location
  • Safe for concurrent producers
  • Safe for concurrent consumers
  • No message corruption
  • No message duplication
  • No message loss

  Example concurrent usage:
    # Producer 1
    for i in {1..100}; do
      echo "Producer1-$i" | mq://concurrent.put
    done &
    
    # Producer 2
    for i in {1..100}; do
      echo "Producer2-$i" | mq://concurrent.put
    done &
    
    # Consumer
    while true; do
      mq://concurrent.get && echo "Processed"
    done

BEST PRACTICES:
  • Create queues before use with .create verb
  • Use meaningful queue names for clarity
  • Check queue length before batch operations
  • Use peek to preview without consuming
  • Handle empty queue exit code 2 in scripts
  • Use stdin for large or binary data
  • Use data argument for simple text messages
  • Purge queues when no longer needed
  • Use separate queues for different priorities
  • Implement error handling for failed processing
  • Use dead letter queues for failed messages
  • Monitor queue lengths to prevent unbounded growth
  • Use atomic operations for reliable concurrent access
  • Avoid long-running operations while holding messages
  • Process messages idempotently when possible
  • Log message processing for debugging
  • Use queue names that indicate purpose
  • Clean up temporary queues after use
  • Use FIFO ordering for guaranteed sequence
  • Combine with other handles for complex workflows
  • Use len to check queue depth before processing
  • Implement backpressure by checking queue length
  • Use multiple consumer processes for parallelism
  • Avoid duplicate queue names across workflows
  • Document queue naming conventions in projects

USE CASES:

  Asynchronous task processing:
    • Background job execution
    • Deferred work processing
    • Long-running task management

  Inter-process communication:
    • Message passing between processes
    • Event notification
    • Command distribution

  Data pipeline:
    • ETL workflows
    • Multi-stage processing
    • Data transformation chains

  Load leveling:
    • Rate limiting
    • Burst handling
    • Resource management

  Reliability patterns:
    • Retry queues
    • Dead letter queues
    • Circuit breaker patterns

LIMITATIONS:
  • File-based (not distributed)
  • No built-in priority support
  • No message expiration (TTL)
  • No message acknowledgment
  • No transactions across queues
  • No pub/sub (point-to-point only)
  • No message filtering
  • No message routing
  • No guaranteed delivery across system crashes
  • No built-in monitoring or metrics
  • Performance limited by filesystem
  • No network transparency

STORAGE LOCATION:
  Queues are stored in the filesystem under Resource Shell's data directory.
  Each queue has its own directory containing message files.

  Structure:
    ~/.local/share/resh/mq/
      ├── queue-name/
      │   ├── msg-0001.txt
      │   ├── msg-0002.txt
      │   └── msg-0003.txt
      └── another-queue/
          └── msg-0001.txt

PERFORMANCE CONSIDERATIONS:
  • Small messages: Fast operations
  • Large messages: Limited by filesystem I/O
  • Many messages: Linear scan for FIFO ordering
  • Concurrent access: Atomic operations overhead
  • Queue length: Check with len for monitoring

  Tips:
  • Keep messages reasonably sized
  • Avoid thousands of messages in single queue
  • Use multiple queues for different workflows
  • Purge queues when no longer needed
  • Monitor queue depths

INTEGRATION WITH OTHER HANDLES:

  With event handle:
    # Queue events for processing
    event://emit(topic="task.created",data="{}") | mq://events.put

  With config handle:
    # Queue configuration updates
    config://app/setting.get | mq://config-updates.put

  With db handle:
    # Queue database operations
    echo "INSERT INTO ..." | mq://db-operations.put
    
    # Process queued operations
    while sql=$(mq://db-operations.get); do
      db://mydb.exec(sql="$sql")
    done

  With log handle:
    # Queue log entries for analysis
    log:///var/log/app.log.tail | mq://log-analysis.put

DEBUGGING:

  Check queue state:
    mq://debug.len              # How many messages?
    mq://debug.peek             # What's next?

  Inspect without consuming:
    mq://debug.peek             # View message
    # Decide if you want to consume it
    mq://debug.get              # Consume if needed

  Monitor queue growth:
    watch -n 1 'mq://monitor.len'

  Dump queue contents (destructive):
    while message=$(mq://dump.get); do
      echo "$message"
    done

MORE INFO:
  For complete documentation of MQ handle operations and examples:
  https://github.com/resource-shell/docs/mq-handle.md

  Use 'mq:// --help=VERB' for detailed help on a specific verb.
"#;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("mq", |u| Ok(Box::new(MQHandle::from_url(u)?)));
}

fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.len() > 120 {
        out.truncate(120);
    }
    if out.is_empty() { "_".to_string() } else { out }
}

pub struct MQHandle {
    #[allow(dead_code)]
    name: String,
    dir: PathBuf,
}

impl MQHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        let name = format!("{}{}", u.host_str().unwrap_or(""), u.path());
        let safe = sanitize_name(&name);
        let base = state_dir().unwrap_or(std::path::PathBuf::from("/tmp"));
        let dir = base.join("resh").join("mq").join(safe);
        Ok(Self { name: name, dir })
    }

    fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::create_dir_all(self.dir.join("_inflight"))?;
        Ok(())
    }

    fn now_ns() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn purge_impl(&self) -> Result<()> {
        // Ensure directory structure exists (idempotent)
        self.ensure()?;
        
        // Purge .msg files from main directory
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg")) {
                    // Handle NotFound errors gracefully (file may have been deleted by concurrent operation)
                    match fs::remove_file(&path) {
                        Ok(()) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        
        // Purge .msg files from _inflight directory
        let inflight = self.dir.join("_inflight");
        if inflight.exists() {
            for entry in fs::read_dir(&inflight)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg")) {
                    // Handle NotFound errors gracefully (file may have been deleted by concurrent operation)
                    match fs::remove_file(&path) {
                        Ok(()) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Check if this is a help request and display help if so
    fn check_and_display_help(verb: &str, args: &Args, io: &mut IoStreams) -> Result<Option<Status>> {
        // Handle help verb specially - Resource Shell framework converts help patterns into this
        if verb == "help" {
            if let Some(help_verb) = args.get("verb") {
                // Verb-specific help: --help=verb or help(verb=verb)
                Self::display_verb_help(help_verb, io)?;
                return Ok(Some(Status::ok()));
            } else {
                // General help: --help or help
                write!(io.stdout, "{}", MQ_HELP_TEXT)?;
                return Ok(Some(Status::ok()));
            }
        }

        // Check for other help patterns (legacy support)
        let is_help_request = verb == "--help" || verb == "-h" ||
            args.get("help").is_some() || 
            args.get("h").is_some() ||
            args.contains_key("--help") ||
            args.contains_key("-h");

        if is_help_request {
            write!(io.stdout, "{}", MQ_HELP_TEXT)?;
            return Ok(Some(Status::ok()));
        }
        
        // Check for verb-specific help: "--help=verb" pattern (if verb itself is the pattern)
        if verb.starts_with("--help=") {
            let help_verb = verb.strip_prefix("--help=").unwrap_or("");
            Self::display_verb_help(help_verb, io)?;
            return Ok(Some(Status::ok()));
        }

        Ok(None)
    }

    /// Display help for a specific verb
    fn display_verb_help(verb: &str, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "create" => {
                write!(io.stdout, r#"
CREATE VERB - MQ HANDLE
======================

DESCRIPTION:
  Create a new message queue directory structure. This operation is idempotent -
  calling it multiple times is safe and will not cause errors.

USAGE:
  mq://queue-name.create

ARGUMENTS:
  None - creates queue directory structure

EXAMPLES:
  mq://myqueue.create
  mq://work-queue.create
  mq://task-backlog.create

BEHAVIOR:
  • Creates queue directory if it doesn't exist
  • Creates _inflight subdirectory for atomic operations
  • Safe to call multiple times (idempotent)
  • No output on success

OUTPUT:
  (no output, exit code 0)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            "put" => {
                write!(io.stdout, r#"
PUT VERB - MQ HANDLE
===================

DESCRIPTION:
  Add a message to the queue. Messages can be provided as a data argument or
  read from stdin. All data is preserved exactly, including binary content.

USAGE:
  mq://queue-name.put(data="message")
  echo "message" | mq://queue-name.put

ARGUMENTS:
  data=TEXT              Message content (optional, uses stdin if not provided)

EXAMPLES:

  Using data argument:
    mq://testqueue.put(data="hello")
    mq://testqueue.put(data="multi\nline\nmessage")

  Using stdin:
    echo "hello-stdin" | mq://stdinqueue.put
    cat file.txt | mq://queue.put
    printf "\x00\x01\x02\xff\xfe" | mq://binary.put

  Pipeline usage:
    date | mq://timestamps.put
    ls -la | mq://listings.put

BEHAVIOR:
  • Messages written atomically (temp file then rename)
  • FIFO ordering maintained automatically
  • Binary data preserved exactly
  • No size limits (filesystem dependent)
  • Safe for concurrent producers

OUTPUT:
  (no output, exit code 0)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            "get" => {
                write!(io.stdout, r#"
GET VERB - MQ HANDLE
===================

DESCRIPTION:
  Retrieve and remove the oldest message from the queue (FIFO order).
  Returns exit code 2 if the queue is empty.

USAGE:
  mq://queue-name.get

ARGUMENTS:
  None - retrieves and removes oldest message

EXAMPLES:
  mq://testqueue.get
  message=$(mq://queue.get)
  
  FIFO example:
    mq://fifo.put(data="first")
    mq://fifo.put(data="second")
    mq://fifo.get    # Returns: first
    mq://fifo.get    # Returns: second
    mq://fifo.get    # Exit code 2 (empty)

  Error handling:
    if mq://queue.get; then
      echo "Got message"
    else
      echo "Queue empty"
    fi

BEHAVIOR:
  • Atomic retrieval (move to _inflight then read)
  • FIFO ordering guaranteed
  • Message removed after successful read
  • Safe for concurrent consumers
  • Binary data preserved exactly

OUTPUT:
  Success: message content (exit code 0)
  Empty: no output (exit code 2)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            "len" => {
                write!(io.stdout, r#"
LEN VERB - MQ HANDLE
===================

DESCRIPTION:
  Return the number of messages currently in the queue.

USAGE:
  mq://queue-name.len

ARGUMENTS:
  None - returns count of messages in queue

EXAMPLES:
  mq://testqueue.len
  count=$(mq://queue.len)
  
  Tracking example:
    mq://tracker.len                    # Returns: 0
    mq://tracker.put(data="one")
    mq://tracker.put(data="two")
    mq://tracker.len                    # Returns: 2
    mq://tracker.get
    mq://tracker.len                    # Returns: 1

  Batch monitoring:
    while [ $(mq://queue.len) -gt 0 ]; do
      mq://queue.get
    done

BEHAVIOR:
  • Counts .msg files in queue directory
  • Safe for concurrent access
  • Fast operation (directory listing)
  • Excludes _inflight messages

OUTPUT:
  Numeric count (exit code 0)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            "peek" => {
                write!(io.stdout, r#"
PEEK VERB - MQ HANDLE
====================

DESCRIPTION:
  View the oldest message from the queue without removing it.
  Returns exit code 2 if the queue is empty.

USAGE:
  mq://queue-name.peek

ARGUMENTS:
  None - views oldest message without removing

EXAMPLES:
  mq://demo.peek
  next=$(mq://queue.peek)
  
  Non-destructive example:
    mq://demo.put(data="one")
    mq://demo.put(data="two")
    mq://demo.peek       # Returns: one
    mq://demo.peek       # Returns: one (still there)
    mq://demo.len        # Returns: 2
    mq://demo.get        # Returns: one (consumed)
    mq://demo.peek       # Returns: two (now first)

  Preview before processing:
    if next=$(mq://queue.peek); then
      echo "Next message: $next"
      if should_process "$next"; then
        mq://queue.get  # Consume it
      fi
    fi

BEHAVIOR:
  • Non-destructive read
  • FIFO ordering (shows oldest)
  • Message remains in queue
  • Safe for concurrent access
  • Binary data preserved exactly

OUTPUT:
  Success: message content (exit code 0)
  Empty: no output (exit code 2)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            "purge" => {
                write!(io.stdout, r#"
PURGE VERB - MQ HANDLE
=====================

DESCRIPTION:
  Remove all messages from the queue, making it empty. This operation is
  idempotent - safe to call multiple times.

USAGE:
  mq://queue-name.purge

ARGUMENTS:
  None - removes all messages from queue

EXAMPLES:
  mq://purge-test.purge
  
  Complete example:
    mq://test.put(data="message1")
    mq://test.put(data="message2")
    mq://test.put(data="message3")
    mq://test.len         # Returns: 3
    mq://test.purge
    mq://test.len         # Returns: 0
    mq://test.get         # Exit code 2 (empty)

  Safe cleanup:
    # Clean up test queues
    mq://test-queue-1.purge
    mq://test-queue-2.purge
    mq://temp-work.purge

BEHAVIOR:
  • Removes all .msg files from queue directory
  • Cleans both main and _inflight directories
  • Idempotent (safe to call multiple times)
  • Atomic operation (files removed individually)
  • Safe for concurrent access

OUTPUT:
  (no output, exit code 0)

For complete help, use: mq:// --help
"#)?;
                Ok(Status::ok())
            }
            _ => {
                write!(io.stdout, "\nUnknown verb: {}. Available verbs: create, put, get, len, peek, purge.\n\nUse --help for full list of verbs.\n", verb)?;
                Ok(Status::err(1, "unknown verb"))
            }
        }
    }
}

impl Handle for MQHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "put", "get", "len", "purge", "peek", "help", "--help", "-h"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = Self::check_and_display_help(verb, args, io)? {
            return Ok(status);
        }

        match verb {
            "create" => {
                match self.ensure() {
                    Ok(_) => Ok(Status::ok()),
                    Err(e) => Ok(Status::err(1, format!("mq create failed: {}", e))),
                }
            }
            "put" => {
                self.ensure()?;
                
                // Get message data from args or stdin
                let data = if let Some(data_str) = args.get("data") {
                    // Use data from arguments if provided
                    data_str.as_bytes().to_vec()
                } else {
                    // Read from stdin if no data argument provided
                    let mut buf = Vec::new();
                    io.stdin.read_to_end(&mut buf)?;
                    buf
                };
                
                // Use atomic write: write to temp file then rename
                let now = Self::now_ns();
                let tmp = self.dir.join(format!("tmp-{}.msg", now));
                let final_path = self.dir.join(format!("{:020}.msg", now));
                
                // Write to temp file
                fs::write(&tmp, &data)?;
                
                // Atomically move to final location
                fs::rename(&tmp, &final_path)?;
                
                Ok(Status::ok())
            }
            "get" => {
                self.ensure()?;
                let mut entries: Vec<_> = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".msg"))
                    .collect();
                entries.sort_by_key(|e| e.path());
                if let Some(first) = entries.first() {
                    let src = first.path();
                    let inflight = self.dir.join("_inflight").join(src.file_name().unwrap());
                    // rename to inflight (atomic lock on same fs)
                    fs::rename(&src, &inflight)?;
                    let mut f = fs::File::open(&inflight)?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    io.stdout.write_all(&buf)?;
                    let _ = fs::remove_file(&inflight);
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(2, "empty"))
                }
            }
            "len" => {
                self.ensure()?;
                let count = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let path = e.path();
                        path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg"))
                    })
                    .count();
                write!(io.stdout, "{}", count)?;
                Ok(Status::ok())
            }
            "purge" => {
                match self.purge_impl() {
                    Ok(()) => Ok(Status::ok()),
                    Err(e) => Ok(Status::err(1, format!("failed to purge queue: {}", e))),
                }
            }
            "peek" => {
                self.ensure()?;
                let mut entries: Vec<_> = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".msg"))
                    .collect();
                entries.sort_by_key(|e| e.path());
                if let Some(first) = entries.first() {
                    let src = first.path();
                    // Read directly without moving/renaming (non-destructive)
                    let mut f = fs::File::open(&src)?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    io.stdout.write_all(&buf)?;
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(2, "empty"))
                }
            }
            _ => {
                bail!("unknown verb for mq://: {}", verb)
            }
        }
    }
}
