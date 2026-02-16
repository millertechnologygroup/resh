use anyhow::{anyhow, Context};
use serde_json::json;
use url::Url;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

#[cfg(unix)]
use nix::sys::resource::{getrlimit, setrlimit, Resource};

// ===========================================================================
// Help text for --help command
// ===========================================================================

const PROC_HELP_TEXT: &str = "
RESOURCE SHELL - PROC HANDLE
============================

USAGE:
  proc://PID.VERB(arguments)
  proc://self.VERB(arguments)

DESCRIPTION:
  The proc handle provides complete control and monitoring of running processes
  on your system. Send signals to control process lifecycle, adjust priority
  levels for CPU scheduling, monitor output logs, and set resource limits to
  control CPU time, memory usage, and file handles. Essential for process
  management, system administration, debugging, and resource control. Works
  with any process you have permission to control.

URL FORMAT:
  proc://PID.VERB(arguments)           Control specific process by ID
  proc://self.VERB(arguments)          Control current process

  PID can be any valid process ID number
  self refers to the current process (Resource Shell itself)

VERB CATEGORIES:

  Signal Operations (9 verbs):
    signal          Send custom signal by name or number
    kill            Send SIGKILL (9) - force terminate
    term            Send SIGTERM (15) - graceful termination
    int             Send SIGINT (2) - interrupt (like Ctrl+C)
    hup             Send SIGHUP (1) - hangup signal
    stop            Send SIGSTOP (19) - pause process
    cont            Send SIGCONT (18) - resume paused process
    usr1            Send SIGUSR1 (30) - user-defined signal 1
    usr2            Send SIGUSR2 (31) - user-defined signal 2

  Priority Operations (5 verbs):
    nice.get        Get current nice value (priority level)
    nice.set        Set exact nice value
    nice.inc        Increase nice value (lower priority)
    nice.dec        Decrease nice value (higher priority)
    setPriority     Set priority using classes or values

  Output Monitoring (1 verb):
    io.peek         Read recent stdout/stderr output

  Resource Limits (1 verb):
    limits.set      Set resource limits (rlimit)

EXAMPLES:

  Signal Operations (signal):
    # Send custom signal by name
    proc://1234.signal(sig=TERM)

    # Send signal by number
    proc://1234.signal(sig=15)

    # Send different signals
    proc://1234.signal(sig=HUP)
    proc://1234.signal(sig=INT)
    proc://1234.signal(sig=KILL)
    proc://1234.signal(sig=STOP)
    proc://1234.signal(sig=CONT)

    # User-defined signals
    proc://1234.signal(sig=USR1)
    proc://1234.signal(sig=USR2)

    # Send to current process
    proc://self.signal(sig=TERM)

  Signal Shortcuts:
    # Force kill process (SIGKILL = 9)
    proc://1234.kill

    # Graceful termination (SIGTERM = 15)
    proc://1234.term

    # Interrupt signal (SIGINT = 2)
    proc://1234.int

    # Hangup signal (SIGHUP = 1)
    proc://1234.hup

    # Pause process (SIGSTOP = 19)
    proc://1234.stop

    # Resume paused process (SIGCONT = 18)
    proc://1234.cont

    # User signals
    proc://1234.usr1
    proc://1234.usr2

    # Shortcuts on current process
    proc://self.term
    proc://self.kill

  Priority Operations - Get (nice.get):
    # Get priority of specific process
    proc://1234.nice.get

    # Get current process priority
    proc://self.nice.get

  Priority Operations - Set (nice.set):
    # Set specific nice value
    proc://1234.nice.set(value=5)

    # Set high priority (negative nice)
    proc://1234.nice.set(value=-5)

    # Set low priority (positive nice)
    proc://1234.nice.set(value=10)

    # Set to default priority
    proc://1234.nice.set(value=0)

    # Set current process priority
    proc://self.nice.set(value=5)

    # Lowest priority
    proc://1234.nice.set(value=19)

    # Highest priority (requires root)
    proc://1234.nice.set(value=-20)

  Priority Operations - Increment (nice.inc):
    # Increase nice by 1 (lower priority)
    proc://1234.nice.inc(delta=1)

    # Increase nice by 5
    proc://1234.nice.inc(delta=5)

    # Make current process lower priority
    proc://self.nice.inc(delta=1)

    # Large increment
    proc://1234.nice.inc(delta=10)

  Priority Operations - Decrement (nice.dec):
    # Decrease nice by 1 (higher priority)
    proc://1234.nice.dec(delta=1)

    # Decrease nice by 5 (may require root)
    proc://1234.nice.dec(delta=5)

    # Make current process higher priority
    proc://self.nice.dec(delta=1)

  Priority Operations - Set Priority (setPriority):
    # Set using priority classes
    proc://1234.setPriority(class=idle)
    proc://1234.setPriority(class=background)
    proc://1234.setPriority(class=normal)
    proc://1234.setPriority(class=high)
    proc://1234.setPriority(class=realtime)

    # Set using exact nice value
    proc://1234.setPriority(nice=5)
    proc://1234.setPriority(nice=-5)
    proc://1234.setPriority(nice=0)

    # Set current process
    proc://self.setPriority(class=background)
    proc://self.setPriority(nice=10)

  Output Monitoring (io.peek):
    # Read stdout (default)
    proc://1234.io.peek

    # Read stderr
    proc://1234.io.peek(stream=stderr)

    # Read both streams
    proc://1234.io.peek(stream=both)

    # Limit bytes read
    proc://1234.io.peek(max_bytes=100)

    # Read from end of file (tail)
    proc://1234.io.peek(tail=200)

    # Read with specific encoding
    proc://1234.io.peek(encoding=utf8)
    proc://1234.io.peek(encoding=base64)
    proc://1234.io.peek(encoding=auto)

    # Plain text output
    proc://1234.io.peek(json=false)

    # Combine options
    proc://1234.io.peek(stream=stderr,max_bytes=500,tail=500)

  Resource Limits (limits.set):
    # Limit open file handles
    proc://1234.limits.set(nofile=2048)
    proc://1234.limits.set(nofile=2048:4096)

    # Limit CPU time
    proc://1234.limits.set(cpu=300s)
    proc://1234.limits.set(cpu=600s)

    # Limit address space (memory)
    proc://1234.limits.set(as=1G)
    proc://1234.limits.set(as=512M)

    # Limit data segment
    proc://1234.limits.set(data=256M)

    # Limit stack size
    proc://1234.limits.set(stack=8M)

    # Limit core file size
    proc://1234.limits.set(core=0)
    proc://1234.limits.set(core=unlimited)

    # Limit file size
    proc://1234.limits.set(fsize=100M)

    # Limit locked memory
    proc://1234.limits.set(memlock=64M)

    # Limit number of processes (Linux)
    proc://1234.limits.set(nproc=100)

    # Multiple limits at once
    proc://1234.limits.set(nofile=4096,cpu=600s,as=1G)

    # Set on current process
    proc://self.limits.set(nofile=2048)

    # Dry run (test without applying)
    proc://1234.limits.set(dry_run=true,nofile=4096)

    # Soft and hard limits
    proc://1234.limits.set(nofile=1024:2048)
    proc://1234.limits.set(cpu=300s:600s)

    # Remove limit
    proc://1234.limits.set(core=unlimited)

SIGNAL ARGUMENTS:
  sig=SIGNAL             Signal name or number (required)
                         Names: TERM, KILL, INT, HUP, STOP, CONT, USR1, USR2, etc.
                         Numbers: 1-31 (depends on platform)

NICE.SET ARGUMENTS:
  value=NUMBER           Nice value (-20 to 19)
                         -20 = highest priority (requires root)
                         0 = normal priority (default)
                         19 = lowest priority

NICE.INC ARGUMENTS:
  delta=NUMBER           Amount to increase nice value
                         Positive number (e.g., 1, 5, 10)

NICE.DEC ARGUMENTS:
  delta=NUMBER           Amount to decrease nice value
                         Positive number (e.g., 1, 5, 10)
                         May require root for negative nice values

SETPRIORITY ARGUMENTS (choose one):
  class=CLASS            Priority class
                         Values: idle, background, normal, high, realtime
  nice=NUMBER            Exact nice value (-20 to 19)

IO.PEEK ARGUMENTS (all optional):
  stream=STREAM          Which stream to read (default: stdout)
                         Values: stdout, stderr, both
  max_bytes=NUMBER       Maximum bytes to return (default: 4096)
  tail=NUMBER            Read from end of file (default: same as max_bytes)
  encoding=ENCODING      Output encoding (default: auto)
                         Values: auto, utf8, base64
  json=BOOL              Return JSON format (default: true)
                         Values: true, false

LIMITS.SET ARGUMENTS:
  Resource names with values (see resource types below)
  pid=PID                Target process ID (optional, uses URL PID)
  dry_run=BOOL           Test without applying (default: false)

SIGNAL TYPES:

  Common signals:
    SIGHUP (1)           Hangup - terminal closed
    SIGINT (2)           Interrupt - Ctrl+C
    SIGQUIT (3)          Quit - Ctrl+\\
    SIGKILL (9)          Kill - force terminate (cannot be caught)
    SIGTERM (15)         Terminate - graceful shutdown
    SIGSTOP (19)         Stop - pause (cannot be caught)
    SIGCONT (18)         Continue - resume
    SIGUSR1 (30)         User-defined signal 1
    SIGUSR2 (31)         User-defined signal 2

  Signal behavior:
    Catchable signals can be handled by the process
    SIGKILL and SIGSTOP cannot be caught or ignored
    SIGTERM allows cleanup before exit
    SIGINT typically terminates interactive programs
    SIGHUP often triggers configuration reload
    USR1/USR2 are application-specific

  Use cases:
    SIGTERM              Normal shutdown with cleanup
    SIGKILL              Force kill unresponsive process
    SIGHUP               Reload configuration
    SIGUSR1/SIGUSR2      Application-specific actions
    SIGSTOP/SIGCONT      Pause/resume for debugging

NICE VALUE SYSTEM:

  Nice value range: -20 to 19

    -20                  Highest priority (most CPU time)
    -10                  Very high priority
    -5                   High priority
    0                    Normal priority (default)
    5                    Lower priority
    10                   Low priority
    19                   Lowest priority (least CPU time)

  Priority rules:
    • Lower nice = higher priority = more CPU time
    • Higher nice = lower priority = less CPU time
    • Normal users can only increase nice (lower priority)
    • Root can set any nice value including negative
    • Nice values are relative, not absolute guarantees
    • Scheduler considers nice along with other factors

  Common scenarios:
    Background tasks     nice 10-19
    Normal programs      nice 0
    Important services   nice -5 to -1 (requires root)
    Real-time tasks      nice -20 to -10 (requires root)

PRIORITY CLASSES:

  Class mappings to nice values:

    idle                 Nice 19 (lowest priority)
                         Use for: non-urgent background tasks, batch jobs

    background           Nice 10 (low priority)
                         Use for: backups, monitoring, indexing

    normal               Nice 0 (default priority)
                         Use for: standard applications, user programs

    high                 Nice -5 (high priority, requires root)
                         Use for: important services, time-sensitive tasks

    realtime             Nice -20 (very high priority, requires root)
                         Use for: critical services, real-time processing

  When to use each class:
    idle      Tasks that can wait, don't care about completion time
    background    Long-running tasks that shouldn't impact interactive use
    normal    Most applications, standard priority
    high      Services that need responsive performance
    realtime  Mission-critical services (use carefully)

RESOURCE LIMIT TYPES:

  Time limits:
    cpu                  CPU time in seconds
                         Format: number + 's' (e.g., '300s', '600s')
                         Limits total CPU time used by process

  Memory limits:
    as                   Address space (virtual memory)
                         Total memory process can allocate
    data                 Data segment size
                         Heap memory size
    stack                Stack size
                         Stack memory for function calls
    memlock              Locked memory (RAM that won't swap)
                         Memory locked in physical RAM

  File limits:
    nofile               Number of open file descriptors
                         Maximum open files/sockets
    fsize                Maximum file size
                         Largest file process can create
    core                 Core dump file size
                         Size of crash dump files

  Process limits:
    nproc                Number of processes (Linux only)
                         Maximum child processes

RESOURCE LIMIT FORMATS:

  Value formats:
    number               Set soft limit, keep hard limit (e.g., '4096')
    soft:hard            Set both limits (e.g., '2048:4096')
    unlimited            Remove limit

  Size suffixes:
    K                    Kilobytes (1000 bytes)
    M                    Megabytes (1000000 bytes)
    G                    Gigabytes (1000000000 bytes)

  Time suffixes:
    s                    Seconds

  Examples:
    nofile=4096          Soft limit 4096 files
    nofile=2048:4096     Soft 2048, hard 4096
    cpu=300s             300 seconds CPU time
    as=1G                1 gigabyte address space
    data=512M            512 megabytes data segment
    core=unlimited       No core dump size limit
    core=0               Disable core dumps

  Soft vs hard limits:
    Soft limit           Working limit, can be raised to hard limit
    Hard limit           Maximum limit, requires root to raise
    Format               soft (implied) or soft:hard

OUTPUT FORMATS:

  signal output:
    {
      \"pid\": 1234,
      \"verb\": \"signal\",
      \"signal\": \"TERM\",
      \"signal_num\": 15,
      \"ok\": true
    }

  nice.get output:
    {
      \"pid\": 1234,
      \"nice\": 5
    }

  nice.set output:
    {
      \"pid\": 1234,
      \"nice\": 10,
      \"changed\": true
    }

  nice.inc output:
    {
      \"pid\": 1234,
      \"nice_before\": 0,
      \"nice_after\": 5,
      \"delta\": 5,
      \"changed\": true
    }

  nice.dec output:
    {
      \"pid\": 1234,
      \"nice_before\": 5,
      \"nice_after\": 0,
      \"delta\": 5,
      \"changed\": true
    }

  setPriority output:
    {
      \"pid\": 1234,
      \"class\": \"background\",
      \"nice\": 10,
      \"previous_nice\": 0,
      \"backend\": \"linux-setpriority\"
    }

  io.peek output (single stream):
    {
      \"pid\": 1234,
      \"stream\": \"stdout\",
      \"encoding\": \"utf8\",
      \"auto_fallback\": false,
      \"bytes_read\": 23,
      \"truncated\": false,
      \"data\": \"hello world\\nmore data\\n\"
    }

  io.peek output (both streams):
    {
      \"pid\": 1234,
      \"streams\": {
        \"stdout\": {
          \"encoding\": \"utf8\",
          \"bytes_read\": 13,
          \"truncated\": false,
          \"data\": \"stdout content\"
        },
        \"stderr\": {
          \"encoding\": \"utf8\",
          \"bytes_read\": 13,
          \"truncated\": false,
          \"data\": \"stderr content\"
        }
      }
    }

  limits.set output:
    {
      \"pid\": 1234,
      \"backend\": \"rlimit\",
      \"results\": {
        \"nofile\": {
          \"requested\": \"4096:8192\",
          \"before\": {
            \"soft\": 1024,
            \"hard\": 4096
          },
          \"after\": {
            \"soft\": 4096,
            \"hard\": 8192
          },
          \"status\": \"ok\"
        }
      }
    }

EXIT CODES:
  0                      Success
  1                      General error (invalid signal, unknown verb)
  2                      Missing or invalid arguments
  3                      Process not found or invalid PID
  4                      Permission denied
  5                      Platform not supported (Windows)

ERROR MESSAGES:

  Signal errors:
    \"invalid signal: NAME\"         Unknown signal name
    \"missing arg: sig\"             sig parameter required

  Process errors:
    \"process not found\"            PID doesn't exist
    \"no such process\"              Process doesn't exist or no permission

  Nice errors:
    \"missing arg: value\"           value parameter required
    \"missing arg: delta\"           delta parameter required
    \"value must be an integer\"     Non-numeric value
    \"nice value out of range\"      Value not between -20 and 19

  Priority errors:
    \"invalid class\"                Unknown priority class
    \"invalid nice value\"           Nice value out of range

  IO errors:
    \"invalid stream value\"         Stream not stdout/stderr/both
    \"log file not found\"           Process log doesn't exist

  Limit errors:
    \"unknown resource\"             Invalid resource name
    \"invalid limit value\"          Malformed limit value

  Platform errors:
    \"platform not supported\"       Windows not supported

COMMON WORKFLOWS:

  Graceful process shutdown:
    # Try graceful termination first
    proc://1234.term

    # Wait a few seconds
    sleep 3

    # Force kill if still running
    proc://1234.kill

  Process priority management:
    # Lower priority for background task
    proc://1234.setPriority(class=background)

    # Or use nice.inc
    proc://1234.nice.inc(delta=10)

    # Restore normal priority later
    proc://1234.setPriority(class=normal)

  Debug unresponsive process:
    # Pause process
    proc://1234.stop

    # Attach debugger or inspect
    # ...

    # Resume process
    proc://1234.cont

  Monitor process output:
    # Check recent stdout
    proc://1234.io.peek

    # Check stderr for errors
    proc://1234.io.peek(stream=stderr)

    # Get more output
    proc://1234.io.peek(max_bytes=1000,tail=1000)

  Limit resource usage:
    # Limit file handles
    proc://1234.limits.set(nofile=1024:2048)

    # Limit CPU time
    proc://1234.limits.set(cpu=600s)

    # Limit memory
    proc://1234.limits.set(as=512M,data=256M)

    # Test limits first
    proc://1234.limits.set(dry_run=true,nofile=2048)

BEST PRACTICES:
  • Use SIGTERM before SIGKILL for graceful shutdown
  • Allow time for processes to clean up after SIGTERM
  • Check if process exists before sending signals
  • Use SIGKILL only as last resort (no cleanup possible)
  • Test priority changes with small deltas first
  • Monitor process behavior after priority changes
  • Use priority classes for consistency
  • Document why specific priorities are set
  • Use negative nice values sparingly (requires root)
  • Avoid setting all processes to high priority
  • Monitor resource usage after setting limits
  • Use dry_run to test limits before applying
  • Set both soft and hard limits appropriately
  • Use core=0 to disable core dumps for sensitive apps
  • Limit file handles to prevent descriptor exhaustion
  • Set CPU limits for untrusted or test code
  • Use memory limits to prevent OOM situations
  • Check io.peek regularly for long-running processes
  • Use tail parameter to get recent output
  • Handle base64 encoding for binary output

SECURITY CONSIDERATIONS:
  • Only send signals to processes you own
  • Root can signal any process - use carefully
  • SIGKILL can't be caught - no cleanup happens
  • Verify PID before sending destructive signals
  • Be careful with negative nice values (root only)
  • Don't rely on process output for security decisions
  • io.peek may expose sensitive data
  • Validate PIDs to avoid accidents
  • Limit resource usage for untrusted code
  • Use limits.set to sandbox processes

TROUBLESHOOTING:

  Process not found:
    • Verify PID with: ps aux | grep PID
    • Check if process exited
    • Ensure PID is correct number
    • Try: proc://PID.nice.get to test access

  Permission denied:
    • Can only control own processes (or root for any)
    • Negative nice requires root
    • Some signals require elevated privileges
    • Check process owner with: ps -p PID -o user=

  Signal doesn't work:
    • Process may ignore some signals
    • SIGKILL and SIGSTOP always work
    • Check process signal handlers
    • Try different signal

  Priority change has no effect:
    • Nice is a hint, not a guarantee
    • Multiple processes share CPU
    • Check actual CPU usage with top
    • Consider other scheduling factors

PLATFORM SUPPORT:

  Linux:
    • Full support for all verbs
    • All signals available
    • Complete rlimit support
    • /proc filesystem for info

  Unix (BSD, macOS):
    • Signal operations supported
    • Priority operations supported
    • io.peek may be limited
    • rlimit support (no nproc)

  Windows:
    • NOT SUPPORTED
    • All verbs will return platform error
    • exit code 5 (platform not supported)

MORE INFO:
  For complete documentation:
  https://man7.org/linux/man-pages/man7/signal.7.html
  https://man7.org/linux/man-pages/man1/nice.1.html
  https://man7.org/linux/man-pages/man2/setrlimit.2.html

  Use 'proc:// --help=VERB' for detailed help on a specific verb.
";

#[derive(Debug)]
struct StreamData {
    encoding: String,
    auto_fallback: bool,
    bytes_read: usize,
    truncated: bool,
    data: String,
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("proc", |u| Ok(Box::new(ProcHandle::from_url(u)?)));
}

pub struct ProcHandle {
    name: String, // Can be a PID or "self"
}

impl ProcHandle {
    pub fn from_url(u: &Url) -> anyhow::Result<Self> {
        // Accept host + path, strip leading slashes, parse as PID or "self"
        let mut name = String::new();
        if let Some(h) = u.host_str() {
            name.push_str(h);
        }
        if !u.path().is_empty() {
            if !name.is_empty() {
                name.push('/');
            }
            name.push_str(u.path().trim_start_matches('/'));
        }

        if name.is_empty() {
            return Err(anyhow!("invalid pid: missing"));
        }

        // Allow "self" or numeric PID
        if name == "self" {
            Ok(Self { name })
        } else {
            let pid: u32 = name.parse()
                .with_context(|| format!("invalid pid: {}", name))?;

            if pid == 0 {
                return Err(anyhow!("invalid pid: must be positive"));
            }

            Ok(Self { name })
        }
    }

    /// Resolve the name to an actual PID
    fn resolve_pid(&self) -> anyhow::Result<libc::pid_t> {
        if self.name == "self" {
            Ok(std::process::id() as libc::pid_t)
        } else {
            let pid: u32 = self.name.parse()
                .with_context(|| format!("invalid pid: {}", self.name))?;
            Ok(pid as libc::pid_t)
        }
    }

    /// Get the nice value for the process
    #[cfg(unix)]
    fn get_nice(&self) -> anyhow::Result<i32> {
        let pid = self.resolve_pid()?;
        
        // Clear errno before the call
        unsafe { *libc::__errno_location() = 0 };
        
        let nice_value = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as u32) };
        
        // Check if an error occurred (getpriority can return -1 as a valid value)
        let errno = unsafe { *libc::__errno_location() };
        if errno != 0 {
            let error = std::io::Error::from_raw_os_error(errno);
            match errno {
                libc::ESRCH => return Err(anyhow!("no such process")),
                libc::EPERM => return Err(anyhow!("permission denied")),
                _ => return Err(anyhow!("getpriority failed: {}", error)),
            }
        }

        Ok(nice_value)
    }

    #[cfg(not(unix))]
    fn get_nice(&self) -> anyhow::Result<i32> {
        Err(anyhow!("proc:// nice operations only supported on Unix-like systems"))
    }

    /// Set the nice value for the process
    #[cfg(unix)]
    fn set_nice(&self, value: i32) -> anyhow::Result<()> {
        // Validate range
        if value < -20 || value > 19 {
            return Err(anyhow!("nice value out of range (-20..19)"));
        }

        let pid = self.resolve_pid()?;
        
        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as u32, value) };
        
        if result != 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => return Err(anyhow!("no such process")),
                Some(libc::EPERM) => return Err(anyhow!("permission denied")),
                Some(libc::EACCES) => return Err(anyhow!("permission denied")),
                _ => return Err(anyhow!("setpriority failed: {}", error)),
            }
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn set_nice(&self, _value: i32) -> anyhow::Result<()> {
        Err(anyhow!("proc:// nice operations only supported on Unix-like systems"))
    }

    /// Handle nice-related operations
    fn handle_nice(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(e) => {
                let error_json = json!({
                    "pid": null,
                    "verb": verb,
                    "ok": false,
                    "error": e.to_string()
                });
                writeln!(io.stdout, "{}", error_json)?;
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        match verb {
            "nice.get" => {
                match self.get_nice() {
                    Ok(nice_value) => {
                        let success_json = json!({
                            "pid": pid,
                            "nice": nice_value
                        });
                        writeln!(io.stdout, "{}", success_json)?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        Ok(Status::err(1, e.to_string()))
                    }
                }
            }
            "nice.set" => {
                let value_str = match args.get("value") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: value"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: value")?;
                        return Ok(Status::err(2, "missing arg: value"));
                    }
                };

                let value: i32 = match value_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "value must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: value must be an integer")?;
                        return Ok(Status::err(2, "value must be an integer"));
                    }
                };

                match self.set_nice(value) {
                    Ok(()) => {
                        let success_json = json!({
                            "pid": pid,
                            "nice": value,
                            "changed": true
                        });
                        writeln!(io.stdout, "{}", success_json)?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        
                        let code = if e.to_string().contains("out of range") {
                            3
                        } else if e.to_string().contains("permission denied") {
                            4
                        } else {
                            1
                        };
                        Ok(Status::err(code, e.to_string()))
                    }
                }
            }
            "nice.inc" => {
                let delta_str = match args.get("delta") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: delta"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: delta")?;
                        return Ok(Status::err(2, "missing arg: delta"));
                    }
                };

                let delta: i32 = match delta_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "delta must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: delta must be an integer")?;
                        return Ok(Status::err(2, "delta must be an integer"));
                    }
                };

                match self.get_nice() {
                    Ok(current) => {
                        let new_value = current + delta;
                        if new_value < -20 || new_value > 19 {
                            let error_json = json!({
                                "pid": pid,
                                "verb": verb,
                                "ok": false,
                                "error": "nice value out of range (-20..19)"
                            });
                            writeln!(io.stdout, "{}", error_json)?;
                            writeln!(io.stderr, "Error: nice value out of range (-20..19)")?;
                            return Ok(Status::err(3, "nice value out of range (-20..19)"));
                        }

                        match self.set_nice(new_value) {
                            Ok(()) => {
                                let success_json = json!({
                                    "pid": pid,
                                    "nice_before": current,
                                    "nice_after": new_value,
                                    "delta": delta,
                                    "changed": true
                                });
                                writeln!(io.stdout, "{}", success_json)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error_json = json!({
                                    "pid": pid,
                                    "verb": verb,
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error_json)?;
                                writeln!(io.stderr, "Error: {}", e)?;
                                
                                let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
                                Ok(Status::err(code, e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        Ok(Status::err(1, e.to_string()))
                    }
                }
            }
            "nice.dec" => {
                let delta_str = match args.get("delta") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: delta"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: delta")?;
                        return Ok(Status::err(2, "missing arg: delta"));
                    }
                };

                let delta: i32 = match delta_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "delta must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: delta must be an integer")?;
                        return Ok(Status::err(2, "delta must be an integer"));
                    }
                };

                match self.get_nice() {
                    Ok(current) => {
                        let new_value = current - delta;
                        if new_value < -20 || new_value > 19 {
                            let error_json = json!({
                                "pid": pid,
                                "verb": verb,
                                "ok": false,
                                "error": "nice value out of range (-20..19)"
                            });
                            writeln!(io.stdout, "{}", error_json)?;
                            writeln!(io.stderr, "Error: nice value out of range (-20..19)")?;
                            return Ok(Status::err(3, "nice value out of range (-20..19)"));
                        }

                        match self.set_nice(new_value) {
                            Ok(()) => {
                                let success_json = json!({
                                    "pid": pid,
                                    "nice_before": current,
                                    "nice_after": new_value,
                                    "delta": delta,
                                    "changed": true
                                });
                                writeln!(io.stdout, "{}", success_json)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error_json = json!({
                                    "pid": pid,
                                    "verb": verb,
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error_json)?;
                                writeln!(io.stderr, "Error: {}", e)?;
                                
                                let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
                                Ok(Status::err(code, e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        Ok(Status::err(1, e.to_string()))
                    }
                }
            }
            _ => {
                let error_json = json!({
                    "pid": pid,
                    "verb": verb,
                    "ok": false,
                    "error": format!("unknown verb: {}", verb)
                });
                writeln!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, format!("unknown verb: {}", verb)))
            }
        }
    }

    /// Handle setPriority verb - class-based priority setting
    #[cfg(unix)]
    fn verb_set_priority(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(_) => {
                writeln!(io.stderr, "Error: invalid pid")?;
                return Ok(Status::err(1, "invalid pid"));
            }
        };

        // Get current nice value for the "previous_nice" field
        let previous_nice = match self.get_nice() {
            Ok(current) => current,
            Err(e) => {
                if e.to_string().contains("no such process") {
                    writeln!(io.stderr, "Error: no such process")?;
                    return Ok(Status::err(4, "no such process"));
                } else if e.to_string().contains("permission denied") {
                    writeln!(io.stderr, "Error: permission denied")?;
                    return Ok(Status::err(4, "permission denied"));
                } else {
                    let msg = format!("failed to get current priority: {}", e);
                    writeln!(io.stderr, "Error: {}", msg)?;
                    return Ok(Status::err(4, msg));
                }
            }
        };

        // Parse arguments
        let (target_nice, resolved_class) = if let Some(nice_str) = args.get("nice") {
            // If nice is provided, use it directly and override class
            match nice_str.parse::<i32>() {
                Ok(nice_val) => {
                    let clamped = nice_val.clamp(-20, 19);
                    let class = match clamped {
                        19 => "idle",
                        10 => "background", 
                        0 => "normal",
                        -5 => "high",
                        -10 => "realtime",
                        _ => "custom"
                    };
                    (clamped, class.to_string())
                }
                Err(_) => {
                    writeln!(io.stderr, "Error: invalid nice value")?;
                    return Ok(Status::err(2, "invalid nice value"));
                }
            }
        } else {
            // Use class mapping
            let class = args.get("class").map(|s| s.as_str()).unwrap_or("normal");
            let nice_val = match class {
                "idle" => 19,
                "background" => 10,
                "normal" => 0,
                "high" => -5,
                "realtime" => -10,
                _ => {
                    writeln!(io.stderr, "Error: invalid class")?;
                    return Ok(Status::err(3, "invalid class"));
                }
            };
            (nice_val, class.to_string())
        };

        // Set the new priority using existing set_nice method
        match self.set_nice(target_nice) {
            Ok(()) => {
                let success_json = json!({
                    "pid": pid,
                    "class": resolved_class,
                    "nice": target_nice,
                    "previous_nice": previous_nice,
                    "backend": "linux-setpriority"
                });
                writeln!(io.stdout, "{}", success_json)?;
                Ok(Status::ok())
            }
            Err(e) => {
                if e.to_string().contains("no such process") {
                    writeln!(io.stderr, "Error: no such process")?;
                    Ok(Status::err(4, "no such process"))
                } else if e.to_string().contains("permission denied") {
                    writeln!(io.stderr, "Error: permission denied")?;
                    Ok(Status::err(4, "permission denied"))
                } else {
                    let msg = format!("setpriority failed: {}", e);
                    writeln!(io.stderr, "Error: {}", msg)?;
                    Ok(Status::err(4, msg))
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn verb_set_priority(&self, _args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        writeln!(io.stderr, "Error: setPriority not supported on this platform")?;
        Ok(Status::err(5, "setPriority not supported on this platform"))
    }

    #[cfg(unix)]
    fn send_signal_internal(&self, _signal_name: &str, signal_num: libc::c_int) -> anyhow::Result<bool> {
        // Use libc::kill to send the signal
        let pid = self.resolve_pid()?;
        let result = unsafe { libc::kill(pid, signal_num) };
        
        if result == 0 {
            Ok(true)
        } else {
            let errno = std::io::Error::last_os_error();
            match errno.raw_os_error() {
                Some(libc::ESRCH) => Ok(false), // Process not found
                Some(libc::EPERM) => Err(anyhow!("permission denied")),
                _ => Err(anyhow!("kill failed: {}", errno)),
            }
        }
    }

    #[cfg(not(unix))]
    fn send_signal_internal(&self, _signal_name: &str, _signal_num: libc::c_int) -> anyhow::Result<bool> {
        Err(anyhow!("proc:// only supported on Unix-like systems"))
    }

    fn resolve_signal(verb: &str, args: &Args) -> anyhow::Result<(String, libc::c_int)> {
        match verb {
            "signal" => {
                let sig = args.get("sig")
                    .ok_or_else(|| anyhow!("missing arg: sig"))?;
                parse_signal_arg(sig)
            }
            "kill" => Ok(("KILL".to_string(), libc::SIGKILL)),
            "term" => Ok(("TERM".to_string(), libc::SIGTERM)),
            "int" => Ok(("INT".to_string(), libc::SIGINT)),
            "hup" => Ok(("HUP".to_string(), libc::SIGHUP)),
            "stop" => Ok(("STOP".to_string(), libc::SIGSTOP)),
            "cont" => Ok(("CONT".to_string(), libc::SIGCONT)),
            "usr1" => Ok(("USR1".to_string(), libc::SIGUSR1)),
            "usr2" => Ok(("USR2".to_string(), libc::SIGUSR2)),
            _ => Err(anyhow!("unknown verb: {}", verb)),
        }
    }

    fn handle_signal(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        #[cfg(not(unix))]
        {
            let pid = self.resolve_pid().unwrap_or(-1);
            let error_json = json!({
                "pid": pid,
                "verb": verb,
                "ok": false,
                "backend": "unsupported",
                "error": "proc:// only supported on Unix-like systems"
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(1, "proc:// only supported on Unix-like systems"));
        }

        #[cfg(unix)]
        {
            let pid = match self.resolve_pid() {
                Ok(p) => p,
                Err(e) => {
                    let error_json = json!({
                        "pid": null,
                        "verb": verb,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(1, e.to_string()));
                }
            };

            let (signal_name, signal_num) = match Self::resolve_signal(verb, args) {
                Ok(result) => result,
                Err(e) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(1, e.to_string()));
                }
            };

            match self.send_signal_internal(&signal_name, signal_num) {
                Ok(true) => {
                    let success_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": true
                    });
                    writeln!(io.stdout, "{}", success_json)?;
                    Ok(Status::ok())
                }
                Ok(false) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": false,
                        "error": "process not found"
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    Ok(Status::err(3, "process not found"))
                }
                Err(e) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    
                    let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
                    Ok(Status::err(code, e.to_string()))
                }
            }
        }
    }

    /// Handle io.peek verb - non-blocking peek at process output logs
    fn handle_io_peek(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(e) => {
                let error_json = json!({
                    "error": format!("invalid pid: {}", e)
                });
                writeln!(io.stdout, "{}", error_json)?;
                return Ok(Status::err(3, format!("invalid pid: {}", e)));
            }
        };

        // Parse arguments
        let stream = args.get("stream").map(|s| s.as_str()).unwrap_or("stdout");
        
        // Parse max_bytes with error handling
        let max_bytes = match args.get("max_bytes") {
            Some(s) => match s.parse::<usize>() {
                Ok(val) => val,
                Err(_) => {
                    let error_json = json!({
                        "error": "max_bytes must be a positive integer",
                        "pid": pid
                    }).to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid max_bytes parameter".to_string()));
                }
            },
            None => 4096
        };
        
        let encoding = args.get("encoding").map(|s| s.as_str()).unwrap_or("auto");
        
        // Parse tail with error handling
        let tail = match args.get("tail") {
            Some(s) => match s.parse::<usize>() {
                Ok(val) => val,
                Err(_) => {
                    let error_json = json!({
                        "error": "tail must be a positive integer", 
                        "pid": pid
                    }).to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid tail parameter".to_string()));
                }
            },
            None => max_bytes
        };
        
        let json_mode = args.get("json")
            .map(|s| !matches!(s.as_str(), "false" | "0" | "no"))
            .unwrap_or(true);

        // Validate stream argument
        if !matches!(stream, "stdout" | "stderr" | "both") {
            let error_json = json!({
                "error": format!("invalid stream value: {}", stream)
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(3, format!("invalid stream value: {}", stream)));
        }

        // Validate encoding argument
        if !matches!(encoding, "auto" | "utf8" | "base64") {
            let error_json = json!({
                "error": format!("invalid encoding value: {}", encoding)
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(3, format!("invalid encoding value: {}", encoding)));
        }

        // Check for raw mode constraints
        if !json_mode && (stream != "stdout") {
            let error_json = json!({
                "error": "raw mode (json=false) only allowed with stream=stdout"
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(3, "raw mode only allowed with stream=stdout"));
        }

        // Get state directory and construct log paths
        let base = dirs::state_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let dir = base.join("resh").join("proc").join(pid.to_string());
        
        match stream {
            "stdout" => {
                let stdout_log = dir.join("stdout.log");
                match self.read_log_file(&stdout_log, max_bytes, tail, encoding) {
                    Ok(stream_data) => {
                        if json_mode {
                            let response = json!({
                                "pid": pid,
                                "stream": "stdout",
                                "encoding": stream_data.encoding,
                                "auto_fallback": stream_data.auto_fallback,
                                "bytes_read": stream_data.bytes_read,
                                "truncated": stream_data.truncated,
                                "data": stream_data.data
                            });
                            writeln!(io.stdout, "{}", response)?;
                        } else {
                            // Raw mode - write data directly
                            write!(io.stdout, "{}", stream_data.data)?;
                        }
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        Ok(Status::err(2, e.to_string()))
                    }
                }
            }
            "stderr" => {
                let stderr_log = dir.join("stderr.log");
                match self.read_log_file(&stderr_log, max_bytes, tail, encoding) {
                    Ok(stream_data) => {
                        let response = json!({
                            "pid": pid,
                            "stream": "stderr",
                            "encoding": stream_data.encoding,
                            "auto_fallback": stream_data.auto_fallback,
                            "bytes_read": stream_data.bytes_read,
                            "truncated": stream_data.truncated,
                            "data": stream_data.data
                        });
                        writeln!(io.stdout, "{}", response)?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        Ok(Status::err(2, e.to_string()))
                    }
                }
            }
            "both" => {
                let stdout_log = dir.join("stdout.log");
                let stderr_log = dir.join("stderr.log");
                
                let stdout_result = self.read_log_file(&stdout_log, max_bytes, tail, encoding);
                let stderr_result = self.read_log_file(&stderr_log, max_bytes, tail, encoding);

                let response = json!({
                    "pid": pid,
                    "streams": {
                        "stdout": match stdout_result {
                            Ok(data) => json!({
                                "encoding": data.encoding,
                                "auto_fallback": data.auto_fallback,
                                "bytes_read": data.bytes_read,
                                "truncated": data.truncated,
                                "data": data.data
                            }),
                            Err(e) => json!({
                                "error": e.to_string()
                            })
                        },
                        "stderr": match stderr_result {
                            Ok(data) => json!({
                                "encoding": data.encoding,
                                "auto_fallback": data.auto_fallback,
                                "bytes_read": data.bytes_read,
                                "truncated": data.truncated,
                                "data": data.data
                            }),
                            Err(e) => json!({
                                "error": e.to_string()
                            })
                        }
                    }
                });
                writeln!(io.stdout, "{}", response)?;
                Ok(Status::ok())
            }
            _ => unreachable!("stream validation should prevent this")
        }
    }

    /// Read and process a log file according to the specified parameters
    fn read_log_file(&self, path: &PathBuf, max_bytes: usize, tail: usize, encoding: &str) -> anyhow::Result<StreamData> {
        use base64::Engine as _;
        
        if !path.exists() {
            return Err(anyhow!("log file not found: {}", path.display()));
        }

        let mut file = File::open(path)
            .with_context(|| format!("failed to open log file: {}", path.display()))?;

        // Get file length
        let file_len = file.metadata()
            .with_context(|| format!("failed to get file metadata: {}", path.display()))?
            .len();

        if file_len == 0 {
            return Ok(StreamData {
                encoding: "utf8".to_string(),
                auto_fallback: false,
                bytes_read: 0,
                truncated: false,
                data: String::new(),
            });
        }

        // Determine how many bytes to read from the end
        let bytes_to_read = std::cmp::min(file_len, tail as u64);
        
        if bytes_to_read > 0 {
            // Seek to the tail position
            file.seek(SeekFrom::End(-(bytes_to_read as i64)))
                .with_context(|| format!("failed to seek in log file: {}", path.display()))?;
        }

        // Read the bytes
        let mut buffer = vec![0u8; bytes_to_read as usize];
        let bytes_read = file.read(&mut buffer)
            .with_context(|| format!("failed to read log file: {}", path.display()))?;
        buffer.truncate(bytes_read);

        // Apply max_bytes limit if needed
        let truncated = bytes_read > max_bytes;
        if truncated {
            let start = bytes_read - max_bytes;
            buffer = buffer[start..].to_vec();
        }

        // Apply encoding
        match encoding {
            "utf8" => {
                let data = String::from_utf8_lossy(&buffer).into_owned();
                Ok(StreamData {
                    encoding: "utf8".to_string(),
                    auto_fallback: false,
                    bytes_read: buffer.len(),
                    truncated,
                    data,
                })
            }
            "base64" => {
                let data = base64::engine::general_purpose::STANDARD.encode(&buffer);
                Ok(StreamData {
                    encoding: "base64".to_string(),
                    auto_fallback: false,
                    bytes_read: buffer.len(),
                    truncated,
                    data,
                })
            }
            "auto" => {
                match String::from_utf8(buffer.clone()) {
                    Ok(utf8_string) => Ok(StreamData {
                        encoding: "utf8".to_string(),
                        auto_fallback: false,
                        bytes_read: buffer.len(),
                        truncated,
                        data: utf8_string,
                    }),
                    Err(_) => {
                        let data = base64::engine::general_purpose::STANDARD.encode(&buffer);
                        Ok(StreamData {
                            encoding: "base64".to_string(),
                            auto_fallback: true,
                            bytes_read: buffer.len(),
                            truncated,
                            data,
                        })
                    }
                }
            }
            _ => Err(anyhow!("invalid encoding: {}", encoding))
        }
    }

    /// Main implementation of limits.set verb
    #[cfg(unix)]
    fn limits_set(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        
        // Determine target PID
        let target_pid = if let Some(pid_str) = args.get("pid") {
            match pid_str.parse::<i32>() {
                Ok(p) if p > 0 => p,
                _ => {
                    let error_json = json!({
                        "pid": null,
                        "backend": "rlimit",
                        "error": format!("invalid pid argument: '{}'", pid_str),
                        "resource": "pid"
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(2, format!("invalid pid argument: '{}'", pid_str)));
                }
            }
        } else {
            self.resolve_pid()?
        };

        // Check if this is check-only mode
        let check_only = args.get("dry_run")
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false);

        let mut results = serde_json::Map::new();
        let mut overall_success = true;

        // Process each resource limit argument
        for (key, value) in args {
            // Skip special arguments
            if key == "pid" || key == "dry_run" {
                continue;
            }

            match self.process_resource_limit(key, value, target_pid, check_only) {
                Ok(resource_result) => {
                    results.insert(key.clone(), resource_result);
                }
                Err(e) => {
                    let error_result = json!({
                        "requested": value,
                        "status": "error",
                        "error": e.to_string()
                    });
                    results.insert(key.clone(), error_result);
                    overall_success = false;
                }
            }
        }

        // Generate final JSON response
        let response = json!({
            "pid": target_pid,
            "backend": "rlimit",
            "results": results
        });

        writeln!(io.stdout, "{}", response)?;
        
        if overall_success {
            Ok(Status::ok())
        } else {
            Ok(Status::err(1, "one or more resource limit operations failed"))
        }
    }

    #[cfg(not(unix))]
    fn limits_set(&self, _args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        
        let error_json = json!({
            "backend": "limits",
            "supported": false,
            "error": "resource limits not supported on this platform"
        });
        writeln!(io.stdout, "{}", error_json)?;
        Ok(Status::err(1, "resource limits not supported on this platform"))
    }

    /// Process a single resource limit setting
    #[cfg(unix)]
    fn process_resource_limit(&self, name: &str, value: &str, _pid: i32, check_only: bool) -> anyhow::Result<serde_json::Value> {
        // Map resource name to nix Resource enum
        let resource = match self.map_resource_name(name)? {
            Some(r) => r,
            None => return Err(anyhow!("unknown resource: '{}'", name)),
        };

        // Get current limits
        let (current_soft, current_hard) = getrlimit(resource)
            .map_err(|e| anyhow!("failed to get current limits for {}: {}", name, e))?;

        // Parse the new limits
        let (new_soft, new_hard) = self.parse_limit_value(value, current_soft, current_hard)?;

        // Validate that soft <= hard
        if new_soft > new_hard {
            return Err(anyhow!("soft limit ({}) cannot exceed hard limit ({})", new_soft, new_hard));
        }

        // Apply the limits if not in check-only mode
        if !check_only {
            setrlimit(resource, new_soft, new_hard)
                .map_err(|e| anyhow!("failed to set limits for {}: {}", name, e))?;
        }

        // Build result JSON
        Ok(json!({
            "requested": value,
            "before": {
                "soft": current_soft,
                "hard": current_hard
            },
            "after": {
                "soft": new_soft,
                "hard": new_hard
            },
            "status": "ok"
        }))
    }

    /// Map resource names to nix Resource enum values
    #[cfg(unix)]
    fn map_resource_name(&self, name: &str) -> anyhow::Result<Option<Resource>> {
        let resource = match name {
            "cpu" => Some(Resource::RLIMIT_CPU),
            "as" => Some(Resource::RLIMIT_AS),
            "data" => Some(Resource::RLIMIT_DATA),
            "stack" => Some(Resource::RLIMIT_STACK),
            "core" => Some(Resource::RLIMIT_CORE),
            "nofile" => Some(Resource::RLIMIT_NOFILE),
            "fsize" => Some(Resource::RLIMIT_FSIZE),
            "memlock" => Some(Resource::RLIMIT_MEMLOCK),
            #[cfg(target_os = "linux")]
            "nproc" => Some(Resource::RLIMIT_NPROC),
            _ => None,
        };
        Ok(resource)
    }

    /// Parse limit value in various formats
    #[cfg(unix)]
    fn parse_limit_value(&self, value: &str, current_soft: u64, current_hard: u64) -> anyhow::Result<(u64, u64)> {
        if value.contains(':') {
            // Format: "soft:hard"
            let parts: Vec<&str> = value.splitn(2, ':').collect();
            let soft_str = parts[0];
            let hard_str = parts[1];

            let new_soft = if soft_str.is_empty() {
                current_soft
            } else {
                self.parse_single_limit(soft_str)?
            };

            let new_hard = if hard_str.is_empty() {
                current_hard
            } else {
                self.parse_single_limit(hard_str)?
            };

            Ok((new_soft, new_hard))
        } else {
            // Single value - set soft limit, keep hard unchanged
            let new_soft = self.parse_single_limit(value)?;
            Ok((new_soft, current_hard))
        }
    }

    /// Parse a single limit value (with potential suffixes)
    #[cfg(unix)]
    fn parse_single_limit(&self, value: &str) -> anyhow::Result<u64> {
        if value == "unlimited" {
            return Ok(u64::MAX); // RLIM_INFINITY equivalent
        }

        // Handle time suffixes for CPU
        if value.ends_with('s') {
            let num_str = &value[..value.len() - 1];
            return num_str.parse::<u64>()
                .map_err(|_| anyhow!("invalid time value: '{}'", value));
        }

        // Handle SI suffixes for byte values
        if value.ends_with('K') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000);
        }

        if value.ends_with('M') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000);
        }

        if value.ends_with('G') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000_000);
        }

        // Plain number
        value.parse::<u64>()
            .map_err(|_| anyhow!("invalid limit value: '{}'", value))
    }
}

impl Handle for ProcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["signal", "kill", "term", "int", "hup", "stop", "cont", "usr1", "usr2", 
          "nice.get", "nice.set", "nice.inc", "nice.dec", "setPriority", "io.peek", "limits.set"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        // Check for help request before processing verbs
        if should_show_help(verb, args) {
            return display_help(io);
        }

        match verb {
            "signal" | "kill" | "term" | "int" | "hup" | "stop" | "cont" | "usr1" | "usr2" => {
                self.handle_signal(verb, args, io)
            }
            "nice.get" | "nice.set" | "nice.inc" | "nice.dec" => {
                self.handle_nice(verb, args, io)
            }
            "setPriority" => {
                self.verb_set_priority(args, io)
            }
            "io.peek" => {
                self.handle_io_peek(args, io)
            }
            "limits.set" => {
                self.limits_set(args, io)
            }
            _ => {
                let pid = self.resolve_pid().unwrap_or(-1);
                let error_json = json!({
                    "pid": pid,
                    "verb": verb,
                    "ok": false,
                    "error": format!("unknown verb: {}", verb)
                });
                writeln!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, format!("unknown verb: {}", verb)))
            }
        }
    }
}

fn parse_signal_arg(sig: &str) -> anyhow::Result<(String, libc::c_int)> {
    // Try to parse as number first
    if let Ok(num) = sig.parse::<i32>() {
        // Map common signal numbers to names for output
        let name = match num {
            1 => "HUP",
            2 => "INT", 
            3 => "QUIT",
            9 => "KILL",
            15 => "TERM",
            17 => "STOP", // Note: SIGSTOP is typically 19 on Linux, 17 on some other systems
            18 => "CONT", // Note: SIGCONT is typically 18 on Linux
            19 => "STOP", // Linux SIGSTOP
            20 => "CONT", // Some systems use 20 for CONT
            30 => "USR1",
            31 => "USR2",
            _ => "UNKNOWN",
        };
        return Ok((name.to_string(), num));
    }

    // Parse as signal name (case-insensitive)
    let sig_upper = sig.to_uppercase();
    let sig_name = if sig_upper.starts_with("SIG") {
        &sig_upper[3..]
    } else {
        &sig_upper
    };

    let signal_num = match sig_name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "CHLD" => libc::SIGCHLD,
        _ => return Err(anyhow!("invalid signal: {}", sig)),
    };

    Ok((sig_name.to_string(), signal_num))
}

// ===========================================================================
// Helper functions for help display
// ===========================================================================

/// Check if help should be displayed based on various help flag patterns
fn should_show_help(method: &str, args: &Args) -> bool {
    // Check if method is help
    if method == "help" || method == "h" {
        return true;
    }

    // Check if method contains help flags
    if method.contains("--help") || method.contains("-h") {
        return true;
    }

    // Check args for help
    if args.contains_key("help") || args.contains_key("h") {
        return true;
    }

    false
}

/// Display comprehensive proc handle help
fn display_help(io: &mut IoStreams) -> anyhow::Result<Status> {
    write!(io.stdout, "{}", PROC_HELP_TEXT)?;
    Ok(Status::ok())
}