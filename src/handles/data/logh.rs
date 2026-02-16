// src/handles/logh.rs
use anyhow::{Result, bail, Context};
use url::Url;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::fs::{File, metadata};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Read};
use std::process::{Command, Stdio};

use crate::core::{
    registry::{Handle, IoStreams, Args},
    status::Status,
};
use std::io::Write;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("log", |u| Ok(Box::new(LogHandle::from_url(u)?)));
}

const LOG_HELP_TEXT: &str = r#"
RESOURCE SHELL - LOG HANDLE
===========================

USAGE:
  log:///path/to/logfile.log.VERB arguments
  log://./relative/path/log.txt.VERB arguments
  log://svc/service-name.VERB arguments

DESCRIPTION:
  The log handle provides access to log files and system services for viewing
  and analyzing log data. It supports both file-based logs and system service
  logs through journalctl. Efficient algorithms handle large log files without
  loading entire files into memory.

URL FORMATS:
  File logs (absolute):  log:///path/to/logfile.log
  File logs (relative):  log://./relative/path/log.txt
  Service logs:          log://svc/service-name

VERBS:
  tail            Show the last lines of a log file (similar to Unix tail)

SYNTAX STYLES:

  Preferred (Space-Separated Arguments):
    resh log:///var/log/syslog.tail lines=10
    resh log:///var/log/syslog.tail pattern=ERROR mode=json
    resh log://./app.log.tail lines=20 pattern=WARN

  Alternative (Quoted URL with Parentheses):
    resh "log:///var/log/syslog.tail(lines=10)"
    resh "log:///var/log/syslog.tail(pattern=ERROR,mode=json)"
    resh "log://./app.log.tail(lines=20,pattern=WARN)"

  Important: When using parentheses syntax, quote the entire URL to avoid
             shell syntax errors.

EXAMPLES:

  Basic tail (last 100 lines):
    log:///tmp/test.log.tail

  Tail with specific line count:
    log:///tmp/test.log.tail lines=3

  Tail with pattern filtering:
    log:///tmp/app.log.tail lines=10 pattern=ERROR

  Tail with JSON output:
    log:///tmp/app.log.tail lines=30 pattern=ERROR mode=json

  Tail absolute path:
    log:///var/log/syslog.tail lines=50

  Tail relative path:
    log://./logs/app.log.tail lines=20 pattern=WARN

  Service log (journalctl):
    log://svc/systemd.tail lines=50

  Service log with pattern:
    log://svc/nginx.tail lines=100 pattern=error

  System log analysis:
    log:///var/log/syslog.tail pattern=error mode=json

  Monitor cron jobs:
    log:///var/log/syslog.tail pattern=CRON lines=20

  Check systemd messages:
    log:///var/log/syslog.tail pattern=systemd lines=30 mode=json

  Application error monitoring:
    log://./logs/app.log.tail pattern=ERROR lines=50 mode=json

  Nginx error logs:
    log:///var/log/nginx/error.log.tail lines=20

  Debug activity:
    log://./debug.log.tail lines=100 pattern=DEBUG

  Multiple filters:
    log:///var/log/syslog.tail lines=50 pattern=ERROR mode=json

  Empty file handling:
    log:///tmp/empty.log.tail lines=10

  Empty file with JSON:
    log:///tmp/empty.log.tail lines=10 mode=json

  Alternative syntax examples:
    resh "log:///var/log/syslog.tail(lines=10)"
    resh "log:///var/log/syslog.tail(pattern=ERROR,mode=json)"
    resh "log://./app.log.tail(lines=20,pattern=WARN)"

TAIL ARGUMENTS:
  lines=N                Number of lines to show (default: 100, must be > 0)
  pattern=TEXT           Filter lines containing this text pattern
  mode=FORMAT            Output format: raw (default), json

OUTPUT MODES:

  raw (default):
    Displays log lines as plain text, one per line.
    Suitable for human reading and Unix pipeline integration.

  json:
    Structured JSON output with metadata.
    Suitable for programmatic parsing and automation.

    Example JSON output:
    {
      "path": "/tmp/app.log",
      "requested_lines": 30,
      "returned_lines": 6,
      "pattern": "ERROR",
      "lines": [
        "line-33 ERROR something happened",
        "line-36 ERROR something happened"
      ]
    }

OUTPUT FORMATS:

  Raw mode success (with lines):
    Line 1
    Line 2
    Line 3
    Line 4
    Line 5

  Raw mode (empty file):
    (no output)

  Raw mode error:
    Error: Log file does not exist: /tmp/nonexistent.log
    (exit code 2)

  JSON mode success:
    {
      "path": "/tmp/app.log",
      "requested_lines": 30,
      "returned_lines": 6,
      "pattern": "ERROR",
      "lines": [
        "line-33 ERROR something happened",
        "line-36 ERROR something happened"
      ]
    }

  JSON mode (empty file):
    {
      "path": "/tmp/empty.log",
      "requested_lines": 10,
      "returned_lines": 0,
      "pattern": null,
      "lines": []
    }

  JSON mode error:
    {
      "error": "Log file does not exist: /tmp/nonexistent.log",
      "path": "/tmp/nonexistent.log",
      "requested_lines": 10,
      "returned_lines": 0
    }
    (exit code 2)

PATTERN FILTERING:
  The pattern argument filters lines containing the specified text.
  Pattern matching is case-sensitive and uses substring matching.

  Examples:
    pattern=ERROR          Match lines containing "ERROR"
    pattern=CRON           Match lines containing "CRON"
    pattern="error"        Match lines containing "error" (lowercase)

  Behavior:
  • Only lines containing the pattern are returned
  • Pattern is applied after tail operation (to last N lines)
  • Case-sensitive matching
  • No regex support (simple substring match)

FILE PATH FORMATS:

  Absolute paths:
    log:///var/log/syslog
    log:///tmp/app.log
    log:///home/user/logs/debug.log

  Relative paths:
    log://./logs/app.log           Relative to current directory
    log://./debug.log              Current directory
    log://./logs/subdir/app.log    Subdirectory path

  Service logs:
    log://svc/systemd              System service via journalctl
    log://svc/nginx                Nginx service logs
    log://svc/postgresql           PostgreSQL service logs

PERFORMANCE NOTES:
  The log handle uses efficient algorithms optimized for file size:

  Small files (< 64KB):
  • Reads entire file into memory
  • Returns last N lines
  • Fast for small log files

  Large files (> 64KB):
  • Uses backward scanning from end of file
  • Reads only necessary data
  • Avoids loading entire file
  • Fast for large log files (GB+)

  This approach ensures fast tail operations on very large log files
  without excessive memory usage.

SERVICE LOG SUPPORT:
  Service logs use journalctl to access systemd service logs.

  Requirements:
  • journalctl must be installed and available
  • Service must exist on the system
  • User must have appropriate permissions

  Examples:
    log://svc/systemd.tail lines=50
    log://svc/nginx.tail lines=100 pattern=error
    log://svc/postgresql.tail lines=30 mode=json

  Note: Service log support depends on system configuration and
        availability of journalctl.

ERROR HANDLING:

  Invalid arguments:
    Error: lines must be greater than 0
    (exit code 2)

    Error: mode must be 'raw' or 'json'
    (exit code 2)

  File access issues:
    Error: Log file does not exist: /path/to/file.log
    (exit code 2)

    Error: Path is not a file: /path/to/directory
    (exit code 2)

    Error: Permission denied: /path/to/file.log
    (standard file access error)

EXIT CODES:
  0                      Success
  2                      Invalid arguments or file access error

COMMON WORKFLOWS:

  Real-time error monitoring:
    # Check for recent errors
    log:///var/log/syslog.tail pattern=error mode=json

    # Monitor application errors
    log://./logs/app.log.tail pattern=ERROR lines=50

  System administration:
    # Check cron job execution
    log:///var/log/syslog.tail pattern=CRON lines=20

    # Monitor systemd services
    log:///var/log/syslog.tail pattern=systemd lines=30

    # Check service-specific logs
    log://svc/nginx.tail lines=100 pattern=error

  Debugging and troubleshooting:
    # Get detailed debug output
    log://./debug.log.tail lines=100 pattern=DEBUG

    # Check recent critical errors
    log://./logs/app.log.tail pattern=CRITICAL mode=json

    # Analyze large log files efficiently
    log:///var/log/huge.log.tail lines=1000 pattern=ERROR

  Automation and scripting:
    # Count recent errors
    ERROR_COUNT=$(log:///var/log/app.log.tail pattern=ERROR mode=json | jq '.returned_lines')

    # Check if any errors occurred
    log:///var/log/syslog.tail pattern=error lines=100 mode=json | jq '.returned_lines > 0'

    # Extract critical log lines
    log:///var/log/app.log.tail pattern=CRITICAL mode=json | jq -r '.lines[]'

    # Using quoted syntax in shell scripts
    ERROR_COUNT=$(resh "log:///var/log/app.log.tail(pattern=ERROR,mode=json)" | jq '.returned_lines')

  Integration with Unix tools:
    # Pipe to grep for additional filtering
    log:///var/log/syslog.tail lines=100 | grep -i "failed"

    # Count occurrences
    log:///var/log/app.log.tail pattern=ERROR | wc -l

    # Search for specific patterns
    log:///var/log/syslog.tail lines=1000 | awk '/error/ {print $0}'

BEST PRACTICES:
  • Use space-separated syntax (preferred) for command-line usage
  • Use quoted parentheses syntax when needed in scripts
  • Specify appropriate line counts to limit output
  • Use pattern filtering to focus on relevant entries
  • Use JSON mode for programmatic parsing and automation
  • Use relative paths for portability in projects
  • Use absolute paths for system logs
  • Set reasonable line limits for large log files
  • Combine with Unix tools (grep, awk, jq) for complex analysis
  • Use service logs for system service monitoring
  • Check exit codes in scripts for error handling
  • Use pattern filtering before JSON parsing for efficiency
  • Keep patterns simple (substring matching only)
  • Use lowercase patterns for case-sensitive searches
  • Monitor empty file cases in automation scripts
  • Handle permission errors appropriately
  • Use efficient tail for large log rotation files
  • Leverage JSON output for metric collection
  • Use pattern filtering to reduce network traffic (remote logs)
  • Consider log rotation when setting line counts

FILE FORMAT SUPPORT:
  The log handle works with any text-based log file format:
  • Plain text logs
  • Syslog format
  • Apache/Nginx logs
  • Application logs
  • Custom log formats
  • No structured format required
  • Line-based text processing

  Note: The handle treats all files as line-based text and does not
        parse structured log formats like JSON logs or XML logs.

LIMITATIONS:
  • No regex pattern matching (simple substring only)
  • No multi-line log entry support
  • No log streaming (one-time tail operation)
  • No follow mode (like tail -f)
  • Service logs require journalctl availability
  • Pattern matching is case-sensitive
  • No time-based filtering
  • No field-based filtering (structured logs)

FUTURE ENHANCEMENTS:
  Potential features for future versions:
  • Follow mode (continuous monitoring)
  • Regex pattern support
  • Time range filtering
  • Structured log parsing (JSON, XML)
  • Multi-line log entry support
  • Log level filtering (ERROR, WARN, INFO, etc.)
  • Field-based filtering for structured logs
  • Log aggregation from multiple files
  • Remote log access (SSH, HTTP)

MORE INFO:
  For complete documentation of log handle operations and examples:
  https://github.com/[your-org]/resource-shell/docs/log-handle.md

  Unix tail command reference:
  https://man7.org/linux/man-pages/man1/tail.1.html

  journalctl documentation:
  https://man7.org/linux/man-pages/man1/journalctl.1.html

  Use 'log:// --help=VERB' for detailed help on a specific verb.
"#;

// Helper function to normalize path components similar to file handle
fn normalize_path(path: PathBuf) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => components.push(part),
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::RootDir => {
                components.clear();
                components.push(std::ffi::OsStr::new(""));
            }
            _ => {}
        }
    }
    
    if components.is_empty() || (components.len() == 1 && components[0].is_empty()) {
        PathBuf::from("/")
    } else if components[0].is_empty() {
        // Absolute path
        let mut result = PathBuf::from("/");
        for component in &components[1..] {
            result.push(component);
        }
        result
    } else {
        // Relative path
        let mut result = PathBuf::new();
        for component in &components {
            result.push(component);
        }
        result
    }
}

#[derive(Debug, Clone)]
pub enum LogSourceKind {
    File(PathBuf),
    Service(String),
}

pub struct LogTarget {
    pub source: LogSourceKind,
}

pub struct LogHandle {
    target: LogTarget,
}

impl LogHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        // Parse scheme-specific target:
        // log:///var/log/syslog -> file path (simplified from spec)
        // log://./logs/app.log -> relative path
        let path = u.path();
        
        // Handle empty path
        if path.is_empty() || path == "/" {
            bail!("File path cannot be empty for log:// URLs");
        }
        
        // Normalize the path similar to file handle
        let file_path = normalize_path(Path::new(path).to_path_buf());
        
        Ok(Self { 
            target: LogTarget { 
                source: LogSourceKind::File(file_path) 
            } 
        })
    }

    /// Check if this is a help request and display help if so
    fn check_and_display_help(verb: &str, io: &mut IoStreams) -> Result<Option<Status>> {
        // Check for help verbs
        if verb == "--help" || verb == "-h" || verb == "help" {
            write!(io.stdout, "{}", LOG_HELP_TEXT)?;
            return Ok(Some(Status::ok()));
        }
        
        // Check for verb-specific help
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
            "tail" => {
                write!(io.stdout, r#"
TAIL VERB - LOG HANDLE
=====================

DESCRIPTION:
  Shows the last lines of a log file, similar to the Unix 'tail' command.
  This is the primary verb for viewing recent log entries.

USAGE:
  log:///path/to/logfile.log.tail [arguments]
  log://./relative/path/log.txt.tail [arguments]
  log://svc/service-name.tail [arguments]

ARGUMENTS:
  lines=N                Number of lines to show (default: 100, must be > 0)
  pattern=TEXT           Filter lines containing this text pattern
  mode=FORMAT            Output format: raw (default), json

EXAMPLES:
  log:///tmp/test.log.tail
  log:///tmp/test.log.tail lines=3
  log:///tmp/app.log.tail lines=10 pattern=ERROR
  log:///tmp/app.log.tail lines=30 pattern=ERROR mode=json
  log://svc/systemd.tail lines=50

PERFORMANCE:
  Uses efficient algorithms optimized for file size:
  • Small files (< 64KB): Reads entire file and returns last N lines
  • Large files (> 64KB): Uses backward scanning to read only necessary data

For complete help, use: log:// --help
"#)?;
                Ok(Status::ok())
            }
            _ => {
                write!(io.stdout, "\nUnknown verb: {}. Currently only 'tail' is supported.\n\nUse --help for full list of verbs.\n", verb)?;
                Ok(Status::err(2, "unknown verb"))
            }
        }
    }

    fn tail(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let lines = args.get("lines")
            .map(|s| s.parse::<usize>().unwrap_or(100))
            .unwrap_or(100);
            
        // Validate lines parameter
        if lines == 0 {
            writeln!(io.stderr, "Error: lines must be greater than 0")?;
            return Ok(Status::err(2, "invalid argument: lines"));
        }
        
        let pattern = args.get("pattern");
        let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("raw");
        
        // Validate mode parameter
        if mode != "raw" && mode != "json" {
            writeln!(io.stderr, "Error: mode must be 'raw' or 'json'")?;
            return Ok(Status::err(2, "invalid argument: mode"));
        }
        
        match &self.target.source {
            LogSourceKind::File(path) => {
                self.tail_file(path, lines, pattern, mode, io)
            }
            LogSourceKind::Service(service_name) => {
                // Keep existing service logic for now
                let mut cmd = Command::new("journalctl");
                cmd.arg("-u").arg(service_name);
                cmd.arg("-n").arg(lines.to_string());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                
                let output = cmd.output()
                    .with_context(|| format!("Failed to execute journalctl for service {}", service_name))?;
                
                io.stdout.write_all(&output.stdout)?;
                if !output.stderr.is_empty() {
                    io.stderr.write_all(&output.stderr)?;
                }
                
                if output.status.success() {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(output.status.code().unwrap_or(1), "journalctl failed"))
                }
            }
        }
    }

    fn tail_file(&self, path: &Path, lines: usize, pattern: Option<&String>, mode: &str, io: &mut IoStreams) -> Result<Status> {
        // Check if file exists
        if !path.exists() {
            let error_msg = format!("Log file does not exist: {}", path.display());
            if mode == "json" {
                let error_obj = json!({
                    "error": error_msg,
                    "path": path.display().to_string(),
                    "requested_lines": lines,
                    "returned_lines": 0
                });
                writeln!(io.stdout, "{}", error_obj)?;
            } else {
                writeln!(io.stdout, "Error: {}", error_msg)?;
            }
            return Ok(Status::err(2, &error_msg));
        }
        
        // Check if path is a file
        if !path.is_file() {
            let error_msg = format!("{} is not a file", path.display());
            if mode == "json" {
                let error_obj = json!({
                    "error": error_msg,
                    "path": path.display().to_string(),
                    "requested_lines": lines,
                    "returned_lines": 0
                });
                writeln!(io.stdout, "{}", error_obj)?;
            } else {
                writeln!(io.stdout, "Error: {}", error_msg)?;
            }
            return Ok(Status::err(2, &error_msg));
        }

        // Use efficient tail algorithm
        let tail_lines = self.efficient_tail(path, lines)?;
        
        // Apply pattern filter if specified
        let filtered_lines = if let Some(pattern_str) = pattern {
            tail_lines.into_iter()
                .filter(|line| line.contains(pattern_str))
                .collect::<Vec<_>>()
        } else {
            tail_lines
        };
        
        // Output based on mode
        if mode == "json" {
            let json_output = json!({
                "path": path.display().to_string(),
                "requested_lines": lines,
                "returned_lines": filtered_lines.len(),
                "pattern": pattern,
                "lines": filtered_lines
            });
            writeln!(io.stdout, "{}", json_output)?;
        } else {
            // Raw mode - just output lines
            for line in filtered_lines {
                writeln!(io.stdout, "{}", line)?;
            }
        }
        
        Ok(Status::ok())
    }

    /// Efficient tail implementation that reads backwards from end of file
    fn efficient_tail(&self, path: &Path, num_lines: usize) -> Result<Vec<String>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open log file: {}", path.display()))?;
        
        let file_size = metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?
            .len();
            
        if file_size == 0 {
            return Ok(Vec::new());
        }
        
        // For small files, just read all lines
        if file_size < 64 * 1024 { // 64KB threshold
            return self.read_all_lines_and_tail(file, num_lines);
        }
        
        // For larger files, use efficient backward scanning
        self.backward_scan_tail(file, file_size, num_lines)
    }
    
    fn read_all_lines_and_tail(&self, file: File, num_lines: usize) -> Result<Vec<String>> {
        let reader = BufReader::new(file);
        let all_lines: Vec<String> = reader.lines()
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to read file lines")?;
        
        let start = if all_lines.len() > num_lines {
            all_lines.len() - num_lines
        } else {
            0
        };
        
        Ok(all_lines[start..].to_vec())
    }
    
    fn backward_scan_tail(&self, mut file: File, file_size: u64, num_lines: usize) -> Result<Vec<String>> {
        const CHUNK_SIZE: usize = 8192; // 8KB chunks
        let file_size_usize = file_size as usize;
        let chunk_size = std::cmp::min(CHUNK_SIZE, file_size_usize);
        let mut buffer = Vec::new();
        let mut pos = file_size_usize;
        let mut lines_found = 0;

        // Read backwards in chunks until we find enough lines or reach start of file
        loop {
            let chunk_start = if pos >= chunk_size {
                pos - chunk_size
            } else {
                0
            };

            let chunk_len = pos - chunk_start;
            if chunk_len == 0 {
                break; // Reached start of file
            }

            // Seek to chunk start
            file.seek(SeekFrom::Start(chunk_start as u64))
                .with_context(|| "failed to seek for backward reading")?;

            // Read chunk
            let mut chunk = vec![0u8; chunk_len];
            file.read_exact(&mut chunk)
                .with_context(|| "failed to read chunk")?;

            // Prepend chunk to buffer (since we're reading backwards)
            chunk.extend_from_slice(&buffer);
            buffer = chunk;

            // Count newlines in the buffer
            lines_found = buffer.iter().filter(|&&b| b == b'\n').count();

            // Stop if we have enough lines or reached start of file
            if lines_found >= num_lines || chunk_start == 0 {
                break;
            }

            pos = chunk_start;
        }
        
        // Convert bytes to string with lossy UTF-8 conversion
        let content = String::from_utf8_lossy(&buffer);
        let all_lines: Vec<&str> = content.lines().collect();
        
        // Handle case where file doesn't end with newline
        let lines = all_lines;
        if !buffer.is_empty() && buffer[buffer.len() - 1] != b'\n' && lines_found > 0 {
            // Last line doesn't end with newline, so we have one more line than newline count
            lines_found += 1;
        }
        
        // Extract the last N lines
        let start = if lines_found > num_lines {
            lines.len() - num_lines
        } else {
            0
        };
        
        Ok(lines[start..].iter().map(|s| s.to_string()).collect())
    }
}

impl Handle for LogHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["tail", "help", "--help", "-h"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = Self::check_and_display_help(verb, io)? {
            return Ok(status);
        }
        
        match verb {
            "tail"   => self.tail(args, io),
            _ => bail!("unknown verb for log://: {}", verb),
        }
    }
}