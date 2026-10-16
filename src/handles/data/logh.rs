// src/handles/logh.rs
use anyhow::{Result, bail, Context};
use url::Url;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::fs::{File, metadata};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Read};
use std::process::{Command, Stdio};

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Handle, IoStreams, Args},
    status::Status,
};
use std::io::Write;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("log", |u| Ok(Box::new(LogHandle::from_url(u)?)));
    reg.set_probe_url("log", "log:///resh-help-probe");
}

/// Metadata for `resh log --help` and `resh log <verb> --help`.
static LOG_HELP: HandleHelp = HandleHelp {
    description: "The log handle reads the most recent lines of a plain-text log file or of \
        a systemd service's journal, scanning files backward from the end so large files are \
        not read in full. A file is named by the URL path, as in log:///var/log/syslog \
        (absolute) or log://./logs/app.log (relative), and log://svc/<service> reads the \
        service's journal through journalctl -u. Output is either the raw lines or a JSON \
        object, with optional substring filtering.",
    usage: "resh log://{/<path>|./<path>|svc/<service>}.<verb>[(key=value,...)]",
    verbs: &[VerbHelp {
        name: "tail",
        definition: "Prints the last lines (default 100) of a log file or service journal, \
            optionally keeping only those lines that contain a pattern, as raw text or as a JSON object.",
        detail: Some(VerbDetail {
            usage: "resh log://{<path>|svc/<service>}.tail [lines=<n>] [pattern=<text>]\n  \
                [mode=raw|json]",
            example: "resh --json-pretty log:///var/log/syslog.tail lines=2 mode=json",
            example_output: Some(
                r#"{
  "lines": [
    "Oct 16 09:12:44 host kernel: eth0: link up",
    "Oct 16 09:13:02 host app[901]: error: disk quota exceeded"
  ],
  "path": "/var/log/syslog",
  "pattern": null,
  "requested_lines": 2,
  "returned_lines": 2
}

Shown with --json-pretty. The default mode=raw prints only the lines. For
log://svc/<service> the JSON object has "service" in place of "path"."#,
            ),
        }),
    }],
};

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
        // log:///var/log/syslog   -> absolute file path
        // log://./logs/app.log    -> path relative to the working directory
        // log://svc/nginx         -> systemd journal of a service (journalctl -u)
        // log://--help[=<verb>]   -> in-URL help (no target)
        let host = u.host_str().unwrap_or("");
        let path = u.path();

        if help::is_help_flag(host.split('=').next().unwrap_or(host)) {
            return Ok(Self { target: LogTarget { source: LogSourceKind::File(PathBuf::new()) } });
        }

        if host == "svc" {
            let service = path.trim_matches('/');
            if service.is_empty() {
                bail!("Service name cannot be empty for log://svc/<service> URLs");
            }
            return Ok(Self { target: LogTarget { source: LogSourceKind::Service(service.to_string()) } });
        }

        if path.is_empty() || path == "/" {
            bail!("File path cannot be empty for log:// URLs");
        }

        let raw = match host {
            "" => PathBuf::from(path),
            "." | ".." => Path::new(host).join(path.trim_start_matches('/')),
            other => bail!(
                "Unsupported log:// host {:?}; use log:///<absolute path>, log://./<relative path> or log://svc/<service>",
                other
            ),
        };

        Ok(Self { target: LogTarget { source: LogSourceKind::File(normalize_path(raw)) } })
    }

    /// Writes the approved help for `help`, `--help`, `-h` and `--help=<verb>`.
    fn check_and_display_help(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Option<Status>> {
        let help_verb = if help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        write!(io.stdout, "{}", help::render_legacy("log", &LOG_HELP, self.verbs(), help_verb))?;
        Ok(Some(Status::ok()))
    }

    /// Arguments for `journalctl` when tailing a service's journal.
    fn journalctl_args(service: &str, lines: usize) -> Vec<String> {
        vec![
            "-u".to_string(),
            service.to_string(),
            "-n".to_string(),
            lines.to_string(),
            "--no-pager".to_string(),
            "-o".to_string(),
            "short".to_string(),
        ]
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
                self.tail_service(service_name, lines, pattern, mode, io)
            }
        }
    }

    fn tail_service(&self, service: &str, lines: usize, pattern: Option<&String>, mode: &str, io: &mut IoStreams) -> Result<Status> {
        let output = Command::new("journalctl")
            .args(Self::journalctl_args(service, lines))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("Failed to execute journalctl for service {}", service))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let error_msg = if stderr.is_empty() {
                format!("journalctl failed for service {}", service)
            } else {
                format!("journalctl failed for service {}: {}", service, stderr)
            };
            if mode == "json" {
                writeln!(io.stdout, "{}", json!({
                    "error": error_msg,
                    "requested_lines": lines,
                    "returned_lines": 0,
                    "service": service
                }))?;
            } else {
                writeln!(io.stderr, "Error: {}", error_msg)?;
            }
            return Ok(Status::err(output.status.code().unwrap_or(1), &error_msg));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let filtered = Self::filter_lines(text.lines().map(str::to_string).collect(), pattern);
        if mode == "json" {
            writeln!(io.stdout, "{}", json!({
                "lines": filtered,
                "pattern": pattern,
                "requested_lines": lines,
                "returned_lines": filtered.len(),
                "service": service
            }))?;
        } else {
            for line in filtered {
                writeln!(io.stdout, "{}", line)?;
            }
        }
        Ok(Status::ok())
    }

    /// Keeps only lines containing `pattern`, or all lines when it is None.
    fn filter_lines(lines: Vec<String>, pattern: Option<&String>) -> Vec<String> {
        match pattern {
            Some(p) => lines.into_iter().filter(|l| l.contains(p.as_str())).collect(),
            None => lines,
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
        let filtered_lines = Self::filter_lines(tail_lines, pattern);
        
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

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&LOG_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        
        match verb {
            "tail"   => self.tail(args, io),
            _ => bail!("unknown verb for log://: {}", verb),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn source(u: &str) -> LogSourceKind {
        LogHandle::from_url(&Url::parse(u).unwrap()).unwrap().target.source
    }

    fn run(h: &LogHandle, verb: &str, args: &Args) -> (Status, String) {
        let (mut i, mut o, mut e) = (Cursor::new(Vec::new()), Cursor::new(Vec::new()), Cursor::new(Vec::new()));
        let mut io = IoStreams { stdin: &mut i, stdout: &mut o, stderr: &mut e };
        let st = h.call(verb, args, &mut io).unwrap();
        (st, String::from_utf8(o.into_inner()).unwrap())
    }

    #[test]
    fn from_url_sources() {
        assert!(matches!(source("log:///var/log/syslog"), LogSourceKind::File(p) if p == Path::new("/var/log/syslog")));
        assert!(matches!(source("log://./logs/app.log"), LogSourceKind::File(p) if p == Path::new("logs/app.log")));
        assert!(matches!(source("log://svc/nginx"), LogSourceKind::Service(s) if s == "nginx"));
        assert!(matches!(source("log:///home/x/my-hosts"), LogSourceKind::File(p) if p == Path::new("/home/x/my-hosts")));
        assert!(LogHandle::from_url(&Url::parse("log://svc/").unwrap()).is_err());
        assert!(LogHandle::from_url(&Url::parse("log://var/log/syslog").unwrap()).is_err());
    }

    #[test]
    fn journalctl_args_name_service_and_count() {
        assert_eq!(
            LogHandle::journalctl_args("nginx", 50),
            ["-u", "nginx", "-n", "50", "--no-pager", "-o", "short"]
        );
    }

    #[test]
    fn legacy_help_renders_approved_help() {
        let h = LogHandle::from_url(&Url::parse("log://--help").unwrap()).unwrap();
        let (st, out) = run(&h, "help", &Args::new());
        assert!(st.ok);
        assert!(out.starts_with("Handle: log"), "{out}");
        let mut args = Args::new();
        args.insert("verb".into(), "tail".into());
        let (_, out) = run(&h, "help", &args);
        assert!(out.contains("Verb: tail"), "{out}");
        let (_, out) = run(&h, "--help=tail", &Args::new());
        assert!(out.contains("Verb: tail"), "{out}");
    }

    #[test]
    fn tail_file_with_pattern_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("app.log");
        std::fs::write(&p, "a ok\nb ERROR one\nc ok\nd ERROR two\n").unwrap();
        let h = LogHandle { target: LogTarget { source: LogSourceKind::File(p) } };
        let mut args = Args::new();
        args.insert("lines".into(), "3".into());
        args.insert("pattern".into(), "ERROR".into());
        args.insert("mode".into(), "json".into());
        let (_, out) = run(&h, "tail", &args);
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["lines"], json!(["b ERROR one", "d ERROR two"]));
    }
}
