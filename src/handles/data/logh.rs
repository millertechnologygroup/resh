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

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("log", |u| Ok(Box::new(LogHandle::from_url(u)?)));
}

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
        &["tail"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "tail"   => self.tail(args, io),
            _ => bail!("unknown verb for log://: {}", verb),
        }
    }
}