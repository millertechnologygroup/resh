use anyhow::{Context, Result, bail};
use base64::prelude::*;
use blake3;
use chrono::{DateTime, Utc};
use globset::Glob;
use md5;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use percent_encoding::percent_decode_str;
use regex::{Regex, RegexBuilder};
use serde_json::json;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::fs::{File, OpenOptions, metadata, remove_dir_all, remove_file};
use std::io::{BufRead, BufReader};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, PathBuf};
use std::time::{Duration, Instant};
use url::Url;
use walkdir::WalkDir;

#[cfg(unix)]
use nix::unistd::{Gid, Group, Uid, User, chown};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use xattr;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// Constants for production safety
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB limit
const BUFFER_SIZE: usize = 8192; // 8KB chunks for streaming

// Helper functions for streaming hash calculation
fn calculate_sha1_hash(file_path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = File::open(file_path).with_context(|| format!("open {:?}", file_path))?;

    // Get file size for validation
    let metadata = file
        .metadata()
        .with_context(|| format!("get metadata for {:?}", file_path))?;
    let file_size = metadata.len();

    // Validate file size
    if file_size > MAX_FILE_SIZE {
        bail!(
            "File too large for hashing: {} bytes (max: {} bytes)",
            file_size,
            MAX_FILE_SIZE
        );
    }

    // Stream the file in chunks
    let mut hasher = Sha1::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read from {:?}", file_path))?;

        if bytes_read == 0 {
            break;
        }

        Sha1Digest::update(&mut hasher, &buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let result = Sha1Digest::finalize(hasher);
    let hash_hex = format!("{:x}", result);

    Ok((hash_hex, total_bytes))
}

fn calculate_sha256_hash(file_path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = File::open(file_path).with_context(|| format!("open {:?}", file_path))?;

    // Get file size for validation
    let metadata = file
        .metadata()
        .with_context(|| format!("get metadata for {:?}", file_path))?;
    let file_size = metadata.len();

    // Validate file size
    if file_size > MAX_FILE_SIZE {
        bail!(
            "File too large for hashing: {} bytes (max: {} bytes)",
            file_size,
            MAX_FILE_SIZE
        );
    }

    // Stream the file in chunks
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read from {:?}", file_path))?;

        if bytes_read == 0 {
            break;
        }

        Sha2Digest::update(&mut hasher, &buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let result = Sha2Digest::finalize(hasher);
    let hash_hex = format!("{:x}", result);

    Ok((hash_hex, total_bytes))
}

fn calculate_sha512_hash(file_path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = File::open(file_path).with_context(|| format!("open {:?}", file_path))?;

    // Get file size for validation
    let metadata = file
        .metadata()
        .with_context(|| format!("get metadata for {:?}", file_path))?;
    let file_size = metadata.len();

    // Validate file size
    if file_size > MAX_FILE_SIZE {
        bail!(
            "File too large for hashing: {} bytes (max: {} bytes)",
            file_size,
            MAX_FILE_SIZE
        );
    }

    // Stream the file in chunks
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read from {:?}", file_path))?;

        if bytes_read == 0 {
            break;
        }

        Sha2Digest::update(&mut hasher, &buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let result = Sha2Digest::finalize(hasher);
    let hash_hex = format!("{:x}", result);

    Ok((hash_hex, total_bytes))
}

// Helper function for MD5 (different trait)
fn calculate_md5_hash(file_path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = File::open(file_path).with_context(|| format!("open {:?}", file_path))?;

    // Get file size for validation
    let metadata = file
        .metadata()
        .with_context(|| format!("get metadata for {:?}", file_path))?;
    let file_size = metadata.len();

    // Validate file size
    if file_size > MAX_FILE_SIZE {
        bail!(
            "File too large for hashing: {} bytes (max: {} bytes)",
            file_size,
            MAX_FILE_SIZE
        );
    }

    // Stream the file in chunks
    let mut context = md5::Context::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read from {:?}", file_path))?;

        if bytes_read == 0 {
            break;
        }

        context.consume(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let digest = context.compute();
    let hash_hex = format!("{:x}", digest);

    Ok((hash_hex, total_bytes))
}

fn calculate_blake3_hash(file_path: &std::path::Path) -> Result<(String, u64)> {
    let mut file = File::open(file_path).with_context(|| format!("open {:?}", file_path))?;

    // Get file size for validation
    let metadata = file
        .metadata()
        .with_context(|| format!("get metadata for {:?}", file_path))?;
    let file_size = metadata.len();

    // Validate file size
    if file_size > MAX_FILE_SIZE {
        bail!(
            "File too large for hashing: {} bytes (max: {} bytes)",
            file_size,
            MAX_FILE_SIZE
        );
    }

    // Stream the file in chunks
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("read from {:?}", file_path))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let result = hasher.finalize();
    let hash_hex = result.to_hex().to_lowercase();

    Ok((hash_hex, total_bytes))
}

// Unified hash computation function for verify verb
fn compute_hash(path: &std::path::Path, algorithm: &str) -> Result<(String, u64)> {
    match algorithm.to_lowercase().as_str() {
        "sha256" => calculate_sha256_hash(path),
        "sha1" => calculate_sha1_hash(path),
        "md5" => calculate_md5_hash(path),
        "blake3" => calculate_blake3_hash(path),
        _ => bail!("unsupported algorithm: {}", algorithm),
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("file", |u| Ok(Box::new(FileHandle::from_url(u.clone())?)));
}

pub struct FileHandle {
    path: PathBuf,
}

fn unescape_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some(' ') => {
                    it.next();
                    out.push(' ');
                }
                Some('\\') => {
                    it.next();
                    out.push('\\');
                }
                Some('t') => {
                    it.next();
                    out.push('\t');
                }
                Some('n') => {
                    it.next();
                    out.push('\n');
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn normalize_path(p: &PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn resolve_file_path(path: &PathBuf) -> Result<PathBuf, anyhow::Error> {
    // If it's an absolute path or file exists as-is, use it
    if path.is_absolute() || path.is_file() {
        return Ok(path.clone());
    }

    // If it's a directory, we can't read it as a file
    if path.is_dir() {
        // Try to find the file in current working directory
        if path.is_relative() {
            let current_dir = std::env::current_dir()
                .with_context(|| "failed to get current working directory")?;
            let cwd_path = current_dir.join(path);
            if cwd_path.is_file() {
                return Ok(cwd_path);
            }
        }
        bail!("{:?} is a directory", path);
    }

    // For relative paths that don't exist, try in current working directory
    if path.is_relative() {
        let current_dir =
            std::env::current_dir().with_context(|| "failed to get current working directory")?;
        let cwd_path = current_dir.join(path);
        if cwd_path.is_file() {
            return Ok(cwd_path);
        }
    }

    // If all else fails, return the original path (will likely cause an error, but that's expected)
    Ok(path.clone())
}

impl FileHandle {
    pub fn from_url(url: Url) -> Result<FileHandle, anyhow::Error> {
        let path_str = if url.host_str().is_some() && !url.host_str().unwrap().is_empty() {
            // Handle case where filename is in host position (e.g., file://test.txt)
            url.host_str().unwrap()
        } else {
            url.path()
        };

        // Decode URL encoding and escape sequences
        let decoded = percent_decode_str(path_str).decode_utf8_lossy().to_string();
        let unescaped = unescape_backslashes(&decoded);
        let path = PathBuf::from(unescaped);
        let normalized = normalize_path(&path);

        Ok(FileHandle { path: normalized })
    }

    /// Process escape sequences in replacement text
    fn unescape_string(s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.peek() {
                    Some('n') => {
                        chars.next();
                        result.push('\n');
                    }
                    Some('t') => {
                        chars.next();
                        result.push('\t');
                    }
                    Some('\\') => {
                        chars.next();
                        result.push('\\');
                    }
                    _ => {
                        result.push(c);
                    }
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Perform literal string replacement with optional count limit
    fn literal_replace(content: &str, pattern: &str, replacement: &str, count_limit: Option<usize>) -> (String, usize) {
        if pattern.is_empty() {
            return (content.to_string(), 0);
        }

        let mut result = String::new();
        let mut last_end = 0;
        let mut count = 0;
        let max_count = count_limit.unwrap_or(usize::MAX);

        for mat in content.match_indices(pattern) {
            let start_pos = mat.0;
            
            if count >= max_count {
                break;
            }

            // Add content before the match
            result.push_str(&content[last_end..start_pos]);
            // Add replacement
            result.push_str(replacement);
            
            last_end = start_pos + pattern.len();
            count += 1;
        }

        // Add remaining content
        result.push_str(&content[last_end..]);
        
        (result, count)
    }

    fn do_grep(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if pattern is provided
        let pattern = match args.get("pattern") {
            Some(p) => p,
            None => return Ok(Status::err(2, "missing arg: pattern")),
        };

        // Parse optional arguments with proper defaults
        let use_regex = match args.get("regex").map(String::as_str) {
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Ok(Status::err(
                    2,
                    format!("invalid value for regex: {}", other),
                ));
            }
            None => true, // default true
        };

        let ignore_case = match args.get("ignore_case").map(String::as_str) {
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Ok(Status::err(
                    2,
                    format!("invalid value for ignore_case: {}", other),
                ));
            }
            None => false, // default false
        };

        let max_matches = match args.get("max") {
            Some(s) => match s.parse::<usize>() {
                Ok(n) => Some(n),
                Err(_) => return Ok(Status::err(2, format!("invalid value for max: {}", s))),
            },
            None => None,
        };

        let before_context = match args.get("before") {
            Some(s) => match s.parse::<usize>() {
                Ok(n) => n,
                Err(_) => return Ok(Status::err(2, format!("invalid value for before: {}", s))),
            },
            None => 0,
        };

        let after_context = match args.get("after") {
            Some(s) => match s.parse::<usize>() {
                Ok(n) => n,
                Err(_) => return Ok(Status::err(2, format!("invalid value for after: {}", s))),
            },
            None => 0,
        };

        let invert = match args.get("invert").map(String::as_str) {
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Ok(Status::err(
                    2,
                    format!("invalid value for invert: {}", other),
                ));
            }
            None => false, // default false
        };

        let format = match args.get("format").map(String::as_str) {
            Some("text") | None => "text",
            Some("json") => "json",
            Some(other) => {
                return Ok(Status::err(
                    2,
                    format!("invalid value for format: {}", other),
                ));
            }
        };

        let line_numbers = match args.get("line_numbers").map(String::as_str) {
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Ok(Status::err(
                    2,
                    format!("invalid value for line_numbers: {}", other),
                ));
            }
            None => {
                // Default true for text mode, can be overridden
                if format == "text" { true } else { false }
            }
        };

        // Check if file exists
        if !self.path.exists() {
            return Ok(Status::err(2, "file does not exist"));
        }

        // Check if it's a directory (not supported in this implementation)
        if self.path.is_dir() {
            return Ok(Status::err(2, "path is a directory, not a file"));
        }

        // Build matcher function
        let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
            match if ignore_case {
                RegexBuilder::new(pattern).case_insensitive(true).build()
            } else {
                Regex::new(pattern)
            } {
                Ok(regex) => Box::new(move |line: &str| regex.is_match(line)),
                Err(e) => return Ok(Status::err(2, format!("invalid regex: {}", e))),
            }
        } else {
            let pattern_owned = pattern.to_string();
            if ignore_case {
                let pattern_lower = pattern.to_lowercase();
                Box::new(move |line: &str| line.to_lowercase().contains(&pattern_lower))
            } else {
                Box::new(move |line: &str| line.contains(&pattern_owned))
            }
        };

        // Open and read file
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                writeln!(io.stderr, "Error opening file: {}", e)?;
                return Ok(Status::err(2, format!("error opening file: {}", e)));
            }
        };

        let reader = BufReader::new(file);
        let mut line_number = 1usize;
        let mut matches_found = 0usize;
        let mut all_lines = Vec::new();
        let mut matching_lines = Vec::new();

        // Read all lines first to handle context properly
        for line_result in reader.lines() {
            match line_result {
                Ok(line_text) => {
                    let is_match = matcher(&line_text) ^ invert; // XOR with invert flag
                    all_lines.push((line_number, line_text, is_match));
                    if is_match {
                        matching_lines.push(line_number - 1); // Store 0-based index
                        matches_found += 1;

                        // Check max matches limit
                        if let Some(max) = max_matches {
                            if matches_found >= max {
                                break;
                            }
                        }
                    }
                    line_number += 1;
                }
                Err(_) => {
                    // Use lossy UTF-8 conversion for non-UTF-8 content
                    // This is a simple fallback - in production you might want more sophisticated handling
                    continue;
                }
            }
        }

        // If no matches found, return appropriate status
        if matches_found == 0 {
            return Ok(Status::err(1, "no matches"));
        }

        // Generate output
        if format == "json" {
            let mut results = Vec::new();

            for &match_idx in &matching_lines {
                if let Some((line_num, line_text, _)) = all_lines.get(match_idx) {
                    let result = serde_json::json!({
                        "path": self.path.to_string_lossy(),
                        "line": line_num,
                        "text": line_text,
                        "matched": true
                    });
                    results.push(result);

                    // Apply max limit in output
                    if let Some(max) = max_matches {
                        if results.len() >= max {
                            break;
                        }
                    }
                }
            }

            writeln!(
                io.stdout,
                "{}",
                serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
            )?;
        } else {
            // Text format with context
            let mut output_lines = std::collections::HashSet::new();

            for &match_idx in &matching_lines {
                // Add before context
                for i in (match_idx.saturating_sub(before_context))..match_idx {
                    output_lines.insert(i);
                }

                // Add the match itself
                output_lines.insert(match_idx);

                // Add after context
                for i in (match_idx + 1)
                    ..=(match_idx + after_context).min(all_lines.len().saturating_sub(1))
                {
                    output_lines.insert(i);
                }

                // Check max limit
                if let Some(max) = max_matches {
                    if output_lines.len() >= max * (1 + before_context + after_context) {
                        break;
                    }
                }
            }

            let mut sorted_output: Vec<_> = output_lines.into_iter().collect();
            sorted_output.sort();

            let mut output_count = 0;
            for &idx in &sorted_output {
                if let Some((line_num, line_text, is_match)) = all_lines.get(idx) {
                    if line_numbers {
                        if before_context > 0 || after_context > 0 {
                            // Use grep-style prefixes for context
                            let prefix = if *is_match { ":" } else { "-" };
                            writeln!(io.stdout, "{}{}:{}", prefix, line_num, line_text)?;
                        } else {
                            writeln!(io.stdout, "{}:{}", line_num, line_text)?;
                        }
                    } else {
                        writeln!(io.stdout, "{}", line_text)?;
                    }

                    // Only count actual matches for max limit, not context lines
                    if *is_match {
                        output_count += 1;
                        if let Some(max) = max_matches {
                            if output_count >= max {
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(Status::ok())
    }

    fn handle_find(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments with defaults
        let name_pattern = args.get("name");
        let entry_type = args.get("type").map(String::as_str);

        // Parse max_depth
        let max_depth = args
            .get("max_depth")
            .map(|s| s.parse::<u64>().with_context(|| "invalid max_depth"))
            .transpose()?;

        // Parse follow_symlinks (case-insensitive)
        let follow_symlinks = args
            .get("follow_symlinks")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        // Parse include_hidden (case-insensitive)
        let include_hidden = args
            .get("include_hidden")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        // Parse limit
        let limit = args
            .get("limit")
            .map(|s| s.parse::<u64>().with_context(|| "invalid limit"))
            .transpose()?;

        // Validate type parameter
        if let Some(t) = entry_type {
            match t {
                "file" | "dir" | "symlink" => {}
                _ => return Ok(Status::err(2, "invalid type")),
            }
        }

        // Build glob matcher if name pattern is provided
        let glob_matcher = if let Some(pattern_str) = name_pattern {
            Some(
                Glob::new(pattern_str)
                    .with_context(|| "invalid name pattern")?
                    .compile_matcher(),
            )
        } else {
            None
        };

        // Check if root path exists
        let resolved_path = resolve_file_path(&self.path)?;
        if !resolved_path.exists() {
            return Ok(Status::err(2, "path not found"));
        }

        let mut results = Vec::new();
        let mut visited_inodes = HashSet::new(); // For symlink loop detection

        // Handle single file case
        if resolved_path.is_file() {
            if self.matches_filters(
                &resolved_path,
                &glob_matcher,
                entry_type,
                include_hidden,
                0,
                &mut visited_inodes,
            )? {
                if let Some(entry) = self.create_find_entry(&resolved_path, 0)? {
                    results.push(entry);
                }
            }
        } else {
            // Directory traversal
            self.traverse_directory(
                &resolved_path,
                &glob_matcher,
                entry_type,
                max_depth,
                follow_symlinks,
                include_hidden,
                limit,
                &mut results,
                &mut visited_inodes,
            )?;
        }

        // Write JSON array to stdout
        serde_json::to_writer(&mut io.stdout, &results)?;
        writeln!(io.stdout)?;

        Ok(Status::ok())
    }

    fn matches_filters(
        &self,
        path: &std::path::Path,
        glob_matcher: &Option<globset::GlobMatcher>,
        entry_type: Option<&str>,
        include_hidden: bool,
        _depth: u32,
        _visited_inodes: &mut HashSet<(u64, u64)>,
    ) -> Result<bool> {
        use std::fs;

        // Get file name for pattern matching and hidden check
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Hidden filter
        if !include_hidden && file_name.starts_with('.') {
            // Always include root even if hidden
            if path != &self.path {
                return Ok(false);
            }
        }

        // Name pattern filter
        if let Some(matcher) = glob_matcher {
            if !matcher.is_match(file_name) {
                return Ok(false);
            }
        }

        // Type filter
        if let Some(expected_type) = entry_type {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to get metadata for {:?}", path))?;

            let file_type = metadata.file_type();
            let matches_type = match expected_type {
                "file" => file_type.is_file(),
                "dir" => file_type.is_dir(),
                "symlink" => file_type.is_symlink(),
                _ => false,
            };

            if !matches_type {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn create_find_entry(
        &self,
        path: &std::path::Path,
        depth: u32,
    ) -> Result<Option<serde_json::Value>> {
        use std::fs;

        let metadata = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(None), // Skip if we can't read metadata
        };

        // Determine type
        let file_type = metadata.file_type();
        let type_str = if file_type.is_file() {
            "file"
        } else if file_type.is_dir() {
            "dir"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };

        // Get absolute path
        let abs_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        // Get size (0 for non-files)
        let size = if file_type.is_file() {
            metadata.len()
        } else {
            0
        };

        // Get mode (Unix-specific)
        let mode_str = {
            #[cfg(unix)]
            {
                format!("{:04o}", metadata.permissions().mode() & 0o7777)
            }
            #[cfg(not(unix))]
            {
                "0".to_string()
            }
        };

        // Get mtime in UTC RFC3339 format
        let mtime_str = metadata
            .modified()
            .ok()
            .map(|time| DateTime::<Utc>::from(time).to_rfc3339())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

        // Check if hidden
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let is_hidden = file_name.starts_with('.');

        Ok(Some(serde_json::json!({
            "path": abs_path.to_string_lossy(),
            "type": type_str,
            "size": size,
            "mode": mode_str,
            "mtime": mtime_str,
            "is_hidden": is_hidden,
            "depth": depth
        })))
    }

    fn traverse_directory(
        &self,
        root: &std::path::Path,
        glob_matcher: &Option<globset::GlobMatcher>,
        entry_type: Option<&str>,
        max_depth: Option<u64>,
        follow_symlinks: bool,
        include_hidden: bool,
        limit: Option<u64>,
        results: &mut Vec<serde_json::Value>,
        visited_inodes: &mut HashSet<(u64, u64)>,
    ) -> Result<()> {
        // Configure walker
        let walker = if let Some(depth) = max_depth {
            WalkDir::new(root)
                .follow_links(follow_symlinks)
                .max_depth(depth as usize)
                .sort_by_file_name()
        } else {
            WalkDir::new(root)
                .follow_links(follow_symlinks)
                .sort_by_file_name()
        };

        for entry in walker {
            // Check limit
            if let Some(lim) = limit {
                if results.len() >= lim as usize {
                    break;
                }
            }

            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    // Log error to stderr but continue
                    let _ = writeln!(&mut std::io::stderr(), "Warning: {}", err);
                    continue;
                }
            };

            let entry_path = entry.path();
            let depth = entry.depth() as u32;

            // Symlink loop detection
            if follow_symlinks {
                if let Ok(metadata) = entry_path.symlink_metadata() {
                    #[cfg(unix)]
                    {
                        let inode = (metadata.dev(), metadata.ino());
                        if metadata.is_dir() && !visited_inodes.insert(inode) {
                            continue; // Skip already visited directory
                        }
                    }
                }
            }

            if self.matches_filters(
                entry_path,
                glob_matcher,
                entry_type,
                include_hidden,
                depth,
                visited_inodes,
            )? {
                if let Some(find_entry) = self.create_find_entry(entry_path, depth)? {
                    results.push(find_entry);
                }
            }
        }

        Ok(())
    }

    fn do_replace(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        use std::io::{Read, Write};
        use std::process;

        // Required argument: pattern
        let pattern = args
            .get("pattern")
            .ok_or_else(|| anyhow::anyhow!("missing arg: pattern"))?;

        // Required argument: replacement
        let replacement_raw = args
            .get("replacement")
            .ok_or_else(|| anyhow::anyhow!("missing arg: replacement"))?;

        // Process escape sequences in replacement
        let replacement = Self::unescape_string(replacement_raw);

        // Parse regex flag (default: false for literal replacement)
        let use_regex = args
            .get("regex")
            .map(|s| s.to_lowercase())
            .map(|s| s == "true")
            .unwrap_or(false);

        // Parse count replacements (default: unlimited)
        let count_limit = args
            .get("count")
            .map(|s| {
                s.parse::<usize>()
                    .with_context(|| format!("Invalid count value: {}", s))
            })
            .transpose()?;

        // Parse dry run flag (default: false)
        let dry_run = args
            .get("dry_run")
            .map(|s| s.to_lowercase())
            .map(|s| s == "true")
            .unwrap_or(false);

        // Parse backup suffix (optional - not in requirements but keeping for compatibility)
        let backup_suffix = args.get("backup");

        // Resolve the file path
        let resolved_path = resolve_file_path(&self.path)
            .with_context(|| format!("failed to resolve file path: {:?}", self.path))?;

        // Check if file exists and is readable
        if !resolved_path.exists() {
            let error_msg = format!("file does not exist: {:?}", resolved_path);
            writeln!(io.stderr, "{}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }

        if !resolved_path.is_file() {
            let error_msg = format!("{:?} is not a file", resolved_path);
            writeln!(io.stderr, "{}", error_msg)?;
            return Ok(Status::err(1, error_msg));
        }

        // Read the file content
        let mut file_content = String::new();
        {
            let mut file = File::open(&resolved_path)
                .with_context(|| format!("failed to read file: {:?}", resolved_path))?;
            file.read_to_string(&mut file_content)
                .with_context(|| format!("file is not valid UTF-8: {:?}", resolved_path))?;
        }

        // Perform replacement
        let (new_content, replacements_count) = if use_regex {
            // Regex replacement
            let regex = match regex::Regex::new(pattern) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(Status::err(2, format!("invalid regex: {}", e)));
                }
            };

            if let Some(max) = count_limit {
                // Limited replacements
                let mut count = 0;
                let mut new_content = String::new();
                let mut last_match_end = 0;
                
                for mat in regex.find_iter(&file_content) {
                    if count >= max {
                        break;
                    }
                    new_content.push_str(&file_content[last_match_end..mat.start()]);
                    new_content.push_str(&replacement);
                    last_match_end = mat.end();
                    count += 1;
                }
                new_content.push_str(&file_content[last_match_end..]);
                (new_content, count)
            } else {
                // Unlimited replacements
                let count = regex.find_iter(&file_content).count();
                let result = regex.replace_all(&file_content, replacement.as_str());
                (result.to_string(), count)
            }
        } else {
            // Literal replacement
            Self::literal_replace(&file_content, pattern, &replacement, count_limit)
        };

        // Get file sizes
        let original_bytes = file_content.len() as u64;
        let new_bytes = new_content.len() as u64;
        let changed = replacements_count > 0 && !dry_run;

        // Prepare JSON response per requirements
        let response = serde_json::json!({
            "path": resolved_path.to_string_lossy(),
            "pattern": pattern,
            "regex": use_regex,
            "count_limit": count_limit,
            "replacements": replacements_count,
            "changed": changed,
            "original_bytes": original_bytes,
            "new_bytes": new_bytes,
            "dry_run": dry_run
        });

        // Write JSON to stdout
        let response_str = serde_json::to_string(&response)
            .with_context(|| "failed to serialize response JSON")?;
        writeln!(io.stdout, "{}", response_str)?;

        // If dry run, don't modify the file
        if dry_run {
            return Ok(Status::ok());
        }

        // If no replacements were made, don't modify the file
        if replacements_count == 0 {
            return Ok(Status::ok());
        }

        // Create backup if requested
        if let Some(suffix) = backup_suffix {
            let backup_path = format!("{}{}", resolved_path.to_string_lossy(), suffix);
            let backup_pathbuf = PathBuf::from(&backup_path);

            std::fs::copy(&resolved_path, &backup_pathbuf)
                .with_context(|| format!("failed to create backup: {:?}", backup_pathbuf))?;
        }

        // Atomic write using temporary file
        let temp_path = {
            let pid = process::id();
            let random = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let mut temp_path = resolved_path.clone();
            let temp_name = format!(
                ".{}.resh.tmp-{}-{}",
                temp_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file"),
                pid,
                random
            );
            temp_path.set_file_name(temp_name);
            temp_path
        };

        // Write to temporary file
        {
            let mut temp_file = File::create(&temp_path)
                .with_context(|| format!("failed to create temporary file: {:?}", temp_path))?;
            temp_file
                .write_all(new_content.as_bytes())
                .with_context(|| format!("failed to write to temporary file: {:?}", temp_path))?;
            temp_file
                .flush()
                .with_context(|| format!("failed to flush temporary file: {:?}", temp_path))?;
        }

        // Atomic rename
        std::fs::rename(&temp_path, &resolved_path).with_context(|| {
            // Clean up temp file on error
            let _ = std::fs::remove_file(&temp_path);
            format!(
                "failed to rename temporary file to target: {:?}",
                resolved_path
            )
        })?;

        Ok(Status::ok())
    }

    fn do_tail(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let lines_arg = args.get("lines");
        let bytes_arg = args.get("bytes");
        let follow_arg = args.get("follow");

        // Validate mutually exclusive arguments
        if lines_arg.is_some() && bytes_arg.is_some() {
            writeln!(io.stderr, "Error: 'lines' and 'bytes' arguments cannot be used together")?;
            return Ok(Status::err(1, "lines and bytes are mutually exclusive"));
        }

        // Parse and validate lines argument
        let num_lines = if let Some(lines_str) = lines_arg {
            match lines_str.parse::<usize>() {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    writeln!(io.stderr, "Error: lines argument must be greater than 0")?;
                    return Ok(Status::err(1, "invalid lines argument: must be > 0"));
                }
                Err(_) => {
                    writeln!(io.stderr, "Error: invalid lines argument: {}", lines_str)?;
                    return Ok(Status::err(1, "invalid lines argument: not a number"));
                }
            }
        } else if bytes_arg.is_none() {
            10 // Default to 10 lines if neither lines nor bytes specified
        } else {
            0 // Will use bytes mode instead
        };

        // Parse and validate bytes argument
        let num_bytes = if let Some(bytes_str) = bytes_arg {
            match bytes_str.parse::<usize>() {
                Ok(n) if n > 0 => Some(n),
                Ok(_) => {
                    writeln!(io.stderr, "Error: bytes argument must be greater than 0")?;
                    return Ok(Status::err(1, "invalid bytes argument: must be > 0"));
                }
                Err(_) => {
                    writeln!(io.stderr, "Error: invalid bytes argument: {}", bytes_str)?;
                    return Ok(Status::err(1, "invalid bytes argument: not a number"));
                }
            }
        } else {
            None
        };

        // Parse follow argument
        let follow = follow_arg
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        // Resolve file path
        let resolved_path = resolve_file_path(&self.path)?;

        // Check if file exists
        if !resolved_path.exists() {
            writeln!(io.stderr, "Error: file does not exist: {}", resolved_path.display())?;
            return Ok(Status::err(2, "file does not exist"));
        }

        // Check if path is a file
        if !resolved_path.is_file() {
            writeln!(io.stderr, "Error: {} is not a file", resolved_path.display())?;
            return Ok(Status::err(1, "path is not a file"));
        }

        // Open file
        let mut file = match File::open(&resolved_path) {
            Ok(f) => f,
            Err(e) => {
                writeln!(io.stderr, "Error: failed to open file: {}", e)?;
                return Ok(Status::err(1, "failed to open file"));
            }
        };

        // Get initial file size
        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(e) => {
                writeln!(io.stderr, "Error: failed to get file metadata: {}", e)?;
                return Ok(Status::err(1, "failed to get file metadata"));
            }
        };
        let file_size = metadata.len();

        // Handle empty file
        if file_size == 0 {
            if follow {
                // For follow mode on empty file, wait for content
                return self.tail_follow_mode(&resolved_path, file_size, num_lines, num_bytes, io);
            } else {
                // Non-follow mode: output nothing and return success
                return Ok(Status::ok());
            }
        }

        // Perform initial tail output
        if let Some(bytes) = num_bytes {
            // Bytes mode
            if let Err(e) = self.tail_by_bytes(&mut file, file_size, bytes, io) {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(1, "tail operation failed"));
            }
        } else {
            // Lines mode
            if let Err(e) = self.tail_by_lines(&mut file, file_size, num_lines, io) {
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(1, "tail operation failed"));
            }
        }

        // Enter follow mode if requested
        if follow {
            return self.tail_follow_mode(&resolved_path, file_size, num_lines, num_bytes, io);
        }

        Ok(Status::ok())
    }

    fn tail_by_bytes(
        &self,
        file: &mut File,
        file_size: u64,
        num_bytes: usize,
        io: &mut IoStreams,
    ) -> Result<()> {
        let bytes_to_read = std::cmp::min(num_bytes as u64, file_size) as usize;

        // Calculate start position
        let start_pos = if bytes_to_read as u64 >= file_size {
            0
        } else {
            file_size - bytes_to_read as u64
        };

        // Seek to position
        file.seek(SeekFrom::Start(start_pos))
            .with_context(|| "failed to seek to tail position")?;

        // Read and output the bytes directly (no encoding transformation)
        let mut buffer = vec![0u8; bytes_to_read];
        file.read_exact(&mut buffer)
            .with_context(|| "failed to read tail bytes")?;

        // Output raw bytes to stdout
        io.stdout.write_all(&buffer)
            .with_context(|| "failed to write to stdout")?;

        Ok(())
    }

    fn tail_by_lines(
        &self,
        file: &mut File,
        file_size: u64,
        num_lines: usize,
        io: &mut IoStreams,
    ) -> Result<()> {
        if num_lines == 0 {
            return Ok(()); // Nothing to output
        }

        // Use backward scanning with fixed-size chunks for efficiency
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

            // Count newlines in the buffer - treat \n as line delimiter
            lines_found = buffer.iter().filter(|&&b| b == b'\n').count();

            // Stop if we have enough lines or reached start of file
            if lines_found >= num_lines || chunk_start == 0 {
                break;
            }

            pos = chunk_start;
        }

        // Extract the last N lines from buffer
        if lines_found == 0 {
            // No newlines found - treat entire buffer as one line and output it
            io.stdout.write_all(&buffer)
                .with_context(|| "failed to write to stdout")?;
        } else {
            // Calculate how many lines to skip from the beginning
            let skip_lines = if lines_found > num_lines {
                lines_found - num_lines
            } else {
                0
            };

            // Find start position after skipping the specified number of lines
            let mut newline_count = 0;
            let mut start_pos = 0;

            for (i, &byte) in buffer.iter().enumerate() {
                if byte == b'\n' {
                    newline_count += 1;
                    if newline_count == skip_lines {
                        start_pos = i + 1; // Start after this newline
                        break;
                    }
                }
            }

            // Output the tail portion
            let tail_bytes = &buffer[start_pos..];
            io.stdout.write_all(tail_bytes)
                .with_context(|| "failed to write to stdout")?;
        }

        Ok(())
    }

    fn tail_follow_mode(
        &self,
        file_path: &PathBuf,
        mut last_size: u64,
        _num_lines: usize,
        _num_bytes: Option<usize>,
        io: &mut IoStreams,
    ) -> Result<Status> {
        let poll_interval = Duration::from_millis(250);

        loop {
            // Check current file size
            let current_metadata = match std::fs::metadata(file_path) {
                Ok(m) => m,
                Err(e) => {
                    writeln!(io.stderr, "Error: file disappeared or became unreadable: {}", e)?;
                    return Ok(Status::err(1, "file became unreadable during follow"));
                }
            };

            let current_size = current_metadata.len();

            if current_size > last_size {
                // File grew - read and output new content
                let mut file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        writeln!(io.stderr, "Error: failed to reopen file: {}", e)?;
                        return Ok(Status::err(1, "failed to reopen file during follow"));
                    }
                };

                // Seek to where we left off
                if let Err(e) = file.seek(SeekFrom::Start(last_size)) {
                    writeln!(io.stderr, "Error: failed to seek in file: {}", e)?;
                    return Ok(Status::err(1, "seek error during follow"));
                }

                // Read and output new data
                let new_size = current_size - last_size;
                let mut buffer = vec![0u8; new_size as usize];
                if let Err(e) = file.read_exact(&mut buffer) {
                    writeln!(io.stderr, "Error: failed to read new content: {}", e)?;
                    return Ok(Status::err(1, "read error during follow"));
                }

                if let Err(e) = io.stdout.write_all(&buffer) {
                    writeln!(io.stderr, "Error: failed to write to stdout: {}", e)?;
                    return Ok(Status::err(1, "write error during follow"));
                }

                last_size = current_size;
            } else if current_size < last_size {
                // File was truncated - treat as if file was reopened
                last_size = current_size;
            }

            // Sleep before next poll
            std::thread::sleep(poll_interval);

            // Check if stdin has been closed (simple way to detect termination)
            // Note: This is a simplified implementation - in a real shell this would
            // be handled by signal handling or other termination mechanisms
        }
    }

    fn do_preview(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments with defaults
        let max_bytes: u64 = args
            .get("max_bytes")
            .and_then(|s| s.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(4096);

        let max_lines: usize = args
            .get("max_lines")
            .and_then(|s| s.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(40);

        let mode = args
            .get("mode")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "auto".to_string());

        let encoding = args
            .get("encoding")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "base64".to_string());

        let include_metadata = args
            .get("include_metadata")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(true);

        // Resolve and validate file path
        let resolved_path = resolve_file_path(&self.path)?;

        // Open file and read preview data
        let mut file = match File::open(&resolved_path) {
            Ok(f) => f,
            Err(e) => {
                return Ok(Status::err(1, &format!("failed to open file: {}", e)));
            }
        };

        // Get file metadata first
        let file_metadata = resolved_path.metadata().ok();
        let file_size_bytes = file_metadata.as_ref().map(|m| m.len()).unwrap_or(0);

        // Read preview data
        let mut buffer = vec![0u8; max_bytes as usize];
        let preview_len_bytes = match file.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                n as u64
            }
            Err(e) => {
                return Ok(Status::err(2, &format!("failed to read file: {}", e)));
            }
        };

        let is_truncated = file_size_bytes > preview_len_bytes;

        // Determine actual mode (auto-detection if needed)
        let (actual_mode, sample, line_count) = match mode.as_str() {
            "text" => {
                // Force text mode
                let text = String::from_utf8_lossy(&buffer);
                let lines = if max_lines > 0 {
                    let all_lines: Vec<&str> = text.split('\n').collect();
                    if all_lines.len() > max_lines {
                        all_lines[..max_lines].join("\n")
                    } else {
                        text.to_string()
                    }
                } else {
                    text.to_string()
                };
                let line_count = lines.matches('\n').count() + if lines.is_empty() { 0 } else { 1 };
                ("text".to_string(), lines, Some(line_count))
            }
            "binary" => {
                // Force binary mode
                let encoded = self.encode_binary_data(&buffer, &encoding);
                ("binary".to_string(), encoded, None)
            }
            "auto" | _ => {
                // Auto-detect based on content
                if self.is_binary_content(&buffer) {
                    let encoded = self.encode_binary_data(&buffer, &encoding);
                    ("binary".to_string(), encoded, None)
                } else {
                    let text = String::from_utf8_lossy(&buffer);
                    let lines = if max_lines > 0 {
                        let all_lines: Vec<&str> = text.split('\n').collect();
                        if all_lines.len() > max_lines {
                            all_lines[..max_lines].join("\n")
                        } else {
                            text.to_string()
                        }
                    } else {
                        text.to_string()
                    };
                    let line_count = lines.matches('\n').count() + if lines.is_empty() { 0 } else { 1 };
                    ("text".to_string(), lines, Some(line_count))
                }
            }
        };

        // Build JSON response
        let mut json_obj = json!({
            "path": resolved_path.display().to_string(),
            "mode": actual_mode,
            "preview_len_bytes": preview_len_bytes,
            "file_size_bytes": file_size_bytes,
            "is_truncated": is_truncated,
            "sample": sample,
            "encoding": if actual_mode == "text" { "utf-8" } else { encoding.as_str() }
        });

        if let Some(count) = line_count {
            json_obj["line_count"] = json!(count);
        } else {
            json_obj["line_count"] = json!(null);
        }

        // Add metadata if requested
        if include_metadata {
            if let Some(metadata) = file_metadata {
                let mut metadata_obj = json!({
                    "exists": true,
                    "is_file": metadata.is_file(),
                    "is_dir": metadata.is_dir()
                });

                // Add permissions (Unix only)
                #[cfg(unix)]
                {
                    metadata_obj["permissions"] = json!(format!("{:04o}", metadata.permissions().mode() & 0o777));
                }
                #[cfg(not(unix))]
                {
                    metadata_obj["permissions"] = json!("unknown");
                }

                // Add modification time
                if let Ok(modified) = metadata.modified() {
                    let datetime = DateTime::<Utc>::from(modified);
                    metadata_obj["modified"] = json!(datetime.to_rfc3339());
                } else {
                    metadata_obj["modified"] = json!(null);
                }

                json_obj["metadata"] = metadata_obj;
            } else {
                json_obj["metadata"] = json!({
                    "exists": false,
                    "is_file": false,
                    "is_dir": false,
                    "permissions": null,
                    "modified": null
                });
            }
        }

        // Output JSON
        writeln!(io.stdout, "{}", json_obj)?;
        Ok(Status::ok())
    }

    /// Detect if content is binary based on presence of control characters
    fn is_binary_content(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let mut control_count = 0;
        for &byte in data {
            // Count control characters, excluding common text characters
            if byte < 0x20 && byte != b'\n' && byte != b'\r' && byte != b'\t' {
                control_count += 1;
            }
        }

        // If more than 10% are control characters, consider it binary
        control_count * 10 > data.len()
    }

    /// Encode binary data according to the specified encoding
    fn encode_binary_data(&self, data: &[u8], encoding: &str) -> String {
        match encoding {
            "hex" => {
                data.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            }
            "base64" | _ => {
                BASE64_STANDARD.encode(data)
            }
        }
    }

    fn do_schema(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments with defaults
        let max_bytes = args
            .get("max_bytes")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(65536); // 64KB default

        let max_rows = args
            .get("max_rows")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(100);

        let format_override = args.get("format").map(|s| s.to_lowercase());

        // Resolve file path
        let resolved_path = resolve_file_path(&self.path).map_err(|e| {
            let _ = writeln!(io.stderr, "Error resolving path: {}", e);
            e
        })?;

        // Check if file exists
        if !resolved_path.exists() {
            return Ok(Status::err(
                2,
                &format!("schema: file not found: {:?}", resolved_path),
            ));
        }

        // Open file and read sample
        let mut file = File::open(&resolved_path).map_err(|e| {
            let status_msg = format!("schema: cannot open file: {}", e);
            let _ = writeln!(io.stderr, "Error: {}", status_msg);
            anyhow::anyhow!(status_msg)
        })?;

        let mut buffer = vec![0u8; max_bytes];
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            let status_msg = format!("schema: cannot read file: {}", e);
            let _ = writeln!(io.stderr, "Error: {}", status_msg);
            anyhow::anyhow!(status_msg)
        })?;

        buffer.truncate(bytes_read);

        // Convert to string for analysis
        let content_str = String::from_utf8_lossy(&buffer);

        // Determine format
        let detected_format = match format_override.as_deref() {
            Some("json") => "json",
            Some("ndjson") => "ndjson",
            Some("csv") => "csv",
            Some("tsv") => "tsv",
            Some("text") => "text",
            Some(other) => {
                return Ok(Status::err(
                    1,
                    &format!("schema: unsupported format override: {}", other),
                ));
            }
            None => detect_format(&content_str),
        };

        // Generate schema based on format
        let schema_result = match detected_format {
            "json" => analyze_json(&content_str, &resolved_path, bytes_read, max_rows),
            "ndjson" => analyze_ndjson(&content_str, &resolved_path, bytes_read, max_rows),
            "csv" => analyze_csv(&content_str, &resolved_path, bytes_read, max_rows),
            "tsv" => analyze_tsv(&content_str, &resolved_path, bytes_read, max_rows),
            "text" => analyze_text(&content_str, &resolved_path, bytes_read),
            _ => analyze_text(&content_str, &resolved_path, bytes_read), // fallback
        };

        let schema_json = match schema_result {
            Ok(schema) => schema,
            Err(e) => {
                return Ok(Status::err(3, &format!("schema: analysis failed: {}", e)));
            }
        };

        // Write JSON schema to stdout
        writeln!(
            io.stdout,
            "{}",
            serde_json::to_string(&schema_json).map_err(|e| {
                let status_msg = format!("schema: JSON serialization failed: {}", e);
                let _ = writeln!(io.stderr, "Error: {}", status_msg);
                anyhow::anyhow!(status_msg)
            })?
        )?;

        Ok(Status::ok())
    }
}

// Schema analysis helper functions

fn detect_format(content: &str) -> &'static str {
    let trimmed = content.trim();

    if trimmed.is_empty() {
        return "text";
    }

    // Try JSON first
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return "json";
        }
    }

    // Check for NDJSON (multiple lines with JSON objects)
    let lines: Vec<_> = trimmed.lines().take(5).collect();
    if lines.len() >= 2 {
        let mut json_lines = 0;
        for line in &lines {
            let line = line.trim();
            if line.starts_with('{') && line.ends_with('}') {
                if serde_json::from_str::<serde_json::Value>(line).is_ok() {
                    json_lines += 1;
                }
            }
        }
        if json_lines >= 2 {
            return "ndjson";
        }
    }

    // Check for CSV/TSV patterns
    let first_line = trimmed.lines().next().unwrap_or("");
    if first_line.contains(',') && first_line.matches(',').count() >= 1 {
        return "csv";
    }
    if first_line.contains('\t') && first_line.matches('\t').count() >= 1 {
        return "tsv";
    }

    "text"
}

fn analyze_json(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
    max_rows: usize,
) -> Result<serde_json::Value> {
    let json_value: serde_json::Value =
        serde_json::from_str(content).with_context(|| "failed to parse JSON")?;

    let mut schema = json!({
        "path": path.to_string_lossy(),
        "format": "json",
        "encoding": "utf-8",
        "byte_sample": byte_sample
    });

    match &json_value {
        serde_json::Value::Array(arr) => {
            let record_count = std::cmp::min(arr.len(), max_rows);
            let fields = infer_fields_from_objects(arr.iter().take(max_rows).collect())?;

            schema["detected"] = json!({
                "json_type": "array",
                "record_count_sampled": record_count,
                "fields": fields
            });
        }
        serde_json::Value::Object(_) => {
            let fields = infer_fields_from_objects(vec![&json_value])?;

            schema["detected"] = json!({
                "json_type": "object",
                "record_count_sampled": 1,
                "fields": fields
            });
        }
        _ => {
            schema["detected"] = json!({
                "json_type": infer_json_type(&json_value),
                "record_count_sampled": 1
            });
        }
    }

    Ok(schema)
}

fn analyze_ndjson(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
    max_rows: usize,
) -> Result<serde_json::Value> {
    let mut objects = Vec::new();
    let mut lines_processed = 0;

    for line in content.lines() {
        if lines_processed >= max_rows {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                if value.is_object() {
                    objects.push(value);
                    lines_processed += 1;
                }
            }
            Err(_) => continue, // Skip invalid JSON lines
        }
    }

    let fields = infer_fields_from_objects(objects.iter().collect())?;

    let schema = json!({
        "path": path.to_string_lossy(),
        "format": "ndjson",
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "record_count_sampled": objects.len(),
            "fields": fields
        }
    });

    Ok(schema)
}

fn analyze_csv(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
    max_rows: usize,
) -> Result<serde_json::Value> {
    analyze_delimited(content, path, byte_sample, max_rows, ',', "csv")
}

fn analyze_tsv(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
    max_rows: usize,
) -> Result<serde_json::Value> {
    analyze_delimited(content, path, byte_sample, max_rows, '\t', "tsv")
}

fn analyze_delimited(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
    max_rows: usize,
    delimiter: char,
    format: &str,
) -> Result<serde_json::Value> {
    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        bail!("empty file");
    }

    // Assume first line is header
    let header_line = lines[0];
    let headers: Vec<String> = header_line
        .split(delimiter)
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect();

    let mut columns = Vec::new();
    for (i, header) in headers.iter().enumerate() {
        let mut column_values = Vec::new();

        // Collect values from data rows (skip header)
        for line in lines.iter().skip(1).take(max_rows.saturating_sub(1)) {
            let fields: Vec<&str> = line.split(delimiter).collect();
            if let Some(value) = fields.get(i) {
                column_values.push(value.trim().trim_matches('"'));
            }
        }

        let types = infer_column_types(&column_values);
        columns.push(json!({
            "name": header,
            "types": types
        }));
    }

    let row_count_sampled =
        std::cmp::min(lines.len().saturating_sub(1), max_rows.saturating_sub(1));

    let schema = json!({
        "path": path.to_string_lossy(),
        "format": format,
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "delimiter": delimiter.to_string(),
            "has_header": true,
            "columns": columns,
            "row_count_sampled": row_count_sampled
        }
    });

    Ok(schema)
}

fn analyze_text(
    content: &str,
    path: &std::path::Path,
    byte_sample: usize,
) -> Result<serde_json::Value> {
    let lines: Vec<&str> = content.lines().collect();
    let line_count = lines.len();

    let total_chars: usize = lines.iter().map(|l| l.len()).sum();
    let avg_line_length = if line_count > 0 {
        total_chars / line_count
    } else {
        0
    };

    // Simple binary detection - check for null bytes or excessive control characters
    let null_bytes = content.bytes().filter(|&b| b == 0).count();
    let control_chars = content
        .bytes()
        .filter(|&b| b < 32 && b != 9 && b != 10 && b != 13)
        .count();
    let is_binary_like =
        null_bytes > 0 || (content.len() > 0 && control_chars * 10 > content.len());

    let schema = json!({
        "path": path.to_string_lossy(),
        "format": "text",
        "encoding": "utf-8",
        "byte_sample": byte_sample,
        "detected": {
            "line_count_sampled": line_count,
            "avg_line_length": avg_line_length,
            "is_binary_like": is_binary_like
        }
    });

    Ok(schema)
}

fn infer_fields_from_objects(objects: Vec<&serde_json::Value>) -> Result<Vec<serde_json::Value>> {
    use std::collections::{HashMap, HashSet};

    let mut field_types: HashMap<String, HashSet<String>> = HashMap::new();

    for obj in objects {
        if let serde_json::Value::Object(map) = obj {
            for (key, value) in map {
                let value_type = infer_value_type(value);
                field_types
                    .entry(key.clone())
                    .or_insert_with(HashSet::new)
                    .insert(value_type);
            }
        }
    }

    let mut fields = Vec::new();
    for (field_name, type_set) in field_types {
        let mut types: Vec<String> = type_set.into_iter().collect();
        types.sort(); // Consistent ordering

        fields.push(json!({
            "name": field_name,
            "types": types
        }));
    }

    // Sort fields by name for consistent output
    fields.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });

    Ok(fields)
}

fn infer_value_type(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(_) => "boolean".to_string(),
        serde_json::Value::Number(n) => {
            if n.is_i64() {
                "integer".to_string()
            } else {
                "number".to_string()
            }
        }
        serde_json::Value::String(s) => {
            // Try to detect datetime patterns
            if is_datetime_like(s) {
                "datetime".to_string()
            } else {
                "string".to_string()
            }
        }
        serde_json::Value::Array(_) => "array".to_string(),
        serde_json::Value::Object(_) => "object".to_string(),
    }
}

fn infer_column_types(values: &[&str]) -> Vec<String> {
    use std::collections::HashSet;
    let mut types = HashSet::new();

    for &value in values {
        if value.is_empty() || value.to_lowercase() == "null" {
            types.insert("null".to_string());
            continue;
        }

        // Try boolean
        match value.to_lowercase().as_str() {
            "true" | "false" => {
                types.insert("boolean".to_string());
                continue;
            }
            _ => {}
        }

        // Try integer
        if value.parse::<i64>().is_ok() {
            types.insert("integer".to_string());
            continue;
        }

        // Try float
        if value.parse::<f64>().is_ok() {
            types.insert("number".to_string());
            continue;
        }

        // Try datetime
        if is_datetime_like(value) {
            types.insert("datetime".to_string());
            continue;
        }

        // Default to string
        types.insert("string".to_string());
    }

    if types.is_empty() {
        types.insert("string".to_string());
    }

    let mut result: Vec<String> = types.into_iter().collect();
    result.sort(); // Consistent ordering
    result
}

fn is_datetime_like(s: &str) -> bool {
    // Simple heuristics for common datetime patterns
    if s.len() < 8 {
        return false;
    }

    // ISO-like patterns: YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, etc.
    if s.contains('-') && s.len() >= 10 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() >= 3 && parts[0].len() == 4 && parts[1].len() == 2 {
            if let (Ok(_), Ok(_)) = (parts[0].parse::<u16>(), parts[1].parse::<u8>()) {
                return true;
            }
        }
    }

    false
}

fn infer_json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

impl FileHandle {
    fn do_summary(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if path exists
        if !self.path.exists() {
            writeln!(io.stderr, "file not found")?;
            return Ok(Status::err(2, "file not found"));
        }

        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("failed to read metadata for {:?}", self.path))?;

        // Handle directories
        if metadata.is_dir() {
            let entry_count = std::fs::read_dir(&self.path)
                .with_context(|| format!("failed to read directory {:?}", self.path))?
                .count();

            let summary = json!({
                "path": self.path.to_string_lossy(),
                "exists": true,
                "is_dir": true,
                "entry_count": entry_count
            });

            serde_json::to_writer(&mut io.stdout, &summary)?;
            writeln!(io.stdout)?;
            return Ok(Status::ok());
        }

        // Handle regular files
        let file_size = metadata.len();

        // Get timestamp
        let modified_timestamp = metadata.modified().ok().and_then(|sys_time| {
            let datetime: DateTime<Utc> = sys_time.into();
            Some(datetime.to_rfc3339())
        });

        // Parse max_bytes argument
        let max_bytes = args
            .get("max_bytes")
            .map(|s| {
                s.parse::<u64>()
                    .with_context(|| {
                        format!("Invalid max_bytes '{}': must be a positive integer", s)
                    })
                    .map(|n| std::cmp::min(n, 1_048_576))
            }) // Clamp to 1MB max
            .transpose()?
            .unwrap_or(65536); // Default 64KB

        // Read file content for analysis
        let mut file =
            File::open(&self.path).with_context(|| format!("failed to open {:?}", self.path))?;

        let bytes_to_read = std::cmp::min(max_bytes, file_size) as usize;
        let mut buffer = vec![0u8; bytes_to_read];
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read from {:?}", self.path))?;
        buffer.truncate(bytes_read);

        // Classify content type
        let content_type = classify_content(&buffer);

        // Create sample (first 512 bytes as UTF-8)
        let sample_size = std::cmp::min(512, buffer.len());
        let sample = String::from_utf8_lossy(&buffer[..sample_size]).to_string();

        let mut summary = json!({
            "path": self.path.to_string_lossy(),
            "exists": true,
            "is_dir": false,
            "size": file_size,
            "modified": modified_timestamp,
            "content_type": content_type,
            "sample": sample
        });

        // Add text statistics for text-like content
        if matches!(content_type, "text" | "json" | "csv") {
            let text_content = String::from_utf8_lossy(&buffer);
            let lines: Vec<&str> = text_content.lines().collect();
            let line_count = lines.len();
            let avg_line_length = if line_count > 0 {
                let total_length: usize = lines.iter().map(|line| line.len()).sum();
                total_length as f64 / line_count as f64
            } else {
                0.0
            };

            if let Some(obj) = summary.as_object_mut() {
                obj.insert("line_count".to_string(), json!(line_count));
                obj.insert("avg_line_length".to_string(), json!(avg_line_length));
            }
        } else if content_type == "binary" {
            if let Some(obj) = summary.as_object_mut() {
                obj.insert("line_count".to_string(), json!(null));
                obj.insert("avg_line_length".to_string(), json!(null));
            }
        }

        serde_json::to_writer(&mut io.stdout, &summary)?;
        writeln!(io.stdout)?;
        Ok(Status::ok())
    }
}

// Helper function to classify content type
fn classify_content(buffer: &[u8]) -> &'static str {
    // Check for binary content (contains null bytes)
    if buffer.contains(&0) {
        return "binary";
    }

    // Try to parse as UTF-8
    match std::str::from_utf8(buffer) {
        Ok(text) => {
            let text = text.trim();

            // Check for JSON
            if (text.starts_with('{') && text.ends_with('}'))
                || (text.starts_with('[') && text.ends_with(']'))
            {
                return "json";
            }

            // Basic CSV detection (contains newlines and commas in structured way)
            let lines: Vec<&str> = text.lines().collect();
            if lines.len() > 1 {
                let has_commas = lines.iter().any(|line| line.contains(','));
                let has_consistent_structure = lines.len() >= 2
                    && lines.iter().take(3).all(|line| line.split(',').count() > 1);
                if has_commas && has_consistent_structure {
                    return "csv";
                }
            }

            "text"
        }
        Err(_) => "binary",
    }
}

impl FileHandle {
    fn do_analyze(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let max_bytes = args
            .get("max_bytes")
            .map(|s| {
                s.parse::<usize>().with_context(|| {
                    format!("Invalid max_bytes '{}': must be a positive integer", s)
                })
            })
            .transpose()?
            .unwrap_or(65536); // Default: 64 KiB

        // Check if file exists and get metadata
        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("failed to read metadata for {:?}", self.path))?;

        let size_bytes = metadata.len();

        // Open and read file
        let mut file = File::open(&self.path)
            .with_context(|| format!("failed to open file {:?}", self.path))?;

        // Read up to max_bytes
        let bytes_to_read = std::cmp::min(max_bytes, size_bytes as usize);
        let mut buffer = vec![0u8; bytes_to_read];
        let sample_bytes = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read file {:?}", self.path))?;

        // Truncate buffer to actual bytes read
        buffer.truncate(sample_bytes);

        // Calculate metrics
        let line_count = buffer.iter().filter(|&&b| b == b'\n').count();

        // Calculate ASCII ratio - ASCII printable + common whitespace
        let ascii_count = buffer
            .iter()
            .filter(|&&b| (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D)
            .count();
        let ascii_ratio = if sample_bytes == 0 {
            0.0
        } else {
            ascii_count as f64 / sample_bytes as f64
        };

        let null_byte_present = buffer.contains(&0x00);

        // Calculate Shannon entropy
        let entropy = self.calculate_entropy(&buffer);

        // Classify content
        let (classification, format_hints) =
            self.classify_content(&buffer, ascii_ratio, null_byte_present);

        // Create result JSON
        let result = serde_json::json!({
            "path": self.path.display().to_string(),
            "size_bytes": size_bytes,
            "sample_bytes": sample_bytes as u64,
            "line_count": line_count,
            "ascii_ratio": ascii_ratio,
            "null_byte_present": null_byte_present,
            "entropy": entropy,
            "classification": classification,
            "format_hints": format_hints
        });

        writeln!(io.stdout, "{}", serde_json::to_string(&result)?)?;
        Ok(Status::ok())
    }

    fn calculate_entropy(&self, buffer: &[u8]) -> f64 {
        if buffer.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in buffer {
            counts[byte as usize] += 1;
        }

        let len = buffer.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    fn classify_content(
        &self,
        buffer: &[u8],
        ascii_ratio: f64,
        null_byte_present: bool,
    ) -> (String, serde_json::Value) {
        let mut is_json = false;
        let mut is_csv = false;
        let mut is_log_like = false;

        if null_byte_present {
            return (
                "binary".to_string(),
                serde_json::json!({
                    "is_json": false,
                    "is_csv": false,
                    "is_log_like": false
                }),
            );
        }

        if ascii_ratio > 0.9 {
            // Try to detect JSON
            if let Ok(content_str) = String::from_utf8(buffer.to_vec()) {
                let trimmed = content_str.trim();
                if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                    || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                {
                    if serde_json::from_str::<serde_json::Value>(&trimmed).is_ok() {
                        is_json = true;
                    }
                }

                // Check for CSV - look for consistent comma-separated fields across lines
                let lines: Vec<&str> = content_str.lines().collect();
                if lines.len() > 1 {
                    let first_line_commas = lines[0].matches(',').count();
                    if first_line_commas > 0 {
                        let consistent_commas = lines
                            .iter()
                            .skip(1)
                            .take(10)
                            .all(|line| line.matches(',').count() == first_line_commas);
                        if consistent_commas {
                            is_csv = true;
                        }
                    }
                }

                // Check for log-like content - timestamps at beginning of lines
                if !is_json && !is_csv {
                    let log_indicators = lines
                        .iter()
                        .take(10)
                        .filter(|line| {
                            let trimmed = line.trim();
                            trimmed.len() > 4
                                && (
                                    trimmed.starts_with("20") && trimmed.chars().nth(4) == Some('-') || // YYYY-
                            trimmed.starts_with("[20") || // [20YY
                            trimmed.contains("T") && trimmed.contains(":")
                                    // ISO timestamps
                                )
                        })
                        .count();

                    if log_indicators > lines.len() / 3 {
                        is_log_like = true;
                    }
                }
            }

            let classification = if is_json {
                "json"
            } else if is_csv {
                "csv"
            } else if is_log_like {
                "log"
            } else {
                "text"
            };

            return (
                classification.to_string(),
                serde_json::json!({
                    "is_json": is_json,
                    "is_csv": is_csv,
                    "is_log_like": is_log_like
                }),
            );
        }

        (
            "binary".to_string(),
            serde_json::json!({
                "is_json": false,
                "is_csv": false,
                "is_log_like": false
            }),
        )
    }

    fn handle_watch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let timeout_ms = args
            .get("timeout_ms")
            .map(|s| {
                s.parse::<u64>().with_context(|| {
                    format!("Invalid timeout_ms '{}': must be a positive integer", s)
                })
            })
            .transpose()?
            .unwrap_or(30000); // Default 30 seconds

        let max_events = args
            .get("max_events")
            .map(|s| {
                s.parse::<u32>().with_context(|| {
                    format!("Invalid max_events '{}': must be a positive integer", s)
                })
            })
            .transpose()?
            .unwrap_or(1); // Default 1 event

        // Parse events filter - comma-separated list
        let events_filter: HashSet<String> = args
            .get("events")
            .map(|s| s.split(',').map(|e| e.trim().to_string()).collect())
            .unwrap_or_else(|| {
                // Default: all event types
                vec![
                    "create".to_string(),
                    "modify".to_string(),
                    "remove".to_string(),
                    "rename".to_string(),
                ]
                .into_iter()
                .collect()
            });

        // Ignore nonblocking for now (as per requirements)
        let _nonblocking = args
            .get("nonblocking")
            .map(|s| s == "true")
            .unwrap_or(false);

        // Validation: if timeout_ms=0, max_events must be set to prevent infinite tests
        if timeout_ms == 0 && max_events == 0 {
            return Ok(Status::err(
                1,
                "timeout_ms=0 requires max_events to be set to prevent infinite execution",
            ));
        }

        // Create watcher
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher =
            notify::recommended_watcher(tx).with_context(|| "failed to create file watcher")?;

        // Watch the exact path (NonRecursive for single file watching)
        watcher
            .watch(&self.path, RecursiveMode::NonRecursive)
            .with_context(|| format!("failed to watch path {:?}", self.path))?;

        let start_time = Instant::now();
        let mut event_count = 0u32;
        let timeout_duration = if timeout_ms > 0 {
            Some(Duration::from_millis(timeout_ms))
        } else {
            None
        };

        // Main event loop
        loop {
            // Check timeout
            if let Some(timeout) = timeout_duration {
                if start_time.elapsed() >= timeout {
                    break;
                }
            }

            // Check max events
            if event_count >= max_events {
                break;
            }

            // Use a small timeout for recv_timeout to periodically check conditions
            let recv_timeout = Duration::from_millis(200);
            match rx.recv_timeout(recv_timeout) {
                Ok(Ok(event)) => {
                    if self.process_watch_event_simple(event, &events_filter, io)? {
                        event_count += 1;
                    }
                }
                Ok(Err(e)) => {
                    return Ok(Status::err(1, format!("watch error: {}", e)));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Continue loop to check conditions
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // Watcher was dropped
                    break;
                }
            }
        }

        Ok(Status::ok())
    }

    fn process_watch_event_simple(
        &self,
        event: Event,
        events_filter: &HashSet<String>,
        io: &mut IoStreams,
    ) -> Result<bool> {
        // Map notify event kind to simple string representation
        let event_type = match event.kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "remove",
            EventKind::Access(_) => "rename", // Access events often include renames
            EventKind::Other => return Ok(false), // Skip other events
            EventKind::Any => return Ok(false), // Skip any events
        };

        // Check if this event type should be included
        if !events_filter.contains(event_type) {
            return Ok(false);
        }

        // Process each path in the event (but there should typically be one for single file watching)
        let mut event_emitted = false;
        for path in &event.paths {
            // Normalize path - try canonicalize, fall back to self.path as string
            let normalized_path = path.canonicalize().unwrap_or_else(|_| self.path.clone());

            // Determine kind (optional coarse type)
            let kind = match event.kind {
                EventKind::Modify(notify::event::ModifyKind::Data(_)) => "data_change",
                EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => "metadata_change",
                EventKind::Modify(_) => "data_change", // Default for modify
                _ => "any",
            };

            // Create JSON event as per requirements
            let event_json = serde_json::json!({
                "event": event_type,
                "path": normalized_path.display().to_string(),
                "kind": kind,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            // Write to stdout as one line of JSON
            writeln!(io.stdout, "{}", serde_json::to_string(&event_json)?)?;
            io.stdout.flush()?;
            event_emitted = true;
        }

        Ok(event_emitted)
    }
}

// Helper functions for chown implementation
#[cfg(unix)]
fn resolve_user_id(user_arg: Option<&String>, uid_arg: Option<&String>) -> Result<Option<Uid>> {
    if let Some(uid_str) = uid_arg {
        // Numeric uid takes precedence
        let uid = uid_str
            .parse::<u32>()
            .with_context(|| format!("invalid uid: {}", uid_str))?;
        Ok(Some(Uid::from_raw(uid)))
    } else if let Some(user_str) = user_arg {
        // Resolve username
        match User::from_name(user_str)? {
            Some(user) => Ok(Some(user.uid)),
            None => bail!("unknown user: {}", user_str),
        }
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn resolve_group_id(group_arg: Option<&String>, gid_arg: Option<&String>) -> Result<Option<Gid>> {
    if let Some(gid_str) = gid_arg {
        // Numeric gid takes precedence
        let gid = gid_str
            .parse::<u32>()
            .with_context(|| format!("invalid gid: {}", gid_str))?;
        Ok(Some(Gid::from_raw(gid)))
    } else if let Some(group_str) = group_arg {
        // Resolve group name
        match Group::from_name(group_str)? {
            Some(group) => Ok(Some(group.gid)),
            None => bail!("unknown group: {}", group_str),
        }
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn chown_recursive(path: &std::path::Path, uid: Option<Uid>, gid: Option<Gid>) -> Result<()> {
    // Apply to the root path first
    chown(path, uid, gid).with_context(|| format!("chown failed for {}", path.display()))?;

    // If it's a directory, recurse
    if path.is_dir() {
        for entry in WalkDir::new(path).min_depth(1) {
            let entry = entry.with_context(|| format!("walking directory {}", path.display()))?;
            chown(entry.path(), uid, gid)
                .with_context(|| format!("chown failed for {}", entry.path().display()))?;
        }
    }

    Ok(())
}

impl FileHandle {
    /// Atomic write operation using temporary file + rename
    fn atomic_write_safe(
        path: &std::path::Path,
        data: &[u8],
        mode: Option<u32>,
        create: bool,
    ) -> Result<std::result::Result<u64, String>> {
        use std::process;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Check create flag
        if !create && !path.exists() {
            return Ok(Err("file does not exist and create=false".to_string()));
        }

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory {:?}", parent))?;
            }
        }

        // Generate unique temporary filename
        let pid = process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_name = format!(".resh_tmp_{}_{}", pid, timestamp % 1000000);

        let temp_path = if let Some(parent) = path.parent() {
            parent.join(&temp_name)
        } else {
            std::path::PathBuf::from(&temp_name)
        };

        // Cleanup guard
        let _cleanup = TempFileCleanup::new(&temp_path);

        // Write to temporary file
        {
            let mut temp_file = File::create(&temp_path)
                .with_context(|| format!("failed to create temporary file {:?}", temp_path))?;

            temp_file
                .write_all(data)
                .with_context(|| "failed to write data to temporary file")?;

            temp_file
                .flush()
                .with_context(|| "failed to flush temporary file")?;

            temp_file
                .sync_all()
                .with_context(|| "failed to sync temporary file")?;
        }

        // Set mode if provided and on Unix
        #[cfg(unix)]
        if let Some(mode_bits) = mode {
            if let Err(e) =
                std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(mode_bits))
            {
                // Non-fatal - log but continue
                eprintln!("Warning: failed to set file mode: {}", e);
            }
        }

        // Atomic rename
        std::fs::rename(&temp_path, path)
            .with_context(|| format!("failed to rename {:?} to {:?}", temp_path, path))?;

        Ok(Ok(data.len() as u64))
    }

    /// Safe append operation
    fn safe_append(
        path: &std::path::Path,
        data: &[u8],
        create: bool,
    ) -> Result<std::result::Result<u64, String>> {
        // Check create flag
        if !create && !path.exists() {
            return Ok(Err("file does not exist and create=false".to_string()));
        }

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent directory {:?}", parent))?;
            }
        }

        // Open file for append
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(create)
            .open(path)
            .with_context(|| format!("failed to open file {:?} for append", path))?;

        // Write data
        file.write_all(data)
            .with_context(|| "failed to write data")?;

        // Flush to ensure data is written
        file.flush().with_context(|| "failed to flush file")?;

        // Optionally sync for durability
        file.sync_all().with_context(|| "failed to sync file")?;

        Ok(Ok(data.len() as u64))
    }
}

// Temporary file cleanup helper
struct TempFileCleanup {
    path: std::path::PathBuf,
}

impl TempFileCleanup {
    fn new(path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl FileHandle {
    /// Cross-filesystem move implementation using copy+delete
    /// Production-ready rename operation with comprehensive error handling
    fn do_rename(
        &self,
        src_path: &std::path::Path,
        dest: &str,
        overwrite: bool,
        create_parents: bool,
        atomic: bool,
        io: &mut IoStreams,
    ) -> Result<Status> {
        // Parse and normalize destination path
        let to_dec = percent_decode_str(dest).decode_utf8_lossy().to_string();
        let to_dec = unescape_backslashes(&to_dec);
        let dest_path = normalize_path(&std::path::PathBuf::from(to_dec));

        // Check if source and destination are the same (idempotent operation)
        if src_path == dest_path {
            return Ok(Status::ok());
        }

        // Check if source exists
        if !src_path.exists() {
            return Ok(Status::err(2, format!("source does not exist: {}", src_path.display())));
        }

        // Create parent directories if requested
        if create_parents {
            if let Some(parent) = dest_path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("failed to create parent directories: {}", parent.display()))
                        .map_err(|e| anyhow::anyhow!("io error: {}", e))?;
                }
            }
        }

        // Handle destination existence and overwrite logic
        if dest_path.exists() {
            if !overwrite {
                return Ok(Status::err(2, "destination exists"));
            }
            
            // Remove destination if overwrite is enabled
            if dest_path.is_dir() {
                remove_dir_all(&dest_path)
                    .with_context(|| format!("failed to remove existing directory: {}", dest_path.display()))
                    .map_err(|e| anyhow::anyhow!("io error: {}", e))?;
            } else {
                remove_file(&dest_path)
                    .with_context(|| format!("failed to remove existing file: {}", dest_path.display()))
                    .map_err(|e| anyhow::anyhow!("io error: {}", e))?;
            }
        }

        // Check that destination parent exists if create_parents is false
        if !create_parents {
            if let Some(parent) = dest_path.parent() {
                if !parent.exists() {
                    return Ok(Status::err(2, format!("destination parent does not exist: {}", parent.display())));
                }
            }
        }

        // Attempt atomic rename first (same filesystem)
        match std::fs::rename(src_path, &dest_path) {
            Ok(_) => {
                // Optional: write minimal JSON summary to stdout
                let summary = serde_json::json!({
                    "renamed": true,
                    "from": src_path.display().to_string(),
                    "to": dest_path.display().to_string()
                });
                writeln!(io.stdout, "{}", summary)?;
                Ok(Status::ok())
            }
            Err(e) => {
                // Check if this is a cross-filesystem error (EXDEV)
                let is_cross_filesystem = e.raw_os_error() == Some(18) // EXDEV on Linux
                    || e.kind() == std::io::ErrorKind::CrossesDevices;

                if is_cross_filesystem && atomic {
                    // For cross-filesystem moves, perform copy + delete with best-effort atomicity
                    self.cross_filesystem_rename(src_path, &dest_path, io)
                } else if is_cross_filesystem && !atomic {
                    // If atomic=false, we can still try copy+delete but without guarantees
                    self.cross_filesystem_rename(src_path, &dest_path, io)
                } else {
                    // Other errors (permissions, etc.)
                    let error_msg = format!("rename {} -> {}: {}", src_path.display(), dest_path.display(), e);
                    if e.to_string().contains("Permission denied") || e.to_string().contains("EACCES") {
                        Ok(Status::err(3, error_msg))
                    } else {
                        Ok(Status::err(1, error_msg))
                    }
                }
            }
        }
    }

    /// Cross-filesystem rename operation (copy + delete)
    fn cross_filesystem_rename(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        io: &mut IoStreams,
    ) -> Result<Status> {
        // Perform copy operation based on source type
        let copy_result = if src_path.is_dir() {
            self.copy_directory_recursive(src_path, dest_path, io)
        } else {
            self.copy_file_with_metadata(src_path, dest_path, io)
        };

        // If copy failed, clean up incomplete destination
        if let Err(e) = &copy_result {
            // Best effort cleanup - remove incomplete destination
            if dest_path.exists() {
                if dest_path.is_dir() {
                    let _ = remove_dir_all(dest_path);
                } else {
                    let _ = remove_file(dest_path);
                }
            }
            let error_msg = format!("cross-filesystem copy failed: {}", e);
            return Ok(Status::err(1, error_msg));
        }

        // Copy succeeded, now delete the source
        let delete_result = if src_path.is_dir() {
            remove_dir_all(src_path)
        } else {
            remove_file(src_path)
        };

        match delete_result {
            Ok(_) => {
                // Success - write minimal JSON summary to stdout
                let summary = serde_json::json!({
                    "renamed": true,
                    "from": src_path.display().to_string(),
                    "to": dest_path.display().to_string(),
                    "cross_filesystem": true
                });
                writeln!(io.stdout, "{}", summary)?;
                Ok(Status::ok())
            }
            Err(e) => {
                // Copy succeeded but delete failed - this is a tricky situation
                // The file/directory has been copied but the original still exists
                let error_msg = format!(
                    "copy succeeded but failed to remove source {}: {} (destination {} may be incomplete)", 
                    src_path.display(), e, dest_path.display()
                );
                Ok(Status::err(1, error_msg))
            }
        }
    }

    /// Parse boolean string arguments
    fn parse_bool_arg(args: &Args, key: &str, default: bool) -> bool {
        args.get(key)
            .map(|s| {
                let s_lower = s.to_lowercase();
                matches!(s_lower.as_str(), "true" | "1" | "yes")
            })
            .unwrap_or(default)
    }

    fn cross_filesystem_move(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        overwrite: bool,
        io: &mut IoStreams,
    ) -> Result<Status> {
        // Remove destination if overwrite is true and it exists
        if overwrite && dest_path.exists() {
            if dest_path.is_dir() {
                remove_dir_all(dest_path).with_context(|| {
                    format!("failed to remove existing directory {:?}", dest_path)
                })?;
            } else {
                remove_file(dest_path).with_context(|| {
                    format!("failed to remove existing file {:?}", dest_path)
                })?;
            }
        }

        // Perform recursive copy based on source type
        if src_path.is_dir() {
            self.copy_directory_recursive(src_path, dest_path, io)?;
        } else {
            self.copy_file_with_metadata(src_path, dest_path, io)?;
        }

        // Only delete source after successful copy
        if src_path.is_dir() {
            remove_dir_all(src_path).with_context(|| {
                format!("failed to remove source directory {:?} after copy", src_path)
            })?;
        } else {
            remove_file(src_path).with_context(|| {
                format!("failed to remove source file {:?} after copy", src_path)
            })?;
        }

        Ok(Status::ok())
    }

    /// Copy a file while preserving metadata when possible
    fn copy_file_with_metadata(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        _io: &mut IoStreams,
    ) -> Result<()> {
        // Use streaming copy to avoid loading large files into memory
        let mut src_file = File::open(src_path)
            .with_context(|| format!("failed to open source file {:?}", src_path))?;
        let mut dest_file = File::create(dest_path)
            .with_context(|| format!("failed to create destination file {:?}", dest_path))?;

        std::io::copy(&mut src_file, &mut dest_file)
            .with_context(|| "failed to copy file contents")?;

        // Flush and sync to ensure data is written
        dest_file.flush().context("failed to flush destination file")?;

        // Preserve file permissions on Unix systems
        #[cfg(unix)]
        {
            if let Ok(src_metadata) = metadata(src_path) {
                let perms = std::fs::Permissions::from_mode(src_metadata.permissions().mode());
                let _ = std::fs::set_permissions(dest_path, perms);
            }
        }

        Ok(())
    }

    /// Recursively copy a directory
    fn copy_directory_recursive(
        &self,
        src_path: &std::path::Path,
        dest_path: &std::path::Path,
        io: &mut IoStreams,
    ) -> Result<()> {
        // Create destination directory
        std::fs::create_dir_all(dest_path)
            .with_context(|| format!("failed to create directory {:?}", dest_path))?;

        // Copy permissions on Unix
        #[cfg(unix)]
        {
            if let Ok(src_metadata) = metadata(src_path) {
                let perms = std::fs::Permissions::from_mode(src_metadata.permissions().mode());
                let _ = std::fs::set_permissions(dest_path, perms);
            }
        }

        // Recursively copy contents
        for entry in std::fs::read_dir(src_path)
            .with_context(|| format!("failed to read directory {:?}", src_path))?
        {
            let entry = entry.context("failed to read directory entry")?;
            let entry_path = entry.path();
            let entry_name = entry.file_name();
            let dest_entry_path = dest_path.join(&entry_name);

            if entry_path.is_dir() {
                self.copy_directory_recursive(&entry_path, &dest_entry_path, io)?;
            } else {
                self.copy_file_with_metadata(&entry_path, &dest_entry_path, io)?;
            }
        }

        Ok(())
    }

    /// Handle ea.get verb - read an extended attribute
    fn verb_ea_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for required name argument
        let name = match args.get("name") {
            Some(n) => n,
            None => {
                writeln!(io.stderr, "missing arg: name")?;
                return Ok(Status::err(1, "missing arg: name"));
            }
        };

        // Parse allow_missing argument (default false)
        let allow_missing = args
            .get("allow_missing")
            .map(|s| s == "true")
            .unwrap_or(false);

        let resolved_path = resolve_file_path(&self.path)?;

        #[cfg(unix)]
        {
            // Try to get the extended attribute
            match xattr::get(&resolved_path, name) {
                Ok(Some(value_bytes)) => {
                    // Determine if the value is valid UTF-8
                    let (value, encoding) = match String::from_utf8(value_bytes.clone()) {
                        Ok(utf8_string) => (utf8_string, "utf-8"),
                        Err(_) => {
                            // Not valid UTF-8, base64 encode it
                            (BASE64_STANDARD.encode(&value_bytes), "base64")
                        }
                    };

                    let response = if encoding == "base64" {
                        json!({
                            "path": resolved_path.display().to_string(),
                            "name": name,
                            "exists": true,
                            "value": value,
                            "encoding": encoding
                        })
                    } else {
                        json!({
                            "path": resolved_path.display().to_string(),
                            "name": name,
                            "exists": true,
                            "value": value
                        })
                    };

                    writeln!(io.stdout, "{}", response)?;
                    Ok(Status::ok())
                }
                Ok(None) => {
                    // Attribute does not exist
                    if allow_missing {
                        let response = json!({
                            "path": resolved_path.display().to_string(),
                            "name": name,
                            "exists": false,
                            "value": serde_json::Value::Null
                        });
                        writeln!(io.stdout, "{}", response)?;
                        Ok(Status::ok())
                    } else {
                        writeln!(io.stderr, "extended attribute not found: {}", name)?;
                        Ok(Status::err(2, &format!("extended attribute not found: {}", name)))
                    }
                }
                Err(e) => {
                    writeln!(io.stderr, "ea.get failed: {}", e)?;
                    Ok(Status::err(1, &format!("ea.get failed: {}", e)))
                }
            }
        }

        #[cfg(not(unix))]
        {
            writeln!(io.stderr, "extended attributes not supported on this platform")?;
            Ok(Status::err(1, "extended attributes not supported on this platform"))
        }
    }

    /// Handle ea.set verb - write/update an extended attribute
    fn verb_ea_set(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for required arguments
        let name = match args.get("name") {
            Some(n) => n,
            None => {
                writeln!(io.stderr, "missing arg: name")?;
                return Ok(Status::err(1, "missing arg: name"));
            }
        };

        let value = match args.get("value") {
            Some(v) => v,
            None => {
                writeln!(io.stderr, "missing arg: value")?;
                return Ok(Status::err(1, "missing arg: value"));
            }
        };

        // Parse mode argument (default upsert)
        let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("upsert");
        if !matches!(mode, "create" | "update" | "upsert") {
            let error_msg = format!("invalid mode: {}; expected one of create|update|upsert", mode);
            writeln!(io.stderr, "{}", error_msg)?;
            return Ok(Status::err(1, &error_msg));
        }

        let resolved_path = resolve_file_path(&self.path)?;

        #[cfg(unix)]
        {
            // Get previous value for response
            let previous_value = match xattr::get(&resolved_path, name) {
                Ok(Some(prev_bytes)) => {
                    match String::from_utf8(prev_bytes.clone()) {
                        Ok(utf8_string) => Some((utf8_string, "utf-8")),
                        Err(_) => Some((BASE64_STANDARD.encode(&prev_bytes), "base64")),
                    }
                }
                Ok(None) => None,
                Err(_) => None, // Treat errors as "not exists" for previous value
            };

            // Handle mode-specific logic
            match mode {
                "create" => {
                    // Check if attribute already exists
                    match xattr::get(&resolved_path, name) {
                        Ok(Some(_)) => {
                            let error_msg = format!("ea.set(create) – attribute already exists: {}", name);
                            writeln!(io.stderr, "{}", error_msg)?;
                            return Ok(Status::err(1, &error_msg));
                        }
                        Ok(None) => {
                            // Attribute doesn't exist, we can create it
                        }
                        Err(e) => {
                            let error_msg = format!("ea.set failed: {}", e);
                            writeln!(io.stderr, "{}", error_msg)?;
                            return Ok(Status::err(1, &error_msg));
                        }
                    }
                }
                "update" => {
                    // Check if attribute exists
                    match xattr::get(&resolved_path, name) {
                        Ok(Some(_)) => {
                            // Attribute exists, we can update it
                        }
                        Ok(None) => {
                            let error_msg = format!("ea.set(update) – attribute does not exist: {}", name);
                            writeln!(io.stderr, "{}", error_msg)?;
                            return Ok(Status::err(2, &error_msg));
                        }
                        Err(e) => {
                            let error_msg = format!("ea.set failed: {}", e);
                            writeln!(io.stderr, "{}", error_msg)?;
                            return Ok(Status::err(1, &error_msg));
                        }
                    }
                }
                "upsert" => {
                    // No pre-check needed for upsert
                }
                _ => unreachable!(), // Already validated above
            }

            // Set the extended attribute
            match xattr::set(&resolved_path, name, value.as_bytes()) {
                Ok(_) => {
                    let response = if let Some((prev_value, encoding)) = previous_value {
                        json!({
                            "path": resolved_path.display().to_string(),
                            "name": name,
                            "mode": mode,
                            "previous": prev_value,
                            "current": value,
                            "encoding": encoding
                        })
                    } else {
                        json!({
                            "path": resolved_path.display().to_string(),
                            "name": name,
                            "mode": mode,
                            "previous": serde_json::Value::Null,
                            "current": value,
                            "encoding": "utf-8"
                        })
                    };

                    writeln!(io.stdout, "{}", response)?;
                    Ok(Status::ok())
                }
                Err(e) => {
                    let error_msg = format!("ea.set failed: {}", e);
                    writeln!(io.stderr, "{}", error_msg)?;
                    Ok(Status::err(1, &error_msg))
                }
            }
        }

        #[cfg(not(unix))]
        {
            writeln!(io.stderr, "extended attributes not supported on this platform")?;
            Ok(Status::err(1, "extended attributes not supported on this platform"))
        }
    }

    /// Validate a tag name according to tag rules
    fn validate_tag(tag: &str) -> bool {
        if tag.is_empty() {
            return false;
        }
        
        tag.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' || c == '.')
    }

    /// Parse and validate multiple tags from a comma-separated string
    fn parse_and_validate_tags(names: &str) -> Result<Vec<String>, String> {
        let mut tags = Vec::new();
        
        for name in names.split(',') {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }
            
            let lowercase = trimmed.to_lowercase();
            if !Self::validate_tag(&lowercase) {
                return Err(format!("invalid tag: {}", trimmed));
            }
            
            tags.push(lowercase);
        }
        
        Ok(tags)
    }

    /// Read tags from extended attributes
    fn read_tags(&self, path: &std::path::Path) -> Result<Vec<String>, anyhow::Error> {
        #[cfg(unix)]
        {
            match xattr::get(path, "user.resh.tags") {
                Ok(Some(value_bytes)) => {
                    let value_str = String::from_utf8(value_bytes)
                        .with_context(|| "tag xattr contains invalid UTF-8")?;
                    
                    if value_str.trim().is_empty() {
                        Ok(Vec::new())
                    } else {
                        Ok(value_str.split(',').map(|s| s.trim().to_string()).collect())
                    }
                }
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(anyhow::anyhow!("failed to read tags: {}", e))
            }
        }
        
        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("extended attributes not supported"))
        }
    }

    /// Write tags to extended attributes
    fn write_tags(&self, path: &std::path::Path, tags: &[String]) -> Result<(), anyhow::Error> {
        #[cfg(unix)]
        {
            if tags.is_empty() {
                // Remove the xattr if no tags
                match xattr::remove(path, "user.resh.tags") {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // Ignore if doesn't exist
                    Err(e) => Err(anyhow::anyhow!("failed to remove tags xattr: {}", e))
                }
            } else {
                let value = tags.join(",");
                xattr::set(path, "user.resh.tags", value.as_bytes())
                    .with_context(|| "failed to write tags xattr")?;
                Ok(())
            }
        }
        
        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("extended attributes not supported"))
        }
    }

    /// Handle tag.add verb - add tags to file
    fn verb_tag_add(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for required name argument
        let name = match args.get("name") {
            Some(n) => n,
            None => {
                writeln!(io.stderr, "missing arg: name")?;
                return Ok(Status::err(1, "missing arg: name"));
            }
        };

        let resolved_path = resolve_file_path(&self.path)?;

        // Ensure the target exists
        if !resolved_path.exists() {
            return Ok(Status::err(2, "not found"));
        }

        #[cfg(unix)]
        {
            // Parse and validate input tags
            let new_tags = match Self::parse_and_validate_tags(name) {
                Ok(tags) => tags,
                Err(err) => {
                    return Ok(Status::err(1, &err));
                }
            };

            // Read existing tags
            let mut existing_tags = match self.read_tags(&resolved_path) {
                Ok(tags) => tags,
                Err(e) => {
                    if e.to_string().contains("not supported") {
                        return Ok(Status::err(95, "extended attributes not supported"));
                    } else {
                        return Ok(Status::err(1, &format!("io error: {}", e)));
                    }
                }
            };

            // Merge tags (union, deduplicate, sort)
            for tag in new_tags {
                if !existing_tags.contains(&tag) {
                    existing_tags.push(tag);
                }
            }
            existing_tags.sort();

            // Write back tags
            if let Err(e) = self.write_tags(&resolved_path, &existing_tags) {
                if e.to_string().contains("not supported") {
                    return Ok(Status::err(95, "extended attributes not supported"));
                } else {
                    return Ok(Status::err(1, &format!("io error: {}", e)));
                }
            }

            // Output JSON
            let response = json!({
                "path": resolved_path.display().to_string(),
                "tags": existing_tags
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&response).unwrap())?;
            Ok(Status::ok())
        }

        #[cfg(not(unix))]
        {
            Ok(Status::err(95, "extended attributes not supported"))
        }
    }

    /// Handle tag.rm verb - remove tags from file
    fn verb_tag_rm(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for required name argument
        let name = match args.get("name") {
            Some(n) => n,
            None => {
                writeln!(io.stderr, "missing arg: name")?;
                return Ok(Status::err(1, "missing arg: name"));
            }
        };

        let resolved_path = resolve_file_path(&self.path)?;

        // Ensure the target exists
        if !resolved_path.exists() {
            return Ok(Status::err(2, "not found"));
        }

        #[cfg(unix)]
        {
            // Parse and validate tags to remove
            let remove_tags = match Self::parse_and_validate_tags(name) {
                Ok(tags) => tags,
                Err(err) => {
                    return Ok(Status::err(1, &err));
                }
            };

            // Read existing tags
            let mut existing_tags = match self.read_tags(&resolved_path) {
                Ok(tags) => tags,
                Err(e) => {
                    if e.to_string().contains("not supported") {
                        return Ok(Status::err(95, "extended attributes not supported"));
                    } else {
                        return Ok(Status::err(1, &format!("io error: {}", e)));
                    }
                }
            };

            // Remove specified tags
            existing_tags.retain(|tag| !remove_tags.contains(tag));
            existing_tags.sort();

            // Write back tags (or remove xattr if empty)
            if let Err(e) = self.write_tags(&resolved_path, &existing_tags) {
                if e.to_string().contains("not supported") {
                    return Ok(Status::err(95, "extended attributes not supported"));
                } else {
                    return Ok(Status::err(1, &format!("io error: {}", e)));
                }
            }

            // Output JSON
            let response = json!({
                "path": resolved_path.display().to_string(),
                "tags": existing_tags
            });
            writeln!(io.stdout, "{}", serde_json::to_string(&response).unwrap())?;
            Ok(Status::ok())
        }

        #[cfg(not(unix))]
        {
            Ok(Status::err(95, "extended attributes not supported"))
        }
    }
}

impl Handle for FileHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "read", "rename", "write", "copy", "delete", "remove", "move", "mv", "exists", "stat", "chmod",
            "chown", "md5", "sha1", "sha256", "sha512", "verify", "append", "find", "grep",
            "replace", "tail", "preview", "schema", "summary", "watch", "analyze", "hash",
            "ea.get", "ea.set", "tag.add", "tag.rm",
        ]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "read" => {
                let resolved_path = resolve_file_path(&self.path)?;
                let mut f = File::open(&resolved_path)
                    .with_context(|| format!("open {:?}", &resolved_path))?;
                std::io::copy(&mut f, &mut io.stdout)?;
                Ok(Status::ok())
            }
            "write" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Determine data source: args or stdin
                let data = match args.get("data") {
                    Some(d) => d.as_bytes().to_vec(),
                    None => {
                        // Read from stdin until EOF
                        let mut buffer = Vec::new();
                        io.stdin
                            .read_to_end(&mut buffer)
                            .with_context(|| "failed to read from stdin")
                            .map_err(|e| anyhow::anyhow!("io error: {}", e))?;
                        buffer
                    }
                };

                // Parse create parameter (default true)
                let create = args.get("create").map(|s| s != "false").unwrap_or(true);

                // Check if file exists when create=false
                if !create && !resolved_path.exists() {
                    return Ok(Status::err(2, "file does not exist and create=false"));
                }

                // Parse mode parameter (Unix only)
                let mode = args
                    .get("mode")
                    .and_then(|s| u32::from_str_radix(s, 8).ok());

                // Perform atomic write using temp file + rename
                let result =
                    Self::atomic_write_safe(&resolved_path, &data, mode, create).map_err(|e| {
                        // Map specific errors to appropriate status codes
                        if e.to_string().contains("Permission denied")
                            || e.to_string().contains("EACCES")
                        {
                            return anyhow::anyhow!("permission error: {}", e);
                        }
                        anyhow::anyhow!("io error: {}", e)
                    })?;

                match result {
                    Ok(bytes_written) => {
                        // Optional: write minimal JSON summary to stdout
                        let summary = serde_json::json!({
                            "written": true,
                            "bytes": bytes_written,
                            "path": resolved_path.display().to_string()
                        });
                        writeln!(io.stdout, "{}", summary)?;
                        Ok(Status::ok())
                    }
                    Err(err_msg) => {
                        if err_msg.contains("permission") {
                            Ok(Status::err(3, err_msg))
                        } else if err_msg.contains("not exist") {
                            Ok(Status::err(2, err_msg))
                        } else {
                            Ok(Status::err(1, err_msg))
                        }
                    }
                }
            }
            "rename" => {
                let resolved_path = resolve_file_path(&self.path)?;
                
                // Parse required 'to' argument
                let to = args
                    .get("to")
                    .ok_or_else(|| anyhow::anyhow!("missing arg: to"))?;

                // Parse optional arguments with defaults
                let overwrite = Self::parse_bool_arg(args, "overwrite", false);
                let create_parents = Self::parse_bool_arg(args, "create_parents", false);
                let atomic = Self::parse_bool_arg(args, "atomic", true);

                // Call the comprehensive rename implementation
                self.do_rename(&resolved_path, to, overwrite, create_parents, atomic, io)
            }
            "copy" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Validate source exists and is not a directory
                if !resolved_path.exists() {
                    writeln!(io.stderr, "source not found")?;
                    return Ok(Status::err(1, "source not found"));
                }

                let metadata = std::fs::metadata(&resolved_path)
                    .with_context(|| format!("failed to get metadata for {:?}", &resolved_path))?;

                if metadata.is_dir() {
                    writeln!(io.stderr, "source is a directory")?;
                    return Ok(Status::err(1, "source is a directory"));
                }

                // Parse destination path
                let to = args
                    .get("to")
                    .ok_or_else(|| anyhow::anyhow!("missing arg: to"))?;
                let to_dec = percent_decode_str(to).decode_utf8_lossy().to_string();
                let to_dec = unescape_backslashes(&to_dec);
                let dest_path = normalize_path(&std::path::PathBuf::from(to_dec));

                // Parse optional arguments
                let overwrite = args
                    .get("overwrite")
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        s_lower == "true" || s_lower == "1" || s_lower == "yes"
                    })
                    .unwrap_or(false);

                let preserve_mode = args
                    .get("preserve_mode")
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        s_lower == "true" || s_lower == "1" || s_lower == "yes"
                    })
                    .unwrap_or(cfg!(unix));

                let preserve_times = args
                    .get("preserve_times")
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        s_lower == "true" || s_lower == "1" || s_lower == "yes"
                    })
                    .unwrap_or(false);

                // Check if destination exists
                if dest_path.exists() && !overwrite {
                    writeln!(io.stderr, "destination exists")?;
                    return Ok(Status::err(1, "destination exists"));
                }

                // Ensure destination parent directory exists
                if let Some(parent) = dest_path.parent() {
                    if !parent.exists() {
                        writeln!(io.stderr, "destination parent does not exist")?;
                        return Ok(Status::err(1, "destination parent does not exist"));
                    }
                }

                // Perform atomic copy using temporary file
                let dest_dir = dest_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));

                // Create temporary file in destination directory
                let temp_name = format!(".resh_tmp_{:x}", std::process::id());
                let temp_path = dest_dir.join(&temp_name);

                // Cleanup temporary file on any error
                let cleanup_temp = |temp_path: &std::path::Path| {
                    if temp_path.exists() {
                        let _ = std::fs::remove_file(temp_path);
                    }
                };

                // Copy contents to temporary file
                let copy_result = (|| -> Result<()> {
                    let mut source = File::open(&resolved_path).with_context(|| {
                        format!("failed to open source file {:?}", &resolved_path)
                    })?;
                    let mut temp = File::create(&temp_path).with_context(|| {
                        format!("failed to create temporary file {:?}", &temp_path)
                    })?;

                    std::io::copy(&mut source, &mut temp)
                        .with_context(|| "failed to copy file contents")?;

                    // Flush and sync
                    temp.flush()
                        .with_context(|| "failed to flush temporary file")?;

                    Ok(())
                })();

                if let Err(e) = copy_result {
                    cleanup_temp(&temp_path);
                    writeln!(io.stderr, "io error: {}", e)?;
                    return Ok(Status::err(1, &format!("io error: {}", e)));
                }

                // Apply metadata if requested (best effort)
                if preserve_mode {
                    #[cfg(unix)]
                    {
                        if let Ok(source_meta) = std::fs::metadata(&resolved_path) {
                            let perms =
                                std::fs::Permissions::from_mode(source_meta.permissions().mode());
                            if let Err(e) = std::fs::set_permissions(&temp_path, perms) {
                                // Log error but continue
                                let _ =
                                    writeln!(io.stderr, "Warning: failed to preserve mode: {}", e);
                            }
                        }
                    }
                }

                // Note: preserve_times is not implemented as it would require additional dependencies
                // This is mentioned in the requirements as optional
                if preserve_times {
                    // Could implement with filetime crate if added to dependencies
                    let _ = writeln!(io.stderr, "Warning: preserve_times not implemented");
                }

                // Atomic rename to final destination
                let rename_result = std::fs::rename(&temp_path, &dest_path).with_context(|| {
                    format!("failed to rename {:?} to {:?}", &temp_path, &dest_path)
                });

                if let Err(e) = rename_result {
                    cleanup_temp(&temp_path);
                    writeln!(io.stderr, "io error: {}", e)?;
                    return Ok(Status::err(1, &format!("io error: {}", e)));
                }

                Ok(Status::ok())
            }
            "delete" | "remove" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Safety check: refuse to delete root directory
                if resolved_path == std::path::Path::new("/") {
                    writeln!(io.stderr, "refusing to delete root path")?;
                    return Ok(Status::err(1, "refusing to delete root path"));
                }

                // Safety check: refuse to delete empty path
                if resolved_path.as_os_str().is_empty() {
                    writeln!(io.stderr, "refusing to delete empty path")?;
                    return Ok(Status::err(1, "refusing to delete empty path"));
                }

                // Parse arguments
                let recursive = args
                    .get("recursive")
                    .map(|s| matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"))
                    .unwrap_or(false);

                let force = args
                    .get("force")
                    .map(|s| matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"))
                    .unwrap_or(false);

                let missing_ok = args
                    .get("missing_ok")
                    .map(|s| matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"))
                    .unwrap_or(false);

                let allow_missing = force || missing_ok;

                // Check if path exists
                if !resolved_path.exists() {
                    if allow_missing {
                        return Ok(Status::ok()); // Treat as success if force/missing_ok is set
                    } else {
                        writeln!(io.stderr, "path not found: {}", resolved_path.display())?;
                        return Ok(Status::err(
                            2,
                            &format!("path not found: {}", resolved_path.display()),
                        ));
                    }
                }

                // Check path type and perform appropriate deletion
                if resolved_path.is_dir() {
                    if recursive {
                        match remove_dir_all(&resolved_path) {
                            Ok(_) => Ok(Status::ok()),
                            Err(e) => {
                                writeln!(
                                    io.stderr,
                                    "failed to delete directory {}: {}",
                                    resolved_path.display(),
                                    e
                                )?;
                                Ok(Status::err(
                                    1,
                                    &format!(
                                        "failed to delete directory {}: {}",
                                        resolved_path.display(),
                                        e
                                    ),
                                ))
                            }
                        }
                    } else {
                        writeln!(io.stderr, "cannot delete directory without recursive=true")?;
                        Ok(Status::err(
                            1,
                            "cannot delete directory without recursive=true",
                        ))
                    }
                } else {
                    // It's a file
                    match remove_file(&resolved_path) {
                        Ok(_) => Ok(Status::ok()),
                        Err(e) => {
                            writeln!(
                                io.stderr,
                                "failed to delete file {}: {}",
                                resolved_path.display(),
                                e
                            )?;
                            Ok(Status::err(
                                1,
                                &format!(
                                    "failed to delete file {}: {}",
                                    resolved_path.display(),
                                    e
                                ),
                            ))
                        }
                    }
                }
            }
            "exists" => {
                use std::fs;

                match fs::symlink_metadata(&self.path) {
                    Ok(meta) => {
                        let ftype = meta.file_type();
                        let kind = if ftype.is_file() {
                            "file"
                        } else if ftype.is_dir() {
                            "dir"
                        } else if ftype.is_symlink() {
                            "symlink"
                        } else {
                            "other"
                        };
                        let obj = json!({
                            "path": self.path.to_string_lossy(),
                            "exists": true,
                            "kind": kind,
                        });
                        write!(io.stdout, "{}", obj.to_string())?;
                        Ok(Status::ok())
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let obj = json!({
                            "path": self.path.to_string_lossy(),
                            "exists": false,
                            "kind": "none",
                        });
                        write!(io.stdout, "{}", obj.to_string())?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        // Fatal I/O error
                        Ok(Status::err(
                            3,
                            format!("exists: failed to stat {:?}: {}", self.path, e),
                        ))
                    }
                }
            }
            "stat" => {
                // Check for nofollow parameter
                let nofollow = args.get("nofollow").map(|s| s.as_str()) == Some("true");

                // Use appropriate metadata function
                let meta_result = if nofollow {
                    std::fs::symlink_metadata(&self.path)
                } else {
                    std::fs::metadata(&self.path)
                };

                let meta = match meta_result {
                    Ok(m) => m,
                    Err(err) => {
                        return Ok(Status::err(2, format!("stat {:?}: {}", &self.path, err)));
                    }
                };

                // Determine file type
                let file_type = if meta.file_type().is_symlink() {
                    "symlink"
                } else if meta.is_file() {
                    "file"
                } else if meta.is_dir() {
                    "dir"
                } else {
                    "other"
                };

                // Helper function to format timestamps as RFC 3339
                let format_timestamp =
                    |time_result: std::io::Result<std::time::SystemTime>| -> Option<String> {
                        time_result
                            .ok()
                            .map(|time| DateTime::<Utc>::from(time).to_rfc3339())
                    };

                // Build JSON object
                let mut json_obj = json!({
                    "path": self.path.display().to_string(),
                    "exists": true,
                    "file_type": file_type,
                    "size": meta.len(),
                    "readonly": meta.permissions().readonly(),
                    "created": format_timestamp(meta.created()),
                    "modified": format_timestamp(meta.modified()),
                    "accessed": format_timestamp(meta.accessed())
                });

                // Add Unix-specific fields
                #[cfg(unix)]
                {
                    if let Some(obj) = json_obj.as_object_mut() {
                        obj.insert(
                            "mode".to_string(),
                            json!(format!("{:04o}", meta.mode() & 0o7777)),
                        );
                        obj.insert("uid".to_string(), json!(meta.uid()));
                        obj.insert("gid".to_string(), json!(meta.gid()));
                    }
                }

                // Add null values for non-Unix platforms
                #[cfg(not(unix))]
                {
                    if let Some(obj) = json_obj.as_object_mut() {
                        obj.insert("mode".to_string(), json!(null));
                        obj.insert("uid".to_string(), json!(null));
                        obj.insert("gid".to_string(), json!(null));
                    }
                }

                writeln!(io.stdout, "{}", json_obj)?;
                Ok(Status::ok())
            }
            "chmod" => {
                #[cfg(unix)]
                {
                    let resolved_path = match resolve_file_path(&self.path) {
                        Ok(path) => path,
                        Err(e) => {
                            let msg = format!("Failed to resolve path: {}", e);
                            writeln!(io.stderr, "{}", msg)?;
                            return Ok(Status::err(1, msg));
                        }
                    };

                    // Check if file exists
                    if !resolved_path.exists() {
                        let msg = format!("No such file: {}", resolved_path.display());
                        writeln!(io.stderr, "{}", msg)?;
                        return Ok(Status::err(1, msg));
                    }

                    // Parse mode argument
                    let mode_str = match args.get("mode") {
                        Some(mode) => mode.trim(),
                        None => {
                            let msg = "missing arg: mode";
                            writeln!(io.stderr, "{}", msg)?;
                            return Ok(Status::err(1, msg));
                        }
                    };

                    // Parse mode as octal
                    let mode = match u32::from_str_radix(mode_str, 8) {
                        Ok(mode) => mode,
                        Err(_) => {
                            let msg = format!("invalid mode: {}", mode_str);
                            writeln!(io.stderr, "{}", msg)?;
                            return Ok(Status::err(1, msg));
                        }
                    };

                    // Get current permissions and set new mode
                    let metadata = match std::fs::metadata(&resolved_path) {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            let msg = format!("Failed to read file metadata: {}", e);
                            writeln!(io.stderr, "{}", msg)?;
                            return Ok(Status::err(1, msg));
                        }
                    };

                    let mut permissions = metadata.permissions();
                    permissions.set_mode(mode);

                    // Set permissions
                    match std::fs::set_permissions(&resolved_path, permissions) {
                        Ok(()) => Ok(Status::ok()),
                        Err(e) => {
                            let msg = format!(
                                "Failed to set permissions on {}: {}",
                                resolved_path.display(),
                                e
                            );
                            writeln!(io.stderr, "{}", msg)?;
                            Ok(Status::err(1, msg))
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    let msg = "chmod not supported on this platform";
                    writeln!(io.stderr, "{}", msg)?;
                    Ok(Status::err(1, msg))
                }
            }
            "chown" => {
                #[cfg(unix)]
                {
                    let resolved_path = resolve_file_path(&self.path)?;

                    // Check if path exists
                    if !resolved_path.exists() {
                        return Ok(Status::err(
                            2,
                            format!("no such file or directory: {}", resolved_path.display()),
                        ));
                    }

                    // Parse arguments
                    let user_arg = args.get("user");
                    let uid_arg = args.get("uid");
                    let group_arg = args.get("group");
                    let gid_arg = args.get("gid");
                    let recursive_arg = args.get("recursive");

                    // Validate at least one argument is provided
                    if user_arg.is_none()
                        && uid_arg.is_none()
                        && group_arg.is_none()
                        && gid_arg.is_none()
                    {
                        return Ok(Status::err(
                            1,
                            "chown requires at least one of user/uid/group/gid",
                        ));
                    }

                    // Resolve user and group IDs
                    let target_uid = match resolve_user_id(user_arg, uid_arg) {
                        Ok(uid) => uid,
                        Err(e) => return Ok(Status::err(1, format!("{}", e))),
                    };

                    let target_gid = match resolve_group_id(group_arg, gid_arg) {
                        Ok(gid) => gid,
                        Err(e) => return Ok(Status::err(1, format!("{}", e))),
                    };

                    // Get current metadata to preserve unspecified values
                    let current_meta = match metadata(&resolved_path) {
                        Ok(meta) => meta,
                        Err(e) => {
                            return Ok(Status::err(2, format!("failed to read metadata: {}", e)));
                        }
                    };

                    // Determine final uid and gid (preserve current if not specified)
                    let final_uid = target_uid.or_else(|| Some(Uid::from_raw(current_meta.uid())));
                    let final_gid = target_gid.or_else(|| Some(Gid::from_raw(current_meta.gid())));

                    // Check if recursive operation is requested
                    let is_recursive = recursive_arg
                        .map(|s| {
                            let s_lower = s.to_lowercase();
                            s_lower == "true" || s_lower == "1" || s_lower == "yes"
                        })
                        .unwrap_or(false);

                    // Perform the chown operation
                    let result = if is_recursive {
                        chown_recursive(&resolved_path, final_uid, final_gid)
                    } else {
                        chown(&resolved_path, final_uid, final_gid).with_context(|| {
                            format!("chown failed for {}", resolved_path.display())
                        })
                    };

                    match result {
                        Ok(()) => Ok(Status::ok()),
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            if error_msg.contains("Operation not permitted")
                                || error_msg.contains("Permission denied")
                            {
                                Ok(Status::err(
                                    13,
                                    format!("permission denied: {}", resolved_path.display()),
                                ))
                            } else {
                                Ok(Status::err(
                                    1,
                                    format!("chown failed for {}: {}", resolved_path.display(), e),
                                ))
                            }
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    Ok(Status::err(95, "chown not supported on this platform"))
                }
            }
            "md5" => {
                let resolved_path = resolve_file_path(&self.path)?;
                let (hash_hex, total_bytes) = calculate_md5_hash(&resolved_path)?;

                let json_result = json!({
                    "path": self.path.to_string_lossy(),
                    "algorithm": "md5",
                    "hash": hash_hex,
                    "size": total_bytes
                });

                writeln!(io.stdout, "{}", json_result)?;
                Ok(Status::ok())
            }
            "sha1" => {
                let resolved_path = resolve_file_path(&self.path)?;
                let (hash_hex, total_bytes) = calculate_sha1_hash(&resolved_path)?;

                let json_result = json!({
                    "path": self.path.to_string_lossy(),
                    "algorithm": "sha1",
                    "hash": hash_hex,
                    "size": total_bytes
                });

                writeln!(io.stdout, "{}", json_result)?;
                Ok(Status::ok())
            }
            "sha256" => {
                let resolved_path = resolve_file_path(&self.path)?;
                let (hash_hex, total_bytes) = calculate_sha256_hash(&resolved_path)?;

                let json_result = json!({
                    "path": self.path.to_string_lossy(),
                    "algorithm": "sha256",
                    "hash": hash_hex,
                    "size": total_bytes
                });

                writeln!(io.stdout, "{}", json_result)?;
                Ok(Status::ok())
            }
            "sha512" => {
                let resolved_path = resolve_file_path(&self.path)?;
                let (hash_hex, total_bytes) = calculate_sha512_hash(&resolved_path)?;

                let json_result = json!({
                    "path": self.path.to_string_lossy(),
                    "algorithm": "sha512",
                    "hash": hash_hex,
                    "size": total_bytes
                });

                writeln!(io.stdout, "{}", json_result)?;
                Ok(Status::ok())
            }
            "hash" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Check if file exists
                if !resolved_path.exists() {
                    writeln!(io.stderr, "file not found: {}", resolved_path.display())?;
                    return Ok(Status::err(1, "file not found"));
                }

                // Check if path is a directory
                let metadata = resolved_path
                    .metadata()
                    .map_err(|e| anyhow::anyhow!("failed to get file metadata: {}", e))?;

                if metadata.is_dir() {
                    writeln!(io.stderr, "is directory: cannot hash directory")?;
                    return Ok(Status::err(3, "is directory"));
                }

                // Check if path is a regular file
                if !metadata.is_file() {
                    writeln!(io.stderr, "not a regular file: {}", resolved_path.display())?;
                    return Ok(Status::err(1, "not a regular file"));
                }

                // Get algorithm from args, default to sha256
                let algo = args.get("algo").map(String::as_str).unwrap_or("sha256");

                // Compute hash based on algorithm
                let (hash_hex, total_bytes) = match algo {
                    "sha256" => calculate_sha256_hash(&resolved_path)?,
                    "sha512" => calculate_sha512_hash(&resolved_path)?,
                    "blake3" => calculate_blake3_hash(&resolved_path)?,
                    _ => {
                        writeln!(io.stderr, "unsupported algorithm: {}", algo)?;
                        return Ok(Status::err(2, "unsupported algorithm"));
                    }
                };

                // Build JSON response
                let json_result = json!({
                    "path": resolved_path.display().to_string(),
                    "algo": algo,
                    "hash_hex": hash_hex,
                    "size_bytes": total_bytes
                });

                writeln!(io.stdout, "{}", json_result)?;
                Ok(Status::ok())
            }
            "verify" => {
                // Parse algorithm argument (default: sha256)
                let algorithm = args
                    .get("algo")
                    .map(|s| s.to_lowercase())
                    .unwrap_or_else(|| "sha256".to_string());

                // Validate algorithm
                let supported_algorithms = ["sha256", "sha1", "md5", "blake3"];
                if !supported_algorithms.contains(&algorithm.as_str()) {
                    let error_msg = format!("unsupported algorithm: {}", algorithm);
                    let result = json!({
                        "path": self.path.display().to_string(),
                        "algorithm": algorithm,
                        "digest": null,
                        "size": null,
                        "expected": null,
                        "expected_any": [],
                        "match": false,
                        "size_match": false,
                        "verified": false,
                        "error": error_msg
                    });
                    writeln!(io.stdout, "{}", result)?;
                    return Ok(Status::err(2, &error_msg));
                }

                // Parse expected digests
                let expected_single = args
                    .get("expected")
                    .map(|s| s.trim().to_lowercase().replace(" ", ""));

                let expected_any: Vec<String> = args
                    .get("expected_any")
                    .map(|s| {
                        s.split(';')
                            .map(|digest| digest.trim().to_lowercase().replace(" ", ""))
                            .filter(|digest| !digest.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();

                // Parse expected size
                let expected_size = args
                    .get("size")
                    .map(|s| {
                        s.parse::<u64>()
                            .with_context(|| format!("invalid size argument: {}", s))
                    })
                    .transpose();

                let expected_size = match expected_size {
                    Ok(size_opt) => size_opt,
                    Err(e) => {
                        let error_msg = format!("invalid size argument: {}", e);
                        let result = json!({
                            "path": self.path.display().to_string(),
                            "algorithm": algorithm,
                            "digest": null,
                            "size": null,
                            "expected": expected_single,
                            "expected_any": expected_any,
                            "match": false,
                            "size_match": false,
                            "verified": false,
                            "error": error_msg
                        });
                        writeln!(io.stdout, "{}", result)?;
                        return Ok(Status::err(2, &error_msg));
                    }
                };

                // Try to resolve the file path and compute hash
                let (digest, actual_size, error_msg) = match resolve_file_path(&self.path) {
                    Ok(resolved_path) => {
                        if !resolved_path.exists() {
                            (None, None, Some("file does not exist".to_string()))
                        } else {
                            match compute_hash(&resolved_path, &algorithm) {
                                Ok((hash_hex, file_size)) => {
                                    (Some(hash_hex), Some(file_size), None)
                                }
                                Err(e) => {
                                    (None, None, Some(format!("hash computation failed: {}", e)))
                                }
                            }
                        }
                    }
                    Err(e) => (None, None, Some(format!("path resolution failed: {}", e))),
                };

                // Compute verification results
                let hash_match = match (&digest, &expected_single, &expected_any) {
                    (Some(_), None, ref any_list) if any_list.is_empty() => {
                        // No expectations - always true
                        true
                    }
                    (Some(computed_digest), Some(expected), ref any_list)
                        if any_list.is_empty() =>
                    {
                        // Only single expected
                        computed_digest == expected
                    }
                    (Some(computed_digest), None, ref any_list) if !any_list.is_empty() => {
                        // Only expected_any list
                        any_list.contains(computed_digest)
                    }
                    (Some(computed_digest), Some(expected), ref any_list)
                        if !any_list.is_empty() =>
                    {
                        // Both expected and expected_any - match either
                        computed_digest == expected || any_list.contains(computed_digest)
                    }
                    _ => {
                        // No digest computed (error case)
                        false
                    }
                };

                let size_match = match (actual_size, expected_size) {
                    (Some(actual), Some(expected)) => actual == expected,
                    (Some(_), None) => true, // No size expectation but file exists - always true
                    (None, _) => false,      // File doesn't exist - always false
                };

                let verified = hash_match && size_match && error_msg.is_none();

                // Build JSON response
                let result = json!({
                    "path": self.path.display().to_string(),
                    "algorithm": algorithm,
                    "digest": digest,
                    "size": actual_size,
                    "expected": expected_single,
                    "expected_any": expected_any,
                    "match": hash_match,
                    "size_match": size_match,
                    "verified": verified,
                    "error": error_msg
                });

                writeln!(io.stdout, "{}", result)?;

                // Return appropriate status
                if let Some(error) = error_msg {
                    Ok(Status::err(2, &error))
                } else if !verified {
                    Ok(Status::err(1, "verification failed"))
                } else {
                    Ok(Status::ok())
                }
            }
            "append" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Determine data source: args or stdin
                let data = match args.get("data") {
                    Some(d) => d.as_bytes().to_vec(),
                    None => {
                        // Read from stdin until EOF
                        let mut buffer = Vec::new();
                        io.stdin
                            .read_to_end(&mut buffer)
                            .with_context(|| "failed to read from stdin")
                            .map_err(|e| anyhow::anyhow!("io error: {}", e))?;
                        buffer
                    }
                };

                // Parse create parameter (default true)
                let create = args.get("create").map(|s| s != "false").unwrap_or(true);

                // Check if file exists when create=false
                if !create && !resolved_path.exists() {
                    return Ok(Status::err(2, "file does not exist and create=false"));
                }

                // Perform append operation
                let result = Self::safe_append(&resolved_path, &data, create).map_err(|e| {
                    // Map specific errors to appropriate status codes
                    if e.to_string().contains("Permission denied")
                        || e.to_string().contains("EACCES")
                    {
                        return anyhow::anyhow!("permission error: {}", e);
                    }
                    anyhow::anyhow!("io error: {}", e)
                })?;

                match result {
                    Ok(bytes_written) => {
                        // Optional: write minimal JSON summary to stdout
                        let summary = serde_json::json!({
                            "appended": true,
                            "bytes": bytes_written,
                            "path": resolved_path.display().to_string()
                        });
                        writeln!(io.stdout, "{}", summary)?;
                        Ok(Status::ok())
                    }
                    Err(err_msg) => {
                        if err_msg.contains("permission") {
                            Ok(Status::err(3, err_msg))
                        } else if err_msg.contains("not exist") {
                            Ok(Status::err(2, err_msg))
                        } else {
                            Ok(Status::err(1, err_msg))
                        }
                    }
                }
            }
            "find" => self.handle_find(args, io),
            "grep" => self.do_grep(args, io),
            "replace" => self.do_replace(args, io),
            "tail" => self.do_tail(args, io),
            "preview" => self.do_preview(args, io),
            "schema" => self.do_schema(args, io),
            "summary" => self.do_summary(args, io),
            "watch" => self.handle_watch(args, io),
            "analyze" => self.do_analyze(args, io),
            "move" | "mv" => {
                let resolved_path = resolve_file_path(&self.path)?;

                // Check if source exists
                if !resolved_path.exists() {
                    writeln!(io.stderr, "source not found: {}", resolved_path.display())?;
                    return Ok(Status::err(2, &format!("source not found: {}", resolved_path.display())));
                }

                // Parse destination path
                let to = args
                    .get("to")
                    .ok_or_else(|| anyhow::anyhow!("missing arg: to"))?;
                let to_dec = percent_decode_str(to).decode_utf8_lossy().to_string();
                let to_dec = unescape_backslashes(&to_dec);
                let mut dest_path = normalize_path(&std::path::PathBuf::from(to_dec));

                // Parse optional overwrite argument
                let overwrite = args
                    .get("overwrite")
                    .map(|s| {
                        let s_lower = s.to_lowercase();
                        s_lower == "true" || s_lower == "1" || s_lower == "yes"
                    })
                    .unwrap_or(false);

                // Handle moving into directory case
                if dest_path.exists() && dest_path.is_dir() {
                    if let Some(filename) = resolved_path.file_name() {
                        dest_path = dest_path.join(filename);
                    }
                }

                // Check destination existence and overwrite rules
                if dest_path.exists() && !overwrite {
                    writeln!(io.stderr, "destination exists")?;
                    return Ok(Status::err(1, "destination exists"));
                }

                // Ensure destination parent directory exists
                if let Some(parent) = dest_path.parent() {
                    if !parent.exists() {
                        writeln!(io.stderr, "destination parent does not exist")?;
                        return Ok(Status::err(1, "destination parent does not exist"));
                    }
                }

                // Attempt rename first (atomic operation)
                match std::fs::rename(&resolved_path, &dest_path) {
                    Ok(_) => Ok(Status::ok()),
                    Err(e) => {
                        // Check if it's a cross-filesystem error (EXDEV)
                        let is_cross_filesystem = e.raw_os_error() == Some(18); // EXDEV on Linux

                        if is_cross_filesystem {
                            // Perform cross-filesystem move (copy + delete)
                            self.cross_filesystem_move(&resolved_path, &dest_path, overwrite, io)
                        } else {
                            writeln!(io.stderr, "move failed from {} to {}: {}", 
                                resolved_path.display(), dest_path.display(), e)?;
                            Ok(Status::err(1, &format!("move failed from {} to {}: {}", 
                                resolved_path.display(), dest_path.display(), e)))
                        }
                    }
                }
            }
            "ea.get" => self.verb_ea_get(args, io),
            "ea.set" => self.verb_ea_set(args, io),
            "tag.add" => self.verb_tag_add(args, io),
            "tag.rm" => self.verb_tag_rm(args, io),
            _ => {
                bail!(
                    "unknown verb for file://: {} (available: read, rename, write, copy, delete, move, mv, exists, stat, chmod, chown, md5, sha1, sha256, sha512, verify, append, find, grep, replace, tail, preview, schema, summary, watch, analyze, hash, ea.get, ea.set, tag.add, tag.rm)",
                    verb
                )
            }
        }
    }
}
