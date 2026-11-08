//! Option parsing for the system verbs. Options arrive as `key=value` words,
//! as the keys of one JSON object in `input=<json>`, or both (a word
//! overrides the same key in `input`). Each verb has one list of accepted
//! options; anything else is refused before any work is done (exit 2,
//! `system.invalid_argument`), as is a value of the wrong type or outside
//! its range.

use super::error::SysError;
use crate::core::registry::Args;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// Argument keys that request help instead of running a verb.
pub const HELP_KEYS: &[&str] = &["help", "--help", "-h", "h"];

/// Upper bound for `sample_duration_ms` and `sample_min_ms` (one minute).
pub const MAX_SAMPLE_MS: u64 = 60_000;

/// Default `timeout_ms` for `info` and `disk`.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

pub const INFO_SCOPES: &[&str] = &[
    "os",
    "kernel",
    "cpu",
    "memory",
    "load",
    "disk",
    "process",
    "pressure",
    "cgroup",
    "virtualization",
];

/// The accepted options of each verb (`input` is accepted by every verb).
pub fn accepted(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "info" => &[
            "scopes",
            "fields",
            "sample_duration_ms",
            "sample_min_ms",
            "per_cpu",
            "max_mounts",
            "max_process_classes",
            "include_raw",
            "include_paths",
            "timeout_ms",
            "format",
        ],
        "uptime" => &[
            "include_idle",
            "include_boot_time",
            "include_human",
            "include_raw",
            "include_paths",
            "format",
        ],
        "load" => &[
            "normalize_per_cpu",
            "include_queue",
            "include_human",
            "include_raw",
            "include_paths",
            "min_cpu_count",
            "format",
        ],
        "memory" => &[
            "include_swap",
            "include_cgroup",
            "include_hugepages",
            "include_human",
            "include_raw",
            "include_paths",
            "format",
        ],
        "cpu" => &[
            "sample_duration_ms",
            "sample_min_ms",
            "per_cpu",
            "include_topology",
            "include_frequency",
            "include_cgroup",
            "include_human",
            "include_raw",
            "include_paths",
            "format",
        ],
        "disk" => &[
            "mount_points",
            "devices",
            "fs_types",
            "include_virtual",
            "max_mounts",
            "include_io",
            "include_fs_types",
            "include_human",
            "include_raw",
            "include_paths",
            "timeout_ms",
            "format",
        ],
        "env.list" => &[
            "pid",
            "names",
            "prefix_filters",
            "regex_filters",
            "include_values",
            "include_sensitive",
            "truncate_length",
            "max_vars",
            "sort_by",
            "sort_order",
            "include_raw",
            "include_paths",
            "format",
        ],
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortBy {
    Name,
    Length,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InfoOptions {
    pub scopes: Vec<String>,
    pub fields: Option<Vec<String>>,
    pub sample_duration_ms: u64,
    pub sample_min_ms: u64,
    pub per_cpu: bool,
    pub max_mounts: u32,
    pub max_process_classes: u32,
    pub include_raw: bool,
    pub include_paths: bool,
    pub timeout_ms: u64,
    pub format: OutputFormat,
}

impl Default for InfoOptions {
    fn default() -> Self {
        Self {
            scopes: ["os", "kernel", "cpu", "memory", "load"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            fields: None,
            sample_duration_ms: 0,
            sample_min_ms: 50,
            per_cpu: false,
            max_mounts: 32,
            max_process_classes: 5,
            include_raw: false,
            include_paths: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UptimeOptions {
    pub include_idle: bool,
    pub include_boot_time: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

impl Default for UptimeOptions {
    fn default() -> Self {
        Self {
            include_idle: true,
            include_boot_time: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoadOptions {
    pub normalize_per_cpu: bool,
    pub include_queue: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub min_cpu_count: u32,
    pub format: OutputFormat,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            normalize_per_cpu: true,
            include_queue: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            min_cpu_count: 1,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MemoryOptions {
    pub include_swap: bool,
    pub include_cgroup: bool,
    pub include_hugepages: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

impl Default for MemoryOptions {
    fn default() -> Self {
        Self {
            include_swap: true,
            include_cgroup: true,
            include_hugepages: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CpuOptions {
    pub sample_duration_ms: u64,
    pub sample_min_ms: u64,
    pub per_cpu: bool,
    pub include_topology: bool,
    pub include_frequency: bool,
    pub include_cgroup: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

impl Default for CpuOptions {
    fn default() -> Self {
        Self {
            sample_duration_ms: 250,
            sample_min_ms: 50,
            per_cpu: true,
            include_topology: true,
            include_frequency: true,
            include_cgroup: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

impl CpuOptions {
    /// The time between the two samples: `sample_duration_ms`, or
    /// `sample_min_ms` when it is 0.
    pub fn interval_ms(&self) -> u64 {
        if self.sample_duration_ms == 0 {
            self.sample_min_ms
        } else {
            self.sample_duration_ms
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DiskOptions {
    pub mount_points: Vec<String>,
    pub devices: Vec<String>,
    pub fs_types: Vec<String>,
    pub include_virtual: bool,
    pub max_mounts: u32,
    pub include_io: bool,
    pub include_fs_types: bool,
    pub include_human: bool,
    pub include_raw: bool,
    pub include_paths: bool,
    pub timeout_ms: u64,
    pub format: OutputFormat,
}

impl Default for DiskOptions {
    fn default() -> Self {
        Self {
            mount_points: vec![],
            devices: vec![],
            fs_types: vec![],
            include_virtual: false,
            max_mounts: 64,
            include_io: true,
            include_fs_types: true,
            include_human: true,
            include_raw: false,
            include_paths: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EnvListOptions {
    pub pid: Option<i64>,
    pub names: Vec<String>,
    pub prefix_filters: Vec<String>,
    pub regex_filters: Vec<String>,
    pub include_values: bool,
    pub include_sensitive: bool,
    pub truncate_length: u32,
    pub max_vars: u32,
    pub sort_by: SortBy,
    pub sort_order: SortOrder,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

impl Default for EnvListOptions {
    fn default() -> Self {
        Self {
            pid: None,
            names: Vec::new(),
            prefix_filters: Vec::new(),
            regex_filters: Vec::new(),
            include_values: true,
            include_sensitive: false,
            truncate_length: 512,
            max_vars: 1024,
            sort_by: SortBy::Name,
            sort_order: SortOrder::Asc,
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        }
    }
}

/// The accepted name closest to `bad` (edit distance at most 2), for a
/// "did you mean" hint.
pub fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// " (did you mean `x`?)" when `bad` looks like a typo of an accepted name.
pub fn did_you_mean(bad: &str, allowed: &[&str]) -> String {
    suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// The merged options of one call: the `input` object, then the plain
/// `key=value` words over it.
fn merged(args: &Args) -> Result<Map<String, Value>, SysError> {
    let mut map = match args.get("input") {
        Some(input) => match serde_json::from_str::<Value>(input) {
            Ok(Value::Object(m)) => m,
            Ok(_) => {
                return Err(SysError::invalid(
                    "input must be a JSON object, for example input={\"format\":\"text\"}",
                ));
            }
            Err(e) => return Err(SysError::invalid(format!("input is not valid JSON: {e}"))),
        },
        None => Map::new(),
    };
    for (k, v) in args {
        if k != "input" && !HELP_KEYS.contains(&k.as_str()) {
            map.insert(k.clone(), Value::String(v.clone()));
        }
    }
    Ok(map)
}

/// Parses the options of `verb`. Unknown keys and unreadable values are
/// refused, naming the argument.
pub fn parse<T: DeserializeOwned>(verb: &str, args: &Args) -> Result<T, SysError> {
    let allowed = accepted(verb).unwrap_or(&[]);
    let map = merged(args)?;
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in &keys {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        let msg = match key.as_str() {
            "timeout_ms" => format!(
                "system {verb} does not take timeout_ms: it only reads files under /proc \
                 and /sys (only info and disk have a time limit)"
            ),
            "dry_run" => format!("system {verb} does not take dry_run: it changes nothing"),
            _ => format!(
                "unknown argument for system {verb}: {key}{}",
                did_you_mean(key, allowed)
            ),
        };
        return Err(SysError::invalid(msg));
    }
    for key in &keys {
        let one: Map<String, Value> = [((*key).clone(), map[key.as_str()].clone())]
            .into_iter()
            .collect();
        if let Err(e) = crate::core::lenient::from_value::<T>(Value::Object(one)) {
            return Err(SysError::invalid(format!(
                "invalid value for {key}: {}",
                describe_value(&map[key.as_str()], &e.to_string())
            )));
        }
    }
    crate::core::lenient::from_value::<T>(Value::Object(map))
        .map_err(|e| SysError::invalid(format!("invalid options: {e}")))
}

fn describe_value(v: &Value, err: &str) -> String {
    let shown = match v {
        Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    };
    // serde's text is "invalid value: string \"x\", expected a boolean";
    // keep only what was expected.
    let expected = err
        .split_once("expected ")
        .map(|(_, e)| e.trim_end_matches(|c: char| c == '.' || c.is_whitespace()))
        .unwrap_or(err);
    let expected = match expected {
        "a boolean" => "true/false, 1/0, yes/no or on/off",
        "u32" | "u64" => "a non-negative whole number",
        "i64" => "a whole number",
        e if e.starts_with("one of") => e,
        e => e,
    };
    format!("{shown} (expected {expected})")
}

fn range(name: &str, v: u64, min: u64, max: u64) -> Result<(), SysError> {
    if v < min || v > max {
        return Err(SysError::invalid(format!(
            "{name} must be between {min} and {max}, got {v}"
        )));
    }
    Ok(())
}

fn sampling(duration: u64, min: u64) -> Result<(), SysError> {
    range("sample_min_ms", min, 1, MAX_SAMPLE_MS)?;
    range("sample_duration_ms", duration, 0, MAX_SAMPLE_MS)?;
    if duration != 0 && duration < min {
        return Err(SysError::invalid(format!(
            "sample_duration_ms ({duration}) must be at least sample_min_ms ({min})"
        )));
    }
    Ok(())
}

/// Every value of `list` must be one of `known`.
fn one_of(name: &str, list: &[String], known: &[&str]) -> Result<(), SysError> {
    for v in list {
        if !known.contains(&v.as_str()) {
            return Err(SysError::invalid(format!(
                "invalid {name} value {v:?}{} (expected one of: {})",
                did_you_mean(v, known),
                known.join(", ")
            )));
        }
    }
    Ok(())
}

fn no_empty(name: &str, list: &[String]) -> Result<(), SysError> {
    if list.iter().any(|v| v.trim().is_empty()) {
        return Err(SysError::invalid(format!("{name} has an empty entry")));
    }
    Ok(())
}

pub fn validate_info(o: &InfoOptions) -> Result<(), SysError> {
    if o.scopes.is_empty() {
        return Err(SysError::invalid(format!(
            "scopes is empty (expected one or more of: {})",
            INFO_SCOPES.join(", ")
        )));
    }
    one_of("scopes", &o.scopes, INFO_SCOPES)?;
    sampling(o.sample_duration_ms, o.sample_min_ms)?;
    if o.per_cpu && o.sample_duration_ms == 0 {
        return Err(SysError::invalid(
            "per_cpu=true needs CPU sampling: set sample_duration_ms (for example 250)",
        ));
    }
    range("max_mounts", o.max_mounts as u64, 1, 100_000)?;
    range(
        "max_process_classes",
        o.max_process_classes as u64,
        0,
        100_000,
    )?;
    range("timeout_ms", o.timeout_ms, 1, 86_400_000)?;
    if o.sample_duration_ms >= o.timeout_ms {
        return Err(SysError::invalid(format!(
            "sample_duration_ms ({}) must be shorter than timeout_ms ({})",
            o.sample_duration_ms, o.timeout_ms
        )));
    }
    if let Some(fields) = &o.fields {
        super::info::validate_fields(fields, &o.scopes)?;
    }
    Ok(())
}

pub fn validate_load(o: &LoadOptions) -> Result<(), SysError> {
    range("min_cpu_count", o.min_cpu_count as u64, 1, 1_000_000)
}

pub fn validate_cpu(o: &CpuOptions) -> Result<(), SysError> {
    sampling(o.sample_duration_ms, o.sample_min_ms)
}

pub fn validate_disk(o: &DiskOptions) -> Result<(), SysError> {
    no_empty("mount_points", &o.mount_points)?;
    no_empty("devices", &o.devices)?;
    no_empty("fs_types", &o.fs_types)?;
    for m in &o.mount_points {
        if !m.starts_with('/') {
            return Err(SysError::invalid(format!(
                "mount_points entry {m:?} is not an absolute path"
            )));
        }
    }
    range("max_mounts", o.max_mounts as u64, 1, 100_000)?;
    range("timeout_ms", o.timeout_ms, 1, 86_400_000)
}

pub fn validate_env_list(o: &EnvListOptions) -> Result<Vec<regex::Regex>, SysError> {
    if let Some(pid) = o.pid
        && pid < 1
    {
        return Err(SysError::invalid(format!(
            "pid must be a positive process ID, got {pid}"
        )));
    }
    no_empty("names", &o.names)?;
    no_empty("prefix_filters", &o.prefix_filters)?;
    range("max_vars", o.max_vars as u64, 1, 1_000_000)?;
    o.regex_filters
        .iter()
        .map(|p| {
            regex::Regex::new(p)
                .map_err(|e| SysError::invalid(format!("invalid regex_filters entry {p:?}: {e}")))
        })
        .collect()
}
