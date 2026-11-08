//! `env.list`: the environment of resh itself or of another process
//! (`/proc/<pid>/environ`), filtered, sorted, truncated and with sensitive
//! values masked.

use super::args::{EnvListOptions, SortBy, SortOrder};
use super::error::SysError;
use super::host::{Host, ReadKind};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

pub const MASK: &str = "***MASKED***";

#[derive(Debug, Clone, Serialize)]
pub struct EnvVar {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub masked: bool,
    pub truncated: bool,
    /// Length of the full value in characters.
    pub value_length: usize,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct EnvHuman {
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct EnvListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub pid: i64,
    pub source: String,
    pub env_count_total: u32,
    pub env_count_returned: u32,
    pub env_count_masked: u32,
    pub env_count_truncated: u32,
    pub truncated_vars: bool,
    pub variables: Vec<EnvVar>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    pub human: EnvHuman,
    pub warnings: Vec<String>,
}

/// Splits a NUL-separated `environ` block into name/value pairs (entries
/// without `=` are skipped).
pub fn parse_environ(bytes: &[u8]) -> Vec<(String, String)> {
    bytes
        .split(|b| *b == 0)
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let s = String::from_utf8_lossy(e);
            let (k, v) = s.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Names that suggest a secret (case-insensitive substrings). `PWD` and
/// `OLDPWD` are directories, not passwords.
pub fn is_sensitive_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == "pwd" || n == "oldpwd" {
        return false;
    }
    const PARTS: &[&str] = &[
        "password",
        "passwd",
        "pass",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "client_secret",
        "cred",
        "cookie",
        "session",
        "database_url",
        "dsn",
    ];
    PARTS.iter().any(|p| n.contains(p)) || (n.contains("auth") && n.contains("key"))
}

/// A URL with user information carries its password whatever the name is.
pub fn value_has_credentials(value: &str) -> bool {
    value.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .contains('@')
    })
}

fn truncate(value: &str, max: u32) -> (String, bool) {
    if max == 0 || value.chars().count() <= max as usize {
        (value.to_string(), false)
    } else {
        (value.chars().take(max as usize).collect(), true)
    }
}

pub fn env_list(
    host: &Host,
    o: &EnvListOptions,
    regexes: &[Regex],
) -> Result<EnvListResponse, SysError> {
    let now = host.now_unix_ms();
    let own = host.pid();
    let (pid, source, vars) = match o.pid {
        None => (own, "process", host.own_env()),
        Some(pid) => {
            let path = format!("/proc/{pid}/environ");
            let bytes = host.read_bytes(&path).map_err(|e| match e.kind {
                ReadKind::NotFound => SysError::new(
                    "system.env_list_pid_not_found",
                    format!("no process with pid {pid} ({e})"),
                ),
                ReadKind::Denied => SysError::new(
                    "system.env_list_permission_denied",
                    format!(
                        "{e}: the environment of another user's process needs that user or root"
                    ),
                ),
                ReadKind::Other => SysError::new("system.env_list_unavailable", e.to_string()),
            })?;
            (pid, "proc", parse_environ(&bytes))
        }
    };
    let total = vars.len() as u32;
    let mut picked: Vec<(String, String)> = vars
        .into_iter()
        .filter(|(n, _)| o.names.is_empty() || o.names.contains(n))
        .filter(|(n, _)| {
            o.prefix_filters.is_empty() || o.prefix_filters.iter().any(|p| n.starts_with(p))
        })
        .filter(|(n, _)| regexes.is_empty() || regexes.iter().any(|r| r.is_match(n)))
        .collect();
    match o.sort_by {
        SortBy::Name => picked.sort_by(|a, b| a.0.cmp(&b.0)),
        SortBy::Length => picked.sort_by(|a, b| {
            a.1.chars()
                .count()
                .cmp(&b.1.chars().count())
                .then(a.0.cmp(&b.0))
        }),
        SortBy::None => {}
    }
    if o.sort_order == SortOrder::Desc && o.sort_by != SortBy::None {
        picked.reverse();
    }
    let mut warnings = Vec::new();
    let matched = picked.len();
    let truncated_vars = matched > o.max_vars as usize;
    if truncated_vars {
        picked.truncate(o.max_vars as usize);
        warnings.push(format!(
            "{matched} variables match; only the first max_vars={} are listed",
            o.max_vars
        ));
    }
    let is_secret = |n: &str, v: &str| {
        !o.include_sensitive && (is_sensitive_name(n) || value_has_credentials(v))
    };
    let mut masked_n = 0;
    let mut truncated_n = 0;
    let variables: Vec<EnvVar> = picked
        .iter()
        .map(|(name, value)| {
            let masked = is_secret(name, value);
            masked_n += u32::from(masked);
            let (shown, cut) = if masked {
                (MASK.to_string(), false)
            } else {
                truncate(value, o.truncate_length)
            };
            truncated_n += u32::from(cut && o.include_values);
            EnvVar {
                name: name.clone(),
                value: o.include_values.then_some(shown),
                masked,
                truncated: cut && o.include_values,
                value_length: value.chars().count(),
                source: source.to_string(),
            }
        })
        .collect();
    let returned = variables.len() as u32;
    // The raw view lists the same variables as entries, masked the same way.
    let raw = o.include_raw.then(|| {
        let environ: Vec<String> = picked
            .iter()
            .map(|(n, v)| {
                if is_secret(n, v) {
                    format!("{n}={MASK}")
                } else {
                    format!("{n}={v}")
                }
            })
            .collect();
        json!({ "environ": environ })
    });
    let paths = o.include_paths.then(|| {
        json!({ "environ": match o.pid {
            None => "/proc/self/environ".to_string(),
            Some(p) => format!("/proc/{p}/environ"),
        }})
    });
    Ok(EnvListResponse {
        ok: true,
        timestamp_unix_ms: now,
        pid,
        source: source.to_string(),
        env_count_total: total,
        env_count_returned: returned,
        env_count_masked: masked_n,
        env_count_truncated: truncated_n,
        truncated_vars,
        variables,
        raw,
        paths,
        human: EnvHuman {
            summary: format!(
                "{returned} of {total} environment variables listed ({masked_n} masked, \
                 {truncated_n} truncated){}",
                if truncated_vars {
                    " [list truncated]"
                } else {
                    ""
                }
            ),
        },
        warnings,
    })
}
