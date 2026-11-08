//! Shared pieces of the `plugin` verbs: error codes, strict argument
//! checking, deadlines and version ordering.

use std::cmp::Ordering;
use std::time::{Duration, Instant};

use crate::core::Args;
use crate::core::status::exit;

/// A failure of a plugin verb: exit status, `plugin.*` error code and
/// message. Printed as `Error: [<code>] <message>` and carried in the JSON
/// result as `"error": {"code", "message"}`.
#[derive(Debug, Clone, PartialEq)]
pub struct PluginError {
    pub exit: i32,
    pub code: &'static str,
    pub message: String,
}

impl PluginError {
    pub fn new(exit: i32, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
        }
    }

    /// Invalid usage (exit 2); nothing was done.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, INVALID_ARGUMENT, message)
    }

    /// The operation failed (exit 1).
    pub fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(exit::FAILED, code, message)
    }

    /// The deadline passed (exit 124).
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(exit::TIMEOUT, TIMEOUT, message)
    }

    pub fn json(&self) -> serde_json::Value {
        crate::core::status::error_json(self.code, &self.message)
    }
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

pub type PResult<T> = std::result::Result<T, PluginError>;

// Every error code the handle emits (documented in plugin.md, section 4.9).
pub const INVALID_ARGUMENT: &str = "plugin.invalid_argument";
pub const INVALID_TARGET: &str = "plugin.invalid_target";
pub const UNKNOWN_VERB: &str = "plugin.unknown_verb";
pub const NOT_INSTALLED: &str = "plugin.not_installed";
pub const NOT_FOUND: &str = "plugin.not_found";
pub const PLATFORM_UNSUPPORTED: &str = "plugin.platform_unsupported";
pub const DOWNLOAD_FAILED: &str = "plugin.download_failed";
pub const CATALOG_INVALID: &str = "plugin.catalog_invalid";
pub const VERIFY_FAILED: &str = "plugin.verify_failed";
pub const EXTRACT_FAILED: &str = "plugin.extract_failed";
pub const INSTALL_FAILED: &str = "plugin.install_failed";
pub const DOWNGRADE_REFUSED: &str = "plugin.downgrade_refused";
pub const NO_UPDATE_AVAILABLE: &str = "plugin.no_update_available";
pub const IN_USE: &str = "plugin.in_use";
pub const REMOVE_FAILED: &str = "plugin.remove_failed";
pub const IO_ERROR: &str = "plugin.io_error";
pub const PERMISSION_DENIED: &str = "plugin.permission_denied";
pub const UNSAFE_PATH: &str = "plugin.unsafe_path";
pub const LOCKED: &str = "plugin.locked";
pub const TIMEOUT: &str = "plugin.timeout";

/// The complete list of codes (tests check each is valid and documented).
#[cfg(test)]
pub const CODES: &[&str] = &[
    INVALID_ARGUMENT,
    INVALID_TARGET,
    UNKNOWN_VERB,
    NOT_INSTALLED,
    NOT_FOUND,
    PLATFORM_UNSUPPORTED,
    DOWNLOAD_FAILED,
    CATALOG_INVALID,
    VERIFY_FAILED,
    EXTRACT_FAILED,
    INSTALL_FAILED,
    DOWNGRADE_REFUSED,
    NO_UPDATE_AVAILABLE,
    IN_USE,
    REMOVE_FAILED,
    IO_ERROR,
    PERMISSION_DENIED,
    UNSAFE_PATH,
    LOCKED,
    TIMEOUT,
];

/// An I/O failure as a plugin error: permission problems get their own code.
pub fn io_error(what: &str, e: &std::io::Error) -> PluginError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        PluginError::failed(PERMISSION_DENIED, format!("{what}: {e}"))
    } else {
        PluginError::failed(IO_ERROR, format!("{what}: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// The verbs, in help order.
pub const VERBS: &[&str] = &[
    "available.list",
    "available.search",
    "available.info",
    "installed.list",
    "install",
    "update",
    "remove",
    "enable",
    "disable",
];

/// The arguments each verb accepts; the help usage lists exactly these.
pub fn verb_args(verb: &str) -> &'static [&'static str] {
    match verb {
        "available.list" => &[
            "query",
            "tags",
            "publisher",
            "platform",
            "include_prerelease",
            "limit",
            "offset",
            "format",
            "source",
        ],
        "available.search" => &[
            "q",
            "tags",
            "owner",
            "name",
            "min_version",
            "max_results",
            "source",
            "offline",
            "refresh",
            "timeout_ms",
            "ca_file",
        ],
        "available.info" => &[
            "name",
            "id",
            "version",
            "channel",
            "os",
            "arch",
            "source",
            "offline",
            "timeout_ms",
            "ca_file",
        ],
        "installed.list" => &[
            "enabled", "name", "prefix", "tag", "source", "limit", "offset", "sort", "order",
            "format",
        ],
        "install" => &[
            "source",
            "registry",
            "url",
            "path",
            "version",
            "verify",
            "force",
            "allow_downgrade",
            "dry_run",
            "timeout_ms",
            "ca_file",
        ],
        "update" => &[
            "registry",
            "url",
            "verify",
            "strict",
            "dry_run",
            "timeout_ms",
            "ca_file",
        ],
        "remove" => &["force", "purge", "dry_run", "timeout_ms"],
        "enable" | "disable" => &["scope", "force", "reason", "dry_run"],
        _ => &[],
    }
}

/// The candidate closest to `bad` (edit distance at most 2, or a prefix of
/// at least three characters), for a "did you mean" hint.
pub fn suggest<'a>(bad: &str, candidates: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    candidates
        .iter()
        .map(|c| (distance(&lower, c), *c))
        .filter(|(d, c)| *d <= 2 || (lower.len() >= 3 && c.starts_with(lower.as_str())))
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// ` (did you mean `x`?)` or "".
pub fn hint(bad: &str, candidates: &[&str]) -> String {
    suggest(bad, candidates)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// Refuses any argument `verb` does not accept (exit 2), naming it.
pub fn check_known(verb: &str, args: &Args) -> PResult<()> {
    let allowed = verb_args(verb);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        let extra = if key == "timeout_ms" {
            " (this verb finishes at once and takes no timeout)".to_string()
        } else if key == "dry_run" {
            " (this verb changes nothing and has no dry run)".to_string()
        } else {
            hint(key, allowed)
        };
        let list = if allowed.is_empty() {
            "none".to_string()
        } else {
            allowed.join(", ")
        };
        return Err(PluginError::usage(format!(
            "unknown argument {key:?} for plugin {verb}{extra}; accepted: {list}; nothing was done"
        )));
    }
    Ok(())
}

/// Typed, strict reads of one verb's arguments. Every malformed value is a
/// usage error (exit 2).
pub struct ArgReader<'a> {
    pub args: &'a Args,
}

impl<'a> ArgReader<'a> {
    pub fn new(args: &'a Args) -> Self {
        Self { args }
    }

    pub fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    /// A string value; present but empty is an error.
    pub fn string(&self, key: &str) -> PResult<Option<String>> {
        match self.args.get(key) {
            None => Ok(None),
            Some(v) if v.is_empty() => Err(PluginError::usage(format!(
                "{key} must not be empty; nothing was done"
            ))),
            Some(v) => Ok(Some(v.clone())),
        }
    }

    pub fn bool(&self, key: &str, default: bool) -> PResult<bool> {
        crate::core::lenient::bool_arg(self.args, key)
            .map(|v| v.unwrap_or(default))
            .map_err(|e| PluginError::usage(format!("{e}; nothing was done")))
    }

    /// One of `choices`; absent gives `default`.
    pub fn choice(
        &self,
        key: &str,
        choices: &[&'static str],
        default: &'static str,
    ) -> PResult<&'static str> {
        match self.args.get(key) {
            None => Ok(default),
            Some(v) => choices.iter().find(|c| **c == v).copied().ok_or_else(|| {
                PluginError::usage(format!(
                    "invalid {key} {v:?}: expected one of {}{}; nothing was done",
                    choices.join(", "),
                    hint(v, choices)
                ))
            }),
        }
    }

    /// An integer in `min..=max`; absent gives `default`.
    pub fn uint(&self, key: &str, min: u64, max: u64, default: u64) -> PResult<u64> {
        match self.args.get(key) {
            None => Ok(default),
            Some(v) => match v.parse::<u64>() {
                Ok(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(PluginError::usage(format!(
                    "invalid {key} {v:?}: expected a whole number from {min} to {max}; nothing was done"
                ))),
            },
        }
    }

    /// `timeout_ms`: milliseconds, 1 ms to 24 hours.
    pub fn timeout_ms(&self, default: u64) -> PResult<u64> {
        self.uint("timeout_ms", 1, MAX_TIMEOUT_MS, default)
    }

    /// `ca_file`: a PEM bundle of extra trusted CAs, loaded now so that a
    /// bad file is refused before anything is done.
    pub fn ca_file(&self) -> PResult<Option<CaFile>> {
        match self.args.get("ca_file") {
            None => Ok(None),
            Some(path) => CaFile::load(path).map(Some),
        }
    }
}

/// Longest accepted `timeout_ms` (24 hours).
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// Extra trusted certificates (`ca_file=<pem>`), added to the built-in roots
/// for one call. Certificate verification always stays on.
#[derive(Clone)]
pub struct CaFile {
    pub path: String,
    pub certs: Vec<reqwest::Certificate>,
}

impl CaFile {
    pub fn load(path: &str) -> PResult<Self> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let bad = |m: String| PluginError::usage(format!("invalid ca_file: {m}; nothing was done"));
        if path.trim().is_empty() {
            return Err(bad("the path is empty".into()));
        }
        let ders = CertificateDer::pem_file_iter(path)
            .map_err(|e| bad(format!("cannot read {path}: {e}")))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| bad(format!("bad certificate in {path}: {e}")))?;
        if ders.is_empty() {
            return Err(bad(format!("no PEM certificate in {path}")));
        }
        let certs = ders
            .iter()
            .map(|d| {
                reqwest::Certificate::from_der(d.as_ref())
                    .map_err(|e| bad(format!("bad certificate in {path}: {e}")))
            })
            .collect::<PResult<Vec<_>>>()?;
        Ok(Self {
            path: path.to_string(),
            certs,
        })
    }
}

impl std::fmt::Debug for CaFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CaFile({:?}, {} certs)", self.path, self.certs.len())
    }
}

// ---------------------------------------------------------------------------
// Deadline
// ---------------------------------------------------------------------------

/// The whole-verb deadline set by `timeout_ms`.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    pub at: Instant,
    pub ms: u64,
}

impl Deadline {
    pub fn after_ms(ms: u64) -> Self {
        Self {
            at: Instant::now() + Duration::from_millis(ms),
            ms,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }

    /// A timeout error when the deadline has passed; `what` says what was
    /// left undone.
    pub fn check(&self, what: &str) -> PResult<()> {
        if self.expired() {
            Err(self.error(what))
        } else {
            Ok(())
        }
    }

    pub fn error(&self, what: &str) -> PluginError {
        PluginError::timeout(format!("timeout_ms={} reached {what}", self.ms))
    }
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// A version in `[v]MAJOR[.MINOR[.PATCH...]][-PRERELEASE][+BUILD]` form with
/// numeric release parts, as used for ordering.
#[derive(Debug, PartialEq, Eq)]
struct Parsed<'a> {
    release: Vec<u64>,
    pre: Option<&'a str>,
}

fn parse_version(v: &str) -> Option<Parsed<'_>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.split('+').next()?;
    let (rel, pre) = match v.split_once('-') {
        Some((r, p)) if !p.is_empty() => (r, Some(p)),
        Some(_) => return None,
        None => (v, None),
    };
    let release = rel
        .split('.')
        .map(|p| {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                p.parse::<u64>().ok()
            }
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Parsed { release, pre })
}

/// True if `v` has a comparable version form (see [`compare_versions`]).
pub fn is_version(v: &str) -> bool {
    parse_version(v).is_some()
}

/// Semantic-version order: release parts numerically (`1.10.0` is newer
/// than `1.9.0`, missing parts count as 0), a pre-release sorts before its
/// release, and build metadata is ignored. `None` when either side is not a
/// version (such as `local` or `unknown`).
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    let (pa, pb) = (parse_version(a)?, parse_version(b)?);
    let n = pa.release.len().max(pb.release.len());
    for i in 0..n {
        let (x, y) = (
            pa.release.get(i).copied().unwrap_or(0),
            pb.release.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    Some(match (pa.pre, pb.pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => compare_prerelease(x, y),
    })
}

/// SemVer pre-release precedence: dot-separated identifiers, numeric ones
/// compared numerically and below alphanumeric ones.
fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut ia = a.split('.');
    let mut ib = b.split('.');
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

/// Total order for sorting: versions by [`compare_versions`], anything that
/// is not a version below every version, then by text.
pub fn version_sort_key_cmp(a: &str, b: &str) -> Ordering {
    match compare_versions(a, b) {
        Some(o) => o,
        None => match (is_version(a), is_version(b)) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => a.cmp(b),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_numerically() {
        use Ordering::*;
        for (a, b, o) in [
            ("1.10.0", "1.9.0", Greater),
            ("1.9.0", "1.10.0", Less),
            ("1.0", "1.0.0", Equal),
            ("v2.0.0", "1.99.99", Greater),
            ("1.0.0-rc.1", "1.0.0", Less),
            ("1.0.0-rc.2", "1.0.0-rc.10", Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Less),
            ("1.0.0-1", "1.0.0-alpha", Less),
            ("1.0.0+build.5", "1.0.0", Equal),
        ] {
            assert_eq!(compare_versions(a, b), Some(o), "{a} vs {b}");
        }
        for (a, b) in [
            ("local", "1.0.0"),
            ("1.0.0", "unknown"),
            ("1..0", "1.0"),
            ("1.0-", "1.0"),
        ] {
            assert_eq!(compare_versions(a, b), None, "{a} vs {b}");
        }
        assert_eq!(version_sort_key_cmp("local", "0.0.1"), Ordering::Less);
    }

    #[test]
    fn every_code_is_valid() {
        for c in CODES {
            assert!(crate::core::status::is_valid_error_code(c), "{c}");
        }
    }

    #[test]
    fn suggestions() {
        assert_eq!(suggest("verfy", verb_args("install")), Some("verify"));
        assert_eq!(suggest("dry-run", verb_args("install")), Some("dry_run"));
        assert_eq!(suggest("zzz", verb_args("install")), None);
    }
}
