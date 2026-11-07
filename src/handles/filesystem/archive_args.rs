//! Argument parsing, error kinds and deadlines shared by the archive verbs.
//!
//! Every option a verb reads is listed once in [`options_for`]; the parser
//! refuses any other key, so a misspelled option is an error instead of
//! being silently ignored, and the help text is tested against the same
//! list.

use std::io;
use std::time::{Duration, Instant};

use crate::core::registry::Args;

/// Options read by `create`.
pub const CREATE_OPTIONS: &[&str] = &[
    "output",
    "sources",
    "format",
    "base_dir",
    "compression_level",
    "include_patterns",
    "exclude_patterns",
    "include_hidden",
    "follow_symlinks",
    "overwrite",
    "preserve_permissions",
    "preserve_timestamps",
    "max_files",
    "max_size_mb",
    "progress",
    "password",
    "timeout_ms",
    "format_output",
];

/// Options read by `extract`.
pub const EXTRACT_OPTIONS: &[&str] = &[
    "archive",
    "destination",
    "includes",
    "excludes",
    "overwrite",
    "strip_components",
    "create_destination",
    "allow_absolute_paths",
    "allow_parent_traversal",
    "allow_symlinks",
    "follow_symlinks",
    "max_entries",
    "max_total_bytes",
    "max_file_bytes",
    "format",
    "compression",
    "fail_on_missing_archive",
    "include_manifest",
    "timeout_ms",
    "format_output",
];

/// Options read by `list`.
pub const LIST_OPTIONS: &[&str] = &[
    "archive",
    "includes",
    "excludes",
    "include_metadata",
    "include_compressed_size",
    "max_entries",
    "max_total_bytes",
    "format",
    "compression",
    "fail_on_missing_archive",
    "timeout_ms",
    "format_output",
];

/// Options read by `test`.
pub const TEST_OPTIONS: &[&str] = &[
    "archive",
    "verify_data",
    "report_entries",
    "stop_on_first_error",
    "max_entries",
    "max_total_bytes",
    "max_file_bytes",
    "format",
    "compression",
    "fail_on_missing_archive",
    "timeout_ms",
    "format_output",
];

/// Options read by `info`.
pub const INFO_OPTIONS: &[&str] = &[
    "archive",
    "scan_entries",
    "max_entries",
    "max_total_bytes",
    "format",
    "compression",
    "fail_on_missing_archive",
    "timeout_ms",
    "format_output",
];

/// Options read by `add`.
pub const ADD_OPTIONS: &[&str] = &[
    "archive",
    "inputs",
    "base_dir",
    "includes",
    "excludes",
    "overwrite",
    "keep_existing_dirs",
    "follow_symlinks",
    "preserve_owner",
    "preserve_permissions",
    "preserve_timestamps",
    "deterministic",
    "backup_suffix",
    "tmp_dir",
    "max_entries",
    "max_total_bytes",
    "format",
    "compression",
    "timeout_ms",
    "format_output",
];

/// Options read by `remove`.
pub const REMOVE_OPTIONS: &[&str] = &[
    "archive",
    "paths",
    "patterns",
    "dir_prefixes",
    "dry_run",
    "remove_empty_dirs",
    "backup_suffix",
    "tmp_dir",
    "max_entries",
    "max_total_bytes",
    "format",
    "compression",
    "fail_on_missing_archive",
    "timeout_ms",
    "format_output",
];

/// The options `verb` reads, or `None` for an unknown verb.
pub fn options_for(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "create" => CREATE_OPTIONS,
        "extract" => EXTRACT_OPTIONS,
        "list" => LIST_OPTIONS,
        "test" => TEST_OPTIONS,
        "info" => INFO_OPTIONS,
        "add" => ADD_OPTIONS,
        "remove" => REMOVE_OPTIONS,
        _ => return None,
    })
}

/// The accepted option closest to `key` when it is a likely typo: at most
/// two edits away, or one of the two contains the other.
pub fn suggest(key: &str, allowed: &[&'static str]) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    allowed
        .iter()
        .map(|a| (edit_distance(&key, a), *a))
        .filter(|(d, a)| {
            *d <= 2 || (key.len() >= 4 && (a.contains(key.as_str()) || key.contains(a)))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn edit_distance(a: &str, b: &str) -> usize {
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

/// A failure of a known kind. The verb reports it as
/// `archive.<verb>_<kind>`, for example `archive.list_invalid_argument`.
#[derive(Debug)]
pub struct Fail {
    pub kind: &'static str,
    pub message: String,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Fail {}

/// An error of kind `kind` (see [`Fail`]).
pub fn fail(kind: &'static str, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail {
        kind,
        message: message.into(),
    })
}

/// The kind of `err`: a [`Fail`] anywhere in its chain, else one derived
/// from an I/O error in the chain (timeout, permission, disk full), else
/// `None`.
pub fn kind_of(err: &anyhow::Error) -> Option<&'static str> {
    for cause in err.chain() {
        if let Some(f) = cause.downcast_ref::<Fail>() {
            return Some(f.kind);
        }
    }
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<io::Error>() {
            if e.kind() == io::ErrorKind::TimedOut {
                return Some("timeout");
            }
        }
    }
    None
}

/// The I/O error kind found in `err`'s chain, if any.
pub fn io_kind(err: &anyhow::Error) -> Option<io::ErrorKind> {
    err.chain()
        .find_map(|c| c.downcast_ref::<io::Error>().map(|e| e.kind()))
}

/// True for the error `tar_limit` raises when a member carries more than
/// the allowed header data.
pub fn is_tar_header_limit(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        c.to_string()
            .starts_with("tar header data for one archive member exceeds")
    })
}

/// Report format.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

/// The time an operation must finish by (`timeout_ms`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Deadline {
    at: Option<Instant>,
    ms: u64,
}

impl Deadline {
    /// No time limit.
    pub fn none() -> Self {
        Self::default()
    }

    /// A limit of `ms` milliseconds from now.
    pub fn after_ms(ms: u64) -> Self {
        Self {
            at: Instant::now().checked_add(Duration::from_millis(ms)),
            ms,
        }
    }

    pub fn is_set(&self) -> bool {
        self.at.is_some()
    }

    fn expired(&self) -> bool {
        self.at.is_some_and(|at| Instant::now() >= at)
    }

    fn message(&self) -> String {
        format!("operation did not finish within timeout_ms={}", self.ms)
    }

    /// Fails with kind `timeout` once the deadline has passed.
    pub fn check(&self) -> anyhow::Result<()> {
        if self.expired() {
            return Err(fail("timeout", self.message()));
        }
        Ok(())
    }

    /// The same check as an I/O error, for use inside readers and writers.
    pub fn check_io(&self) -> io::Result<()> {
        if self.expired() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, self.message()));
        }
        Ok(())
    }
}

/// A reader that fails with `TimedOut` once the deadline passes, so a
/// single large or slow entry cannot outlive `timeout_ms`.
pub struct DeadlineReader<R> {
    inner: R,
    deadline: Deadline,
}

impl<R> DeadlineReader<R> {
    pub fn new(inner: R, deadline: Deadline) -> Self {
        Self { inner, deadline }
    }
}

impl<R: io::Read> io::Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.deadline.check_io()?;
        self.inner.read(buf)
    }
}

impl<R: io::Seek> io::Seek for DeadlineReader<R> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.deadline.check_io()?;
        self.inner.seek(pos)
    }
}

/// Reads the arguments of one verb. Construction refuses keys the verb
/// does not read; each accessor refuses a value it cannot read instead of
/// substituting a default.
pub struct Parser<'a> {
    args: &'a Args,
}

impl<'a> Parser<'a> {
    pub fn new(args: &'a Args, verb: &str) -> anyhow::Result<Self> {
        let allowed = options_for(verb).unwrap_or(&[]);
        let mut unknown: Vec<&str> = args
            .keys()
            .map(String::as_str)
            .filter(|k| !allowed.contains(k))
            .collect();
        unknown.sort_unstable();
        if let Some(first) = unknown.first() {
            let hint = suggest(first, allowed)
                .map(|s| format!(" (did you mean {s:?}?)"))
                .unwrap_or_default();
            return Err(fail(
                "invalid_argument",
                format!(
                    "unknown option {first:?} for archive {verb}{hint}; accepted options: {}",
                    allowed.join(", ")
                ),
            ));
        }
        Ok(Self { args })
    }

    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.args.get(key).map(String::as_str)
    }

    /// A required, non-empty string. Missing or empty fails with `kind`.
    pub fn required(&self, key: &str, kind: &'static str) -> anyhow::Result<String> {
        match self.get(key) {
            None => Err(fail(kind, format!("Missing required parameter: {key}"))),
            Some("") => Err(fail(kind, format!("{key} cannot be empty"))),
            Some(v) => Ok(v.to_string()),
        }
    }

    /// An optional string; present but empty fails with `kind`.
    pub fn optional(&self, key: &str, kind: &'static str) -> anyhow::Result<Option<String>> {
        match self.get(key) {
            None => Ok(None),
            Some("") => Err(fail(kind, format!("{key} cannot be empty"))),
            Some(v) => Ok(Some(v.to_string())),
        }
    }

    /// A boolean in one of the CLI spellings (`true/false`, `1/0`, `yes/no`,
    /// `on/off`, any case).
    pub fn bool(&self, key: &str, default: bool) -> anyhow::Result<bool> {
        match self.get(key) {
            None => Ok(default),
            Some(v) => crate::core::lenient::parse_bool(v).ok_or_else(|| {
                fail(
                    "invalid_argument",
                    format!(
                        "invalid value for {key}: {v:?} (expected true/false, 1/0, yes/no or on/off)"
                    ),
                )
            }),
        }
    }

    /// A whole number written with the digits 0-9 only; `None` if absent.
    pub fn opt_u64(&self, key: &str, kind: &'static str) -> anyhow::Result<Option<u64>> {
        let Some(v) = self.get(key) else {
            return Ok(None);
        };
        if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = v.parse::<u64>() {
                return Ok(Some(n));
            }
        }
        Err(fail(
            kind,
            format!(
                "invalid value for {key}: {v:?} (expected a whole number from 0 to {})",
                u64::MAX
            ),
        ))
    }

    /// Like [`Self::opt_u64`] with a default.
    pub fn u64(&self, key: &str, default: u64, kind: &'static str) -> anyhow::Result<u64> {
        Ok(self.opt_u64(key, kind)?.unwrap_or(default))
    }

    /// A JSON array of strings; absent means empty.
    pub fn list(&self, key: &str, kind: &'static str) -> anyhow::Result<Vec<String>> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some(v) => serde_json::from_str::<Vec<String>>(v).map_err(|e| {
                fail(
                    kind,
                    format!(
                        "Invalid {key} format - must be a JSON array of strings, for example [\"a\",\"b\"]: {e}"
                    ),
                )
            }),
        }
    }

    pub fn output_format(&self) -> anyhow::Result<OutputFormat> {
        match self.get("format_output") {
            None | Some("json") => Ok(OutputFormat::Json),
            Some("text") => Ok(OutputFormat::Text),
            Some(v) => Err(fail(
                "invalid_argument",
                format!("invalid value for format_output: {v:?} (expected json or text)"),
            )),
        }
    }

    /// `timeout_ms`: a positive whole number of milliseconds, or no limit.
    pub fn deadline(&self) -> anyhow::Result<Deadline> {
        match self.opt_u64("timeout_ms", "invalid_argument")? {
            None => Ok(Deadline::none()),
            Some(0) => Err(fail(
                "invalid_argument",
                "invalid value for timeout_ms: \"0\" (expected a positive whole number of milliseconds)",
            )),
            Some(ms) => Ok(Deadline::after_ms(ms)),
        }
    }
}

/// The backup name for `archive` and `suffix`: `<archive>.<suffix>`, where a
/// leading dot in `suffix` is optional.
pub fn backup_path(archive: &str, suffix: &str) -> std::path::PathBuf {
    let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
    std::path::PathBuf::from(format!("{archive}.{suffix}"))
}

/// Validates a `backup_suffix` value: non-empty and a plain name part.
pub fn check_backup_suffix(suffix: &str) -> anyhow::Result<()> {
    let bare = suffix.strip_prefix('.').unwrap_or(suffix);
    if bare.is_empty() || bare.contains('/') || bare.contains('\0') {
        return Err(fail(
            "invalid_argument",
            format!(
                "invalid value for backup_suffix: {suffix:?} (expected a file name suffix such as .bak)"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn kind(e: anyhow::Error) -> &'static str {
        kind_of(&e).unwrap()
    }

    #[test]
    fn unknown_options_are_refused() {
        let a = args(&[("archive", "a.tar"), ("verbose", "1")]);
        let e = Parser::new(&a, "list").err().unwrap();
        assert_eq!(kind_of(&e), Some("invalid_argument"));
        assert!(e.to_string().contains("\"verbose\""), "{e}");
        assert!(Parser::new(&args(&[("archive", "a")]), "list").is_ok());
    }

    #[test]
    fn typos_get_a_suggestion() {
        assert_eq!(suggest("destnation", EXTRACT_OPTIONS), Some("destination"));
        assert_eq!(suggest("dryrun", REMOVE_OPTIONS), Some("dry_run"));
        assert_eq!(suggest("timeout", LIST_OPTIONS), Some("timeout_ms"));
        assert_eq!(suggest("zzzz", LIST_OPTIONS), None);
        let a = args(&[("archive", "a.tar"), ("include", "[]")]);
        let e = Parser::new(&a, "list").err().unwrap().to_string();
        assert!(e.contains("did you mean \"includes\"?"), "{e}");
    }

    #[test]
    fn booleans_are_strict() {
        let a = args(&[("x", "YES"), ("y", "off"), ("z", "maybe")]);
        let p = Parser { args: &a };
        assert!(p.bool("x", false).unwrap());
        assert!(!p.bool("y", true).unwrap());
        assert!(p.bool("missing", true).unwrap());
        let e = p.bool("z", true).unwrap_err();
        assert!(e.to_string().contains("z"));
        assert_eq!(kind(e), "invalid_argument");
    }

    #[test]
    fn numbers_are_digits_only() {
        for bad in [
            "",
            "-1",
            "+1",
            "1.5",
            "1e3",
            " 1",
            "18446744073709551616",
            "10MB",
        ] {
            let a = args(&[("n", bad)]);
            let p = Parser { args: &a };
            assert_eq!(kind(p.opt_u64("n", "k").unwrap_err()), "k", "{bad:?}");
        }
        let a = args(&[("n", "18446744073709551615")]);
        assert_eq!(
            Parser { args: &a }.opt_u64("n", "k").unwrap(),
            Some(u64::MAX)
        );
    }

    #[test]
    fn lists_require_json_arrays_of_strings() {
        for bad in ["a.txt", "[1]", "{\"a\":1}", "[\"a\""] {
            let a = args(&[("l", bad)]);
            assert_eq!(
                kind(Parser { args: &a }.list("l", "bad_list").unwrap_err()),
                "bad_list"
            );
        }
    }

    #[test]
    fn timeout_and_output_format() {
        let a = args(&[("timeout_ms", "0")]);
        assert!(Parser { args: &a }.deadline().is_err());
        let a = args(&[("timeout_ms", "soon")]);
        assert!(Parser { args: &a }.deadline().is_err());
        let a = args(&[("timeout_ms", "50")]);
        assert!(Parser { args: &a }.deadline().unwrap().is_set());
        let a = args(&[("format_output", "yaml")]);
        assert!(Parser { args: &a }.output_format().is_err());
        let d = Deadline::after_ms(1);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(kind(d.check().unwrap_err()), "timeout");
        let io = anyhow::Error::new(d.check_io().unwrap_err());
        assert_eq!(kind_of(&io), Some("timeout"));
        assert!(Deadline::none().check().is_ok());
    }

    #[test]
    fn backup_names() {
        assert_eq!(backup_path("a.tar", "bak"), backup_path("a.tar", ".bak"));
        assert_eq!(backup_path("a.tar", ".bak").to_str(), Some("a.tar.bak"));
        assert!(check_backup_suffix("").is_err());
        assert!(check_backup_suffix(".").is_err());
        assert!(check_backup_suffix("x/y").is_err());
        assert!(check_backup_suffix(".orig").is_ok());
    }
}
