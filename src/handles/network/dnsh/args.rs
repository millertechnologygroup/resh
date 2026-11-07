//! Argument checking shared by the dns verbs: the accepted options of each
//! verb (help usage lists exactly these), unknown-argument refusal with a
//! "did you mean" hint, and readers for booleans, numbers and server lists.

use crate::core::registry::Args;
use std::net::IpAddr;

/// A usage error: nothing was done (exit 2).
#[derive(Debug, Clone, PartialEq)]
pub struct ArgError {
    pub code: &'static str,
    pub message: String,
}

impl ArgError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type ArgResult<T> = std::result::Result<T, ArgError>;

/// Code for an argument the verb does not take.
pub const DNS_UNKNOWN_ARGUMENT: &str = "dns.unknown_argument";
/// Code for a bad value of an option that has no more specific code
/// (booleans, `format`, `max_cname_depth`, ...).
pub const DNS_INVALID_ARGUMENT: &str = "dns.invalid_argument";

pub const LOOKUP_ARGS: &[&str] = &[
    "name",
    "rtype",
    "servers",
    "port",
    "use_tcp",
    "timeout_ms",
    "retries",
    "dnssec",
    "follow_cname",
    "include_authority",
    "include_additional",
    "randomize_servers",
    "format",
];

pub const RESOLVE_ARGS: &[&str] = &[
    "name",
    "mode",
    "family",
    "servers",
    "port",
    "use_tcp",
    "timeout_ms",
    "retries",
    "dnssec",
    "max_cname_depth",
    "follow_srv",
    "validate_reverse",
    "want_raw",
    "format",
];

pub const TRACE_ARGS: &[&str] = &[
    "name",
    "rtype",
    "root_servers",
    "prefer_ipv6",
    "port",
    "use_tcp",
    "timeout_ms",
    "retries",
    "dnssec",
    "max_depth",
    "follow_cname",
    "include_additional",
    "want_raw",
    "format",
];

pub const ZONE_FETCH_ARGS: &[&str] = &[
    "zone",
    "servers",
    "port",
    "transfer",
    "serial",
    "use_tcp",
    "timeout_ms",
    "retries",
    "dnssec",
    "max_records",
    "prefer_ipv6",
    "tsig_key_name",
    "tsig_secret",
    "tsig_algorithm",
    "include_raw",
    "format",
];

pub const ZONE_UPDATE_ARGS: &[&str] = &[
    "zone",
    "adds",
    "deletes",
    "prerequisites",
    "max_changes",
    "servers",
    "port",
    "use_tcp",
    "timeout_ms",
    "retries",
    "tsig_key_name",
    "tsig_secret",
    "tsig_algorithm",
    "dry_run",
    "include_raw",
    "format",
];

/// The options `verb` accepts, or `None` for an unknown verb.
pub fn verb_options(verb: &str) -> Option<&'static [&'static str]> {
    match verb {
        "lookup" => Some(LOOKUP_ARGS),
        "resolve" => Some(RESOLVE_ARGS),
        "trace" => Some(TRACE_ARGS),
        "zone.fetch" => Some(ZONE_FETCH_ARGS),
        "zone.update" => Some(ZONE_UPDATE_ARGS),
        _ => None,
    }
}

/// The accepted option closest to `bad` (edit distance at most 2 after
/// lowercasing and mapping `-` to `_`), for a "did you mean" hint.
pub fn suggest(bad: &str, allowed: &[&'static str]) -> Option<&'static str> {
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

/// Refuses the first argument (in sorted order) that `verb` does not take.
pub fn check_unknown(verb: &str, args: &Args) -> ArgResult<()> {
    let allowed = verb_options(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let Some(bad) = keys.into_iter().find(|k| !allowed.contains(&k.as_str())) else {
        return Ok(());
    };
    let message = match bad.as_str() {
        "dry_run" => format!("dns {verb} does not take dry_run; only zone.update has a dry run"),
        _ => format!(
            "unknown argument for dns {verb}: {bad}{}",
            suggest(bad, allowed)
                .map(|s| format!(" (did you mean `{s}`?)"))
                .unwrap_or_default()
        ),
    };
    Err(ArgError::new(DNS_UNKNOWN_ARGUMENT, message))
}

/// A boolean option: `true|false|1|0|yes|no|on|off` (any case).
pub fn bool_opt(args: &Args, key: &str, default: bool) -> ArgResult<bool> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| ArgError::new(DNS_INVALID_ARGUMENT, e.to_string()))
}

/// An unsigned integer option in `min..=max`.
pub fn uint_opt<T>(
    args: &Args,
    key: &str,
    default: T,
    min: u64,
    max: u64,
    code: &'static str,
) -> ArgResult<T>
where
    T: TryFrom<u64> + Copy,
{
    let Some(raw) = args.get(key) else {
        return Ok(default);
    };
    let bad = || {
        ArgError::new(
            code,
            format!("invalid {key}: {raw:?} (expected an integer from {min} to {max})"),
        )
    };
    let v: u64 = raw.trim().parse().map_err(|_| bad())?;
    if v < min || v > max {
        return Err(bad());
    }
    T::try_from(v).map_err(|_| bad())
}

/// A required, non-empty string option that does not look like an option.
pub fn required_str<'a>(args: &'a Args, key: &str, code: &'static str) -> ArgResult<&'a str> {
    match args.get(key).map(String::as_str) {
        None => Err(ArgError::new(
            code,
            format!("missing required argument: {key}"),
        )),
        Some(v) if v.trim().is_empty() => {
            Err(ArgError::new(code, format!("{key} must not be empty")))
        }
        Some(v) if v.starts_with('-') => Err(ArgError::new(
            code,
            format!("invalid {key}: {v:?} (must not start with '-')"),
        )),
        Some(v) => Ok(v),
    }
}

/// `format=json|text`.
pub fn format_opt(args: &Args) -> ArgResult<super::OutputFormat> {
    match args.get("format") {
        None => Ok(super::OutputFormat::Json),
        Some(v) => super::OutputFormat::from_str(v).map_err(|_| {
            ArgError::new(
                DNS_INVALID_ARGUMENT,
                format!("invalid format: {v:?} (expected json or text)"),
            )
        }),
    }
}

/// A server list: a JSON array of strings or a comma-separated list. An
/// empty value or `[]` is an empty list.
pub fn server_list(args: &Args, key: &str, code: &'static str) -> ArgResult<Vec<String>> {
    let Some(raw) = args.get(key) else {
        return Ok(Vec::new());
    };
    let trimmed = raw.trim();
    let items: Vec<String> = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed)
            .map_err(|e| ArgError::new(code, format!("invalid {key} JSON array {raw:?}: {e}")))?
    } else if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split(',').map(|s| s.to_string()).collect()
    };
    let items: Vec<String> = items.into_iter().map(|s| s.trim().to_string()).collect();
    if let Some(bad) = items.iter().find(|s| s.is_empty() || s.starts_with('-')) {
        return Err(ArgError::new(
            code,
            format!("invalid {key}: {bad:?} is not a server address"),
        ));
    }
    Ok(items)
}

/// A server list whose entries must all be IP addresses.
pub fn ip_list(args: &Args, key: &str, code: &'static str) -> ArgResult<Vec<String>> {
    let list = server_list(args, key, code)?;
    for s in &list {
        if s.parse::<IpAddr>().is_err() {
            return Err(ArgError::new(
                code,
                format!("invalid {key}: {s:?} is not an IP address"),
            ));
        }
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(kv: &[(&str, &str)]) -> Args {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn unknown_arguments_are_refused_with_a_hint() {
        let e = check_unknown("lookup", &a(&[("name", "x"), ("rtpye", "A")])).unwrap_err();
        assert_eq!(e.code, DNS_UNKNOWN_ARGUMENT);
        assert!(e.message.contains("did you mean `rtype`?"), "{}", e.message);
        let e = check_unknown("trace", &a(&[("dry_run", "true")])).unwrap_err();
        assert!(e.message.contains("does not take dry_run"));
        assert!(check_unknown("zone.update", &a(&[("dry_run", "true")])).is_ok());
        let e = check_unknown("lookup", &a(&[("zzz", "1")])).unwrap_err();
        assert!(!e.message.contains("did you mean"), "{}", e.message);
    }

    #[test]
    fn readers_validate_values() {
        assert!(bool_opt(&a(&[("x", "yes")]), "x", false).unwrap());
        assert!(!bool_opt(&a(&[("x", "OFF")]), "x", true).unwrap());
        assert!(bool_opt(&a(&[("x", "maybe")]), "x", true).is_err());
        assert_eq!(
            uint_opt::<u16>(&a(&[]), "p", 53, 1, 65535, "c").unwrap(),
            53
        );
        assert!(uint_opt::<u16>(&a(&[("p", "0")]), "p", 53, 1, 65535, "c").is_err());
        assert!(uint_opt::<u16>(&a(&[("p", "70000")]), "p", 53, 1, 65535, "c").is_err());
        assert!(uint_opt::<u16>(&a(&[("p", "-1")]), "p", 53, 1, 65535, "c").is_err());
        assert_eq!(
            server_list(&a(&[("s", "1.2.3.4, 5.6.7.8")]), "s", "c").unwrap(),
            vec!["1.2.3.4", "5.6.7.8"]
        );
        assert_eq!(
            server_list(&a(&[("s", r#"["1.2.3.4"]"#)]), "s", "c").unwrap(),
            vec!["1.2.3.4"]
        );
        assert!(server_list(&a(&[("s", "1.2.3.4,,x")]), "s", "c").is_err());
        assert!(server_list(&a(&[("s", "[1")]), "s", "c").is_err());
        assert!(ip_list(&a(&[("s", "ns.example.com")]), "s", "c").is_err());
        assert!(required_str(&a(&[("n", "-x")]), "n", "c").is_err());
        assert!(required_str(&a(&[("n", " ")]), "n", "c").is_err());
    }
}
