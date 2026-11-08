//! Strict argument checking for `firewall://` (project convention 1).
//!
//! Every verb has one list of accepted options. An unknown option, a value
//! outside an option's accepted set, a malformed boolean or number, or an
//! option another option rules out is refused with exit status 2 and
//! `firewall.invalid_argument` before anything runs. Field values that end
//! up in backend commands (ports, addresses, names, comments) are checked
//! later by the verb's own validation, with their own error codes.

use crate::core::lenient;
use crate::core::registry::Args;

/// The verbs, in help order.
pub(crate) const VERBS: &[&str] = &[
    "rules.list",
    "rules.add",
    "rules.delete",
    "rules.save",
    "rules.reload",
    "status",
    "enable",
    "disable",
];

/// Largest accepted `timeout_ms` (one hour).
pub(crate) const MAX_TIMEOUT_MS: u64 = 3_600_000;
/// Largest accepted `max_rules`.
pub(crate) const MAX_MAX_RULES: u64 = 1_000_000;
/// Largest accepted `limit` (rules.delete).
pub(crate) const MAX_DELETE_LIMIT: u64 = 100_000;

/// The default whole-verb deadline of `verb`, in milliseconds.
pub(crate) fn default_timeout_ms(verb: &str) -> u64 {
    match verb {
        "rules.reload" | "enable" | "disable" => 60_000,
        _ => 30_000,
    }
}

/// The options `verb` accepts, exactly as its help usage lists them.
pub(crate) fn accepted(verb: &str) -> &'static [&'static str] {
    match verb {
        "status" => &[
            "backend",
            "family",
            "include_metrics",
            "include_rules_summary",
            "timeout_ms",
            "format_output",
        ],
        "rules.list" => &[
            "backend",
            "family",
            "table",
            "chain",
            "direction",
            "action",
            "proto",
            "sport",
            "dport",
            "saddr",
            "daddr",
            "in_iface",
            "out_iface",
            "to",
            "comment_contains",
            "include_backend_raw",
            "include_counters",
            "max_rules",
            "timeout_ms",
            "format_output",
        ],
        "rules.add" => &[
            "backend",
            "family",
            "direction",
            "action",
            "table",
            "chain",
            "proto",
            "sport",
            "dport",
            "saddr",
            "daddr",
            "in_iface",
            "out_iface",
            "to",
            "zone",
            "log_prefix",
            "rate_limit",
            "comment",
            "position",
            "dry_run",
            "idempotent",
            "timeout_ms",
            "format_output",
        ],
        "rules.delete" => &[
            "backend",
            "family",
            "rule_id",
            "match_mode",
            "zone",
            "table",
            "chain",
            "direction",
            "action",
            "proto",
            "sport",
            "dport",
            "saddr",
            "daddr",
            "in_iface",
            "out_iface",
            "to",
            "comment_contains",
            "limit",
            "dry_run",
            "require_match",
            "timeout_ms",
            "format_output",
        ],
        "rules.save" => &[
            "path",
            "backend",
            "family",
            "include_all_backends",
            "format",
            "compress",
            "include_metadata",
            "dry_run",
            "overwrite",
            "create_dirs",
            "timeout_ms",
            "format_output",
        ],
        "rules.reload" => &[
            "path",
            "backend",
            "family",
            "source_format",
            "dry_run",
            "validate_only",
            "backup_before_apply",
            "timeout_ms",
            "format_output",
        ],
        "enable" => &[
            "path",
            "backend",
            "family",
            "source_format",
            "dry_run",
            "validate_only",
            "backup_before_apply",
            "fail_if_already_enabled",
            "timeout_ms",
            "format_output",
        ],
        "disable" => &[
            "path",
            "backend",
            "family",
            "source_format",
            "dry_run",
            "validate_only",
            "backup_before_apply",
            "fail_if_already_disabled",
            "timeout_ms",
            "format_output",
        ],
        _ => &[],
    }
}

/// Boolean options (any verb).
const BOOLEANS: &[&str] = &[
    "include_metrics",
    "include_rules_summary",
    "include_backend_raw",
    "include_counters",
    "dry_run",
    "idempotent",
    "require_match",
    "include_all_backends",
    "include_metadata",
    "overwrite",
    "create_dirs",
    "validate_only",
    "backup_before_apply",
    "fail_if_already_enabled",
    "fail_if_already_disabled",
];

/// The values an enumerated option accepts on `verb` (case-insensitive).
fn choices(verb: &str, key: &str) -> Option<&'static [&'static str]> {
    Some(match key {
        "backend" if verb == "status" => {
            &["auto", "all", "iptables", "nftables", "ufw", "firewalld"]
        }
        "backend" => &["auto", "iptables", "nftables", "ufw", "firewalld"],
        "family" => &["any", "ipv4", "ipv6"],
        "format_output" => &["json", "text"],
        "direction" => &["input", "output", "forward", "prerouting", "postrouting"],
        "action" => &[
            "accept",
            "drop",
            "reject",
            "log",
            "masquerade",
            "dnat",
            "snat",
            "redirect",
        ],
        "position" => &["append", "insert"],
        "match_mode" => &["exact", "subset"],
        "format" => &["normalized_json", "backend_native", "both"],
        "compress" => &["none", "gzip"],
        "source_format" => &["auto", "backend_native", "normalized_json"],
        _ => return None,
    })
}

/// The closest accepted name to a mistyped one, if any is close enough.
pub(crate) fn suggest(bad: &str, allowed: &[&'static str]) -> Option<&'static str> {
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
    let norm = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| {
            let d = if norm.len() >= 3 && (a.starts_with(norm.as_str()) || norm.starts_with(a)) {
                1
            } else {
                distance(&norm, a)
            };
            (d, *a)
        })
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn hint(bad: &str, allowed: &[&'static str]) -> String {
    suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// An integer option within `min..=max`.
pub(crate) fn u64_in(args: &Args, key: &str, min: u64, max: u64) -> Result<Option<u64>, String> {
    let Some(raw) = args.get(key) else {
        return Ok(None);
    };
    let digits = !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit());
    match raw.parse::<u64>() {
        Ok(v) if digits && (min..=max).contains(&v) => Ok(Some(v)),
        _ => Err(format!(
            "invalid value for {key}: {raw:?} (expected an integer from {min} to {max})"
        )),
    }
}

/// A boolean option: absent is `default`; a value outside the CLI spellings
/// (`true/false/1/0/yes/no/on/off`) is an error.
pub(crate) fn flag(args: &Args, key: &str, default: bool) -> bool {
    // `check` has already refused malformed values.
    lenient::bool_arg(args, key)
        .ok()
        .flatten()
        .unwrap_or(default)
}

/// A boolean option for the option parsers: absent is `default`, a value
/// outside the CLI spellings is an `invalid_argument` error.
pub(crate) fn bool_or(args: &Args, key: &str, default: bool) -> anyhow::Result<bool> {
    lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| {
            super::FirewallError::InvalidArgument {
                message: e.to_string(),
            }
            .into()
        })
}

/// Checks every argument of `verb`. `Err` holds the message for
/// `firewall.invalid_argument` (exit 2); nothing has been run.
pub(crate) fn check(verb: &str, args: &Args) -> Result<(), String> {
    let allowed = accepted(verb);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        let value = &args[key];
        if !allowed.contains(&key.as_str()) {
            if key == "dry_run" {
                // A verb that changes nothing has no dry-run mode; asking
                // for one is refused rather than silently ignored.
                return match lenient::dry_run(args) {
                    Ok(false) => continue,
                    Ok(true) => Err(format!(
                        "firewall {verb} changes nothing and has no dry-run mode; nothing was done"
                    )),
                    Err(e) => Err(e.to_string()),
                };
            }
            return Err(format!(
                "unknown argument for {verb}: {key}{}",
                hint(key, allowed)
            ));
        }
        if value.chars().any(|c| c.is_control()) {
            return Err(format!(
                "invalid value for {key}: control characters are not allowed"
            ));
        }
        if BOOLEANS.contains(&key.as_str()) {
            lenient::bool_arg(args, key).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(values) = choices(verb, key) {
            let lower = value.to_ascii_lowercase();
            if !values.contains(&lower.as_str()) {
                return Err(format!(
                    "invalid value for {key}: {value:?} (expected {}){}",
                    values.join(", "),
                    hint(&lower, values)
                ));
            }
            continue;
        }
        match key.as_str() {
            "timeout_ms" => {
                u64_in(args, key, 1, MAX_TIMEOUT_MS)?;
            }
            "max_rules" => {
                u64_in(args, key, 1, MAX_MAX_RULES)?;
            }
            "limit" => {
                u64_in(args, key, 1, MAX_DELETE_LIMIT)?;
            }
            "path" if value.is_empty() => {
                return Err("invalid value for path: it is empty".to_string());
            }
            _ => {}
        }
    }

    // Combinations no verb can carry out.
    let is = |key: &str| flag(args, key, false);
    if is("dry_run") && is("validate_only") {
        return Err("give dry_run=true or validate_only=true, not both".to_string());
    }
    if verb == "rules.save"
        && is("include_all_backends")
        && args
            .get("backend")
            .is_some_and(|b| !b.eq_ignore_ascii_case("auto"))
    {
        return Err(
            "include_all_backends=true saves every available backend; it cannot be combined \
             with backend="
                .to_string()
                + &args["backend"],
        );
    }
    if verb == "rules.add" {
        let action = args.get("action").map(|a| a.to_ascii_lowercase());
        let nat = matches!(action.as_deref(), Some("dnat") | Some("snat"));
        if nat && !args.contains_key("to") {
            return Err(format!(
                "action={} needs to=<addr>[:port]",
                action.unwrap_or_default()
            ));
        }
        if !nat && args.contains_key("to") {
            return Err("to applies to action=dnat or action=snat".to_string());
        }
    }
    if verb == "rules.add" && args.contains_key("log_prefix") {
        let action = args.get("action").map(|a| a.to_ascii_lowercase());
        if action.as_deref() != Some("log") {
            return Err("log_prefix needs action=log".to_string());
        }
    }
    if verb == "rules.delete" && args.contains_key("match_mode") && args.contains_key("rule_id") {
        return Err(
            "match_mode applies to a delete by filters; rule_id already selects one rule"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn unknown_arguments_are_refused_with_a_suggestion() {
        let e = check("status", &args(&[("backnd", "ufw")])).unwrap_err();
        assert!(e.contains("unknown argument for status: backnd"), "{e}");
        assert!(e.contains("did you mean `backend`"), "{e}");
        let e = check("rules.add", &args(&[("before_rule_id", "3")])).unwrap_err();
        assert!(e.contains("unknown argument"), "{e}");
    }

    #[test]
    fn dry_run_on_read_only_verbs() {
        assert!(check("status", &args(&[("dry_run", "false")])).is_ok());
        let e = check("rules.list", &args(&[("dry_run", "true")])).unwrap_err();
        assert!(e.contains("no dry-run mode"), "{e}");
        assert!(check("status", &args(&[("dry_run", "maybe")])).is_err());
    }

    #[test]
    fn values_are_checked() {
        for (verb, k, v) in [
            ("status", "include_metrics", "sure"),
            ("status", "timeout_ms", "soon"),
            ("status", "timeout_ms", "0"),
            ("status", "timeout_ms", "+5"),
            ("rules.list", "max_rules", "0"),
            ("rules.list", "backend", "all"),
            ("status", "backend", "pf"),
            ("rules.add", "position", "before"),
            ("rules.add", "action", "allow"),
            ("rules.delete", "limit", "0"),
            ("rules.delete", "match_mode", "fuzzy"),
            ("rules.save", "compress", "zstd"),
            ("rules.save", "path", ""),
            ("enable", "source_format", "yaml"),
            ("disable", "family", "inet"),
            ("rules.list", "format_output", "xml"),
            ("rules.list", "comment_contains", "a\nb"),
        ] {
            assert!(check(verb, &args(&[(k, v)])).is_err(), "{verb} {k}={v}");
        }
        assert!(check("status", &args(&[("backend", "ALL"), ("timeout_ms", "10")])).is_ok());
        assert!(check("rules.add", &args(&[("idempotent", "no")])).is_ok());
    }

    #[test]
    fn combinations_are_checked() {
        assert!(
            check(
                "enable",
                &args(&[("dry_run", "1"), ("validate_only", "yes")])
            )
            .is_err()
        );
        assert!(
            check(
                "rules.save",
                &args(&[("include_all_backends", "true"), ("backend", "ufw")])
            )
            .is_err()
        );
        assert!(check("rules.add", &args(&[("log_prefix", "x")])).is_err());
        assert!(
            check(
                "rules.add",
                &args(&[("log_prefix", "x"), ("action", "log")])
            )
            .is_ok()
        );
        assert!(
            check(
                "rules.delete",
                &args(&[("rule_id", "INPUT:1"), ("match_mode", "subset")])
            )
            .is_err()
        );
    }

    #[test]
    fn every_verb_has_an_accepted_list() {
        for verb in VERBS {
            assert!(!accepted(verb).is_empty(), "{verb}");
            assert!(accepted(verb).contains(&"timeout_ms"), "{verb}");
            assert!(accepted(verb).contains(&"format_output"), "{verb}");
        }
    }
}
