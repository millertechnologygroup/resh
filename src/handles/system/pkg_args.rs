//! Strict argument checking and error codes for `pkg://` (project
//! conventions 1, 2 and 8).
//!
//! Every pkg verb reads one argument, `input=<json>`. Any other command-line
//! argument, and any key of the JSON object that the verb does not accept, is
//! refused with exit status 2 and `pkg.invalid_argument` before anything runs.
//! Each verb has one list of accepted keys here, and a test checks that its
//! help usage lists exactly these keys.

use serde_json::Value;

/// The keys each verb accepts inside `input`, in help order.
pub(crate) fn accepted(verb: &str) -> &'static [&'static str] {
    match verb {
        "info" => &[
            "manager",
            "packages",
            "include_dependencies",
            "include_reverse_deps",
            "include_files",
            "include_repo",
            "timeout_ms",
            "env",
        ],
        "search" => &[
            "manager",
            "query",
            "search_in",
            "exact",
            "case_sensitive",
            "limit",
            "offset",
            "include_installed",
            "include_versions",
            "include_repo",
            "timeout_ms",
            "extra_args",
            "env",
        ],
        "list_installed" => &[
            "manager",
            "filter",
            "prefix",
            "include_versions",
            "include_repo",
            "include_size",
            "include_install_reason",
            "limit",
            "offset",
            "timeout_ms",
            "env",
        ],
        "snapshot" => &[
            "manager",
            "scope",
            "include_versions",
            "include_repo",
            "include_arch",
            "include_install_reason",
            "include_os_metadata",
            "exclude_patterns",
            "format",
            "timeout_ms",
            "env",
        ],
        "install" => &[
            "manager",
            "packages",
            "update_cache",
            "assume_yes",
            "only_if_missing",
            "reinstall",
            "upgrade",
            "allow_downgrade",
            "dry_run",
            "timeout_ms",
            "arch",
            "extra_args",
            "env",
        ],
        "remove" => &[
            "manager",
            "packages",
            "purge",
            "recursive",
            "assume_yes",
            "only_if_installed",
            "fail_if_missing",
            "dry_run",
            "timeout_ms",
            "arch",
            "extra_args",
            "env",
        ],
        "update" => &[
            "manager",
            "packages",
            "refresh_index",
            "upgrade",
            "assume_yes",
            "security_only",
            "check_only",
            "dry_run",
            "timeout_ms",
            "extra_args",
            "env",
        ],
        "upgrade" => &[
            "manager",
            "packages",
            "refresh_index",
            "assume_yes",
            "security_only",
            "check_only",
            "dry_run",
            "timeout_ms",
            "extra_args",
            "env",
        ],
        "restore" | "apply_lock" => &[
            "manager",
            "lockfile",
            "format",
            "mode",
            "allow_downgrades",
            "allow_removals",
            "allow_newer",
            "on_missing_package",
            "on_repo_mismatch",
            "on_platform_mismatch",
            "include_dependencies",
            "dry_run",
            "timeout_ms",
            "extra_args",
            "env",
        ],
        _ => &[],
    }
}

/// The keys of one package entry (`install`, `remove`). `source` is accepted
/// here so that it gets its own explanation (no manager can take it).
pub(crate) const PACKAGE_KEYS: &[&str] = &["name", "version", "source"];

/// Keys that read as options of a verb but are refused with a reason.
fn refused(verb: &str, key: &str) -> Option<String> {
    match (verb, key) {
        ("info" | "list_installed" | "snapshot", "extra_args") => Some(format!(
            "extra_args is not supported by pkg {verb}: it runs several package-manager \
             queries, so there is no single command to add the arguments to"
        )),
        ("snapshot", "inline") => Some(
            "inline is not supported (the lockfile is always returned in the lockfile \
             field); remove it from the request"
                .to_string(),
        ),
        ("info" | "search" | "list_installed" | "snapshot", "dry_run" | "dry-run" | "dryrun") => {
            Some(format!(
                "dry_run is not supported by pkg {verb}: it only reads, so there is nothing \
             to preview"
            ))
        }
        _ => None,
    }
}

/// The accepted name closest to `bad` (a case or `-`/`_` difference, a prefix
/// either way, or an edit distance of at most 2), for a "did you mean" hint.
pub(crate) fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let norm = |s: &str| s.to_ascii_lowercase().replace('-', "_");
    let b = norm(bad);
    if let Some(hit) = allowed.iter().find(|a| norm(a) == b) {
        return Some(hit);
    }
    let mut best: Option<(&'a str, usize)> = None;
    for a in allowed {
        let d = distance(&b, &norm(a));
        if d <= 2 && best.is_none_or(|(_, bd)| d < bd) {
            best = Some((a, d));
        }
    }
    if let Some((a, _)) = best {
        return Some(a);
    }
    if b.len() >= 4 {
        return allowed
            .iter()
            .find(|a| norm(a).starts_with(&b) || b.starts_with(&norm(a)))
            .copied();
    }
    None
}

fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn hint(bad: &str, allowed: &[&str]) -> String {
    suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// Checks the command-line arguments: only `input` is read. Returns the input
/// text, or the reason for the refusal.
pub(crate) fn check_args<'a>(
    verb: &str,
    args: &'a crate::core::registry::Args,
) -> Result<&'a str, String> {
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        if key == "input" {
            continue;
        }
        let inner = accepted(verb);
        let where_ = if inner.contains(&key.as_str()) || suggest(key, inner).is_some() {
            let name = suggest(key, inner).unwrap_or(key);
            format!("; put it inside the JSON object, as in input={{\"{name}\":...}}")
        } else {
            hint(key, &["input"])
        };
        return Err(format!(
            "unknown argument `{key}` for pkg {verb}: the only argument is input=<json>{where_}"
        ));
    }
    match args.get("input") {
        Some(text) => Ok(text.as_str()),
        None => Err(format!(
            "missing input=<json> for pkg {verb} (see `resh pkg {verb} --help`)"
        )),
    }
}

/// Parses `input` and checks its keys against the verb's list (and the
/// package-entry keys). Returns the JSON object, or the reason for refusing it.
pub(crate) fn check_input(verb: &str, text: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(text)
        .map_err(|e| format!("input is not valid JSON for pkg {verb}: {e}"))?;
    let Some(object) = value.as_object() else {
        return Err(format!("input for pkg {verb} must be a JSON object"));
    };
    let allowed = accepted(verb);
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    for key in keys {
        if let Some(reason) = refused(verb, key) {
            return Err(format!("{reason}; nothing was run"));
        }
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "unknown input key `{key}` for pkg {verb}{}; accepted keys: {}",
                hint(key, allowed),
                allowed.join(", ")
            ));
        }
    }
    if matches!(verb, "install" | "remove") {
        if let Some(Value::Array(packages)) = object.get("packages") {
            for (i, entry) in packages.iter().enumerate() {
                let Some(entry) = entry.as_object() else {
                    return Err(format!(
                        "packages[{i}] must be an object such as {{\"name\":\"jq\"}}"
                    ));
                };
                let mut keys: Vec<&String> = entry.keys().collect();
                keys.sort();
                for key in keys {
                    if PACKAGE_KEYS.contains(&key.as_str()) && !entry[key].is_string() {
                        return Err(format!(
                            "invalid value for `packages[{i}].{key}`: it must be a string"
                        ));
                    }
                    if !PACKAGE_KEYS.contains(&key.as_str()) {
                        return Err(format!(
                            "unknown key `{key}` in packages[{i}]{}; a package entry has \
                             name and version",
                            hint(key, PACKAGE_KEYS)
                        ));
                    }
                }
            }
        }
    }
    if let Some(env) = object.get("env") {
        check_env(env)?;
    }
    Ok(value)
}

/// `env` must be an object of strings whose names can be set in a process
/// environment.
fn check_env(env: &Value) -> Result<(), String> {
    let Some(env) = env.as_object() else {
        return Err("env must be an object of NAME: value strings".to_string());
    };
    for (name, value) in env {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(format!(
                "env name {name:?} is invalid: it must be non-empty, without '=' or NUL"
            ));
        }
        match value.as_str() {
            Some(v) if !v.contains('\0') => {}
            Some(_) => return Err(format!("env value of {name} contains NUL")),
            None => return Err(format!("env value of {name} must be a string")),
        }
    }
    Ok(())
}

/// Every error code the pkg handle emits, with its exit status. `pkg.md`
/// documents each one (a test checks it).
#[cfg(test)]
pub(crate) const ERROR_CODES: &[(&str, i32)] = &[
    ("pkg.unknown_verb", 2),
    ("pkg.invalid_argument", 2),
    ("pkg.unsupported_option", 2),
    ("pkg.invalid_lockfile", 2),
    ("pkg.manager_mismatch", 2),
    ("pkg.manager_not_found", 1),
    ("pkg.not_found", 1),
    ("pkg.permission_denied", 1),
    ("pkg.dependency_failure", 1),
    ("pkg.conflict", 1),
    ("pkg.index_failed", 1),
    ("pkg.command_failed", 1),
    ("pkg.partial_failure", 1),
    ("pkg.platform_mismatch", 1),
    ("pkg.repo_mismatch", 1),
    ("pkg.unresolved", 1),
    ("pkg.downgrade_refused", 1),
    ("pkg.timeout", 124),
];
