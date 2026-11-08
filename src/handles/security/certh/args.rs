//! Strict argument checking for every `cert` verb: unknown arguments,
//! options of another mode, and invalid values are refused (exit 2,
//! `cert.invalid_argument`) before any file is read or written.

use serde_json::Value;

use super::errors::{CResult, CertError};
use crate::core::Args;

/// The verbs, in help order.
pub const VERBS: &[&str] = &[
    "info",
    "verify",
    "chain.info",
    "generate",
    "csr.create",
    "sign",
    "csr.sign",
    "renew",
];

const INFO_ARGS: &[&str] = &[
    "format",
    "encoding",
    "fingerprint_algs",
    "include_pem",
    "include_raw",
];
const VERIFY_ARGS: &[&str] = &[
    "hostname",
    "purpose",
    "trust",
    "trust_paths",
    "trust_pem",
    "ca_file",
    "max_chain_depth",
    "min_rsa_bits",
    "allow_self_signed",
    "allow_expired",
    "allow_not_yet_valid",
    "check_revocation",
    "keypair_target",
    "include_chain_report",
    "encoding",
    "format",
];
const CHAIN_INFO_ARGS: &[&str] = &[
    "trust",
    "trust_paths",
    "trust_pem",
    "ca_file",
    "max_depth",
    "max_paths",
    "include_raw_subjects",
    "include_raw_issuers",
    "include_cert_refs",
    "encoding",
    "format",
];
const GENERATE_ARGS: &[&str] = &[
    "mode",
    "algorithm",
    "rsa_bits",
    "ecdsa_curve",
    "subject",
    "sans",
    "is_ca",
    "path_len",
    "not_before",
    "not_after",
    "not_after_offset_days",
    "signer_ca",
    "signer_key",
    "signer_key_passphrase",
    "key_format",
    "key_encoding",
    "cert_encoding",
    "csr_encoding",
    "key_passphrase",
    "key_kdf",
    "key_kdf_iterations",
    "output",
    "overwrite",
    "format",
    "timeout_ms",
];
const CSR_CREATE_ARGS: &[&str] = &[
    "subject",
    "key_strategy",
    "existing_key_path",
    "existing_key_passphrase",
    "new_key_output_path",
    "new_key_passphrase",
    "algorithm",
    "rsa_bits",
    "ecdsa_curve",
    "key_format",
    "key_encoding",
    "key_kdf",
    "key_kdf_iterations",
    "csr_encoding",
    "sans",
    "key_usage",
    "extended_key_usage",
    "include_csr_pem",
    "include_new_key_pem",
    "overwrite",
    "format",
    "timeout_ms",
];
/// `sign` with `mode=data` (the default).
pub const SIGN_DATA_ARGS: &[&str] = &[
    "mode",
    "signer_key",
    "signer_key_passphrase",
    "data_source",
    "data_bytes_base64",
    "signature_output_path",
    "signature_algorithm",
    "signature_encoding",
    "signature_format",
    "signer_cert",
    "include_signature_bytes",
    "overwrite",
    "format",
    "timeout_ms",
];
/// `sign` with `mode=csr`.
pub const SIGN_CSR_ARGS: &[&str] = &[
    "mode",
    "signer_key",
    "signer_key_passphrase",
    "signer_cert",
    "csr_source",
    "csr_encoding",
    "cert_output_path",
    "cert_encoding",
    "not_before",
    "not_after",
    "not_after_offset_days",
    "is_ca",
    "path_len",
    "key_usage",
    "extended_key_usage",
    "sans_override",
    "include_cert_pem",
    "overwrite",
    "format",
    "timeout_ms",
];
const CSR_SIGN_ARGS: &[&str] = &[
    "signer_ca",
    "signer_key",
    "signer_key_passphrase",
    "cert_output_path",
    "csr_encoding",
    "cert_encoding",
    "copy_subject",
    "subject_common_name",
    "subject_organization",
    "subject_country",
    "copy_sans",
    "sans_override",
    "copy_key_usage",
    "key_usage_override",
    "copy_extended_key_usage",
    "extended_key_usage_override",
    "is_ca",
    "path_len",
    "not_before",
    "not_after",
    "not_after_offset_days",
    "serial_strategy",
    "serial_override",
    "include_cert_pem",
    "overwrite",
    "format",
];
const RENEW_ARGS: &[&str] = &[
    "renewal_mode",
    "signer_ca",
    "signer_key",
    "signer_key_passphrase",
    "key_strategy",
    "existing_key_path",
    "key_passphrase",
    "algorithm",
    "rsa_bits",
    "ecdsa_curve",
    "key_format",
    "key_encoding",
    "key_kdf",
    "key_kdf_iterations",
    "new_key_output_path",
    "new_cert_output_path",
    "cert_encoding",
    "copy_subject",
    "subject_override",
    "copy_sans",
    "sans_override",
    "copy_key_usage",
    "key_usage_override",
    "copy_extended_key_usage",
    "extended_key_usage_override",
    "is_ca",
    "path_len",
    "not_before",
    "not_after",
    "not_after_offset_days",
    "include_cert_pem",
    "include_new_key_pem",
    "overwrite",
    "format",
    "timeout_ms",
];

/// The arguments `verb` accepts (one list per verb; the help usage lists
/// exactly these). For `sign` this is the union of both modes.
pub fn verb_args(verb: &str) -> Option<Vec<&'static str>> {
    base_args(verb).map(|v| expand(&v))
}

/// The three sources of each passphrase option `<name>`: `<name>=<pass>`,
/// `<name>_env=<VAR>` and `<name>_stdin=true`.
pub fn expand(list: &[&'static str]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for a in list {
        out.push(*a);
        if a.ends_with("_passphrase") {
            out.push(leak(format!("{a}_env")));
            out.push(leak(format!("{a}_stdin")));
        }
    }
    out
}

/// The option names are a small fixed set; each derived name is made once.
fn leak(s: String) -> &'static str {
    use std::sync::{Mutex, OnceLock};
    static NAMES: OnceLock<Mutex<Vec<&'static str>>> = OnceLock::new();
    let mut names = NAMES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(n) = names.iter().find(|n| **n == s) {
        return n;
    }
    let n: &'static str = Box::leak(s.into_boxed_str());
    names.push(n);
    n
}

fn base_args(verb: &str) -> Option<Vec<&'static str>> {
    Some(match verb {
        "info" => INFO_ARGS.to_vec(),
        "verify" => VERIFY_ARGS.to_vec(),
        "chain.info" => CHAIN_INFO_ARGS.to_vec(),
        "generate" => GENERATE_ARGS.to_vec(),
        "csr.create" => CSR_CREATE_ARGS.to_vec(),
        "sign" => {
            let mut v = SIGN_DATA_ARGS.to_vec();
            for a in SIGN_CSR_ARGS {
                if !v.contains(a) {
                    v.push(a);
                }
            }
            v
        }
        "csr.sign" => CSR_SIGN_ARGS.to_vec(),
        "renew" => RENEW_ARGS.to_vec(),
        _ => return None,
    })
}

/// Default deadline of the verbs that accept `timeout_ms`.
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000;
const MAX_TIMEOUT_MS: u64 = 86_400_000;

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
        .map(|c| (distance(&lower, &c.to_ascii_lowercase()), *c))
        .filter(|(d, c)| {
            *d <= 2 || (lower.len() >= 3 && c.to_ascii_lowercase().starts_with(lower.as_str()))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// ` (did you mean `x`?)` or "".
pub fn hint(bad: &str, candidates: &[&str]) -> String {
    suggest(bad, candidates)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// Typed, strict access to one verb's arguments.
pub struct Reader<'a> {
    pub args: &'a Args,
    /// The passphrase read from stdin (`<name>_passphrase_stdin=true`).
    stdin: Option<String>,
    /// Warnings for stderr (a passphrase given on the command line).
    pub warnings: std::cell::RefCell<Vec<String>>,
}

impl<'a> Reader<'a> {
    /// Refuses any argument `verb` does not accept, then gives typed access.
    pub fn new(verb: &'a str, args: &'a Args, input: &mut dyn std::io::Read) -> CResult<Self> {
        let allowed = verb_args(verb).unwrap_or_default();
        let mut keys: Vec<&String> = args.keys().collect();
        keys.sort();
        for key in keys {
            if allowed.contains(&key.as_str()) {
                continue;
            }
            let message = match key.as_str() {
                "timeout_ms" => format!(
                    "cert {verb} does not accept timeout_ms: it only reads local files of \
                     bounded size and finishes at once"
                ),
                "dry_run" => format!("cert {verb} does not accept dry_run"),
                "disallow_weak_signatures" if verb == "verify" => {
                    "disallow_weak_signatures was removed: weak signature algorithms \
                     (SHA-1, MD5) are always rejected"
                        .to_string()
                }
                _ => format!(
                    "unknown argument for cert {verb}: {key}{} (accepted: {})",
                    hint(key, &allowed),
                    allowed.join(", ")
                ),
            };
            return Err(CertError::usage(message));
        }
        // One source per passphrase, and at most one read from stdin.
        let mut from_stdin = Vec::new();
        for base in allowed.iter().filter(|a| a.ends_with("_passphrase")) {
            let env = format!("{base}_env");
            let stdin = format!("{base}_stdin");
            let on_stdin = crate::core::lenient::bool_arg(args, &stdin)
                .map_err(|e| CertError::usage(e.to_string()))?
                .unwrap_or(false);
            let given = usize::from(args.contains_key(*base))
                + usize::from(args.contains_key(&env))
                + usize::from(on_stdin);
            if given > 1 {
                return Err(CertError::usage(format!(
                    "give {base} one way only: {base}=, {env}= or {stdin}=true"
                )));
            }
            if on_stdin {
                from_stdin.push(stdin);
            }
        }
        if from_stdin.len() > 1 {
            return Err(CertError::usage(format!(
                "only one passphrase can be read from stdin per call ({})",
                from_stdin.join(", ")
            )));
        }
        let stdin = match from_stdin.first() {
            None => None,
            Some(name) => {
                let mut text = String::new();
                input.read_to_string(&mut text).map_err(|e| {
                    CertError::usage(format!(
                        "{name}: cannot read the passphrase from stdin: {e}"
                    ))
                })?;
                let text = text
                    .strip_suffix('\n')
                    .map(|t| t.strip_suffix('\r').unwrap_or(t))
                    .unwrap_or(&text)
                    .to_string();
                Some(text)
            }
        };
        Ok(Self {
            args,
            stdin,
            warnings: Default::default(),
        })
    }

    /// True if `key` is given; for a passphrase option, from any source.
    pub fn has(&self, key: &str) -> bool {
        if key.ends_with("_passphrase") {
            return self.args.contains_key(key)
                || self.args.contains_key(&format!("{key}_env"))
                || self.args.contains_key(&format!("{key}_stdin"));
        }
        self.args.contains_key(key)
    }

    /// Refuses `keys` that are present, because `why` (for example "with
    /// mode=key") makes them meaningless.
    pub fn refuse(&self, keys: &[&str], why: &str) -> CResult<()> {
        for k in keys {
            if self.has(k) {
                let k = if self.args.contains_key(*k) {
                    k.to_string()
                } else {
                    format!("{k}_env/{k}_stdin")
                };
                return Err(CertError::usage(format!(
                    "{k} is not used {why}; remove it"
                )));
            }
        }
        Ok(())
    }

    /// Requires `key` when `why` holds.
    pub fn require(&self, key: &str, why: &str) -> CResult<()> {
        if self.has(key) {
            Ok(())
        } else {
            Err(CertError::usage(format!("{key} is required {why}")))
        }
    }

    /// The raw value (may contain line breaks, for PEM text); never empty.
    pub fn raw(&self, key: &str) -> CResult<Option<String>> {
        match self.args.get(key) {
            None => Ok(None),
            Some(v) if v.is_empty() => Err(CertError::usage(format!("{key} must not be empty"))),
            Some(v) => Ok(Some(v.clone())),
        }
    }

    /// A text value: never empty, no control characters.
    pub fn text(&self, key: &str) -> CResult<Option<String>> {
        let v = self.raw(key)?;
        if let Some(s) = &v
            && s.chars().any(char::is_control)
        {
            return Err(CertError::usage(format!(
                "{key} must not contain line breaks or other control characters"
            )));
        }
        Ok(v)
    }

    /// A passphrase from `<key>=`, `<key>_env=<VAR>` or `<key>_stdin=true`:
    /// never empty, no line breaks, never echoed in messages. The plain
    /// option adds a warning (process lists and shell history show it).
    pub fn passphrase(&self, key: &str) -> CResult<Option<String>> {
        let (value, source) = if let Some(v) = self.args.get(key) {
            self.warnings.borrow_mut().push(format!(
                "Warning: {key}= puts the passphrase on the command line, where the process \
                 list and shell history can show it; use {key}_env=<VAR> or \
                 {key}_stdin=true"
            ));
            (v.clone(), key.to_string())
        } else if let Some(var) = self.args.get(&format!("{key}_env")) {
            let ok = var
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !ok {
                return Err(CertError::usage(format!(
                    "{key}_env must name an environment variable, got {var:?}"
                )));
            }
            match std::env::var(var) {
                Ok(v) => (v, format!("environment variable {var}")),
                Err(_) => {
                    return Err(CertError::usage(format!(
                        "{key}_env: environment variable {var} is not set (or not UTF-8)"
                    )));
                }
            }
        } else if self.opt_flag(&format!("{key}_stdin"))? == Some(true) {
            (self.stdin.clone().unwrap_or_default(), "stdin".to_string())
        } else {
            return Ok(None);
        };
        if value.is_empty() {
            return Err(CertError::usage(format!(
                "{key}: the passphrase from {source} is empty"
            )));
        }
        if value.contains('\n') || value.contains('\r') {
            return Err(CertError::usage(format!(
                "{key}: the passphrase from {source} contains a line break"
            )));
        }
        Ok(Some(value))
    }

    /// A boolean in the CLI spellings (`true|false|1|0|yes|no|on|off`).
    pub fn flag(&self, key: &str, default: bool) -> CResult<bool> {
        Ok(self.opt_flag(key)?.unwrap_or(default))
    }

    pub fn opt_flag(&self, key: &str) -> CResult<Option<bool>> {
        crate::core::lenient::bool_arg(self.args, key).map_err(|e| CertError::usage(e.to_string()))
    }

    /// One of `choices` (exact spelling), or `default` when absent.
    pub fn choice(&self, key: &str, choices: &[&'static str]) -> CResult<Option<&'static str>> {
        let Some(v) = self.args.get(key) else {
            return Ok(None);
        };
        match choices.iter().find(|c| **c == v.as_str()) {
            Some(c) => Ok(Some(c)),
            None => Err(CertError::usage(format!(
                "invalid value for {key}: {v:?}{} (accepted: {})",
                hint(v, choices),
                choices.join(", ")
            ))),
        }
    }

    /// A whole number in `min..=max`.
    pub fn uint(&self, key: &str, min: u64, max: u64) -> CResult<Option<u64>> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        match raw.parse::<u64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(Some(n)),
            _ => Err(CertError::usage(format!(
                "invalid value for {key}: {raw:?} (expected a whole number from {min} to {max})"
            ))),
        }
    }

    /// `timeout_ms` (1 ms to 24 h), default [`DEFAULT_TIMEOUT_MS`].
    pub fn timeout(&self) -> CResult<std::time::Duration> {
        Ok(std::time::Duration::from_millis(
            self.uint("timeout_ms", 1, MAX_TIMEOUT_MS)?
                .unwrap_or(DEFAULT_TIMEOUT_MS),
        ))
    }

    /// An RFC 3339 timestamp, or one of the keywords in `keywords`.
    pub fn time_or(
        &self,
        key: &str,
        keywords: &[&'static str],
    ) -> CResult<Option<std::result::Result<chrono::DateTime<chrono::Utc>, &'static str>>> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        if let Some(k) = keywords.iter().find(|k| **k == raw.as_str()) {
            return Ok(Some(Err(k)));
        }
        match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(dt) => Ok(Some(Ok(dt.with_timezone(&chrono::Utc)))),
            Err(_) => Err(CertError::usage(format!(
                "invalid value for {key}: {raw:?} (expected an RFC 3339 timestamp such as \
                 2030-01-01T00:00:00Z{})",
                if keywords.is_empty() {
                    String::new()
                } else {
                    format!(" or {}", keywords.join(", "))
                }
            ))),
        }
    }

    /// A list given as a JSON array of strings or as comma-separated items.
    /// Items are trimmed; empty items are refused.
    pub fn list(&self, key: &str) -> CResult<Option<Vec<String>>> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        let items: Vec<String> = if raw.trim_start().starts_with('[') {
            let v: Value = serde_json::from_str(raw).map_err(|e| {
                CertError::usage(format!("invalid value for {key}: not a JSON array ({e})"))
            })?;
            let arr = v.as_array().ok_or_else(|| {
                CertError::usage(format!("invalid value for {key}: not a JSON array"))
            })?;
            arr.iter()
                .map(|x| {
                    x.as_str().map(|s| s.trim().to_string()).ok_or_else(|| {
                        CertError::usage(format!(
                            "invalid value for {key}: every item must be a string"
                        ))
                    })
                })
                .collect::<CResult<_>>()?
        } else {
            raw.split(',').map(|s| s.trim().to_string()).collect()
        };
        if items.iter().any(String::is_empty) {
            return Err(CertError::usage(format!(
                "invalid value for {key}: empty item"
            )));
        }
        Ok(Some(items))
    }

    /// A JSON object whose keys are all in `fields`.
    pub fn object(
        &self,
        key: &str,
        fields: &[&str],
    ) -> CResult<Option<serde_json::Map<String, Value>>> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        let v: Value = serde_json::from_str(raw)
            .map_err(|e| CertError::usage(format!("invalid JSON for {key}: {e}")))?;
        let Value::Object(map) = v else {
            return Err(CertError::usage(format!(
                "invalid value for {key}: expected a JSON object"
            )));
        };
        for k in map.keys() {
            if !fields.contains(&k.as_str()) {
                return Err(CertError::usage(format!(
                    "unknown field in {key}: {k}{} (accepted: {})",
                    hint(k, fields),
                    fields.join(", ")
                )));
            }
        }
        Ok(Some(map))
    }
}

/// Fields of a `subject` JSON object.
pub const SUBJECT_FIELDS: &[&str] = &[
    "common_name",
    "organization",
    "organizational_unit",
    "country",
    "state_or_province",
    "locality",
];

/// Parses a subject object: `common_name` is a string, every other field a
/// string or an array of strings.
pub fn subject_from_map(
    key: &str,
    map: &serde_json::Map<String, Value>,
) -> CResult<super::CertSubject> {
    let mut s = super::CertSubject::default();
    let bad = |field: &str, what: &str| {
        CertError::usage(format!("invalid {key}.{field}: expected {what}"))
    };
    for (field, value) in map {
        if field == "common_name" {
            let cn = value
                .as_str()
                .filter(|c| !c.trim().is_empty())
                .ok_or_else(|| bad(field, "a non-empty string"))?;
            s.common_name = Some(cn.to_string());
            continue;
        }
        let items: Vec<String> = match value {
            Value::String(v) => vec![v.clone()],
            Value::Array(a) => a
                .iter()
                .map(|x| x.as_str().map(String::from))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| bad(field, "a string or an array of strings"))?,
            _ => return Err(bad(field, "a string or an array of strings")),
        };
        if items.iter().any(|i| i.trim().is_empty()) {
            return Err(bad(field, "non-empty strings"));
        }
        if field == "country" && items.iter().any(|c| c.len() != 2) {
            return Err(bad(field, "two-letter country codes"));
        }
        match field.as_str() {
            "organization" => s.organization = items,
            "organizational_unit" => s.organizational_unit = items,
            "country" => s.country = items,
            "state_or_province" => s.state_or_province = items,
            "locality" => s.locality = items,
            _ => unreachable!("fields are checked by Reader::object"),
        }
    }
    Ok(s)
}

/// Checks SAN entries (`DNS:`, `IP:`, `EMAIL:`, `URI:`).
pub fn check_sans(key: &str, sans: &[String]) -> CResult<()> {
    super::parse_san_list(sans)
        .map(|_| ())
        .map_err(|e| CertError::usage(format!("invalid {key}: {e}")))
}

/// The key usage names accepted in `key_usage` lists.
pub const KEY_USAGES: &[&str] = &[
    "digitalSignature",
    "contentCommitment",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

/// The extended key usage names accepted in `extended_key_usage` lists.
pub const EXTENDED_KEY_USAGES: &[&str] = &[
    "serverAuth",
    "clientAuth",
    "codeSigning",
    "emailProtection",
    "timeStamping",
    "ocspSigning",
];

pub fn key_usages(r: &Reader, key: &str) -> CResult<Option<Vec<super::CertKeyUsage>>> {
    use super::CertKeyUsage as K;
    let Some(items) = r.list(key)? else {
        return Ok(None);
    };
    items
        .iter()
        .map(|u| {
            Ok(match u.as_str() {
                "digitalSignature" => K::DigitalSignature,
                "contentCommitment" => K::ContentCommitment,
                "keyEncipherment" => K::KeyEncipherment,
                "dataEncipherment" => K::DataEncipherment,
                "keyAgreement" => K::KeyAgreement,
                "keyCertSign" => K::KeyCertSign,
                // crlSign was the spelling accepted before; cRLSign is RFC 5280's.
                "cRLSign" | "crlSign" => K::CrlSign,
                "encipherOnly" => K::EncipherOnly,
                "decipherOnly" => K::DecipherOnly,
                other => {
                    return Err(CertError::usage(format!(
                        "invalid {key} item: {other:?}{} (accepted: {})",
                        hint(other, KEY_USAGES),
                        KEY_USAGES.join(", ")
                    )));
                }
            })
        })
        .collect::<CResult<Vec<_>>>()
        .map(Some)
}

pub fn extended_key_usages(
    r: &Reader,
    key: &str,
) -> CResult<Option<Vec<super::CertExtendedKeyUsage>>> {
    use super::CertExtendedKeyUsage as E;
    let Some(items) = r.list(key)? else {
        return Ok(None);
    };
    items
        .iter()
        .map(|u| {
            Ok(match u.as_str() {
                "serverAuth" => E::ServerAuth,
                "clientAuth" => E::ClientAuth,
                "codeSigning" => E::CodeSigning,
                "emailProtection" => E::EmailProtection,
                "timeStamping" => E::TimeStamping,
                "ocspSigning" => E::OcspSigning,
                other => {
                    return Err(CertError::usage(format!(
                        "invalid {key} item: {other:?}{} (accepted: {})",
                        hint(other, EXTENDED_KEY_USAGES),
                        EXTENDED_KEY_USAGES.join(", ")
                    )));
                }
            })
        })
        .collect::<CResult<Vec<_>>>()
        .map(Some)
}
