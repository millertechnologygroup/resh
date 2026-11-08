//! Coded errors for every `cert` verb: `Error: [cert.<code>] <message>` on
//! stderr, `{"ok": false, "error": {"code", "message"}}` on stdout for
//! `format=json`, and the 0/1/2/124 exit codes.

use serde_json::{Value, json};

use crate::core::status::exit;

/// Every top-level error code the handle emits, with its exit code. Each one
/// is documented in docs/Security_Secrets/cert.md (checked by a test).
#[cfg(test)]
pub const ERROR_CODES: &[(&str, i32)] = &[
    ("cert.invalid_argument", exit::USAGE),
    ("cert.passphrase_required", exit::USAGE),
    ("cert.signer_required", exit::USAGE),
    ("cert.not_found", exit::FAILED),
    ("cert.read_failed", exit::FAILED),
    ("cert.parse_failed", exit::FAILED),
    ("cert.unsupported_type", exit::FAILED),
    ("cert.verification_failed", exit::FAILED),
    ("cert.target_exists", exit::FAILED),
    ("cert.symlink_refused", exit::FAILED),
    ("cert.write_failed", exit::FAILED),
    ("cert.key_load_failed", exit::FAILED),
    ("cert.key_decrypt_failed", exit::FAILED),
    ("cert.key_unsupported", exit::FAILED),
    ("cert.signer_load_failed", exit::FAILED),
    ("cert.keypair_mismatch", exit::FAILED),
    ("cert.csr_invalid", exit::FAILED),
    ("cert.sign_failed", exit::FAILED),
    ("cert.generation_failed", exit::FAILED),
    ("cert.trust_load_failed", exit::FAILED),
    ("cert.timeout", exit::TIMEOUT),
];

/// Codes reported per check in `verify` results (`checks.<name>.error_code`)
/// and per chain in `chain.info`; documented in cert.md too.
#[cfg(test)]
pub const CHECK_CODES: &[&str] = &[
    "cert.unsupported_version",
    "cert.signature_algorithm_mismatch",
    "cert.weak_signature",
    "cert.weak_key",
    "cert.trust_load_failed",
    "cert.self_signed_not_allowed",
    "cert.bad_signature",
    "cert.issuer_not_found",
    "cert.issuer_not_ca",
    "cert.ca_used_as_end_entity",
    "cert.path_len_exceeded",
    "cert.name_constraint_violation",
    "cert.chain_expired",
    "cert.chain_not_yet_valid",
    "cert.chain_too_long",
    "cert.chain_invalid",
    "cert.unsupported_signature_algorithm",
    "cert.expired",
    "cert.not_yet_valid",
    "cert.hostname_mismatch",
    "cert.invalid_hostname",
    "cert.eku_mismatch",
    "cert.key_usage_mismatch",
    "cert.eku_parse_failed",
    "cert.key_usage_parse_failed",
    "cert.keypair_load_failed",
    "cert.keypair_mismatch",
    "cert.key_parse_failed",
    "cert.revocation_not_implemented",
];

/// A failure of a cert verb.
#[derive(Debug, Clone)]
pub struct CertError {
    pub exit: i32,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl CertError {
    pub fn new(exit: i32, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Invalid usage: an unknown argument, a bad value, a missing or
    /// conflicting option (exit 2, nothing was done).
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, "cert.invalid_argument", message)
    }

    /// The operation failed (exit 1).
    pub fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(exit::FAILED, code, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(exit::TIMEOUT, "cert.timeout", message)
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// `{"code", "message"[, "details"]}`.
    pub fn to_json(&self) -> Value {
        let mut v = json!({ "code": self.code, "message": self.message });
        if let Some(d) = &self.details {
            v["details"] = d.clone();
        }
        v
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub type CResult<T> = std::result::Result<T, CertError>;

/// Maps an I/O error reading an input file to `cert.not_found` or
/// `cert.read_failed`.
pub fn read_error(what: &str, path: &str, e: &std::io::Error) -> CertError {
    if e.kind() == std::io::ErrorKind::NotFound {
        CertError::failed("cert.not_found", format!("{what} not found: {path}"))
    } else {
        CertError::failed(
            "cert.read_failed",
            format!("cannot read {what} {path}: {e}"),
        )
    }
}
