//! The verbs: strict argument parsing, then the work, then the output.
//! Every failure is a [`CertError`]; `CertHandle::call` prints it.

// The parsers fill a default options value field by field, in the order
// the checks must run (an earlier refusal wins).
#![allow(clippy::field_reassign_with_default)]

use std::collections::HashMap;

use ::pem::Pem;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use serde_json::{Value, json};
use x509_parser::prelude::*;

use super::args::{self, Reader};
use super::errors::{CResult, CertError};
use super::fileio::{self, Gate, read_input};
use super::keys::{self, LoadedKey};
use super::*;
use crate::core::status::{Status, exit};

/// A verb's output.
pub enum Out {
    Json(Value),
    Text(String),
}

pub struct Done {
    pub out: Out,
    pub status: Status,
}

impl Done {
    fn ok(json: bool, value: Value, text: impl FnOnce(&Value) -> String) -> CResult<Done> {
        Ok(Done {
            out: if json {
                Out::Json(value)
            } else {
                Out::Text(text(&value))
            },
            status: Status::ok(),
        })
    }
}

fn format_json(r: &Reader) -> CResult<bool> {
    Ok(r.choice("format", &["json", "text"])?.unwrap_or("json") == "json")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "(none)".to_string(),
        other => other.to_string(),
    }
}

fn warnings_text(out: &mut String, warnings: &Value) {
    out.push_str("Warnings:\n");
    let w = warnings.as_array().cloned().unwrap_or_default();
    if w.is_empty() {
        out.push_str("  (none)\n");
    }
    for x in w {
        out.push_str(&format!("  {}\n", s(&x)));
    }
}

// ---------------------------------------------------------------------------
// Shared option parsing
// ---------------------------------------------------------------------------

fn algorithm_opt(r: &Reader) -> CResult<Option<CertAlgorithm>> {
    Ok(r.choice("algorithm", &["rsa", "ecdsa", "ed25519"])?
        .map(|a| match a {
            "rsa" => CertAlgorithm::Rsa,
            "ecdsa" => CertAlgorithm::Ecdsa,
            _ => CertAlgorithm::Ed25519,
        }))
}

/// rsa_bits (only with RSA) and ecdsa_curve (only with ECDSA).
fn key_size_opts(r: &Reader, algorithm: &CertAlgorithm) -> CResult<(u16, EcdsaCurve)> {
    if !matches!(algorithm, CertAlgorithm::Rsa) {
        r.refuse(&["rsa_bits"], "unless algorithm=rsa")?;
    }
    if !matches!(algorithm, CertAlgorithm::Ecdsa) {
        r.refuse(&["ecdsa_curve"], "unless algorithm=ecdsa")?;
    }
    let bits = match r.args.get("rsa_bits") {
        None => 2048,
        Some(v) => match v.as_str() {
            "2048" => 2048,
            "3072" => 3072,
            "4096" => 4096,
            _ => {
                return Err(CertError::usage(format!(
                    "invalid value for rsa_bits: {v:?} (accepted: 2048, 3072, 4096)"
                )));
            }
        },
    };
    let curve = match r.args.get("ecdsa_curve").map(String::as_str) {
        None | Some("P-256") => EcdsaCurve::P256,
        Some("P-384") => EcdsaCurve::P384,
        Some(c @ ("P-521" | "secp256k1")) => {
            return Err(CertError::usage(format!(
                "ecdsa_curve={c} is not supported (accepted: P-256, P-384)"
            )));
        }
        Some(c) => {
            return Err(CertError::usage(format!(
                "invalid value for ecdsa_curve: {c:?}{} (accepted: P-256, P-384)",
                args::hint(c, &["P-256", "P-384"])
            )));
        }
    };
    Ok((bits, curve))
}

fn encoding_opt(r: &Reader, key: &str) -> CResult<Encoding> {
    Ok(match r.choice(key, &["pem", "der"])?.unwrap_or("pem") {
        "der" => Encoding::Der,
        _ => Encoding::Pem,
    })
}

/// key_format, checked against the algorithm.
fn key_format_opt(r: &Reader, algorithm: &CertAlgorithm) -> CResult<KeyFormat> {
    let f = match r
        .choice("key_format", &["pkcs8", "pkcs1", "sec1"])?
        .unwrap_or("pkcs8")
    {
        "pkcs1" => KeyFormat::Pkcs1,
        "sec1" => KeyFormat::Sec1,
        _ => KeyFormat::Pkcs8,
    };
    match (&f, algorithm) {
        (KeyFormat::Pkcs1, a) if !matches!(a, CertAlgorithm::Rsa) => Err(CertError::usage(
            "key_format=pkcs1 is only valid for RSA keys",
        )),
        (KeyFormat::Sec1, a) if !matches!(a, CertAlgorithm::Ecdsa) => Err(CertError::usage(
            "key_format=sec1 is only valid for ECDSA keys",
        )),
        _ => Ok(f),
    }
}

/// The passphrase that encrypts a written key (`pass_key`), with
/// key_kdf and key_kdf_iterations. Encryption needs key_format=pkcs8.
fn key_encryption_opts(
    r: &Reader,
    pass_key: &str,
    format: &KeyFormat,
) -> CResult<Option<(String, u32)>> {
    let pass = r.passphrase(pass_key)?;
    if pass.is_none() {
        r.refuse(
            &["key_kdf", "key_kdf_iterations"],
            &format!("without {pass_key}"),
        )?;
        return Ok(None);
    }
    if !matches!(format, KeyFormat::Pkcs8) {
        return Err(CertError::usage(format!(
            "{pass_key} needs key_format=pkcs8: only PKCS#8 keys can be encrypted"
        )));
    }
    if r.choice("key_kdf", &["pbkdf2", "argon2id"])? == Some("argon2id") {
        return Err(CertError::usage(
            "key_kdf=argon2id is not available: encrypted PKCS#8 keys use PBKDF2 \
             (key_kdf=pbkdf2, the default)",
        ));
    }
    let iterations = r
        .uint(
            "key_kdf_iterations",
            super::keyenc::MIN_ITERATIONS,
            super::keyenc::MAX_ITERATIONS,
        )?
        .map(|n| n as u32)
        .unwrap_or(super::keyenc::DEFAULT_ITERATIONS);
    Ok(pass.map(|p| (p, iterations)))
}

fn subject_opt(r: &Reader, key: &str) -> CResult<Option<CertSubject>> {
    match r.object(key, args::SUBJECT_FIELDS)? {
        None => Ok(None),
        Some(map) => {
            let s = args::subject_from_map(key, &map)?;
            for (field, values) in [
                ("organization", &s.organization),
                ("organizational_unit", &s.organizational_unit),
                ("country", &s.country),
                ("state_or_province", &s.state_or_province),
                ("locality", &s.locality),
            ] {
                if values.len() > 1 {
                    return Err(CertError::usage(format!(
                        "{key}.{field}: only one value per field is supported"
                    )));
                }
            }
            Ok(Some(s))
        }
    }
}

fn require_common_name(key: &str, s: &Option<CertSubject>, why: &str) -> CResult<()> {
    match s {
        Some(s) if s.common_name.is_some() => Ok(()),
        _ => Err(CertError::usage(format!(
            "{key} with a common_name is required {why}, for example \
             {key}='{{\"common_name\":\"example.com\"}}'"
        ))),
    }
}

fn sans_opt(r: &Reader, key: &str) -> CResult<Option<Vec<String>>> {
    let v = r.list(key)?;
    if let Some(sans) = &v {
        args::check_sans(key, sans)?;
    }
    Ok(v)
}

/// not_before / not_after / not_after_offset_days.
fn validity_opts(
    r: &Reader,
    carry_over: bool,
) -> CResult<(NotBeforeSetting, bool, Option<DateTime<Utc>>, i64)> {
    let keywords: &[&'static str] = if carry_over {
        &["now", "carry_over_start"]
    } else {
        &["now"]
    };
    let (not_before, carry) = match r.time_or("not_before", keywords)? {
        None | Some(Err("now")) => (NotBeforeSetting::Now, false),
        Some(Err(_)) => (NotBeforeSetting::Now, true),
        Some(Ok(dt)) => (NotBeforeSetting::Explicit(dt), false),
    };
    let not_after = match r.time_or("not_after", &[])? {
        Some(Ok(dt)) => Some(dt),
        _ => None,
    };
    if not_after.is_some() && r.has("not_after_offset_days") {
        return Err(CertError::usage(
            "give not_after or not_after_offset_days, not both",
        ));
    }
    let offset = r.uint("not_after_offset_days", 1, 36_500)?.unwrap_or(365) as i64;
    if let (NotBeforeSetting::Explicit(start), Some(end)) = (&not_before, not_after)
        && end <= *start
    {
        return Err(CertError::usage(format!(
            "not_after ({}) must be later than not_before ({})",
            end.to_rfc3339(),
            start.to_rfc3339()
        )));
    }
    if let (NotBeforeSetting::Now, Some(end)) = (&not_before, not_after)
        && !carry
        && end <= Utc::now()
    {
        return Err(CertError::usage(format!(
            "not_after ({}) is in the past",
            end.to_rfc3339()
        )));
    }
    Ok((not_before, carry, not_after, offset))
}

/// is_ca and path_len (path_len only with is_ca=true).
fn ca_opts(r: &Reader) -> CResult<(Option<bool>, Option<u8>)> {
    let is_ca = r.opt_flag("is_ca")?;
    let path_len = r.uint("path_len", 0, 255)?.map(|n| n as u8);
    if path_len.is_some() && is_ca != Some(true) {
        return Err(CertError::usage("path_len needs is_ca=true"));
    }
    Ok((is_ca, path_len))
}

fn signer_ca_of(ca_path: &str, key: &LoadedKey) -> CResult<CaSigner> {
    let ca_data = read_input("signer CA certificate", ca_path)
        .map_err(|e| CertError::failed("cert.signer_load_failed", e.message))?;
    let kp_der = key.pkcs8_der.clone();
    load_ca_signer(&ca_data, ca_path, &kp_der, "signer key").map_err(|e| {
        let msg = format!("{e:#}");
        if msg.contains("does not match") {
            CertError::failed("cert.keypair_mismatch", msg)
        } else {
            CertError::failed("cert.signer_load_failed", msg)
        }
    })
}

fn load_signer_key(r_pass: Option<&str>, path: &str) -> CResult<LoadedKey> {
    keys::load_key("signer key", path, r_pass, "signer_key_passphrase").map_err(|e| {
        if e.code == "cert.not_found" || e.code == "cert.read_failed" {
            CertError::failed("cert.signer_load_failed", e.message)
        } else {
            e
        }
    })
}

fn write_outputs(files: &[(&str, &[u8], bool)], overwrite: bool) -> CResult<()> {
    // Paths this run created, removed again if a later write fails, so a
    // failure does not leave half a set behind.
    let mut created: Vec<&str> = Vec::new();
    for (path, data, private) in files {
        let existed = fileio::exists(path);
        let r = if *private {
            fileio::write_private(path, data, overwrite)
        } else {
            fileio::write_public(path, data, overwrite)
        };
        if let Err(e) = r {
            for p in created {
                let _ = std::fs::remove_file(fileio::plain_path(p));
            }
            return Err(e);
        }
        if !existed {
            created.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

impl CertHandle {
    /// Runs `verb`; also returns the warnings for stderr.
    pub(super) fn dispatch(
        &self,
        verb: &str,
        args: &Args,
        stdin: &mut dyn std::io::Read,
    ) -> (CResult<Done>, Vec<String>) {
        let r = match Reader::new(verb, args, stdin) {
            Ok(r) => r,
            Err(e) => return (Err(e), Vec::new()),
        };
        let result = self.run_verb(verb, &r);
        (result, r.warnings.take())
    }

    fn run_verb(&self, verb: &str, r: &Reader) -> CResult<Done> {
        match verb {
            "info" => self.run_info(r),
            "verify" => self.run_verify(r),
            "chain.info" => self.run_chain_info(r),
            "generate" => self.run_generate(r),
            "csr.create" => self.run_csr_create(r),
            "sign" => self.run_sign(r),
            "csr.sign" => self.run_csr_sign(r),
            "renew" => self.run_renew(r),
            other => Err(CertError::usage(format!(
                "unknown verb for cert://: {other}{}",
                args::hint(other, args::VERBS)
            ))),
        }
    }

    fn run_info(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        let encoding = r
            .choice("encoding", &["auto", "pem", "der"])?
            .unwrap_or("auto");
        let algs = r
            .list("fingerprint_algs")?
            .unwrap_or_else(|| vec!["sha256".to_string()]);
        for a in &algs {
            if !FINGERPRINT_ALGS.contains(&a.as_str()) {
                return Err(CertError::usage(format!(
                    "invalid fingerprint_algs item: {a:?}{} (accepted: {})",
                    args::hint(a, FINGERPRINT_ALGS),
                    FINGERPRINT_ALGS.join(", ")
                )));
            }
        }
        let opts = CertInfoOptions {
            format: OutputFormat::Json,
            encoding: CertEncoding::Auto,
            fingerprint_algs: algs,
            include_pem: r.flag("include_pem", false)?,
            include_raw: r.flag("include_raw", false)?,
        };
        let data = read_input("certificate file", &self.target_path)?;
        let pem = match encoding {
            "pem" => true,
            "der" => false,
            _ => looks_like_pem(&data),
        };
        let parsed = if pem {
            self.parse_pem_content(&data, &opts)
        } else {
            self.parse_der_content(&data, &opts)
        };
        let response = parsed.map_err(|e| {
            CertError::failed("cert.parse_failed", format!("{}: {e:#}", self.target_path))
        })?;
        let value = self.info_json(&response);
        Done::ok(json, value, info_text)
    }
}

fn info_text(v: &Value) -> String {
    let mut out = format!("Type: {}\nEncoding: {}\n", s(&v["type"]), s(&v["encoding"]));
    let objects = v["objects"].as_array().cloned().unwrap_or_default();
    for (i, o) in objects.iter().enumerate() {
        out.push_str(&format!("\n[{}] {}\n", i + 1, s(&o["kind"])));
        let dn = |x: &Value| s(&x["raw_dn"]);
        match o["kind"].as_str() {
            Some("certificate") => {
                out.push_str(&format!("  Subject: {}\n", dn(&o["subject"])));
                out.push_str(&format!("  Issuer: {}\n", dn(&o["issuer"])));
                out.push_str(&format!("  Serial: {}\n", s(&o["serial_number"])));
                out.push_str(&format!(
                    "  Validity: {} to {} ({})\n",
                    s(&o["validity"]["not_before"]),
                    s(&o["validity"]["not_after"]),
                    if o["validity"]["is_currently_valid"] == true {
                        "currently valid"
                    } else {
                        "not currently valid"
                    }
                ));
                out.push_str(&format!("  Public Key: {}\n", key_line(&o["public_key"])));
                out.push_str(&format!(
                    "  CA: {}\n",
                    if o["is_ca"] == true { "yes" } else { "no" }
                ));
                let list = |k: &str| {
                    o["extensions"][k]
                        .as_array()
                        .map(|a| a.iter().map(s).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default()
                };
                for (label, k) in [
                    ("SANs", "subject_alt_names"),
                    ("Key Usage", "key_usage"),
                    ("Extended Key Usage", "extended_key_usage"),
                ] {
                    let l = list(k);
                    if !l.is_empty() {
                        out.push_str(&format!("  {label}: {l}\n"));
                    }
                }
            }
            Some("csr") => {
                out.push_str(&format!("  Subject: {}\n", dn(&o["subject"])));
                out.push_str(&format!("  Public Key: {}\n", key_line(&o["public_key"])));
                out.push_str(&format!(
                    "  Signature valid: {}\n",
                    s(&o["public_key"]["signature_valid"])
                ));
            }
            Some("private_key") => {
                out.push_str(&format!("  Algorithm: {}\n", s(&o["algorithm"])));
                out.push_str(&format!("  Format: {}\n", s(&o["key_format"])));
                out.push_str(&format!(
                    "  Encrypted: {}\n",
                    if o["is_encrypted"] == true {
                        "yes"
                    } else {
                        "no"
                    }
                ));
            }
            _ => {
                out.push_str(&format!("  Algorithm: {}\n", s(&o["algorithm"])));
            }
        }
        if let Some(fps) = o["fingerprints"].as_object() {
            let mut keys: Vec<&String> = fps.keys().collect();
            keys.sort();
            for k in keys {
                out.push_str(&format!("  {}: {}\n", k.to_uppercase(), s(&fps[k])));
            }
        }
    }
    out
}

fn key_line(k: &Value) -> String {
    let mut line = s(&k["algorithm"]);
    if let Some(c) = k["curve"].as_str() {
        line.push_str(&format!(" {c}"));
    }
    if let Some(b) = k["key_size"].as_u64() {
        line.push_str(&format!(" ({b} bits)"));
    }
    line
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// A trust anchor (DER) and where it came from.
type Anchor = (Vec<u8>, &'static str);

/// Anchors from trust_paths, ca_file and trust_pem, plus the system bundle
/// when `system`. Returns the anchors with their source and warnings.
fn load_anchors(r: &Reader, system: bool) -> CResult<(Vec<Anchor>, Vec<String>)> {
    let mut anchors = Vec::new();
    let mut warnings = Vec::new();
    if system {
        match trust::system_anchors() {
            Some((path, ders)) => {
                if ders.is_empty() {
                    warnings.push(format!("The system CA bundle {path} has no certificates"));
                }
                anchors.extend(ders.into_iter().map(|d| (d, "system")));
            }
            None => warnings.push(
                "No system CA bundle found; only trust_paths, ca_file and trust_pem anchors \
                 are used"
                    .to_string(),
            ),
        }
    }
    if let Some(paths) = r.list("trust_paths")? {
        anchors.extend(
            trust::anchors_from_paths("trust_paths", &paths)?
                .into_iter()
                .map(|d| (d, "mount")),
        );
    }
    if let Some(ca) = r.text("ca_file")? {
        anchors.extend(
            trust::anchors_from_paths("ca_file", &[ca])?
                .into_iter()
                .map(|d| (d, "mount")),
        );
    }
    if let Some(pem) = r.raw("trust_pem")? {
        anchors.extend(
            trust::anchors_from_pem("trust_pem", &pem)?
                .into_iter()
                .map(|d| (d, "inline")),
        );
    }
    Ok((anchors, warnings))
}

/// Refuses trust modes whose source was not given.
fn check_trust_sources(r: &Reader, trust: &str) -> CResult<()> {
    if trust.contains("mount") && !r.has("trust_paths") && !r.has("ca_file") {
        return Err(CertError::usage(format!(
            "trust={trust} needs trust_paths=<path>,... or ca_file=<pem>"
        )));
    }
    if trust.contains("inline") && !r.has("trust_pem") {
        return Err(CertError::usage(format!(
            "trust={trust} needs trust_pem=<pem>"
        )));
    }
    // Validate the list syntax now, before anything is read.
    r.list("trust_paths")?;
    r.text("ca_file")?;
    r.raw("trust_pem")?;
    Ok(())
}

impl CertHandle {
    fn run_verify(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        let mut opts = CertVerifyOptions::default();
        let encoding = r
            .choice("encoding", &["auto", "pem", "der"])?
            .unwrap_or("auto");
        opts.hostname = r.text("hostname")?;
        opts.purpose = match r
            .choice(
                "purpose",
                &[
                    "server_auth",
                    "client_auth",
                    "code_signing",
                    "email_protection",
                    "any",
                ],
            )?
            .unwrap_or("any")
        {
            "server_auth" => Purpose::ServerAuth,
            "client_auth" => Purpose::ClientAuth,
            "code_signing" => Purpose::CodeSigning,
            "email_protection" => Purpose::EmailProtection,
            _ => Purpose::Any,
        };
        let trust_mode = r
            .choice("trust", &["system", "mount", "inline"])?
            .unwrap_or("system");
        opts.trust = match trust_mode {
            "mount" => TrustMode::Mount,
            "inline" => TrustMode::Inline,
            _ => TrustMode::System,
        };
        check_trust_sources(r, trust_mode)?;
        opts.max_chain_depth = r.uint("max_chain_depth", 1, 20)?.unwrap_or(10) as u8;
        opts.min_rsa_bits = r.uint("min_rsa_bits", 2048, 16384)?.unwrap_or(2048) as u16;
        opts.allow_self_signed = r.flag("allow_self_signed", false)?;
        opts.allow_expired = r.flag("allow_expired", false)?;
        opts.allow_not_yet_valid = r.flag("allow_not_yet_valid", false)?;
        opts.check_revocation = match r.choice("check_revocation", &["none", "soft", "hard"])? {
            Some("soft") => RevocationMode::Soft,
            Some("hard") => RevocationMode::Hard,
            _ => RevocationMode::None,
        };
        opts.keypair_target = r.text("keypair_target")?;
        opts.include_chain_report = r.flag("include_chain_report", true)?;

        let data = read_input("certificate file", &self.target_path)?;
        let pem = match encoding {
            "pem" => true,
            "der" => false,
            _ => looks_like_pem(&data),
        };
        let kind = if pem {
            let blocks = pem_blocks(&data);
            if blocks.is_empty() {
                return Err(CertError::failed(
                    "cert.parse_failed",
                    format!("{}: no PEM block found", self.target_path),
                ));
            }
            if blocks.iter().any(|b| b.tag() == "CERTIFICATE") {
                CertObjectKind::Certificate
            } else if blocks.iter().any(|b| b.tag().ends_with("PRIVATE KEY")) {
                CertObjectKind::PrivateKey
            } else if blocks
                .iter()
                .any(|b| b.tag().contains("CERTIFICATE REQUEST"))
            {
                CertObjectKind::Csr
            } else if blocks.iter().any(|b| b.tag() == "PUBLIC KEY") {
                CertObjectKind::PublicKey
            } else {
                CertObjectKind::Unknown
            }
        } else if X509Certificate::from_der(&data).is_ok() {
            CertObjectKind::Certificate
        } else if keys::parse_key(&data, "key", None, "").is_ok() || keyenc::is_encrypted(&data) {
            CertObjectKind::PrivateKey
        } else {
            return Err(CertError::failed(
                "cert.parse_failed",
                format!("{}: not a DER certificate or private key", self.target_path),
            ));
        };
        let encoding_name = if pem { "pem" } else { "der" };

        let response =
            match kind {
                CertObjectKind::Certificate => {
                    let bundle = if pem {
                        certificate_ders(&data)
                    } else {
                        vec![data.clone()]
                    };
                    let Some((_, cert)) = bundle
                        .first()
                        .and_then(|d| X509Certificate::from_der(d).ok())
                    else {
                        return Err(CertError::failed(
                            "cert.parse_failed",
                            format!("{}: the certificate cannot be parsed", self.target_path),
                        ));
                    };
                    let (anchors, mut warnings) =
                        load_anchors(r, matches!(opts.trust, TrustMode::System))?;
                    let anchor_ders: Vec<Vec<u8>> = anchors.into_iter().map(|(d, _)| d).collect();
                    let mut checks = HashMap::new();
                    checks.insert(
                        "structure".to_string(),
                        self.verify_certificate_structure(&cert, &opts),
                    );
                    let (chain_check, chain_report, path) =
                        chain_check(&bundle, &anchor_ders, &cert, &opts);
                    checks.insert("chain".to_string(), chain_check);
                    checks.insert(
                        "time".to_string(),
                        self.verify_certificate_time(&cert, &opts),
                    );
                    checks.insert(
                        "hostname".to_string(),
                        hostname_check(&bundle[0], &cert, &opts),
                    );
                    checks.insert(
                        "usage".to_string(),
                        usage_check(&cert, &bundle, &path, &anchor_ders, &opts),
                    );
                    checks.insert("keypair".to_string(), keypair_check(&cert, &opts));
                    checks.insert(
                        "revocation".to_string(),
                        self.verify_revocation(&cert, &opts),
                    );
                    match opts.check_revocation {
                        RevocationMode::None => warnings
                            .push("Revocation not checked (check_revocation=none)".to_string()),
                        RevocationMode::Soft => warnings
                            .push("Revocation not checked (check_revocation=soft)".to_string()),
                        RevocationMode::Hard => {}
                    }
                    CertVerifyResponse {
                        ok: checks.values().all(|c| c.ok),
                        target: format!("cert://{}", self.target_path),
                        cert_type: CertObjectKind::Certificate,
                        encoding: encoding_name.to_string(),
                        checks,
                        chain_report: if opts.include_chain_report {
                            chain_report
                        } else {
                            Vec::new()
                        },
                        warnings,
                        policy: self.create_policy_json(&opts),
                    }
                }
                CertObjectKind::PrivateKey => {
                    let mut checks = HashMap::new();
                    let structure = match keys::parse_key(&data, &self.target_path, None, "") {
                        Ok(k) => CheckResult::ok(&format!("Private key parsed ({})", k.describe())),
                        Err(e) if e.code == "cert.passphrase_required" => CheckResult::unsupported(
                            "The private key is encrypted; verify cannot decrypt it",
                            "cert.key_parse_failed",
                        ),
                        Err(e) => CheckResult::fail(&e.message, "cert.key_parse_failed"),
                    };
                    checks.insert("structure".to_string(), structure);
                    for name in [
                        "chain",
                        "time",
                        "hostname",
                        "usage",
                        "keypair",
                        "revocation",
                    ] {
                        checks.insert(
                            name.to_string(),
                            CheckResult::skipped("Not applicable for private keys"),
                        );
                    }
                    CertVerifyResponse {
                        ok: checks.values().all(|c| c.ok),
                        target: format!("cert://{}", self.target_path),
                        cert_type: CertObjectKind::PrivateKey,
                        encoding: encoding_name.to_string(),
                        checks,
                        chain_report: Vec::new(),
                        warnings: Vec::new(),
                        policy: self.create_policy_json(&opts),
                    }
                }
                other => {
                    return Err(CertError::failed(
                        "cert.unsupported_type",
                        format!(
                            "{}: verify checks certificates and private keys, not a {}",
                            self.target_path,
                            match other {
                                CertObjectKind::Csr => "CSR (use info)",
                                CertObjectKind::PublicKey => "public key",
                                _ => "file of this type",
                            }
                        ),
                    ));
                }
            };

        let mut value = self.verify_json(&response);
        let status = if response.ok {
            Status::ok()
        } else {
            let mut failed: Vec<&str> = [
                "structure",
                "chain",
                "time",
                "hostname",
                "usage",
                "keypair",
                "revocation",
            ]
            .into_iter()
            .filter(|n| response.checks.get(*n).is_some_and(|c| !c.ok))
            .collect();
            failed.dedup();
            let e = CertError::failed(
                "cert.verification_failed",
                format!(
                    "{}: verification failed ({})",
                    self.target_path,
                    failed
                        .iter()
                        .map(|n| format!("{n}: {}", response.checks[*n].message))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            );
            value["error"] = e.to_json();
            Status::coded(e.exit, e.code, &e.message)
        };
        let out = if json {
            Out::Json(value)
        } else {
            Out::Text(self.format_verify_text(&response))
        };
        Ok(Done { out, status })
    }
}

/// The chain check: the first certificate validated by webpki through the
/// others in the file to a trust anchor. Returns the check, the chain report
/// and the validated path (DER, leaf first, anchor last).
fn chain_check(
    bundle: &[Vec<u8>],
    anchors: &[Vec<u8>],
    leaf: &X509Certificate,
    opts: &CertVerifyOptions,
) -> (CheckResult, Vec<ChainLink>, Vec<Vec<u8>>) {
    let link = |index: usize, c: &X509Certificate, anchor: bool| ChainLink {
        index,
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        is_ca: is_ca_cert(c),
        is_trust_anchor: anchor,
    };
    if anchors.iter().any(|a| a == &bundle[0]) {
        return (
            CheckResult::ok("Certificate is itself a trust anchor"),
            vec![link(0, leaf, true)],
            vec![bundle[0].clone()],
        );
    }
    // Validate at a time inside the leaf's validity when the policy allows
    // an expired or not yet valid certificate (the time check reports it).
    let now = now_unix() as i64;
    let v = leaf.validity();
    let (at, note) = if now > v.not_after.timestamp() && opts.allow_expired {
        (
            v.not_after.timestamp(),
            " (evaluated at the certificate's expiry, allow_expired=true)",
        )
    } else if now < v.not_before.timestamp() && opts.allow_not_yet_valid {
        (
            v.not_before.timestamp(),
            " (evaluated at the certificate's start, allow_not_yet_valid=true)",
        )
    } else {
        (now, "")
    };
    match trust::validate(
        &bundle[0],
        &bundle[1..],
        anchors,
        at.max(0) as u64,
        trust::Eku::Any,
    ) {
        Ok(path) => {
            let links: Vec<ChainLink> = path
                .iter()
                .enumerate()
                .filter_map(|(i, d)| {
                    X509Certificate::from_der(d)
                        .ok()
                        .map(|(_, c)| link(i, &c, i == path.len() - 1))
                })
                .collect();
            if path.len() > usize::from(opts.max_chain_depth) {
                return (
                    CheckResult::fail(
                        &format!(
                            "Chain of {} certificates exceeds max_chain_depth={}",
                            path.len(),
                            opts.max_chain_depth
                        ),
                        "cert.chain_too_long",
                    ),
                    links,
                    path,
                );
            }
            for d in &path {
                if let Ok((_, c)) = X509Certificate::from_der(d) {
                    let k = describe_spki(c.public_key());
                    if k.algorithm == "rsa" && k.bits.unwrap_or(0) < usize::from(opts.min_rsa_bits)
                    {
                        return (
                            CheckResult::fail(
                                &format!(
                                    "{} has a {}-bit RSA key; policy requires {}",
                                    c.subject(),
                                    k.bits.unwrap_or(0),
                                    opts.min_rsa_bits
                                ),
                                "cert.weak_key",
                            ),
                            links,
                            path,
                        );
                    }
                }
            }
            let anchor = path
                .last()
                .and_then(|d| X509Certificate::from_der(d).ok())
                .map(|(_, c)| c.subject().to_string())
                .unwrap_or_default();
            (
                CheckResult::ok(&format!(
                    "Chain of {} certificate(s) verified to trust anchor {anchor}{note}",
                    path.len()
                )),
                links,
                path,
            )
        }
        Err(e) => {
            let links = vec![link(0, leaf, false)];
            if is_self_issued(leaf)
                && matches!(
                    e,
                    webpki::Error::UnknownIssuer | webpki::Error::CaUsedAsEndEntity
                )
            {
                return match verify_cert_signed_by(leaf, leaf.public_key()) {
                    SignatureCheck::Valid if opts.allow_self_signed => (
                        CheckResult::ok(
                            "Self-signed certificate allowed by policy; self-signature verified",
                        ),
                        links,
                        vec![bundle[0].clone()],
                    ),
                    SignatureCheck::Valid => (
                        CheckResult::fail(
                            "Self-signed certificate is not a trust anchor and \
                             allow_self_signed is false",
                            "cert.self_signed_not_allowed",
                        ),
                        links,
                        Vec::new(),
                    ),
                    SignatureCheck::Invalid => (
                        CheckResult::fail(
                            "Self-signed certificate has an invalid signature",
                            "cert.bad_signature",
                        ),
                        links,
                        Vec::new(),
                    ),
                    SignatureCheck::Unsupported(m) => (
                        CheckResult::unsupported(
                            &format!("Self-signature not verified: {m}"),
                            "cert.unsupported_signature_algorithm",
                        ),
                        links,
                        Vec::new(),
                    ),
                };
            }
            let (code, unsupported, msg) = trust::describe_error(&e);
            let message = format!("{}{note}", capitalize(&msg));
            let check = if unsupported {
                CheckResult::unsupported(&message, code)
            } else {
                CheckResult::fail(&message, code)
            };
            (check, links, Vec::new())
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn hostname_check(
    leaf_der: &[u8],
    cert: &X509Certificate,
    opts: &CertVerifyOptions,
) -> CheckResult {
    let Some(host) = &opts.hostname else {
        return CheckResult::skipped("No hostname specified");
    };
    match trust::valid_for_host(leaf_der, host) {
        Err(m) => CheckResult::fail(&m, "cert.invalid_hostname"),
        Ok(true) => {
            let matched = san_strings(cert).into_iter().find(|san| {
                san.strip_prefix("DNS:")
                    .is_some_and(|d| dns_name_matches(d, host))
                    || san.strip_prefix("IP:").is_some_and(|ip| ip == host)
            });
            CheckResult::ok(&match matched {
                Some(san) => format!("Hostname {host} matches {}", san.replacen(':', " SAN ", 1)),
                None => format!("Hostname {host} matches the subject alternative names"),
            })
        }
        Ok(false) => {
            let sans = san_strings(cert);
            CheckResult::fail(
                &if sans.is_empty() {
                    format!(
                        "Hostname {host} does not match: the certificate has no subject \
                         alternative names (the common name is not used)"
                    )
                } else {
                    format!("Hostname {host} does not match {}", sans.join(", "))
                },
                "cert.hostname_mismatch",
            )
        }
    }
}

fn usage_check(
    cert: &X509Certificate,
    bundle: &[Vec<u8>],
    path: &[Vec<u8>],
    anchors: &[Vec<u8>],
    opts: &CertVerifyOptions,
) -> CheckResult {
    let leaf = check_purpose(cert, &opts.purpose);
    if !leaf.ok || matches!(opts.purpose, Purpose::Any) || path.len() < 2 {
        return leaf;
    }
    // The extended key usage of the issuers must allow the purpose too.
    let eku = match opts.purpose {
        Purpose::ServerAuth => trust::Eku::ServerAuth,
        Purpose::ClientAuth => trust::Eku::ClientAuth,
        Purpose::CodeSigning => trust::Eku::CodeSigning,
        _ => trust::Eku::EmailProtection,
    };
    let at = cert
        .validity()
        .not_after
        .timestamp()
        .min(now_unix() as i64)
        .max(cert.validity().not_before.timestamp());
    match trust::validate(&bundle[0], &bundle[1..], anchors, at.max(0) as u64, eku) {
        Ok(_) => leaf,
        Err(e) => {
            let (code, _, msg) = trust::describe_error(&e);
            CheckResult::fail(&capitalize(&msg), code)
        }
    }
}

fn keypair_check(cert: &X509Certificate, opts: &CertVerifyOptions) -> CheckResult {
    let Some(target) = &opts.keypair_target else {
        return CheckResult::skipped("No keypair_target specified");
    };
    let key = match keys::load_key("private key", target, None, "") {
        Ok(k) => k,
        Err(e) if e.code == "cert.passphrase_required" => {
            return CheckResult::fail(
                &format!("Private key {target} is encrypted; verify cannot decrypt it"),
                "cert.keypair_load_failed",
            );
        }
        Err(e) => return CheckResult::fail(&e.message, "cert.keypair_load_failed"),
    };
    match key.key_pair() {
        Ok(kp) if kp.public_key_raw() == spki_key_bytes(cert.public_key()) => CheckResult::ok(
            &format!("Private key {target} matches the certificate public key"),
        ),
        Ok(_) => CheckResult::fail(
            &format!("Private key {target} does not match the certificate public key"),
            "cert.keypair_mismatch",
        ),
        Err(e) => CheckResult::fail(&e.message, "cert.keypair_load_failed"),
    }
}

// ---------------------------------------------------------------------------
// chain.info
// ---------------------------------------------------------------------------

impl CertHandle {
    fn run_chain_info(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        let encoding = r
            .choice("encoding", &["auto", "pem", "der"])?
            .unwrap_or("auto");
        let trust_mode = r
            .choice(
                "trust",
                &[
                    "none",
                    "system",
                    "mount",
                    "inline",
                    "system+mount",
                    "system+inline",
                    "mount+inline",
                ],
            )?
            .unwrap_or("none");
        check_trust_sources(r, trust_mode)?;
        let opts = chain::Options {
            max_depth: r.uint("max_depth", 1, 50)?.unwrap_or(10) as usize,
            max_paths: r.uint("max_paths", 1, 20)?.unwrap_or(5) as usize,
            include_raw_subjects: r.flag("include_raw_subjects", false)?,
            include_raw_issuers: r.flag("include_raw_issuers", false)?,
            include_cert_refs: r.flag("include_cert_refs", true)?,
        };
        let data = read_input("certificate bundle", &self.target_path)?;
        let pem = match encoding {
            "pem" => true,
            "der" => false,
            _ => looks_like_pem(&data),
        };
        let bundle = if pem {
            certificate_ders(&data)
        } else if X509Certificate::from_der(&data).is_ok() {
            vec![data.clone()]
        } else {
            Vec::new()
        };
        if bundle.is_empty() {
            return Err(CertError::failed(
                "cert.parse_failed",
                format!("{}: no certificate found", self.target_path),
            ));
        }
        let (anchors, warnings) = load_anchors(r, trust_mode.contains("system"))?;
        let mut value = chain::report(
            &self.target_path,
            if pem { "pem" } else { "der" },
            &bundle,
            &anchors,
            now_unix(),
            &opts,
        )?;
        if let Some(w) = value["warnings"].as_array_mut() {
            for x in warnings {
                w.insert(0, json!(x));
            }
        }
        Done::ok(json, value, chain::text)
    }
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

const OUTPUT_FIELDS: &[&str] = &[
    "write_key",
    "write_cert",
    "write_csr",
    "return_key",
    "return_cert",
    "return_csr",
];

impl CertHandle {
    fn parse_generate(&self, r: &Reader) -> CResult<(CertGenerateOptions, Option<(String, u32)>)> {
        let mut o = CertGenerateOptions::default();
        o.format = if format_json(r)? {
            OutputFormat::Json
        } else {
            OutputFormat::Text
        };
        o.mode = match r
            .choice("mode", &["key", "self_signed", "csr", "leaf_cert"])?
            .unwrap_or("key")
        {
            "self_signed" => CertGenerateMode::SelfSigned,
            "csr" => CertGenerateMode::Csr,
            "leaf_cert" => CertGenerateMode::LeafCert,
            _ => CertGenerateMode::Key,
        };
        let cert_opts: &[&str] = &[
            "is_ca",
            "path_len",
            "not_before",
            "not_after",
            "not_after_offset_days",
            "cert_encoding",
        ];
        let signer_opts: &[&str] = &["signer_ca", "signer_key", "signer_key_passphrase"];
        match o.mode {
            CertGenerateMode::Key => {
                r.refuse(&["subject", "sans", "csr_encoding"], "with mode=key")?;
                r.refuse(cert_opts, "with mode=key")?;
                r.refuse(signer_opts, "with mode=key")?;
            }
            CertGenerateMode::Csr => {
                r.refuse(cert_opts, "with mode=csr")?;
                r.refuse(signer_opts, "with mode=csr")?;
            }
            CertGenerateMode::SelfSigned => {
                r.refuse(&["csr_encoding"], "with mode=self_signed")?;
                r.refuse(signer_opts, "with mode=self_signed")?;
            }
            CertGenerateMode::LeafCert => {
                r.refuse(&["csr_encoding"], "with mode=leaf_cert")?;
                r.require("signer_ca", "with mode=leaf_cert")?;
                r.require("signer_key", "with mode=leaf_cert")?;
            }
        }
        o.algorithm = algorithm_opt(r)?.unwrap_or(CertAlgorithm::Rsa);
        (o.rsa_bits, o.ecdsa_curve) = key_size_opts(r, &o.algorithm)?;
        o.key_format = key_format_opt(r, &o.algorithm)?;
        o.key_encoding = encoding_opt(r, "key_encoding")?;
        o.cert_encoding = encoding_opt(r, "cert_encoding")?;
        o.csr_encoding = encoding_opt(r, "csr_encoding")?;
        o.subject = subject_opt(r, "subject")?;
        if !matches!(o.mode, CertGenerateMode::Key) {
            require_common_name("subject", &o.subject, "for this mode")?;
        }
        o.sans = sans_opt(r, "sans")?.unwrap_or_default();
        let (is_ca, path_len) = ca_opts(r)?;
        o.is_ca = is_ca.unwrap_or(false);
        o.path_len = path_len;
        let (nb, _, na, off) = validity_opts(r, false)?;
        o.not_before = nb;
        o.not_after = na;
        o.not_after_offset_days = off;
        o.signer_ca = r.text("signer_ca")?;
        o.signer_key = r.text("signer_key")?;
        o.signer_key_passphrase = r.passphrase("signer_key_passphrase")?;
        let encryption = key_encryption_opts(r, "key_passphrase", &o.key_format)?;
        o.overwrite = r.flag("overwrite", false)?;
        if let Some(map) = r.object("output", OUTPUT_FIELDS)? {
            for (k, v) in &map {
                let b = json_bool(v)
                    .ok_or_else(|| CertError::usage(format!("output.{k} must be true or false")))?;
                let applies = match k.as_str() {
                    "write_cert" | "return_cert" => matches!(
                        o.mode,
                        CertGenerateMode::SelfSigned | CertGenerateMode::LeafCert
                    ),
                    "write_csr" | "return_csr" => matches!(o.mode, CertGenerateMode::Csr),
                    _ => true,
                };
                if !applies {
                    return Err(CertError::usage(format!(
                        "output.{k} is not used with this mode; remove it"
                    )));
                }
                match k.as_str() {
                    "write_key" => o.output.write_key = b,
                    "write_cert" => o.output.write_cert = b,
                    "write_csr" => o.output.write_csr = b,
                    "return_key" => o.output.return_key = b,
                    "return_cert" => o.output.return_cert = b,
                    _ => o.output.return_csr = b,
                }
            }
        }
        if matches!(o.mode, CertGenerateMode::Key) && !o.output.write_key && !o.output.return_key {
            return Err(CertError::usage(
                "output.write_key and output.return_key are both false: the key would be \
                 neither written nor returned",
            ));
        }
        Ok((o, encryption))
    }

    fn run_generate(&self, r: &Reader) -> CResult<Done> {
        let (opts, encryption) = self.parse_generate(r)?;
        let timeout = r.timeout()?;
        let json = matches!(opts.format, OutputFormat::Json);
        let t = &self.target_path;
        let key_path = format!("{t}-key.pem");
        let cert_path = format!("{t}.pem");
        let csr_path = format!("{t}.csr");
        let has_cert = matches!(
            opts.mode,
            CertGenerateMode::SelfSigned | CertGenerateMode::LeafCert
        );
        let mut outputs: Vec<&str> = Vec::new();
        if opts.output.write_key {
            outputs.push(&key_path);
        }
        if has_cert && opts.output.write_cert {
            outputs.push(&cert_path);
        }
        if matches!(opts.mode, CertGenerateMode::Csr) && opts.output.write_csr {
            outputs.push(&csr_path);
        }
        fileio::check_outputs(&outputs, opts.overwrite)?;

        // The signer of a leaf certificate is loaded before any work.
        let mut warnings = Vec::new();
        let ca = match (&opts.mode, &opts.signer_ca, &opts.signer_key) {
            (CertGenerateMode::LeafCert, Some(ca), Some(key)) => {
                let k = load_signer_key(opts.signer_key_passphrase.as_deref(), key)?;
                warnings.extend(k.warning.clone());
                Some((ca.clone(), k.pkcs8_der.clone()))
            }
            _ => None,
        };

        let this = self.clone();
        let (key_path2, cert_path2, csr_path2) =
            (key_path.clone(), cert_path.clone(), csr_path.clone());
        let value = fileio::run_with_deadline(timeout, move |gate| {
            this.generate_now(
                opts,
                encryption,
                ca,
                warnings,
                gate,
                [key_path2, cert_path2, csr_path2],
            )
        })?;
        Done::ok(json, value, generate_text)
    }

    fn generate_now(
        &self,
        opts: CertGenerateOptions,
        encryption: Option<(String, u32)>,
        ca: Option<(String, Vec<u8>)>,
        mut warnings: Vec<String>,
        gate: &Gate,
        [key_path, cert_path, csr_path]: [String; 3],
    ) -> CResult<Value> {
        let gen_failed =
            |e: anyhow::Error| CertError::failed("cert.generation_failed", format!("{e:#}"));
        let key_pair = keys::generate_key(&opts.algorithm, opts.rsa_bits, &opts.ecdsa_curve)?;
        let subject = opts.subject.clone().unwrap_or_default();

        let (cert_der, csr_der) = match opts.mode {
            CertGenerateMode::Key => (None, None),
            CertGenerateMode::Csr => {
                let mut params = CertificateParams::new(vec![]);
                params.distinguished_name =
                    build_distinguished_name(&subject).map_err(gen_failed)?;
                params.subject_alt_names = parse_san_list(&opts.sans).map_err(gen_failed)?;
                params.alg = key_pair.algorithm();
                params.key_pair = Some(
                    KeyPair::from_der(&key_pair.serialize_der())
                        .map_err(|e| gen_failed(e.into()))?,
                );
                let csr = Certificate::from_params(params)
                    .and_then(|c| c.serialize_request_der())
                    .map_err(|e| gen_failed(e.into()))?;
                (None, Some(csr))
            }
            CertGenerateMode::SelfSigned | CertGenerateMode::LeafCert => {
                let mut params = CertificateParams::new(vec![]);
                params.distinguished_name =
                    build_distinguished_name(&subject).map_err(gen_failed)?;
                params.subject_alt_names = parse_san_list(&opts.sans).map_err(gen_failed)?;
                let (start, end) =
                    validity_window(&opts.not_before, opts.not_after, opts.not_after_offset_days)
                        .map_err(|e| CertError::usage(format!("{e:#}")))?;
                params.not_before = to_offset_datetime(start).map_err(gen_failed)?;
                params.not_after = to_offset_datetime(end).map_err(gen_failed)?;
                params.serial_number = Some(random_serial());
                params.is_ca = if opts.is_ca {
                    params.key_usages = vec![
                        rcgen::KeyUsagePurpose::KeyCertSign,
                        rcgen::KeyUsagePurpose::CrlSign,
                        rcgen::KeyUsagePurpose::DigitalSignature,
                    ];
                    IsCa::Ca(match opts.path_len {
                        Some(n) => BasicConstraints::Constrained(n),
                        None => BasicConstraints::Unconstrained,
                    })
                } else {
                    IsCa::ExplicitNoCa
                };
                params.alg = key_pair.algorithm();
                params.key_pair = Some(
                    KeyPair::from_der(&key_pair.serialize_der())
                        .map_err(|e| gen_failed(e.into()))?,
                );
                let der = match &ca {
                    Some((ca_path, ca_key_der)) => {
                        let signer = load_ca_signer(
                            &read_input("signer CA certificate", ca_path).map_err(|e| {
                                CertError::failed("cert.signer_load_failed", e.message)
                            })?,
                            ca_path,
                            ca_key_der,
                            "signer key",
                        )
                        .map_err(|e| {
                            let m = format!("{e:#}");
                            if m.contains("does not match") {
                                CertError::failed("cert.keypair_mismatch", m)
                            } else {
                                CertError::failed("cert.signer_load_failed", m)
                            }
                        })?;
                        params.use_authority_key_identifier_extension = true;
                        Certificate::from_params(params)
                            .and_then(|c| c.serialize_der_with_signer(&signer.cert))
                    }
                    None => Certificate::from_params(params).and_then(|c| c.serialize_der()),
                }
                .map_err(|e| gen_failed(e.into()))?;
                (Some(der), None)
            }
        };

        let key_bytes = keys::encode_key(
            &key_pair,
            &opts.algorithm,
            &opts.key_format,
            &opts.key_encoding,
            encryption.as_ref().map(|(p, i)| (p.as_str(), *i)),
        )?;
        let cert_bytes = cert_der
            .as_ref()
            .map(|d| encode_cert_der(d, &opts.cert_encoding));
        let csr_bytes = csr_der.as_ref().map(|d| match opts.csr_encoding {
            Encoding::Pem => {
                pem_encode_lf(&Pem::new("CERTIFICATE REQUEST", d.clone())).into_bytes()
            }
            Encoding::Der => d.clone(),
        });

        let mut files: Vec<(&str, &[u8], bool)> = Vec::new();
        if opts.output.write_key {
            files.push((&key_path, &key_bytes, true));
        }
        if let (true, Some(b)) = (opts.output.write_cert, &cert_bytes) {
            files.push((&cert_path, b, false));
        }
        if let (true, Some(b)) = (opts.output.write_csr, &csr_bytes) {
            files.push((&csr_path, b, false));
        }
        gate.commit()?;
        write_outputs(&files, opts.overwrite)?;

        if cert_der.is_some() && !opts.output.write_cert && !opts.output.return_cert {
            warnings.push(
                "Certificate was neither written nor returned (output.write_cert and \
                 output.return_cert are false)"
                    .to_string(),
            );
        }
        if csr_der.is_some() && !opts.output.write_csr && !opts.output.return_csr {
            warnings.push(
                "CSR was neither written nor returned (output.write_csr and output.return_csr \
                 are false)"
                    .to_string(),
            );
        }
        if !opts.output.write_key && !opts.output.return_key {
            warnings.push(
                "The private key was neither written nor returned (output.write_key and \
                 output.return_key are false)"
                    .to_string(),
            );
        }
        let summary = match &cert_der {
            Some(d) => Some(summarize_cert_der(d).map_err(gen_failed)?),
            None => None,
        };
        let subject_json = match (&summary, &opts.subject) {
            (Some(s), _) => json!(s.subject),
            (None, Some(sub)) => {
                let mut m = serde_json::Map::new();
                if let Some(cn) = &sub.common_name {
                    m.insert("common_name".into(), json!(cn));
                }
                for (k, v) in [
                    ("organization", &sub.organization),
                    ("organizational_unit", &sub.organizational_unit),
                    ("country", &sub.country),
                    ("state_or_province", &sub.state_or_province),
                    ("locality", &sub.locality),
                ] {
                    if !v.is_empty() {
                        m.insert(k.into(), json!(v));
                    }
                }
                Value::Object(m)
            }
            _ => Value::Null,
        };
        let pem_key = matches!(opts.key_encoding, Encoding::Pem);
        let return_key = opts.output.return_key;
        let cert_pem = matches!(opts.cert_encoding, Encoding::Pem);
        let csr_pem = matches!(opts.csr_encoding, Encoding::Pem);
        Ok(json!({
            "ok": true,
            "target": self.target_path,
            "mode": match opts.mode {
                CertGenerateMode::Key => "key",
                CertGenerateMode::SelfSigned => "self_signed",
                CertGenerateMode::Csr => "csr",
                CertGenerateMode::LeafCert => "leaf_cert",
            },
            "algorithm": format!("{:?}", opts.algorithm).to_lowercase(),
            "rsa_bits": matches!(opts.algorithm, CertAlgorithm::Rsa).then_some(opts.rsa_bits),
            "ecdsa_curve": matches!(opts.algorithm, CertAlgorithm::Ecdsa)
                .then(|| format!("{:?}", opts.ecdsa_curve)),
            "encodings": {
                "key": format!("{:?}", opts.key_encoding).to_lowercase(),
                "cert": format!("{:?}", opts.cert_encoding).to_lowercase(),
                "csr": format!("{:?}", opts.csr_encoding).to_lowercase(),
            },
            "subject": subject_json,
            "sans": opts.sans,
            "is_ca": summary.as_ref().map(|s| s.is_ca).unwrap_or(opts.is_ca),
            "path_len": summary.as_ref().map(|s| s.path_len).unwrap_or(opts.path_len),
            "validity": summary.as_ref().map(|s| json!({
                "not_before": s.not_before,
                "not_after": s.not_after,
            })),
            "key": {
                "stored_at": opts.output.write_key.then_some(&key_path),
                "encrypted": encryption.is_some(),
                "key_format": format!("{:?}", opts.key_format).to_lowercase(),
            },
            "certificate": summary.as_ref().map(|s| json!({
                "stored_at": opts.output.write_cert.then_some(&cert_path),
                "serial_number": s.serial_hex,
                "fingerprints": s.fingerprints,
            })),
            "csr": csr_der.as_ref().map(|d| json!({
                "stored_at": opts.output.write_csr.then_some(&csr_path),
                "fingerprints": { "sha256": fingerprint("sha256", d) },
            })),
            "returned": {
                "key_pem": (return_key && pem_key).then(|| String::from_utf8_lossy(&key_bytes).into_owned()),
                "key_der_base64": (return_key && !pem_key).then(|| BASE64_STANDARD.encode(&key_bytes)),
                "cert_pem": cert_der.as_ref().filter(|_| opts.output.return_cert && cert_pem)
                    .map(|d| pem_encode_lf(&Pem::new("CERTIFICATE", d.clone()))),
                "cert_der_base64": cert_der.as_ref().filter(|_| opts.output.return_cert && !cert_pem)
                    .map(|d| BASE64_STANDARD.encode(d)),
                "csr_pem": csr_der.as_ref().filter(|_| opts.output.return_csr && csr_pem)
                    .map(|d| pem_encode_lf(&Pem::new("CERTIFICATE REQUEST", d.clone()))),
                "csr_der_base64": csr_der.as_ref().filter(|_| opts.output.return_csr && !csr_pem)
                    .map(|d| BASE64_STANDARD.encode(d)),
            },
            "warnings": warnings,
        }))
    }
}

fn generate_text(v: &Value) -> String {
    let mut out = format!(
        "Target: {}\nMode: {}\nAlgorithm: {}",
        s(&v["target"]),
        s(&v["mode"]),
        s(&v["algorithm"])
    );
    if let Some(b) = v["rsa_bits"].as_u64() {
        out.push_str(&format!(" {b}-bit"));
    }
    if let Some(c) = v["ecdsa_curve"].as_str() {
        out.push_str(&format!(" {c}"));
    }
    out.push('\n');
    if let Some(dn) = v["subject"]["raw_dn"].as_str() {
        out.push_str(&format!("Subject: {dn}\n"));
    } else if let Some(cn) = v["subject"]["common_name"].as_str() {
        out.push_str(&format!("Subject: CN={cn}\n"));
    }
    if let Some(sans) = v["sans"].as_array().filter(|a| !a.is_empty()) {
        out.push_str(&format!(
            "SANs: {}\n",
            sans.iter().map(s).collect::<Vec<_>>().join(", ")
        ));
    }
    if v["validity"].is_object() {
        out.push_str(&format!(
            "Validity: {} to {}\n",
            s(&v["validity"]["not_before"]),
            s(&v["validity"]["not_after"])
        ));
    }
    out.push_str(&format!(
        "Key: {} ({}, {})\n",
        s(&v["key"]["stored_at"]),
        s(&v["key"]["key_format"]),
        if v["key"]["encrypted"] == true {
            "encrypted"
        } else {
            "not encrypted"
        }
    ));
    if v["certificate"].is_object() {
        out.push_str(&format!(
            "Certificate: {}\n  Serial: {}\n  SHA256: {}\n",
            s(&v["certificate"]["stored_at"]),
            s(&v["certificate"]["serial_number"]),
            s(&v["certificate"]["fingerprints"]["sha256"])
        ));
    }
    if v["csr"].is_object() {
        out.push_str(&format!("CSR: {}\n", s(&v["csr"]["stored_at"])));
    }
    warnings_text(&mut out, &v["warnings"]);
    out
}

// ---------------------------------------------------------------------------
// csr.create
// ---------------------------------------------------------------------------

/// DER of a keyUsage extension value.
fn key_usage_ext(usages: &[CertKeyUsage]) -> CResult<rcgen::CustomExtension> {
    use der::Encode;
    use x509_cert::ext::pkix::{KeyUsage as Ku, KeyUsages as K};
    let mut flags = der::flagset::FlagSet::<K>::default();
    for u in usages {
        flags |= match u {
            CertKeyUsage::DigitalSignature => K::DigitalSignature,
            CertKeyUsage::ContentCommitment => K::NonRepudiation,
            CertKeyUsage::KeyEncipherment => K::KeyEncipherment,
            CertKeyUsage::DataEncipherment => K::DataEncipherment,
            CertKeyUsage::KeyAgreement => K::KeyAgreement,
            CertKeyUsage::KeyCertSign => K::KeyCertSign,
            CertKeyUsage::CrlSign => K::CRLSign,
            CertKeyUsage::EncipherOnly => K::EncipherOnly,
            CertKeyUsage::DecipherOnly => K::DecipherOnly,
        };
    }
    let der = Ku(flags).to_der().map_err(|e| {
        CertError::failed(
            "cert.generation_failed",
            format!("cannot encode key usage: {e}"),
        )
    })?;
    let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 15], der);
    ext.set_criticality(true);
    Ok(ext)
}

/// DER of an extKeyUsage extension value.
fn extended_key_usage_ext(usages: &[CertExtendedKeyUsage]) -> CResult<rcgen::CustomExtension> {
    use der::Encode;
    use x509_cert::ext::pkix::ExtendedKeyUsage as Eku;
    let oid = |s: &str| der::asn1::ObjectIdentifier::new_unwrap(s);
    let oids = usages
        .iter()
        .map(|u| match u {
            CertExtendedKeyUsage::ServerAuth => oid("1.3.6.1.5.5.7.3.1"),
            CertExtendedKeyUsage::ClientAuth => oid("1.3.6.1.5.5.7.3.2"),
            CertExtendedKeyUsage::CodeSigning => oid("1.3.6.1.5.5.7.3.3"),
            CertExtendedKeyUsage::EmailProtection => oid("1.3.6.1.5.5.7.3.4"),
            CertExtendedKeyUsage::TimeStamping => oid("1.3.6.1.5.5.7.3.8"),
            CertExtendedKeyUsage::OcspSigning => oid("1.3.6.1.5.5.7.3.9"),
        })
        .collect();
    let der = Eku(oids).to_der().map_err(|e| {
        CertError::failed(
            "cert.generation_failed",
            format!("cannot encode extended key usage: {e}"),
        )
    })?;
    Ok(rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        der,
    ))
}

/// A CSR (DER) for `key_pair` with the subject, SANs and requested key
/// usage and extended key usage.
fn build_csr(
    key_pair: &KeyPair,
    subject: &CertSubject,
    sans: &[String],
    ku: &[CertKeyUsage],
    eku: &[CertExtendedKeyUsage],
) -> CResult<Vec<u8>> {
    let failed = |e: &dyn std::fmt::Display| {
        CertError::failed(
            "cert.generation_failed",
            format!("cannot build the CSR: {e:#}"),
        )
    };
    let mut params = CertificateParams::new(vec![]);
    params.distinguished_name = build_distinguished_name(subject).map_err(|e| failed(&e))?;
    params.subject_alt_names = parse_san_list(sans).map_err(|e| failed(&e))?;
    if !ku.is_empty() {
        params.custom_extensions.push(key_usage_ext(ku)?);
    }
    if !eku.is_empty() {
        params.custom_extensions.push(extended_key_usage_ext(eku)?);
    }
    params.alg = key_pair.algorithm();
    params.key_pair = Some(KeyPair::from_der(&key_pair.serialize_der()).map_err(|e| failed(&e))?);
    Certificate::from_params(params)
        .and_then(|c| c.serialize_request_der())
        .map_err(|e| failed(&e))
}

impl CertHandle {
    fn run_csr_create(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        let subject = subject_opt(r, "subject")?;
        require_common_name("subject", &subject, "for csr.create")?;
        let subject = subject.unwrap_or_default();
        let generate = r
            .choice("key_strategy", &["reuse", "generate"])?
            .unwrap_or("reuse")
            == "generate";
        let gen_only: &[&str] = &[
            "new_key_output_path",
            "new_key_passphrase",
            "rsa_bits",
            "ecdsa_curve",
            "key_format",
            "key_encoding",
            "key_kdf",
            "key_kdf_iterations",
            "include_new_key_pem",
        ];
        let algorithm = algorithm_opt(r)?;
        let mut gen_opts = None;
        if generate {
            r.refuse(
                &["existing_key_path", "existing_key_passphrase"],
                "with key_strategy=generate",
            )?;
            r.require("new_key_output_path", "with key_strategy=generate")?;
            let alg = algorithm.clone().unwrap_or(CertAlgorithm::Rsa);
            let (bits, curve) = key_size_opts(r, &alg)?;
            let format = key_format_opt(r, &alg)?;
            let encoding = encoding_opt(r, "key_encoding")?;
            let enc = key_encryption_opts(r, "new_key_passphrase", &format)?;
            gen_opts = Some((alg, bits, curve, format, encoding, enc));
        } else {
            r.refuse(gen_only, "with key_strategy=reuse")?;
            r.require("existing_key_path", "with key_strategy=reuse (the default)")?;
        }
        let existing = r.text("existing_key_path")?;
        let existing_pass = r.passphrase("existing_key_passphrase")?;
        let new_key_path = r.text("new_key_output_path")?;
        let csr_encoding = encoding_opt(r, "csr_encoding")?;
        let sans = sans_opt(r, "sans")?.unwrap_or_default();
        let ku = args::key_usages(r, "key_usage")?.unwrap_or_default();
        let eku = args::extended_key_usages(r, "extended_key_usage")?.unwrap_or_default();
        let include_csr = r.flag("include_csr_pem", false)?;
        let include_key = r.flag("include_new_key_pem", false)?;
        let overwrite = r.flag("overwrite", false)?;
        let timeout = r.timeout()?;

        let mut outputs = vec![self.target_path.as_str()];
        if let Some(p) = &new_key_path {
            if fileio::plain_path(p) == fileio::plain_path(&self.target_path) {
                return Err(CertError::usage(
                    "new_key_output_path must differ from the CSR path",
                ));
            }
            outputs.push(p);
        }
        fileio::check_outputs(&outputs, overwrite)?;

        let mut warnings: Vec<String> = Vec::new();
        let loaded = match &existing {
            Some(path) => {
                let k = keys::load_key(
                    "existing key",
                    path,
                    existing_pass.as_deref(),
                    "existing_key_passphrase",
                )?;
                if let Some(a) = &algorithm {
                    let want = format!("{a:?}").to_lowercase();
                    if want != k.algorithm {
                        return Err(CertError::failed(
                            "cert.keypair_mismatch",
                            format!(
                                "algorithm={want} was given, but {path} is a {} key",
                                k.describe()
                            ),
                        ));
                    }
                }
                warnings.extend(k.warning.clone());
                Some(k)
            }
            None => None,
        };

        let this = self.clone();
        let value = fileio::run_with_deadline(timeout, move |gate| {
            let (key_pair, key_info, key_bytes) = match (&loaded, &gen_opts) {
                (Some(k), _) => (
                    k.key_pair()?,
                    json!({
                        "reused": true,
                        "algorithm": k.algorithm,
                        "rsa_bits": k.rsa_bits,
                        "ecdsa_curve": k.curve,
                        "path": existing,
                        "encoding": k.encoding,
                        "key_format": k.format,
                        "encrypted": k.encrypted,
                    }),
                    None,
                ),
                (None, Some((alg, bits, curve, format, encoding, enc))) => {
                    let kp = keys::generate_key(alg, *bits, curve)?;
                    let bytes = keys::encode_key(
                        &kp,
                        alg,
                        format,
                        encoding,
                        enc.as_ref().map(|(p, i)| (p.as_str(), *i)),
                    )?;
                    let info = json!({
                        "reused": false,
                        "algorithm": format!("{alg:?}").to_lowercase(),
                        "rsa_bits": matches!(alg, CertAlgorithm::Rsa).then_some(*bits),
                        "ecdsa_curve": matches!(alg, CertAlgorithm::Ecdsa).then(|| match curve {
                            EcdsaCurve::P256 => "P-256",
                            EcdsaCurve::P384 => "P-384",
                        }),
                        "path": new_key_path,
                        "encoding": format!("{encoding:?}").to_lowercase(),
                        "key_format": format!("{format:?}").to_lowercase(),
                        "encrypted": enc.is_some(),
                    });
                    (kp, info, Some((bytes, matches!(encoding, Encoding::Pem))))
                }
                (None, None) => unreachable!("reuse needs existing_key_path"),
            };
            let csr_der = build_csr(&key_pair, &subject, &sans, &ku, &eku)?;
            let csr_pem = pem_encode_lf(&Pem::new("CERTIFICATE REQUEST", csr_der.clone()));
            let csr_bytes = match csr_encoding {
                Encoding::Pem => csr_pem.clone().into_bytes(),
                Encoding::Der => csr_der.clone(),
            };
            let mut files: Vec<(&str, &[u8], bool)> =
                vec![(this.target_path.as_str(), &csr_bytes, false)];
            if let (Some(p), Some((bytes, _))) = (&new_key_path, &key_bytes) {
                files.push((p, bytes, true));
            }
            gate.commit()?;
            write_outputs(&files, overwrite)?;
            let desc = describe_csr(&csr_der)
                .map_err(|e| CertError::failed("cert.generation_failed", format!("{e:#}")))?;
            Ok(json!({
                "ok": true,
                "csr_target": this.target_path,
                "csr": {
                    "path": this.target_path,
                    "encoding": format!("{csr_encoding:?}").to_lowercase(),
                    "subject": desc.subject,
                    "sans": desc.sans,
                    "key_usage": ku.iter().map(key_usage_name).collect::<Vec<_>>(),
                    "extended_key_usage": eku.iter().map(eku_name).collect::<Vec<_>>(),
                    "fingerprints": { "sha256": fingerprint("sha256", &csr_der) },
                },
                "key_strategy": if loaded.is_some() { "reuse" } else { "generate" },
                "key": key_info,
                "returned": {
                    "csr_pem": (include_csr && matches!(csr_encoding, Encoding::Pem)).then_some(&csr_pem),
                    "csr_der_base64": (include_csr && matches!(csr_encoding, Encoding::Der))
                        .then(|| BASE64_STANDARD.encode(&csr_der)),
                    "new_key_pem": key_bytes.as_ref().filter(|(_, pem)| include_key && *pem)
                        .map(|(b, _)| String::from_utf8_lossy(b).into_owned()),
                    "new_key_der_base64": key_bytes.as_ref().filter(|(_, pem)| include_key && !*pem)
                        .map(|(b, _)| BASE64_STANDARD.encode(b)),
                },
                "warnings": warnings,
            }))
        })?;
        Done::ok(json, value, csr_create_text)
    }
}

fn key_usage_name(k: &CertKeyUsage) -> &'static str {
    match k {
        CertKeyUsage::DigitalSignature => "digitalSignature",
        CertKeyUsage::ContentCommitment => "contentCommitment",
        CertKeyUsage::KeyEncipherment => "keyEncipherment",
        CertKeyUsage::DataEncipherment => "dataEncipherment",
        CertKeyUsage::KeyAgreement => "keyAgreement",
        CertKeyUsage::KeyCertSign => "keyCertSign",
        CertKeyUsage::CrlSign => "cRLSign",
        CertKeyUsage::EncipherOnly => "encipherOnly",
        CertKeyUsage::DecipherOnly => "decipherOnly",
    }
}

fn eku_name(e: &CertExtendedKeyUsage) -> &'static str {
    match e {
        CertExtendedKeyUsage::ServerAuth => "serverAuth",
        CertExtendedKeyUsage::ClientAuth => "clientAuth",
        CertExtendedKeyUsage::CodeSigning => "codeSigning",
        CertExtendedKeyUsage::EmailProtection => "emailProtection",
        CertExtendedKeyUsage::TimeStamping => "timeStamping",
        CertExtendedKeyUsage::OcspSigning => "ocspSigning",
    }
}

fn csr_create_text(v: &Value) -> String {
    let mut out = format!(
        "CSR: {} ({})\nSubject: {}\n",
        s(&v["csr"]["path"]),
        s(&v["csr"]["encoding"]),
        s(&v["csr"]["subject"]["raw_dn"])
    );
    for (label, k) in [
        ("SANs", "sans"),
        ("Key Usage", "key_usage"),
        ("Extended Key Usage", "extended_key_usage"),
    ] {
        if let Some(a) = v["csr"][k].as_array().filter(|a| !a.is_empty()) {
            out.push_str(&format!(
                "{label}: {}\n",
                a.iter().map(s).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    out.push_str(&format!(
        "SHA256: {}\nKey strategy: {}\nKey: {} ({} {}, {})\n",
        s(&v["csr"]["fingerprints"]["sha256"]),
        s(&v["key_strategy"]),
        s(&v["key"]["path"]),
        s(&v["key"]["algorithm"]),
        s(&v["key"]["key_format"]),
        if v["key"]["encrypted"] == true {
            "encrypted"
        } else {
            "not encrypted"
        }
    ));
    warnings_text(&mut out, &v["warnings"]);
    out
}

// ---------------------------------------------------------------------------
// Issuing from a CSR (sign mode=csr and csr.sign)
// ---------------------------------------------------------------------------

/// What a CSR asks for.
struct CsrRequest {
    dn: rcgen::DistinguishedName,
    sans: Vec<rcgen::SanType>,
    key_usage: Vec<CertKeyUsage>,
    extended_key_usage: Vec<CertExtendedKeyUsage>,
    public_key: Vec<u8>,
    alg: &'static rcgen::SignatureAlgorithm,
    ignored: Vec<String>,
}

fn dn_from_name(name: &X509Name) -> CResult<rcgen::DistinguishedName> {
    use x509_parser::der_parser::asn1_rs::Tag;
    let bad = || CertError::failed("cert.csr_invalid", "unsupported subject name in the CSR");
    let mut dn = rcgen::DistinguishedName::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid: Vec<u64> = attr.attr_type().iter().ok_or_else(bad)?.collect();
            let data = attr.attr_value().data;
            let text = || {
                std::str::from_utf8(data)
                    .map(str::to_string)
                    .map_err(|_| bad())
            };
            let value = match attr.attr_value().header.tag() {
                Tag::PrintableString => rcgen::DnValue::PrintableString(text()?),
                Tag::Utf8String => rcgen::DnValue::Utf8String(text()?),
                Tag::Ia5String => rcgen::DnValue::Ia5String(text()?),
                Tag::BmpString => rcgen::DnValue::BmpString(data.to_vec()),
                Tag::T61String => rcgen::DnValue::TeletexString(data.to_vec()),
                Tag::UniversalString => rcgen::DnValue::UniversalString(data.to_vec()),
                _ => return Err(bad()),
            };
            dn.push(rcgen::DnType::from_oid(&oid), value);
        }
    }
    Ok(dn)
}

fn read_csr_request(csr_der: &[u8]) -> CResult<CsrRequest> {
    use x509_parser::certification_request::X509CertificationRequest;
    let invalid = |m: String| CertError::failed("cert.csr_invalid", m);
    let (_, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("cannot parse the CSR: {e}")))?;
    let info = &csr.certification_request_info;
    match verify_signature_with_key(
        &csr.signature_algorithm.algorithm.to_id_string(),
        &info.subject_pki,
        info.raw,
        &csr.signature_value.data,
    ) {
        SignatureCheck::Valid => {}
        SignatureCheck::Invalid => {
            return Err(invalid("the CSR signature does not verify".into()));
        }
        SignatureCheck::Unsupported(m) => {
            return Err(invalid(format!("the CSR signature cannot be checked: {m}")));
        }
    }
    let mut req = CsrRequest {
        dn: dn_from_name(&info.subject)?,
        sans: Vec::new(),
        key_usage: Vec::new(),
        extended_key_usage: Vec::new(),
        public_key: spki_key_bytes(&info.subject_pki).to_vec(),
        alg: rcgen_alg_for_key(&describe_spki(&info.subject_pki))
            .map_err(|e| invalid(format!("{e:#}")))?,
        ignored: Vec::new(),
    };
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            match ext {
                ParsedExtension::SubjectAlternativeName(san) => {
                    for gn in &san.general_names {
                        req.sans.push(match gn {
                            GeneralName::DNSName(d) => rcgen::SanType::DnsName(d.to_string()),
                            GeneralName::RFC822Name(m) => rcgen::SanType::Rfc822Name(m.to_string()),
                            GeneralName::URI(u) => rcgen::SanType::URI(u.to_string()),
                            GeneralName::IPAddress(b) => match b.len() {
                                4 => rcgen::SanType::IpAddress(std::net::IpAddr::from(
                                    <[u8; 4]>::try_from(*b)
                                        .map_err(|_| invalid("bad IP SAN".into()))?,
                                )),
                                16 => rcgen::SanType::IpAddress(std::net::IpAddr::from(
                                    <[u8; 16]>::try_from(*b)
                                        .map_err(|_| invalid("bad IP SAN".into()))?,
                                )),
                                _ => return Err(invalid("bad IP SAN in the CSR".into())),
                            },
                            other => {
                                req.ignored.push(format!("subjectAltName {other:?}"));
                                continue;
                            }
                        });
                    }
                }
                ParsedExtension::KeyUsage(k) => {
                    for (set, u) in [
                        (k.digital_signature(), CertKeyUsage::DigitalSignature),
                        (k.non_repudiation(), CertKeyUsage::ContentCommitment),
                        (k.key_encipherment(), CertKeyUsage::KeyEncipherment),
                        (k.data_encipherment(), CertKeyUsage::DataEncipherment),
                        (k.key_agreement(), CertKeyUsage::KeyAgreement),
                        (k.key_cert_sign(), CertKeyUsage::KeyCertSign),
                        (k.crl_sign(), CertKeyUsage::CrlSign),
                        (k.encipher_only(), CertKeyUsage::EncipherOnly),
                        (k.decipher_only(), CertKeyUsage::DecipherOnly),
                    ] {
                        if set {
                            req.key_usage.push(u);
                        }
                    }
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    for (set, u) in [
                        (e.server_auth, CertExtendedKeyUsage::ServerAuth),
                        (e.client_auth, CertExtendedKeyUsage::ClientAuth),
                        (e.code_signing, CertExtendedKeyUsage::CodeSigning),
                        (e.email_protection, CertExtendedKeyUsage::EmailProtection),
                        (e.time_stamping, CertExtendedKeyUsage::TimeStamping),
                        (e.ocsp_signing, CertExtendedKeyUsage::OcspSigning),
                    ] {
                        if set {
                            req.extended_key_usage.push(u);
                        }
                    }
                }
                other => req
                    .ignored
                    .push(format!("{other:?}").chars().take(60).collect()),
            }
        }
    }
    Ok(req)
}

/// The certificate settings for an issue from a CSR.
struct IssueSettings {
    subject_override: Option<CertSubject>,
    copy_subject: bool,
    sans_override: Option<Vec<String>>,
    copy_sans: bool,
    key_usage: Option<Vec<CertKeyUsage>>,
    copy_key_usage: bool,
    extended_key_usage: Option<Vec<CertExtendedKeyUsage>>,
    copy_extended_key_usage: bool,
    not_before: NotBeforeSetting,
    not_after: Option<DateTime<Utc>>,
    not_after_offset_days: i64,
    is_ca: bool,
    path_len: Option<u8>,
    serial: Option<Vec<u8>>,
}

/// Issues a certificate for the CSR, signed by `ca`. Returns the DER and
/// warnings about requested extensions that were not copied.
fn issue_for_csr(
    csr_der: &[u8],
    st: &IssueSettings,
    ca: &CaSigner,
) -> CResult<(Vec<u8>, Vec<String>)> {
    let req = read_csr_request(csr_der)?;
    let failed =
        |e: &dyn std::fmt::Display| CertError::failed("cert.sign_failed", format!("{e:#}"));
    let mut warnings: Vec<String> = req
        .ignored
        .iter()
        .map(|x| format!("Requested extension not copied: {x}"))
        .collect();
    let remote = PublicKeyOnly {
        raw: req.public_key.clone(),
        alg: req.alg,
    };
    let key_pair = KeyPair::from_remote(Box::new(remote)).map_err(|e| failed(&e))?;
    let mut p = CertificateParams::new(vec![]);
    p.alg = req.alg;
    p.key_pair = Some(key_pair);
    p.distinguished_name = match (&st.subject_override, st.copy_subject) {
        (Some(sub), true) => {
            let mut dn = req.dn.clone();
            let fields: [(rcgen::DnType, Vec<String>); 6] = [
                (
                    rcgen::DnType::CommonName,
                    sub.common_name.iter().cloned().collect(),
                ),
                (rcgen::DnType::OrganizationName, sub.organization.clone()),
                (
                    rcgen::DnType::OrganizationalUnitName,
                    sub.organizational_unit.clone(),
                ),
                (rcgen::DnType::CountryName, sub.country.clone()),
                (
                    rcgen::DnType::StateOrProvinceName,
                    sub.state_or_province.clone(),
                ),
                (rcgen::DnType::LocalityName, sub.locality.clone()),
            ];
            for (ty, values) in fields {
                for v in values {
                    dn.remove(ty.clone());
                    dn.push(ty.clone(), v);
                }
            }
            dn
        }
        (Some(sub), false) => build_distinguished_name(sub).map_err(|e| failed(&e))?,
        (None, _) => req.dn.clone(),
    };
    p.subject_alt_names = match (&st.sans_override, st.copy_sans) {
        (Some(s), _) => parse_san_list(s).map_err(|e| failed(&e))?,
        (None, true) => req.sans.clone(),
        (None, false) => Vec::new(),
    };
    let ku = match (&st.key_usage, st.copy_key_usage) {
        (Some(k), _) => k.clone(),
        (None, true) => req.key_usage.clone(),
        (None, false) => Vec::new(),
    };
    if st.key_usage.is_some() && !req.key_usage.is_empty() && !st.copy_key_usage {
        let names = |v: &[CertKeyUsage]| {
            let mut n: Vec<&str> = v.iter().map(key_usage_name).collect();
            n.sort();
            n
        };
        if names(&ku) != names(&req.key_usage) {
            warnings.push(format!(
                "The key usage requested in the CSR ({}) was replaced by {}",
                names(&req.key_usage).join(", "),
                names(&ku).join(", ")
            ));
        }
    }
    if st.extended_key_usage.is_some()
        && !req.extended_key_usage.is_empty()
        && !st.copy_extended_key_usage
    {
        let names = |v: &[CertExtendedKeyUsage]| {
            let mut n: Vec<&str> = v.iter().map(eku_name).collect();
            n.sort();
            n
        };
        let wanted: Vec<CertExtendedKeyUsage> = st.extended_key_usage.clone().unwrap_or_default();
        if names(&wanted) != names(&req.extended_key_usage) {
            warnings.push(format!(
                "The extended key usage requested in the CSR ({}) was replaced by {}",
                names(&req.extended_key_usage).join(", "),
                names(&wanted).join(", ")
            ));
        }
    }
    p.key_usages = ku.iter().map(rcgen_key_usage).collect();
    let eku = match (&st.extended_key_usage, st.copy_extended_key_usage) {
        (Some(k), _) => k.clone(),
        (None, true) => req.extended_key_usage.clone(),
        (None, false) => Vec::new(),
    };
    p.extended_key_usages = eku.iter().map(rcgen_extended_key_usage).collect();
    let (start, end) = validity_window(&st.not_before, st.not_after, st.not_after_offset_days)
        .map_err(|e| CertError::usage(format!("{e:#}")))?;
    p.not_before = to_offset_datetime(start).map_err(|e| failed(&e))?;
    p.not_after = to_offset_datetime(end).map_err(|e| failed(&e))?;
    p.serial_number = Some(match &st.serial {
        Some(b) => rcgen::SerialNumber::from(b.clone()),
        None => random_serial(),
    });
    p.is_ca = if st.is_ca {
        IsCa::Ca(match st.path_len {
            Some(n) => BasicConstraints::Constrained(n),
            None => BasicConstraints::Unconstrained,
        })
    } else {
        IsCa::ExplicitNoCa
    };
    p.use_authority_key_identifier_extension = true;
    let der = Certificate::from_params(p)
        .and_then(|c| c.serialize_der_with_signer(&ca.cert))
        .map_err(|e| failed(&e))?;
    Ok((der, warnings))
}

fn csr_from_file(source: &str, hint: &str) -> CResult<(Vec<u8>, &'static str)> {
    let data = read_input("CSR", source)?;
    let h = match hint {
        "pem" => EncodingHint::Pem,
        "der" => EncodingHint::Der,
        _ => EncodingHint::Auto,
    };
    csr_der_from_bytes(&data, &h)
        .map_err(|e| CertError::failed("cert.csr_invalid", format!("{source}: {e:#}")))
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

impl CertHandle {
    fn run_sign(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        let csr_mode = r.choice("mode", &["data", "csr"])?.unwrap_or("data") == "csr";
        let allowed = args::expand(if csr_mode {
            args::SIGN_CSR_ARGS
        } else {
            args::SIGN_DATA_ARGS
        });
        let mode_name = if csr_mode { "mode=csr" } else { "mode=data" };
        for k in r.args.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(CertError::usage(format!(
                    "{k} is not used with {mode_name}; remove it"
                )));
            }
        }
        r.require("signer_key", "")?;
        let signer_key_path = r.text("signer_key")?.unwrap_or_default();
        let pass = r.passphrase("signer_key_passphrase")?;
        let overwrite = r.flag("overwrite", false)?;
        let timeout = r.timeout()?;
        if csr_mode {
            self.sign_csr_mode(r, json, signer_key_path, pass, overwrite, timeout)
        } else {
            self.sign_data_mode(r, json, signer_key_path, pass, overwrite, timeout)
        }
    }

    fn sign_data_mode(
        &self,
        r: &Reader,
        json: bool,
        signer_key_path: String,
        pass: Option<String>,
        overwrite: bool,
        timeout: std::time::Duration,
    ) -> CResult<Done> {
        let source = r.text("data_source")?;
        let inline = match r.raw("data_bytes_base64")? {
            Some(b) => Some(BASE64_STANDARD.decode(b.trim()).map_err(|e| {
                CertError::usage(format!("data_bytes_base64 is not valid base64: {e}"))
            })?),
            None => None,
        };
        match (&source, &inline) {
            (None, None) => {
                return Err(CertError::usage(
                    "give the data to sign: data_source=<path> or data_bytes_base64=<base64>",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(CertError::usage(
                    "give data_source or data_bytes_base64, not both",
                ));
            }
            _ => {}
        }
        let algorithm = r
            .choice(
                "signature_algorithm",
                &[
                    "rsa_pss_sha256",
                    "rsa_pss_sha384",
                    "rsa_pkcs1_sha256",
                    "rsa_pkcs1_sha384",
                    "ecdsa_sha256",
                    "ecdsa_sha384",
                    "ecdsa_sha512",
                    "ed25519",
                ],
            )?
            .map(|a| match a {
                "rsa_pss_sha256" => SignatureAlgorithm::RsaPssSha256,
                "rsa_pss_sha384" => SignatureAlgorithm::RsaPssSha384,
                "rsa_pkcs1_sha256" => SignatureAlgorithm::RsaPkcs1Sha256,
                "rsa_pkcs1_sha384" => SignatureAlgorithm::RsaPkcs1Sha384,
                "ecdsa_sha256" => SignatureAlgorithm::EcdsaSha256,
                "ecdsa_sha384" => SignatureAlgorithm::EcdsaSha384,
                "ecdsa_sha512" => SignatureAlgorithm::EcdsaSha512,
                _ => SignatureAlgorithm::Ed25519,
            });
        let format = match r
            .choice("signature_format", &["raw", "cms_detached", "cms_attached"])?
            .unwrap_or("raw")
        {
            "cms_detached" => SignatureFormat::CmsDetached,
            "cms_attached" => SignatureFormat::CmsAttached,
            _ => SignatureFormat::Raw,
        };
        let encoding = match r
            .choice("signature_encoding", &["base64", "pem", "der"])?
            .unwrap_or("base64")
        {
            "pem" => SignatureEncoding::Pem,
            "der" => SignatureEncoding::Der,
            _ => SignatureEncoding::Base64,
        };
        let signer_cert_path = r.text("signer_cert")?;
        let cms = !matches!(format, SignatureFormat::Raw);
        if cms && signer_cert_path.is_none() {
            return Err(CertError::usage(
                "signature_format=cms_detached|cms_attached needs signer_cert (the certificate \
                 of signer_key)",
            ));
        }
        if !cms && signer_cert_path.is_some() {
            return Err(CertError::usage(
                "signer_cert is only used with signature_format=cms_detached|cms_attached; \
                 remove it",
            ));
        }
        let output = r.text("signature_output_path")?;
        if output.is_none() && r.has("overwrite") {
            return Err(CertError::usage(
                "overwrite is only used with signature_output_path; remove it",
            ));
        }
        let include = r.flag("include_signature_bytes", false)?;
        if let Some(o) = &output {
            fileio::check_outputs(&[o], overwrite)?;
        }

        let key = load_signer_key(pass.as_deref(), &signer_key_path)?;
        let mut warnings: Vec<String> = key.warning.iter().cloned().collect();
        let signer = key.signer()?;
        let algorithm = match algorithm {
            Some(a) => a,
            None => self
                .default_signature_algorithm(&signer)
                .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?,
        };
        let cert = match &signer_cert_path {
            Some(path) => {
                let data = read_input("signer certificate", path)
                    .map_err(|e| CertError::failed("cert.signer_load_failed", e.message))?;
                let c = parse_cms_signer_cert(&data, path)
                    .map_err(|e| CertError::failed("cert.signer_load_failed", format!("{e:#}")))?;
                if !signer_key_matches_cert(&signer, &c) {
                    return Err(CertError::failed(
                        "cert.keypair_mismatch",
                        format!(
                            "signer_key {signer_key_path} does not match the public key of \
                             signer_cert {path}"
                        ),
                    ));
                }
                Some(c)
            }
            None => None,
        };
        if output.is_none() && !include {
            warnings.push(
                "Signature not kept (no signature_output_path, include_signature_bytes)"
                    .to_string(),
            );
        }

        let this = self.clone();
        let target = self.target_path.clone();
        let value = fileio::run_with_deadline(timeout, move |gate| {
            let data = match (&source, inline) {
                (Some(src), _) => this.read_data(src)?,
                (None, Some(d)) => d,
                (None, None) => Vec::new(),
            };
            let attached = match format {
                SignatureFormat::Raw => None,
                SignatureFormat::CmsDetached => Some(false),
                SignatureFormat::CmsAttached => Some(true),
            };
            let sig = match (attached, &cert) {
                (Some(att), Some(c)) => {
                    this.create_cms_signature(&data, &signer, &algorithm, c, att)
                }
                _ => this.create_signature(&data, &signer, &algorithm),
            }
            .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
            let label = if attached.is_some() {
                "CMS"
            } else {
                "SIGNATURE"
            };
            let encoded = this
                .encode_signature(&sig, &encoding, label)
                .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
            gate.commit()?;
            if let Some(o) = &output {
                write_outputs(&[(o, &encoded, false)], overwrite)?;
            }
            Ok(json!({
                "ok": true,
                "mode": "data",
                "signer": target,
                "signer_key": signer_key_path,
                "signer_cert": signer_cert_path,
                "algorithm": format!("{algorithm:?}"),
                "signature_format": format!("{format:?}"),
                "signature_encoding": format!("{encoding:?}"),
                "data": {
                    "source": source.clone().unwrap_or_else(|| "base64".to_string()),
                    "length_bytes": data.len(),
                },
                "signature": {
                    "stored_at": output,
                    "bytes_base64": include.then(|| BASE64_STANDARD.encode(&sig)),
                },
                "csr_source": null,
                "csr_subject": null,
                "cert": null,
                "cert_pem": null,
                "warnings": warnings,
            }))
        })?;
        Done::ok(json, value, sign_text)
    }

    /// Reads the data to sign (any size; the deadline bounds the time).
    fn read_data(&self, source: &str) -> CResult<Vec<u8>> {
        if let Some(text) = source.strip_prefix("string:") {
            return Ok(text.as_bytes().to_vec());
        }
        let path = fileio::plain_path(source);
        std::fs::read(path).map_err(|e| super::errors::read_error("data_source", path, &e))
    }

    fn sign_csr_mode(
        &self,
        r: &Reader,
        json: bool,
        signer_key_path: String,
        pass: Option<String>,
        overwrite: bool,
        timeout: std::time::Duration,
    ) -> CResult<Done> {
        r.require("csr_source", "with mode=csr")?;
        r.require("signer_cert", "with mode=csr (the CA certificate)")?;
        r.require("cert_output_path", "with mode=csr")?;
        let csr_source = r.text("csr_source")?.unwrap_or_default();
        let csr_encoding = r
            .choice("csr_encoding", &["auto", "pem", "der"])?
            .unwrap_or("auto");
        let signer_cert = r.text("signer_cert")?.unwrap_or_default();
        let output = r.text("cert_output_path")?.unwrap_or_default();
        let cert_encoding = encoding_opt(r, "cert_encoding")?;
        let (not_before, _, not_after, offset) = validity_opts(r, false)?;
        let (is_ca, path_len) = ca_opts(r)?;
        let ku = args::key_usages(r, "key_usage")?
            .unwrap_or_else(|| vec![CertKeyUsage::DigitalSignature]);
        let eku = args::extended_key_usages(r, "extended_key_usage")?
            .unwrap_or_else(|| vec![CertExtendedKeyUsage::ServerAuth]);
        let sans = sans_opt(r, "sans_override")?;
        let include = r.flag("include_cert_pem", false)?;
        fileio::check_outputs(&[&output], overwrite)?;

        let key = load_signer_key(pass.as_deref(), &signer_key_path)?;
        let ca = signer_ca_of(&signer_cert, &key)?;
        let (csr_der, csr_enc) = csr_from_file(&csr_source, csr_encoding)?;
        let settings = IssueSettings {
            subject_override: None,
            copy_subject: true,
            sans_override: sans,
            copy_sans: true,
            key_usage: Some(ku),
            copy_key_usage: false,
            extended_key_usage: Some(eku),
            copy_extended_key_usage: false,
            not_before,
            not_after,
            not_after_offset_days: offset,
            is_ca: is_ca.unwrap_or(false),
            path_len,
            serial: None,
        };
        let mut warnings: Vec<String> = key.warning.iter().cloned().collect();
        let (der, w) = issue_for_csr(&csr_der, &settings, &ca)?;
        warnings.extend(w);
        let summary = summarize_cert_der(&der)
            .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
        let csr = describe_csr(&csr_der)
            .map_err(|e| CertError::failed("cert.csr_invalid", format!("{e:#}")))?;
        let bytes = encode_cert_der(&der, &cert_encoding);
        let target = self.target_path.clone();
        let value = fileio::run_with_deadline(timeout, move |gate| {
            gate.commit()?;
            write_outputs(&[(&output, &bytes, false)], overwrite)?;
            Ok(json!({
                "ok": true,
                "mode": "csr",
                "signer": target,
                "signer_key": signer_key_path,
                "signer_cert": signer_cert,
                "algorithm": X509Certificate::from_der(&der)
                    .map(|(_, c)| signature_algorithm_name(&c.signature_algorithm.algorithm.to_id_string()))
                    .unwrap_or("unknown"),
                "signature_format": null,
                "signature_encoding": null,
                "data": null,
                "signature": null,
                "csr_source": csr_source,
                "csr_encoding": csr_enc,
                "csr_subject": csr.subject,
                "cert": {
                    "stored_at": output,
                    "encoding": format!("{cert_encoding:?}").to_lowercase(),
                    "subject": summary.subject,
                    "issuer": summary.issuer,
                    "serial_number": summary.serial_hex,
                    "fingerprints": summary.fingerprints,
                    "validity": { "not_before": summary.not_before, "not_after": summary.not_after },
                    "is_ca": summary.is_ca,
                    "path_len": summary.path_len,
                    "sans": summary.sans,
                    "key_usage": summary.key_usage,
                    "extended_key_usage": summary.extended_key_usage,
                },
                "cert_pem": include.then(|| pem_encode_lf(&Pem::new("CERTIFICATE", der.clone()))),
                "warnings": warnings,
            }))
        })?;
        Done::ok(json, value, sign_text)
    }
}

fn sign_text(v: &Value) -> String {
    let mut out = format!(
        "Signer: {}\nMode: {}\nSigner Key: {}\n",
        s(&v["signer"]),
        s(&v["mode"]),
        s(&v["signer_key"])
    );
    if let Some(c) = v["signer_cert"].as_str() {
        out.push_str(&format!("Signer Cert: {c}\n"));
    }
    out.push_str(&format!("Algorithm: {}\n", s(&v["algorithm"])));
    if v["mode"] == "data" {
        out.push_str(&format!(
            "Format: {} ({})\nData: {} ({} bytes)\nSignature: {}\n",
            s(&v["signature_format"]),
            s(&v["signature_encoding"]),
            s(&v["data"]["source"]),
            v["data"]["length_bytes"],
            match v["signature"]["stored_at"].as_str() {
                Some(p) => format!("written to {p}"),
                None if v["signature"]["bytes_base64"].is_string() => {
                    "included in the JSON output".to_string()
                }
                None => "not kept".to_string(),
            }
        ));
    } else {
        let c = &v["cert"];
        out.push_str(&format!(
            "CSR: {}\nCertificate: {}\n  Subject: {}\n  Issuer: {}\n  Serial: {}\n  Validity: {} to {}\n  SHA256: {}\n",
            s(&v["csr_source"]),
            s(&c["stored_at"]),
            s(&c["subject"]["raw_dn"]),
            s(&c["issuer"]["raw_dn"]),
            s(&c["serial_number"]),
            s(&c["validity"]["not_before"]),
            s(&c["validity"]["not_after"]),
            s(&c["fingerprints"]["sha256"])
        ));
    }
    warnings_text(&mut out, &v["warnings"]);
    out
}

// ---------------------------------------------------------------------------
// csr.sign (programmatic; the stage parser reads cert://x.csr.sign as sign)
// ---------------------------------------------------------------------------

impl CertHandle {
    fn run_csr_sign(&self, r: &Reader) -> CResult<Done> {
        let json = format_json(r)?;
        for k in ["signer_ca", "signer_key", "cert_output_path"] {
            r.require(k, "for csr.sign")?;
        }
        let signer_ca = r.text("signer_ca")?.unwrap_or_default();
        let signer_key_path = r.text("signer_key")?.unwrap_or_default();
        let pass = r.passphrase("signer_key_passphrase")?;
        let output = r.text("cert_output_path")?.unwrap_or_default();
        let csr_encoding = r
            .choice("csr_encoding", &["auto", "pem", "der"])?
            .unwrap_or("auto");
        let cert_encoding = encoding_opt(r, "cert_encoding")?;
        let copy_subject = r.flag("copy_subject", true)?;
        let mut sub = CertSubject::default();
        let mut has_sub = false;
        if let Some(cn) = r.text("subject_common_name")? {
            sub.common_name = Some(cn);
            has_sub = true;
        }
        if let Some(o) = r.text("subject_organization")? {
            sub.organization = vec![o];
            has_sub = true;
        }
        if let Some(c) = r.text("subject_country")? {
            if c.len() != 2 {
                return Err(CertError::usage(
                    "subject_country must be a two-letter code",
                ));
            }
            sub.country = vec![c];
            has_sub = true;
        }
        if !copy_subject && !has_sub {
            return Err(CertError::usage(
                "copy_subject=false needs subject_common_name (or subject_organization, \
                 subject_country)",
            ));
        }
        let copy_sans = r.flag("copy_sans", true)?;
        let sans = sans_opt(r, "sans_override")?;
        let copy_ku = r.flag("copy_key_usage", true)?;
        let ku = args::key_usages(r, "key_usage_override")?;
        let copy_eku = r.flag("copy_extended_key_usage", true)?;
        let eku = args::extended_key_usages(r, "extended_key_usage_override")?;
        let (not_before, _, not_after, offset) = validity_opts(r, false)?;
        let (is_ca, path_len) = ca_opts(r)?;
        let strategy = r.choice("serial_strategy", &["random", "uuid", "increment"])?;
        if strategy == Some("increment") {
            return Err(CertError::usage(
                "serial_strategy=increment is not supported (there is no serial number store); \
                 use random, uuid or serial_override",
            ));
        }
        let serial = match r.text("serial_override")? {
            Some(hex_str) => {
                if strategy.is_some() {
                    return Err(CertError::usage(
                        "give serial_override or serial_strategy, not both",
                    ));
                }
                let bytes = hex::decode(hex_str.trim_start_matches("0x").replace(':', ""))
                    .ok()
                    .filter(|b| !b.is_empty() && b.len() <= 20 && b.iter().any(|x| *x != 0))
                    .ok_or_else(|| {
                        CertError::usage(format!(
                            "serial_override must be 1 to 20 bytes of hex, not zero: {hex_str:?}"
                        ))
                    })?;
                Some(bytes)
            }
            None if strategy == Some("uuid") => {
                // A positive 16-byte serial: the top bit is cleared and the
                // next set, so the encoding is always 16 bytes.
                let mut b = uuid::Uuid::new_v4().as_bytes().to_vec();
                b[0] = (b[0] & 0x7f) | 0x40;
                Some(b)
            }
            None => None,
        };
        let include = r.flag("include_cert_pem", false)?;
        let overwrite = r.flag("overwrite", false)?;
        fileio::check_outputs(&[&output], overwrite)?;

        let (csr_der, csr_enc) = csr_from_file(&self.target_path, csr_encoding)?;
        let key = load_signer_key(pass.as_deref(), &signer_key_path)?;
        let ca = signer_ca_of(&signer_ca, &key)?;
        let settings = IssueSettings {
            subject_override: has_sub.then_some(sub),
            copy_subject,
            sans_override: sans,
            copy_sans,
            key_usage: ku,
            copy_key_usage: copy_ku,
            extended_key_usage: eku,
            copy_extended_key_usage: copy_eku,
            not_before,
            not_after,
            not_after_offset_days: offset,
            is_ca: is_ca.unwrap_or(false),
            path_len,
            serial,
        };
        let mut warnings: Vec<String> = key.warning.iter().cloned().collect();
        let (der, w) = issue_for_csr(&csr_der, &settings, &ca)?;
        warnings.extend(w);
        let summary = summarize_cert_der(&der)
            .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
        let csr = describe_csr(&csr_der)
            .map_err(|e| CertError::failed("cert.csr_invalid", format!("{e:#}")))?;
        let bytes = encode_cert_der(&der, &cert_encoding);
        write_outputs(&[(&output, &bytes, false)], overwrite)?;
        let pem_out = matches!(cert_encoding, Encoding::Pem);
        let value = json!({
            "ok": true,
            "csr_target": self.target_path,
            "signer": { "signer_ca": signer_ca, "signer_key": signer_key_path },
            "csr": {
                "encoding": csr_enc,
                "subject": csr.subject,
                "sans": csr.sans,
                "public_key": {
                    "algorithm": csr.public_key.algorithm.to_uppercase(),
                    "rsa_bits": csr.public_key.bits.filter(|_| csr.public_key.algorithm == "rsa"),
                    "ecdsa_curve": csr.public_key.curve,
                },
            },
            "certificate": {
                "path": output,
                "encoding": format!("{cert_encoding:?}").to_lowercase(),
                "subject": summary.subject,
                "issuer": summary.issuer,
                "validity": { "not_before": summary.not_before, "not_after": summary.not_after },
                "is_ca": summary.is_ca,
                "path_len": summary.path_len,
                "serial_number": summary.serial_hex,
                "fingerprints": summary.fingerprints,
                "sans": summary.sans,
                "key_usage": summary.key_usage,
                "extended_key_usage": summary.extended_key_usage,
            },
            "returned": {
                "cert_pem": (include && pem_out).then(|| pem_encode_lf(&Pem::new("CERTIFICATE", der.clone()))),
                "cert_der_base64": (include && !pem_out).then(|| BASE64_STANDARD.encode(&der)),
            },
            "warnings": warnings,
        });
        Done::ok(json, value, |v| {
            let c = &v["certificate"];
            let mut out = format!(
                "CSR: {}\nCertificate: {}\n  Subject: {}\n  Issuer: {}\n  Serial: {}\n  Validity: {} to {}\n  SHA256: {}\n",
                s(&v["csr_target"]),
                s(&c["path"]),
                s(&c["subject"]["raw_dn"]),
                s(&c["issuer"]["raw_dn"]),
                s(&c["serial_number"]),
                s(&c["validity"]["not_before"]),
                s(&c["validity"]["not_after"]),
                s(&c["fingerprints"]["sha256"])
            );
            warnings_text(&mut out, &v["warnings"]);
            out
        })
    }
}

// ---------------------------------------------------------------------------
// renew
// ---------------------------------------------------------------------------

impl CertHandle {
    fn parse_renew(&self, r: &Reader) -> CResult<(CertRenewOptions, Option<(String, u32)>)> {
        let mut o = CertRenewOptions::default();
        o.format = if format_json(r)? {
            OutputFormat::Json
        } else {
            OutputFormat::Text
        };
        o.renewal_mode = match r
            .choice("renewal_mode", &["auto", "self_signed", "explicit_signer"])?
            .unwrap_or("auto")
        {
            "self_signed" => CertRenewalMode::SelfSigned,
            "explicit_signer" => CertRenewalMode::ExplicitSigner,
            _ => CertRenewalMode::Auto,
        };
        match o.renewal_mode {
            CertRenewalMode::SelfSigned => r.refuse(
                &["signer_ca", "signer_key", "signer_key_passphrase"],
                "with renewal_mode=self_signed",
            )?,
            CertRenewalMode::ExplicitSigner => {
                r.require("signer_ca", "with renewal_mode=explicit_signer")?;
                r.require("signer_key", "with renewal_mode=explicit_signer")?;
            }
            CertRenewalMode::Auto => {
                if r.has("signer_ca") != r.has("signer_key") {
                    return Err(CertError::usage("give signer_ca and signer_key together"));
                }
            }
        }
        if !r.has("signer_key") {
            r.refuse(&["signer_key_passphrase"], "without signer_key")?;
        }
        o.signer_ca = r.text("signer_ca")?;
        o.signer_key = r.text("signer_key")?;
        o.signer_key_passphrase = r.passphrase("signer_key_passphrase")?;
        o.key_strategy = match r
            .choice("key_strategy", &["reuse", "rekey"])?
            .unwrap_or("reuse")
        {
            "rekey" => KeyStrategy::Rekey,
            _ => KeyStrategy::Reuse,
        };
        let mut encryption = None;
        match o.key_strategy {
            KeyStrategy::Reuse => {
                r.refuse(
                    &[
                        "algorithm",
                        "rsa_bits",
                        "ecdsa_curve",
                        "key_format",
                        "key_encoding",
                        "key_kdf",
                        "key_kdf_iterations",
                        "new_key_output_path",
                        "include_new_key_pem",
                    ],
                    "with key_strategy=reuse (the default)",
                )?;
                o.existing_key_path = r.text("existing_key_path")?;
                o.key_passphrase = r.passphrase("key_passphrase")?;
            }
            KeyStrategy::Rekey => {
                r.refuse(&["existing_key_path"], "with key_strategy=rekey")?;
                o.algorithm = algorithm_opt(r)?;
                if let Some(a) = &o.algorithm {
                    let (bits, curve) = key_size_opts(r, a)?;
                    o.rsa_bits = bits;
                    if r.has("ecdsa_curve") {
                        o.ecdsa_curve = Some(curve);
                    }
                    o.key_format = key_format_opt(r, a)?;
                } else {
                    // The algorithm follows the old key; its options are
                    // checked once that is known.
                    r.uint("rsa_bits", 2048, 4096)?;
                    if r.has("ecdsa_curve") {
                        o.ecdsa_curve = Some(key_size_opts(r, &CertAlgorithm::Ecdsa)?.1);
                    }
                    if r.has("rsa_bits") {
                        o.rsa_bits = key_size_opts(r, &CertAlgorithm::Rsa)?.0;
                    }
                    o.key_format = match r
                        .choice("key_format", &["pkcs8", "pkcs1", "sec1"])?
                        .unwrap_or("pkcs8")
                    {
                        "pkcs1" => KeyFormat::Pkcs1,
                        "sec1" => KeyFormat::Sec1,
                        _ => KeyFormat::Pkcs8,
                    };
                }
                o.key_encoding = encoding_opt(r, "key_encoding")?;
                o.new_key_output_path = r.text("new_key_output_path")?;
                encryption = key_encryption_opts(r, "key_passphrase", &o.key_format)?;
                o.key_passphrase = encryption.as_ref().map(|(p, _)| p.clone());
            }
        }
        o.cert_encoding = encoding_opt(r, "cert_encoding")?;
        o.new_cert_output_path = r.text("new_cert_output_path")?;
        o.copy_subject = r.flag("copy_subject", true)?;
        o.subject_override = subject_opt(r, "subject_override")?;
        if !o.copy_subject {
            require_common_name(
                "subject_override",
                &o.subject_override,
                "with copy_subject=false",
            )?;
        }
        o.copy_sans = r.flag("copy_sans", true)?;
        o.sans_override = sans_opt(r, "sans_override")?;
        o.copy_key_usage = r.flag("copy_key_usage", true)?;
        o.key_usage_override = args::key_usages(r, "key_usage_override")?;
        o.copy_extended_key_usage = r.flag("copy_extended_key_usage", true)?;
        o.extended_key_usage_override =
            args::extended_key_usages(r, "extended_key_usage_override")?;
        (o.is_ca, o.path_len) = {
            let is_ca = r.opt_flag("is_ca")?;
            let path_len = r.uint("path_len", 0, 255)?.map(|n| n as u8);
            if path_len.is_some() && is_ca == Some(false) {
                return Err(CertError::usage(
                    "path_len needs a CA certificate (not is_ca=false)",
                ));
            }
            (is_ca, path_len)
        };
        let (nb, carry, na, off) = validity_opts(r, true)?;
        o.not_before = nb;
        o.carry_over_start = carry;
        o.not_after = na;
        o.not_after_offset_days = off;
        o.include_cert_pem = r.flag("include_cert_pem", false)?;
        o.include_new_key_pem = r.flag("include_new_key_pem", false)?;
        o.overwrite = r.flag("overwrite", false)?;
        Ok((o, encryption))
    }

    fn run_renew(&self, r: &Reader) -> CResult<Done> {
        let (opts, encryption) = self.parse_renew(r)?;
        let timeout = r.timeout()?;
        let json = matches!(opts.format, OutputFormat::Json);

        let old_data = read_input("certificate", &self.target_path)?;
        let old_der = certificate_ders(&old_data)
            .into_iter()
            .next()
            .ok_or_else(|| {
                CertError::failed(
                    "cert.parse_failed",
                    format!("{}: no certificate found", self.target_path),
                )
            })?;
        let old = self
            .parse_der_certificate_for_renewal(&old_der)
            .map_err(|e| CertError::failed("cert.parse_failed", format!("{e:#}")))?;
        let mut warnings = Vec::new();
        let signer = self
            .determine_signer_strategy(&opts, &old, &mut warnings)
            .ok()
            .flatten()
            .ok_or_else(|| {
                CertError::new(
                    exit::USAGE,
                    "cert.signer_required",
                    format!(
                        "{} is signed by {}: pass signer_ca and signer_key (or \
                         renewal_mode=self_signed to replace it with a self-signed certificate)",
                        self.target_path,
                        old.issuer
                            .get("raw_dn")
                            .and_then(|v| v.as_str())
                            .unwrap_or("a CA")
                    ),
                )
            })?;
        warnings.clear();

        // The old key (reuse) and its algorithm (rekey without algorithm=).
        let (_, old_cert) = X509Certificate::from_der(&old_der)
            .map_err(|e| CertError::failed("cert.parse_failed", e.to_string()))?;
        let old_key = describe_spki(old_cert.public_key());
        let old_spki = spki_key_bytes(old_cert.public_key()).to_vec();
        let mut opts = opts;
        if matches!(opts.key_strategy, KeyStrategy::Rekey) && opts.algorithm.is_none() {
            let alg = match old_key.algorithm.as_str() {
                "rsa" => CertAlgorithm::Rsa,
                "ecdsa" => CertAlgorithm::Ecdsa,
                "ed25519" => CertAlgorithm::Ed25519,
                other => {
                    return Err(CertError::usage(format!(
                        "cannot rekey a {other} key; pass algorithm=rsa|ecdsa|ed25519"
                    )));
                }
            };
            if r.has("rsa_bits") && !matches!(alg, CertAlgorithm::Rsa) {
                return Err(CertError::usage(
                    "rsa_bits is not used: the old key is not RSA",
                ));
            }
            if r.has("ecdsa_curve") && !matches!(alg, CertAlgorithm::Ecdsa) {
                return Err(CertError::usage(
                    "ecdsa_curve is not used: the old key is not ECDSA",
                ));
            }
            if !r.has("rsa_bits")
                && matches!(alg, CertAlgorithm::Rsa)
                && let Some(b) = old_key.bits.and_then(|b| u16::try_from(b).ok())
                && [2048, 3072, 4096].contains(&b)
            {
                opts.rsa_bits = b;
            }
            match (&opts.key_format, &alg) {
                (KeyFormat::Pkcs1, a) if !matches!(a, CertAlgorithm::Rsa) => {
                    return Err(CertError::usage(
                        "key_format=pkcs1 is only valid for RSA keys",
                    ));
                }
                (KeyFormat::Sec1, a) if !matches!(a, CertAlgorithm::Ecdsa) => {
                    return Err(CertError::usage(
                        "key_format=sec1 is only valid for ECDSA keys",
                    ));
                }
                _ => {}
            }
            opts.algorithm = Some(alg);
        }
        let reuse_key: Option<LoadedKey> = match opts.key_strategy {
            KeyStrategy::Reuse => {
                let explicit = opts.existing_key_path.is_some();
                let path = opts
                    .existing_key_path
                    .clone()
                    .unwrap_or_else(|| self.derive_existing_key_path());
                if fileio::exists(&path) {
                    let k = keys::load_key(
                        "existing key",
                        &path,
                        opts.key_passphrase.as_deref(),
                        "key_passphrase",
                    )?;
                    let kp = k.key_pair()?;
                    if kp.public_key_raw() != old_spki.as_slice() {
                        return Err(CertError::failed(
                            "cert.keypair_mismatch",
                            format!("{path} does not match the certificate's public key"),
                        ));
                    }
                    warnings.extend(k.warning.clone());
                    Some(k)
                } else if explicit {
                    return Err(CertError::failed(
                        "cert.not_found",
                        format!("existing_key_path {path} not found"),
                    ));
                } else if signer.signer_ca.is_none() {
                    return Err(CertError::failed(
                        "cert.key_load_failed",
                        format!(
                            "a self-signed renewal with key_strategy=reuse needs the \
                             certificate's private key, which was not found at {path}; pass \
                             existing_key_path=<path> or key_strategy=rekey"
                        ),
                    ));
                } else {
                    if opts.key_passphrase.is_some() {
                        return Err(CertError::usage(format!(
                            "key_passphrase was given, but there is no key at {path}"
                        )));
                    }
                    warnings.push(format!(
                        "Private key not found at {path}; the new certificate reuses the old \
                         public key"
                    ));
                    None
                }
            }
            KeyStrategy::Rekey => None,
        };
        let ca_key = match &signer.signer_key {
            Some(k) => Some(load_signer_key(opts.signer_key_passphrase.as_deref(), k)?),
            None => None,
        };
        if let Some(k) = &ca_key {
            warnings.extend(k.warning.clone());
        }
        let ca = match (&signer.signer_ca, &ca_key) {
            (Some(path), Some(k)) => Some(signer_ca_of(path, k)?),
            _ => None,
        };

        let new_cert_path = opts
            .new_cert_output_path
            .clone()
            .unwrap_or_else(|| self.derive_renewed_cert_path());
        let new_key_path = matches!(opts.key_strategy, KeyStrategy::Rekey).then(|| {
            opts.new_key_output_path
                .clone()
                .unwrap_or_else(|| self.derive_renewed_key_path(&new_cert_path))
        });
        if fileio::plain_path(&new_cert_path) == fileio::plain_path(&self.target_path)
            && !opts.overwrite
        {
            return Err(CertError::usage(
                "new_cert_output_path is the certificate being renewed; pass overwrite=true \
                 to replace it",
            ));
        }
        let mut outputs = vec![new_cert_path.as_str()];
        if let Some(p) = &new_key_path {
            outputs.push(p);
        }
        fileio::check_outputs(&outputs, opts.overwrite)?;

        let old_info = json!({
            "path": self.target_path,
            "encoding": if looks_like_pem(&old_data) { "pem" } else { "der" },
            "subject": old.subject,
            "issuer": old.issuer,
            "validity": old.validity,
            "is_ca": old.is_ca,
            "fingerprints": old.fingerprints,
        });
        let signer_json = json!({
            "mode": signer.mode,
            "signer_ca": signer.signer_ca,
            "signer_key": signer.signer_key,
        });
        let this = self.clone();
        let value = fileio::run_with_deadline(timeout, move |gate| {
            let (subject_key, key_json, new_key_bytes) = match (&opts.key_strategy, &reuse_key) {
                (KeyStrategy::Reuse, Some(k)) => (
                    k.key_pair()?,
                    json!({
                        "reused": true,
                        "algorithm": k.algorithm,
                        "rsa_bits": k.rsa_bits,
                        "ecdsa_curve": k.curve,
                        "stored_at": opts.existing_key_path.clone()
                            .unwrap_or_else(|| this.derive_existing_key_path()),
                        "encrypted": k.encrypted,
                    }),
                    None,
                ),
                (KeyStrategy::Reuse, None) => {
                    let alg = rcgen_alg_for_key(&old_key)
                        .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
                    let kp = KeyPair::from_remote(Box::new(PublicKeyOnly {
                        raw: old_spki.clone(),
                        alg,
                    }))
                    .map_err(|e| CertError::failed("cert.sign_failed", e.to_string()))?;
                    (
                        kp,
                        json!({
                            "reused": true,
                            "algorithm": old_key.algorithm,
                            "rsa_bits": old_key.bits.filter(|_| old_key.algorithm == "rsa"),
                            "ecdsa_curve": old_key.curve,
                            "stored_at": null,
                            "encrypted": false,
                        }),
                        None,
                    )
                }
                (KeyStrategy::Rekey, _) => {
                    let alg = opts.algorithm.clone().unwrap_or(CertAlgorithm::Ecdsa);
                    let curve =
                        opts.ecdsa_curve
                            .clone()
                            .unwrap_or(match old_key.curve.as_deref() {
                                Some("P-384") => EcdsaCurve::P384,
                                _ => EcdsaCurve::P256,
                            });
                    let kp = keys::generate_key(&alg, opts.rsa_bits, &curve)?;
                    let bytes = keys::encode_key(
                        &kp,
                        &alg,
                        &opts.key_format,
                        &opts.key_encoding,
                        encryption.as_ref().map(|(p, i)| (p.as_str(), *i)),
                    )?;
                    let info = json!({
                        "reused": false,
                        "algorithm": format!("{alg:?}").to_lowercase(),
                        "rsa_bits": matches!(alg, CertAlgorithm::Rsa).then_some(opts.rsa_bits),
                        "ecdsa_curve": matches!(alg, CertAlgorithm::Ecdsa).then(|| match curve {
                            EcdsaCurve::P384 => "P-384",
                            EcdsaCurve::P256 => "P-256",
                        }),
                        "stored_at": new_key_path,
                        "encrypted": encryption.is_some(),
                    });
                    let subject = KeyPair::from_der(&kp.serialize_der())
                        .map_err(|e| CertError::failed("cert.generation_failed", e.to_string()))?;
                    (subject, info, Some(bytes))
                }
            };
            let mut params = this
                .build_renewal_params(
                    &opts,
                    &old_der,
                    subject_key,
                    matches!(opts.key_strategy, KeyStrategy::Rekey),
                )
                .map_err(|e| {
                    let m = format!("{e:#}");
                    if m.contains("must be later") {
                        CertError::usage(m)
                    } else {
                        CertError::failed("cert.sign_failed", m)
                    }
                })?;
            let issued = match &ca {
                Some(ca) => {
                    params.use_authority_key_identifier_extension = true;
                    Certificate::from_params(params)
                        .and_then(|c| c.serialize_der_with_signer(&ca.cert))
                }
                None => Certificate::from_params(params).and_then(|c| c.serialize_der()),
            }
            .map_err(|e| {
                CertError::failed(
                    "cert.sign_failed",
                    format!("cannot issue the certificate: {e}"),
                )
            })?;
            let cert_bytes = encode_cert_der(&issued, &opts.cert_encoding);
            let mut files: Vec<(&str, &[u8], bool)> = vec![(&new_cert_path, &cert_bytes, false)];
            if let (Some(p), Some(b)) = (&new_key_path, &new_key_bytes) {
                files.push((p, b, true));
            }
            gate.commit()?;
            write_outputs(&files, opts.overwrite)?;
            let sm = summarize_cert_der(&issued)
                .map_err(|e| CertError::failed("cert.sign_failed", format!("{e:#}")))?;
            let key_pem = matches!(opts.key_encoding, Encoding::Pem);
            Ok(json!({
                "ok": true,
                "old_cert": old_info,
                "new_cert": {
                    "path": new_cert_path,
                    "encoding": format!("{:?}", opts.cert_encoding).to_lowercase(),
                    "subject": sm.subject,
                    "issuer": sm.issuer,
                    "validity": { "not_before": sm.not_before, "not_after": sm.not_after },
                    "is_ca": sm.is_ca,
                    "path_len": sm.path_len,
                    "serial_number": sm.serial_hex,
                    "sans": sm.sans,
                    "key_usage": sm.key_usage,
                    "extended_key_usage": sm.extended_key_usage,
                    "fingerprints": sm.fingerprints,
                },
                "key_strategy": format!("{:?}", opts.key_strategy).to_lowercase(),
                "key": key_json,
                "signer": signer_json,
                "returned": {
                    "cert_pem": opts.include_cert_pem
                        .then(|| pem_encode_lf(&Pem::new("CERTIFICATE", issued.clone()))),
                    "new_key_pem": new_key_bytes.as_ref()
                        .filter(|_| opts.include_new_key_pem && key_pem)
                        .map(|b| String::from_utf8_lossy(b).into_owned()),
                    "new_key_der_base64": new_key_bytes.as_ref()
                        .filter(|_| opts.include_new_key_pem && !key_pem)
                        .map(|b| BASE64_STANDARD.encode(b)),
                },
                "warnings": warnings,
            }))
        })?;
        Done::ok(json, value, renew_text)
    }
}

fn renew_text(v: &Value) -> String {
    let n = &v["new_cert"];
    let o = &v["old_cert"];
    let k = &v["key"];
    let key_desc = if k["reused"] == true {
        "reused existing".to_string()
    } else {
        let mut d = s(&k["algorithm"]);
        if let Some(b) = k["rsa_bits"].as_u64() {
            d.push_str(&format!(" {b}-bit"));
        } else if let Some(c) = k["ecdsa_curve"].as_str() {
            d.push_str(&format!(" {c}"));
        }
        d
    };
    let mut out = format!(
        "Old certificate: {}\nNew certificate: {}\nRenewal mode: {}\nKey strategy: {} ({key_desc})\n\n",
        s(&o["path"]),
        s(&n["path"]),
        s(&v["signer"]["mode"]),
        s(&v["key_strategy"]),
    );
    out.push_str(&format!(
        "Old Subject: {}\nNew Subject: {}\nNew Issuer: {}\nNew Serial: {}\nNew SHA256: {}\n\n",
        s(&o["subject"]["raw_dn"]),
        s(&n["subject"]["raw_dn"]),
        s(&n["issuer"]["raw_dn"]),
        s(&n["serial_number"]),
        s(&n["fingerprints"]["sha256"])
    ));
    out.push_str(&format!(
        "Old Validity:\n  Not Before: {}\n  Not After : {}\n\nNew Validity:\n  Not Before: {}\n  Not After : {}\n\n",
        s(&o["validity"]["not_before"]),
        s(&o["validity"]["not_after"]),
        s(&n["validity"]["not_before"]),
        s(&n["validity"]["not_after"])
    ));
    out.push_str("Signer:\n");
    match v["signer"]["signer_ca"].as_str() {
        Some(ca) => out.push_str(&format!(
            "  CA: {ca}\n  Key: {}\n",
            s(&v["signer"]["signer_key"])
        )),
        None => out.push_str("  self-signed\n"),
    }
    if k["reused"] == false {
        out.push_str(&format!(
            "\nKey:\n  New key stored at: {}\n  Encrypted: {}\n",
            s(&k["stored_at"]),
            if k["encrypted"] == true { "yes" } else { "no" }
        ));
    }
    out.push('\n');
    warnings_text(&mut out, &v["warnings"]);
    out
}
