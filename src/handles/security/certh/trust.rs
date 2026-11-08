//! Trust anchors and certificate path validation for `verify` and
//! `chain.info`. The trust decision is made by rustls-webpki (RFC 5280 path
//! building: signatures, validity of every certificate, basic constraints,
//! path length, name constraints, extended key usage); this module only
//! loads the anchors and maps webpki's errors to cert check codes.

use std::path::{Path, PathBuf};

use rustls::pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
};
use webpki::{EndEntityCert, KeyPurposeIdIter};

use super::errors::{CResult, CertError};
use super::fileio::{MAX_INPUT_BYTES, plain_path, read_input};

/// System CA bundles tried, in order, for the system trust store (after
/// `SSL_CERT_FILE`).
pub const SYSTEM_TRUST_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Signature algorithms accepted in a path (RSA 2048-8192 bits PKCS#1 v1.5
/// and PSS, ECDSA P-256/P-384, Ed25519).
static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// The certificates of the system CA bundle (`SSL_CERT_FILE` first), and
/// the file they came from; `None` when no bundle is readable.
pub fn system_anchors() -> Option<(String, Vec<Vec<u8>>)> {
    let env = std::env::var("SSL_CERT_FILE").ok();
    for path in env
        .iter()
        .map(String::as_str)
        .chain(SYSTEM_TRUST_BUNDLES.iter().copied())
    {
        if let Ok(data) = read_input("CA bundle", path) {
            return Some((path.to_string(), super::certificate_ders(&data)));
        }
    }
    None
}

/// Every certificate in the files (or the files of the directories) in
/// `paths`. `option` names the argument, for messages.
pub fn anchors_from_paths(option: &str, paths: &[String]) -> CResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for path in paths {
        let p = Path::new(plain_path(path));
        let files: Vec<PathBuf> = if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| {
                    CertError::failed(
                        "cert.trust_load_failed",
                        format!("cannot read {option} directory {path}: {e}"),
                    )
                })?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|f| {
                    f.is_file()
                        && f.metadata()
                            .map(|m| m.len() <= MAX_INPUT_BYTES)
                            .unwrap_or(false)
                })
                .collect();
            v.sort();
            v
        } else {
            vec![p.to_path_buf()]
        };
        let mut found = 0;
        for f in files {
            let data = read_input(option, &f.to_string_lossy())
                .map_err(|e| CertError::failed("cert.trust_load_failed", e.message))?;
            let ders = super::certificate_ders(&data);
            found += ders.len();
            out.extend(ders);
        }
        if found == 0 {
            return Err(CertError::failed(
                "cert.trust_load_failed",
                format!("no certificate found in {option} {path}"),
            ));
        }
    }
    Ok(out)
}

/// The certificates in PEM text given on the command line (`\n` escapes
/// are accepted, since a PEM block is hard to pass on one line).
pub fn anchors_from_pem(option: &str, text: &str) -> CResult<Vec<Vec<u8>>> {
    let text = text.replace("\\n", "\n");
    let ders = super::certificate_ders(text.as_bytes());
    if ders.is_empty() {
        return Err(CertError::usage(format!(
            "{option} does not contain a PEM certificate"
        )));
    }
    Ok(ders)
}

/// The extended key usage a path is validated for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Eku {
    /// Any purpose: the extended key usage is not checked.
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
}

const EKU_SERVER_AUTH: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 1];
const EKU_CLIENT_AUTH: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 2];
const EKU_CODE_SIGNING: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 3];
const EKU_EMAIL_PROTECTION: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 4];

struct AnyEku;

impl webpki::ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        // Still refuse a malformed extension.
        for id in iter {
            id?;
        }
        Ok(())
    }
}

/// Validates `leaf` up to one of `anchors`, with `intermediates` as
/// candidate issuers, at `unix_time`. Returns the path as DER, leaf first and
/// the trust anchor last.
pub fn validate(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    unix_time: u64,
    eku: Eku,
) -> Result<Vec<Vec<u8>>, webpki::Error> {
    let leaf_der = CertificateDer::from(leaf);
    let ee = EndEntityCert::try_from(&leaf_der)?;
    let anchor_ders: Vec<CertificateDer> = anchors
        .iter()
        .map(|a| CertificateDer::from(a.as_slice()))
        .collect();
    // Anchors webpki cannot use (for example a malformed certificate) are skipped.
    let parsed: Vec<(usize, TrustAnchor)> = anchor_ders
        .iter()
        .enumerate()
        .filter_map(|(i, d)| webpki::anchor_from_trusted_cert(d).ok().map(|a| (i, a)))
        .collect();
    let trust: Vec<TrustAnchor> = parsed.iter().map(|(_, a)| a.clone()).collect();
    let inter: Vec<CertificateDer> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(unix_time));
    let path = match eku {
        Eku::Any => ee.verify_for_usage(ALGS, &trust, &inter, time, AnyEku, None, None),
        other => {
            let usage = webpki::KeyUsage::required_if_present(match other {
                Eku::ServerAuth => EKU_SERVER_AUTH,
                Eku::ClientAuth => EKU_CLIENT_AUTH,
                Eku::CodeSigning => EKU_CODE_SIGNING,
                _ => EKU_EMAIL_PROTECTION,
            });
            ee.verify_for_usage(ALGS, &trust, &inter, time, usage, None, None)
        }
    }?;
    let mut chain = vec![leaf.to_vec()];
    chain.extend(
        path.intermediate_certificates()
            .map(|c| c.der().as_ref().to_vec()),
    );
    // Order the intermediates from the leaf upwards by name.
    let mut ordered = vec![chain.remove(0)];
    while !chain.is_empty() {
        let issuer = super::issuer_raw(ordered.last().map(Vec::as_slice).unwrap_or_default());
        match chain.iter().position(|c| super::subject_raw(c) == issuer) {
            Some(i) => ordered.push(chain.remove(i)),
            None => ordered.append(&mut chain),
        }
    }
    let anchor = path.anchor();
    if let Some((i, _)) = parsed.iter().find(|(_, a)| {
        a.subject.as_ref() == anchor.subject.as_ref()
            && a.subject_public_key_info.as_ref() == anchor.subject_public_key_info.as_ref()
    }) {
        ordered.push(anchors[*i].clone());
    }
    Ok(ordered)
}

/// Whether the leaf is valid for `host` (a DNS name or an IP address), as
/// webpki decides for TLS server names (subjectAltName only; the common
/// name is not used).
pub fn valid_for_host(leaf: &[u8], host: &str) -> Result<bool, String> {
    let name = ServerName::try_from(host)
        .map_err(|_| format!("{host:?} is not a valid DNS name or IP address"))?;
    let der = CertificateDer::from(leaf);
    let ee = EndEntityCert::try_from(&der).map_err(|e| format!("{e:?}"))?;
    Ok(ee.verify_is_valid_for_subject_name(&name).is_ok())
}

/// A check code, whether the failure means "not supported" rather than
/// "invalid", and a short description of a webpki error.
pub fn describe_error(e: &webpki::Error) -> (&'static str, bool, String) {
    use webpki::Error as E;
    match e {
        E::UnknownIssuer => (
            "cert.issuer_not_found",
            false,
            "no path to a trust anchor: an issuer is missing from the bundle and trust store"
                .into(),
        ),
        E::InvalidSignatureForPublicKey => (
            "cert.bad_signature",
            false,
            "a signature in the chain does not verify".into(),
        ),
        E::UnsupportedSignatureAlgorithmContext(_)
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => (
            "cert.unsupported_signature_algorithm",
            true,
            "a signature algorithm or key in the chain is not supported (RSA 2048-8192 bits \
             with SHA-256/384/512, ECDSA P-256/P-384 and Ed25519 are; SHA-1 and MD5 are not)"
                .into(),
        ),
        E::CertExpired { .. } => (
            "cert.chain_expired",
            false,
            "a certificate in the chain has expired".into(),
        ),
        E::CertNotValidYet { .. } => (
            "cert.chain_not_yet_valid",
            false,
            "a certificate in the chain is not yet valid".into(),
        ),
        E::CaUsedAsEndEntity => (
            "cert.ca_used_as_end_entity",
            false,
            "the certificate is a CA certificate, which webpki does not accept as the \
             end-entity of a chain"
                .into(),
        ),
        E::EndEntityUsedAsCa => (
            "cert.issuer_not_ca",
            false,
            "an issuer in the chain is not a CA".into(),
        ),
        E::PathLenConstraintViolated => (
            "cert.path_len_exceeded",
            false,
            "a CA's path length constraint is exceeded".into(),
        ),
        E::NameConstraintViolation => (
            "cert.name_constraint_violation",
            false,
            "a name constraint of an issuer is violated".into(),
        ),
        E::MaximumPathDepthExceeded
        | E::MaximumPathBuildCallsExceeded
        | E::MaximumSignatureChecksExceeded => (
            "cert.chain_too_long",
            false,
            "the chain is too long or too many candidate paths were tried".into(),
        ),
        E::RequiredEkuNotFoundContext(_) => (
            "cert.eku_mismatch",
            false,
            "the extended key usage of a certificate in the chain does not allow the purpose"
                .into(),
        ),
        E::UnsupportedCertVersion => (
            "cert.unsupported_version",
            false,
            "a certificate in the chain is not X.509 v3".into(),
        ),
        other => (
            "cert.chain_invalid",
            false,
            format!("the chain is invalid ({other:?})"),
        ),
    }
}
