use anyhow::{Context, Result, bail};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, digest};
use serde_json::{Value, json};
use std::collections::HashMap;
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::*;

// Additional imports for certificate generation
use ::pem::Pem;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use pkcs8::{DecodePrivateKey, PrivateKeyInfo as Pkcs8PrivateKeyInfo};
use rcgen::KeyPair;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, IsCa, SanType};
use rsa::pkcs1::DecodeRsaPrivateKey; // Add this import for from_pkcs1_der
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePrivateKey};

// Additional imports for signing functionality
use ed25519_dalek::Signature as Ed25519Signature;
use hex;
use p256::ecdsa::Signature as P256Signature;
use p384::ecdsa::Signature as P384Signature;
use ring::digest;
use rsa::Pss;
use rsa::signature::Signer;
use sha2::Digest;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

mod args;
mod chain;
mod errors;
mod fileio;
mod keyenc;
mod keys;
#[cfg(test)]
mod tests;
mod trust;
mod verbs;

/// Metadata for `resh cert --help` and `resh cert <verb> --help`.
static CERT_HELP: HandleHelp = HandleHelp {
    description: "The cert handle inspects and manages X.509 certificates, private keys, and \
        certificate signing requests stored as PEM or DER files, using pure Rust crypto \
        libraries (x509-parser, rcgen, ring, rustls-webpki, rsa, p256, p384, ed25519-dalek) \
        with no OpenSSL dependency. It covers inspection, verification, chain analysis, key and certificate \
        generation, CSR creation, signing, and renewal. The target is a file path, written as \
        cert:///etc/ssl/certs/server.pem for an absolute path or cert://./server.pem for a \
        relative one.",
    usage: "resh cert://<file-path>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "info",
            definition: "Reads a PEM or DER file holding certificates, a CSR, or a private key \
                and reports, for each object, its type, serial number, subject, issuer, \
                validity, public key, extensions, and fingerprints.",
            detail: Some(VerbDetail {
                usage: "resh cert://<path>.info [format=json|text] [encoding=auto|pem|der]\n  \
                    [fingerprint_algs=sha1,sha256,sha384,sha512] [include_pem=true|false]\n  \
                    [include_raw=true|false]",
                example: "resh --json-pretty cert://./server.pem.info",
                example_output: Some(
                    r#"{
  "encoding": "pem",
  "objects": [
    {
      "extensions": {
        "authority_key_id": "85:AB:5E:DA:...:CF:16:F3:3C",
        "basic_constraints": {
          "ca": false,
          "critical": true,
          "path_len": null
        },
        "extended_key_usage": [],
        "key_usage": [],
        "subject_alt_names": [
          "DNS:web.test"
        ],
        "subject_key_id": "85:D3:F5:24:...:D7:B8:5A:F0"
      },
      "fingerprints": {
        "sha256": "A1:D8:59:5D:...:31:BC:FD:1A"
      },
      "is_ca": false,
      "issuer": {
        "common_name": "Example CA",
        "raw_dn": "CN=Example CA"
      },
      "kind": "certificate",
      "public_key": {
        "algorithm": "ECDSA",
        "curve": "P-256",
        "key_size": 256
      },
      "serial_number": "7C0906C15584DDC109D5A214E2944D94",
      "subject": {
        "common_name": "web.test",
        "raw_dn": "CN=web.test"
      },
      "validity": {
        "is_currently_valid": true,
        "not_after": "2027-11-08T11:33:38+00:00",
        "not_before": "2026-11-08T11:33:38+00:00"
      },
      "version": 2
    }
  ],
  "type": "certificate"
}

Shown for a CA-signed PEM certificate with --json-pretty. version is
zero-based (2 means X.509 v3). A bundle reports type certificatechain with
one object per certificate; a CSR, private key (also an encrypted one) or
public key reports kind csr, private_key or public_key. Fingerprints are
digests of the whole DER certificate."#,
                ),
            }),
        },
        VerbHelp {
            name: "verify",
            definition: "Checks a certificate's structure, its chain to a trust anchor \
                (validated by rustls-webpki), validity period, hostname, purpose, and \
                private key against a policy, and reports each check as passed, failed, \
                skipped, not_checked, or unsupported; exits 1 if any check fails.",
            detail: Some(VerbDetail {
                usage: "resh cert://<path>.verify [hostname=<name>]\n  \
                    [purpose=server_auth|client_auth|code_signing|email_protection|any]\n  \
                    [trust=system|mount|inline] [trust_paths=<path>,...] [ca_file=<pem>]\n  \
                    [trust_pem=<pem>] [max_chain_depth=<n>] [min_rsa_bits=<n>]\n  \
                    [allow_self_signed=true|false] [allow_expired=true|false]\n  \
                    [allow_not_yet_valid=true|false] [check_revocation=none|soft|hard]\n  \
                    [keypair_target=<key-path>]\n  \
                    [include_chain_report=true|false] [encoding=auto|pem|der]\n  \
                    [format=json|text]",
                example: "resh cert://./web.pem.verify trust_paths=ca.pem hostname=web.test \
                    format=text",
                example_output: Some(
                    r#"Target: cert://./web.pem
Type: certificate (pem)
Overall: OK

[STRUCTURE]
  OK: Certificate parsed (X.509 v3, ecdsa-with-SHA256, ecdsa 256-bit key)

[CHAIN]
  OK: Chain of 2 certificate(s) verified to trust anchor CN=Example CA

[TIME]
  OK: Certificate is currently valid

[HOSTNAME]
  OK: Hostname web.test matches DNS SAN web.test

[USAGE]
  SKIPPED: No purpose requested (purpose=any)

[KEYPAIR]
  SKIPPED: No keypair_target specified

[REVOCATION]
  SKIPPED: Revocation checking disabled (check_revocation=none)

[Chain Report]
  0: CN=web.test
  1: CN=Example CA (TRUSTED)

Warnings:
  Revocation not checked (check_revocation=none)

Shown for a leaf issued by the CA in ca.pem. The first certificate in the
file is verified and any others are used as intermediates. The default
trust=system uses the system CA bundle; trust_paths, ca_file and trust_pem
add anchors. Chains use RSA 2048-8192 bits, ECDSA P-256/P-384 or Ed25519
(SHA-1 is never accepted). Revocation is not implemented: soft reports
not_checked and hard fails. format=json adds a status field per check."#,
                ),
            }),
        },
        VerbHelp {
            name: "chain.info",
            definition: "Parses a certificate bundle, finds its leaf certificates, and \
                reports every chain from each leaf through the bundle and the trust \
                anchors, linking issuers by name and signature; a chain is trusted only \
                when rustls-webpki validates it to an anchor.",
            detail: Some(VerbDetail {
                usage: "resh cert://<bundle-path>.chain.info\n  \
                    [trust=none|system|mount|inline|system+mount|system+inline|mount+inline]\n  \
                    [trust_paths=<path>,...] [ca_file=<pem>] [trust_pem=<pem>]\n  \
                    [max_depth=<n>] [max_paths=<n>] [include_raw_subjects=true|false]\n  \
                    [include_raw_issuers=true|false] [include_cert_refs=true|false]\n  \
                    [encoding=auto|pem|der] [format=json|text]",
                example: "resh cert://./bundle.pem.chain.info trust_paths=ca.pem format=text",
                example_output: Some(
                    r#"Target: cert://./bundle.pem
Encoding: pem
Trust anchors loaded: 1

Leaf Candidates:
  [0] CN=web.test

Chain 0 (length=2)
  Trust Status : trusted
  Reason       : Validated to trust anchor CN=Example CA (mount)
  [0] Leaf (target_bundle)
      Subject : CN=web.test
      Issuer  : CN=Example CA
      Key     : ECDSA P-256
  [1] Root (target_bundle, trust anchor)
      Subject : CN=Example CA
      Issuer  : CN=Example CA
      Key     : ECDSA P-256, CA

Warnings:
  (none)

Shown for bundle.pem holding web.pem and ca.pem. trust_status is trusted,
invalid (ends at an anchor but fails validation), untrusted_root,
self_signed_untrusted or incomplete. The default trust=none uses only
trust_paths, ca_file and trust_pem as anchors."#,
                ),
            }),
        },
        VerbHelp {
            name: "generate",
            definition: "Generates a private key, a self-signed certificate, a CA-signed \
                leaf certificate, or a CSR and writes it beside the target path as \
                <target>-key.pem (mode 0600, encrypted PKCS#8 with key_passphrase), \
                <target>.pem, or <target>.csr.",
            detail: Some(VerbDetail {
                usage: "resh cert://<base-path>.generate [mode=key|self_signed|csr|leaf_cert]\n  \
                    [algorithm=rsa|ecdsa|ed25519] [rsa_bits=2048|3072|4096]\n  \
                    [ecdsa_curve=P-256|P-384] [subject=<json>] [sans=<json-array>]\n  \
                    [is_ca=true|false] [path_len=<n>] [not_before=now|<rfc3339>]\n  \
                    [not_after=<rfc3339>] [not_after_offset_days=<n>]\n  \
                    [signer_ca=<path>] [signer_key=<path>]\n  \
                    [signer_key_passphrase=<pass> | signer_key_passphrase_env=<VAR>\n  \
                    | signer_key_passphrase_stdin=true]\n  \
                    [key_format=pkcs8|pkcs1|sec1] [key_encoding=pem|der]\n  \
                    [cert_encoding=pem|der] [csr_encoding=pem|der]\n  \
                    [key_passphrase=<pass> | key_passphrase_env=<VAR>\n  \
                    | key_passphrase_stdin=true]\n  \
                    [key_kdf=pbkdf2] [key_kdf_iterations=<n>]\n  \
                    [output=<json>] [overwrite=true|false] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty cert://./server.generate mode=key algorithm=ecdsa",
                example_output: Some(
                    r#"{
  "algorithm": "ecdsa",
  "certificate": null,
  "csr": null,
  "ecdsa_curve": "P256",
  "encodings": {
    "cert": "pem",
    "csr": "pem",
    "key": "pem"
  },
  "is_ca": false,
  "key": {
    "encrypted": false,
    "key_format": "pkcs8",
    "stored_at": "./server-key.pem"
  },
  "mode": "key",
  "ok": true,
  "path_len": null,
  "returned": {
    "cert_der_base64": null,
    "cert_pem": null,
    "csr_der_base64": null,
    "csr_pem": null,
    "key_der_base64": null,
    "key_pem": null
  },
  "rsa_bits": null,
  "sans": [],
  "subject": null,
  "target": "./server",
  "validity": null,
  "warnings": []
}

Shown with --json-pretty. mode=leaf_cert needs signer_ca and signer_key
(signer_key_passphrase for an encrypted CA key). key_passphrase writes an
encrypted PKCS#8 key (PBKDF2-HMAC-SHA256, AES-256-CBC). Give a passphrase
as <name>_env=<VAR> or <name>_stdin=true; <name>=<pass> works but warns.
Default timeout_ms is 300000; at the deadline nothing is written (exit
124)."#,
                ),
            }),
        },
        VerbHelp {
            name: "csr.create",
            definition: "Creates a certificate signing request at the target path, signed \
                with an existing key (encrypted keys need existing_key_passphrase) or \
                with a newly generated key that it also saves, requesting the SANs, key \
                usage and extended key usage given.",
            detail: Some(VerbDetail {
                usage: "resh cert://<csr-path>.csr.create subject=<json>\n  \
                    [key_strategy=reuse|generate] [existing_key_path=<path>]\n  \
                    [existing_key_passphrase=<pass> | existing_key_passphrase_env=<VAR>\n  \
                    | existing_key_passphrase_stdin=true]\n  \
                    [new_key_output_path=<path>]\n  \
                    [new_key_passphrase=<pass> | new_key_passphrase_env=<VAR>\n  \
                    | new_key_passphrase_stdin=true]\n  \
                    [algorithm=rsa|ecdsa|ed25519]\n  \
                    [rsa_bits=2048|3072|4096] [ecdsa_curve=P-256|P-384]\n  \
                    [key_format=pkcs8|pkcs1|sec1] [key_encoding=pem|der]\n  \
                    [key_kdf=pbkdf2] [key_kdf_iterations=<n>] [csr_encoding=pem|der]\n  \
                    [sans=<json-array>] [key_usage=<list>] [extended_key_usage=<list>]\n  \
                    [include_csr_pem=true|false] [include_new_key_pem=true|false]\n  \
                    [overwrite=true|false] [format=json|text] [timeout_ms=<ms>]",
                example: "resh cert://web.csr.create existing_key_path=k \
                    subject='{\"common_name\":\"web\"}'",
                example_output: Some(
                    r#"{
  "csr": {
    "encoding": "pem",
    "extended_key_usage": [],
    "fingerprints": {
      "sha256": "89:D5:8E:CC:...:39:FA:9A:97"
    },
    "key_usage": [],
    "path": "web",
    "sans": [],
    "subject": {
      "common_name": "web",
      "raw_dn": "CN=web"
    }
  },
  "csr_target": "web",
  "key": {
    "algorithm": "ecdsa",
    "ecdsa_curve": "P-256",
    "encoding": "pem",
    "encrypted": false,
    "key_format": "pkcs8",
    "path": "k",
    "reused": true,
    "rsa_bits": null
  },
  "key_strategy": "reuse",
  "ok": true,
  "returned": {
    "csr_der_base64": null,
    "csr_pem": null,
    "new_key_der_base64": null,
    "new_key_pem": null
  },
  "warnings": []
}

Shown for an existing P-256 key in k. The CSR is written to the target
path exactly. The algorithm is read from the key; algorithm= only checks
it. key_usage and extended_key_usage take names such as digitalSignature
or serverAuth, as a JSON array or comma list."#,
                ),
            }),
        },
        VerbHelp {
            name: "sign",
            definition: "Signs a file or base64 data with a private key, as a raw signature \
                or, with signature_format=cms_detached|cms_attached and the key's signer_cert, \
                as a CMS SignedData, or with mode=csr issues a certificate for a CSR signed by \
                the CA in signer_cert and signer_key, using the target only as the signer \
                label in the output.",
            detail: Some(VerbDetail {
                usage: "resh cert://<label>.sign [mode=data] signer_key=<path>\n  \
                    [signer_key_passphrase=<pass> | signer_key_passphrase_env=<VAR>\n  \
                    | signer_key_passphrase_stdin=true]\n  \
                    data_source=<path>\n  \
                    (or data_bytes_base64=<b64>) [signature_output_path=<path>]\n  \
                    [signature_algorithm=<alg>] [signature_encoding=base64|pem|der]\n  \
                    [signature_format=raw|cms_detached|cms_attached signer_cert=<path>]\n  \
                    [include_signature_bytes=true|false]\n  \
                    resh cert://<label>.sign mode=csr signer_key=<path> csr_source=<path>\n  \
                    signer_cert=<path> cert_output_path=<path> [csr_encoding=auto|pem|der]\n  \
                    [cert_encoding=pem|der] [not_before=now|<rfc3339>]\n  \
                    [not_after=<rfc3339>] [not_after_offset_days=<n>]\n  \
                    [is_ca=true|false] [path_len=<n>] [key_usage=<list>]\n  \
                    [extended_key_usage=<list>] [sans_override=<list>]\n  \
                    [include_cert_pem=true|false]\n  \
                    both modes: [overwrite=true|false] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty cert://./ca.sign signer_key=ca-key.pem \
                    data_source=app.tar",
                example_output: Some(
                    r#"{
  "algorithm": "EcdsaSha256",
  "cert": null,
  "cert_pem": null,
  "csr_source": null,
  "csr_subject": null,
  "data": {
    "length_bytes": 20480,
    "source": "app.tar"
  },
  "mode": "data",
  "ok": true,
  "signature": {
    "bytes_base64": null,
    "stored_at": null
  },
  "signature_encoding": "Base64",
  "signature_format": "Raw",
  "signer": "./ca",
  "signer_cert": null,
  "signer_key": "ca-key.pem",
  "warnings": [
    "Signature not kept (no signature_output_path, include_signature_bytes)"
  ]
}

Shown for a P-256 signer key with --json-pretty. Pass
signature_output_path or include_signature_bytes=true to keep the
signature. signature_format=cms_detached or cms_attached needs
signer_cert, the certificate of signer_key, and produces a CMS SignedData
(RFC 5652) as a DER ContentInfo encoded with signature_encoding (PEM
label CMS). With mode=csr the CSR signature is verified and the
certificate keeps the CSR subject, SANs, and public key."#,
                ),
            }),
        },
        VerbHelp {
            name: "csr.sign",
            definition: "Cannot be run from the command line, because cert://<target>.csr.sign \
                is parsed as the sign verb; programmatic callers get the same certificate \
                issuing as sign with mode=csr, which is the command to use instead.",
            detail: Some(VerbDetail {
                usage: "resh cert://<target>.csr.sign\n  \
                    (runs the sign verb with target <target>.csr; see the example)",
                example: "resh cert sign --help",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "renew",
            definition: "Issues a replacement for an existing certificate with the same \
                subject, SANs, and extensions, signed by signer_ca and signer_key or \
                self-signed, reusing the existing key or generating a new one, and \
                reports the new certificate's real details.",
            detail: Some(VerbDetail {
                usage: "resh cert://<cert-path>.renew\n  \
                    [renewal_mode=auto|self_signed|explicit_signer] [signer_ca=<path>]\n  \
                    [signer_key=<path>]\n  \
                    [signer_key_passphrase=<pass> | signer_key_passphrase_env=<VAR>\n  \
                    | signer_key_passphrase_stdin=true]\n  \
                    [key_strategy=reuse|rekey] [existing_key_path=<path>]\n  \
                    [key_passphrase=<pass> | key_passphrase_env=<VAR>\n  \
                    | key_passphrase_stdin=true]\n  \
                    [algorithm=rsa|ecdsa|ed25519]\n  \
                    [rsa_bits=2048|3072|4096] [ecdsa_curve=P-256|P-384]\n  \
                    [key_format=pkcs8|pkcs1|sec1] [key_encoding=pem|der]\n  \
                    [key_kdf=pbkdf2] [key_kdf_iterations=<n>]\n  \
                    [new_key_output_path=<path>] [new_cert_output_path=<path>]\n  \
                    [cert_encoding=pem|der] [copy_subject=true|false]\n  \
                    [subject_override=<json>] [copy_sans=true|false]\n  \
                    [sans_override=<list>] [copy_key_usage=true|false]\n  \
                    [key_usage_override=<list>] [copy_extended_key_usage=true|false]\n  \
                    [extended_key_usage_override=<list>] [is_ca=true|false]\n  \
                    [path_len=<n>] [not_before=now|carry_over_start|<rfc3339>]\n  \
                    [not_after=<rfc3339>] [not_after_offset_days=<n>]\n  \
                    [include_cert_pem=true|false] [include_new_key_pem=true|false]\n  \
                    [overwrite=true|false] [format=json|text] [timeout_ms=<ms>]",
                example: "resh cert://./server.pem.renew format=text",
                example_output: Some(
                    r#"Old certificate: ./server.pem
New certificate: ./server-renewed.pem
Renewal mode: auto
Key strategy: reuse (reused existing)

Old Subject: CN=Example CA
New Subject: CN=Example CA
New Issuer: CN=Example CA
New Serial: 3EE388C46643ADB4F8B6111A9846AF57
New SHA256: 37:55:D5:8C:DC:F4:76:2F:...:AA:D0:22:A6:7C:19:CD:10

Old Validity:
  Not Before: 2026-11-08T11:33:38+00:00
  Not After : 2027-11-08T11:33:38+00:00

New Validity:
  Not Before: 2026-11-08T11:33:39+00:00
  Not After : 2027-11-08T11:33:39+00:00

Signer:
  self-signed

Warnings:
  (none)

Shown for a self-signed certificate with the default key_strategy=reuse,
which signs with the key in existing_key_path (default <name>-key.pem;
key_passphrase if it is encrypted). A CA-signed certificate needs
signer_ca and signer_key; with reuse and no key file, its public key is
reused. key_strategy=rekey saves the new key as <name>-renewed-key.pem."#,
                ),
            }),
        },
    ],
};

// Certificate generation types
#[derive(Debug, Clone)]
pub enum CertGenerateMode {
    Key,
    SelfSigned,
    Csr,
    LeafCert,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertAlgorithm {
    Rsa,
    Ecdsa,
    Ed25519,
}

#[derive(Debug, Clone)]
/// Supported ECDSA curves. P-521 and secp256k1 are rejected when options
/// are parsed.
pub enum EcdsaCurve {
    P256,
    P384,
}

#[derive(Debug, Clone)]
pub enum KeyFormat {
    Pkcs8,
    Pkcs1,
    Sec1,
}

#[derive(Debug, Clone)]
pub enum Encoding {
    Pem,
    Der,
}

#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    RsaPssSha256,
    RsaPkcs1Sha256,
    RsaPssSha384,
    RsaPkcs1Sha384,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
}

#[derive(Debug, Clone)]
pub enum SignatureFormat {
    Raw,
    CmsDetached,
    CmsAttached,
}

#[derive(Debug, Clone)]
pub enum SignatureEncoding {
    Pem,
    Der,
    Base64,
}

#[derive(Debug, Clone)]
pub enum EncodingHint {
    Auto,
    Pem,
    Der,
}

#[derive(Debug, Clone)]
pub enum NotBeforeSetting {
    Now,
    Explicit(DateTime<Utc>),
}

#[derive(Debug, Clone)]
pub enum CertKeyUsage {
    DigitalSignature,
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

#[derive(Debug, Clone)]
pub enum CertExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct CertSubject {
    pub common_name: Option<String>,
    pub organization: Vec<String>,
    pub organizational_unit: Vec<String>,
    pub country: Vec<String>,
    pub state_or_province: Vec<String>,
    pub locality: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CertGenerateOutputOptions {
    pub write_key: bool,
    pub write_cert: bool,
    pub write_csr: bool,
    pub return_key: bool,
    pub return_cert: bool,
    pub return_csr: bool,
}

impl Default for CertGenerateOutputOptions {
    fn default() -> Self {
        Self {
            write_key: true,
            write_cert: true,
            write_csr: true,
            return_key: false,
            return_cert: true,
            return_csr: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertGenerateOptions {
    pub mode: CertGenerateMode,
    pub algorithm: CertAlgorithm,
    pub rsa_bits: u16,
    pub ecdsa_curve: EcdsaCurve,
    pub key_format: KeyFormat,
    pub key_encoding: Encoding,
    pub cert_encoding: Encoding,
    pub csr_encoding: Encoding,
    pub subject: Option<CertSubject>,
    pub sans: Vec<String>,
    pub is_ca: bool,
    pub path_len: Option<u8>,
    pub key_usage: Vec<CertKeyUsage>,
    pub extended_key_usage: Vec<CertExtendedKeyUsage>,
    pub not_before: NotBeforeSetting,
    pub not_after: Option<DateTime<Utc>>,
    pub not_after_offset_days: i64,
    pub signer_ca: Option<String>,
    pub signer_key: Option<String>,
    pub signer_key_passphrase: Option<String>,
    pub key_passphrase: Option<String>,
    pub key_kdf_iterations: u32,
    pub overwrite: bool,
    pub output: CertGenerateOutputOptions,
    pub format: OutputFormat,
}

impl Default for CertGenerateOptions {
    fn default() -> Self {
        Self {
            mode: CertGenerateMode::Key,
            algorithm: CertAlgorithm::Rsa,
            rsa_bits: 2048,
            ecdsa_curve: EcdsaCurve::P256,
            key_format: KeyFormat::Pkcs8,
            key_encoding: Encoding::Pem,
            cert_encoding: Encoding::Pem,
            csr_encoding: Encoding::Pem,
            subject: None,
            sans: Vec::new(),
            is_ca: false,
            path_len: None,
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            not_before: NotBeforeSetting::Now,
            not_after: None,
            not_after_offset_days: 365,
            signer_ca: None,
            signer_key: None,
            signer_key_passphrase: None,
            key_passphrase: None,
            key_kdf_iterations: 100_000,
            overwrite: false,
            output: CertGenerateOutputOptions::default(),
            format: OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertRenewOptions {
    pub renewal_mode: CertRenewalMode,
    pub signer_ca: Option<String>,
    pub signer_key: Option<String>,
    pub signer_key_passphrase: Option<String>,

    pub key_strategy: KeyStrategy,
    /// Private key of the certificate being renewed (key_strategy=reuse).
    pub existing_key_path: Option<String>,
    pub algorithm: Option<CertAlgorithm>,
    pub rsa_bits: u16,
    pub ecdsa_curve: Option<EcdsaCurve>,
    pub key_format: KeyFormat,
    pub key_encoding: Encoding,
    pub new_key_output_path: Option<String>,
    pub key_passphrase: Option<String>,
    pub key_kdf_iterations: u32,

    pub cert_encoding: Encoding,
    pub new_cert_output_path: Option<String>,
    pub copy_subject: bool,
    pub subject_override: Option<CertSubject>,
    pub copy_sans: bool,
    pub sans_override: Option<Vec<String>>,
    pub copy_key_usage: bool,
    pub key_usage_override: Option<Vec<CertKeyUsage>>,
    pub copy_extended_key_usage: bool,
    pub extended_key_usage_override: Option<Vec<CertExtendedKeyUsage>>,
    pub is_ca: Option<bool>,
    pub path_len: Option<u8>,

    pub not_before: NotBeforeSetting,
    /// not_before=carry_over_start: keep the old certificate's start time.
    pub carry_over_start: bool,
    pub not_after: Option<DateTime<Utc>>,
    pub not_after_offset_days: i64,

    pub overwrite: bool,
    pub format: OutputFormat,
    pub include_cert_pem: bool,
    pub include_new_key_pem: bool,
}

impl Default for CertRenewOptions {
    fn default() -> Self {
        Self {
            renewal_mode: CertRenewalMode::Auto,
            signer_ca: None,
            signer_key: None,
            signer_key_passphrase: None,

            key_strategy: KeyStrategy::Reuse,
            existing_key_path: None,
            algorithm: None,
            rsa_bits: 2048,
            ecdsa_curve: None,
            key_format: KeyFormat::Pkcs8,
            key_encoding: Encoding::Pem,
            new_key_output_path: None,
            key_passphrase: None,
            key_kdf_iterations: 100_000,

            cert_encoding: Encoding::Pem,
            new_cert_output_path: None,
            copy_subject: true,
            subject_override: None,
            copy_sans: true,
            sans_override: None,
            copy_key_usage: true,
            key_usage_override: None,
            copy_extended_key_usage: true,
            extended_key_usage_override: None,
            is_ca: None,
            path_len: None,

            not_before: NotBeforeSetting::Now,
            carry_over_start: false,
            not_after: None,
            not_after_offset_days: 365,

            overwrite: false,
            format: OutputFormat::Json,
            include_cert_pem: false,
            include_new_key_pem: false,
        }
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("cert", |u| Ok(Box::new(CertHandle::from_url(u.clone())?)));
}

#[derive(Debug, Clone)]
pub struct CertHandle {
    target_path: String,
}

#[derive(Debug, Clone)]
pub enum CertEncoding {
    Auto,
    Pem,
    Der,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone)]
pub enum Purpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    Any,
}

// Certificate renewal types
#[derive(Debug, Clone)]
pub enum CertRenewalMode {
    Auto,
    SelfSigned,
    ExplicitSigner,
}

#[derive(Debug, Clone)]
pub enum KeyStrategy {
    Reuse,
    Rekey,
}

#[derive(Debug, Clone)]
pub enum TrustMode {
    System,
    Mount,
    Inline,
}

#[derive(Debug, Clone)]
pub enum RevocationMode {
    None,
    Soft,
    Hard,
}

#[derive(Debug, Clone)]
pub struct CertInfoOptions {
    pub format: OutputFormat,
    pub encoding: CertEncoding,
    pub fingerprint_algs: Vec<String>,
    pub include_pem: bool,
    pub include_raw: bool,
}

impl Default for CertInfoOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            encoding: CertEncoding::Auto,
            fingerprint_algs: vec!["sha256".to_string()],
            include_pem: false,
            include_raw: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertVerifyOptions {
    pub format: OutputFormat,
    pub encoding: CertEncoding,
    pub purpose: Purpose,
    pub hostname: Option<String>,
    pub trust: TrustMode,
    pub trust_paths: Vec<String>,
    pub trust_pem: Option<String>,
    pub allow_self_signed: bool,
    pub allow_expired: bool,
    pub allow_not_yet_valid: bool,
    pub max_chain_depth: u8,
    pub check_revocation: RevocationMode,
    pub min_rsa_bits: u16,
    pub keypair_target: Option<String>,
    pub include_chain_report: bool,
}

impl Default for CertVerifyOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            encoding: CertEncoding::Auto,
            purpose: Purpose::Any,
            hostname: None,
            trust: TrustMode::System,
            trust_paths: Vec::new(),
            trust_pem: None,
            allow_self_signed: false,
            allow_expired: false,
            allow_not_yet_valid: false,
            max_chain_depth: 10,
            check_revocation: RevocationMode::None,
            min_rsa_bits: 2048,
            keypair_target: None,
            include_chain_report: true,
        }
    }
}

/// Outcome of one verify check. Only `Passed` means the check was performed
/// and succeeded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CheckStatus {
    Passed,
    Failed,
    /// Not requested by the policy (for example no hostname given).
    Skipped,
    /// Requested in a mode that tolerates not checking (soft revocation).
    NotChecked,
    /// Requested but not implemented for this input.
    Unsupported,
}

impl CheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Passed => "passed",
            CheckStatus::Failed => "failed",
            CheckStatus::Skipped => "skipped",
            CheckStatus::NotChecked => "not_checked",
            CheckStatus::Unsupported => "unsupported",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            CheckStatus::Passed => "OK",
            CheckStatus::Failed => "FAILED",
            CheckStatus::Skipped => "SKIPPED",
            CheckStatus::NotChecked => "NOT CHECKED",
            CheckStatus::Unsupported => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    /// False when this check makes the overall result invalid.
    pub ok: bool,
    pub status: CheckStatus,
    pub message: String,
    pub error_code: Option<String>,
}

impl CheckResult {
    fn with(status: CheckStatus, ok: bool, message: &str, error_code: Option<&str>) -> Self {
        Self {
            ok,
            status,
            message: message.to_string(),
            error_code: error_code.map(|c| c.to_string()),
        }
    }

    pub fn ok(message: &str) -> Self {
        Self::with(CheckStatus::Passed, true, message, None)
    }

    pub fn fail(message: &str, error_code: &str) -> Self {
        Self::with(CheckStatus::Failed, false, message, Some(error_code))
    }

    pub fn skipped(message: &str) -> Self {
        Self::with(CheckStatus::Skipped, true, message, None)
    }

    pub fn not_checked(message: &str) -> Self {
        Self::with(CheckStatus::NotChecked, true, message, None)
    }

    pub fn unsupported(message: &str, error_code: &str) -> Self {
        Self::with(CheckStatus::Unsupported, false, message, Some(error_code))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertObjectKind {
    Certificate,
    CertificateChain,
    PrivateKey,
    PublicKey,
    Csr,
    Unknown,
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub kind: CertObjectKind,
    pub version: u32,
    pub serial_number: String,
    pub subject: HashMap<String, Value>,
    pub issuer: HashMap<String, Value>,
    pub validity: HashMap<String, Value>,
    pub public_key: HashMap<String, Value>,
    pub fingerprints: HashMap<String, String>,
    pub extensions: HashMap<String, Value>,
    pub is_ca: bool,
    pub pem: Option<String>,
    pub raw_der_base64: Option<String>,
}

#[derive(Debug)]
pub struct PrivateKeyInfo {
    pub kind: CertObjectKind,
    pub algorithm: String,
    pub encoding: String,
    pub is_encrypted: bool,
    pub key_info: HashMap<String, Value>,
    pub associated_cert_subject: Option<String>,
    pub pem: Option<String>,
}

#[derive(Debug)]
pub struct PublicKeyInfo {
    pub kind: CertObjectKind,
    pub algorithm: String,
    pub key_info: HashMap<String, Value>,
    pub pem: Option<String>,
}

#[derive(Debug)]
pub struct CsrInfo {
    pub kind: CertObjectKind,
    pub subject: HashMap<String, Value>,
    pub fingerprints: HashMap<String, String>,
    pub public_key: HashMap<String, Value>,
    pub extensions: HashMap<String, Value>,
    pub pem: Option<String>,
}

#[derive(Debug)]
pub enum CertObject {
    Certificate(CertificateInfo),
    PrivateKey(PrivateKeyInfo),
    PublicKey(PublicKeyInfo),
    Csr(CsrInfo),
}

#[derive(Debug)]
pub struct CertInfoResponse {
    pub cert_type: CertObjectKind,
    pub encoding: String,
    pub objects: Vec<CertObject>,
}

#[derive(Debug)]
pub struct CertVerifyResponse {
    pub ok: bool,
    pub target: String,
    pub cert_type: CertObjectKind,
    pub encoding: String,
    pub checks: HashMap<String, CheckResult>,
    pub chain_report: Vec<ChainLink>,
    pub warnings: Vec<String>,
    pub policy: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ChainLink {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub is_ca: bool,
    pub is_trust_anchor: bool,
}

#[derive(Debug)]
pub struct SignerInfo {
    pub mode: String,
    pub signer_ca: Option<String>,
    pub signer_key: Option<String>,
}

impl CertHandle {
    pub fn from_url(url: Url) -> Result<Self> {
        // In-URL help forms (cert://--help, cert://-h, cert://--help=<verb>).
        // Exact matches only, so targets such as /home/x/my-hosts.pem are not help.
        let path = url.path();
        let host = url.host_str().unwrap_or("");
        let is_help = |s: &str| {
            help::is_help_flag(s) || s.trim_start_matches(['/', '.']).starts_with("--help=")
        };
        if is_help(host) || (host.is_empty() && is_help(path)) {
            // Return a dummy handle - help will be detected in call()
            return Ok(Self {
                target_path: "help".to_string(),
            });
        }

        // Extract the target path from the URL
        let target_path = match url.host_str() {
            // cert://./relative/path or cert://name/path
            Some(host) if !host.is_empty() => format!("{}{}", host, url.path()),
            // cert:///absolute/path keeps its leading slash
            _ => url.path().to_string(),
        };

        if target_path.is_empty() {
            bail!("cert URL must contain a target path");
        }

        Ok(CertHandle { target_path })
    }

    fn calculate_fingerprints(&self, cert_der: &[u8]) -> HashMap<String, String> {
        let mut fingerprints = HashMap::new();

        // SHA256 fingerprint
        let sha256_hash = digest(&SHA256, cert_der);
        let sha256_hex = hex::encode_upper(sha256_hash.as_ref())
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        fingerprints.insert("sha256".to_string(), sha256_hex);

        fingerprints
    }

    /// Default path of the existing private key for a certificate:
    /// `<stem>-key.pem`, matching what generate writes.
    fn derive_existing_key_path(&self) -> String {
        let t = &self.target_path;
        match t.strip_suffix(".pem").or_else(|| t.strip_suffix(".crt")) {
            Some(stem) => format!("{}-key.pem", stem),
            None => format!("{}-key.pem", t),
        }
    }

    fn derive_renewed_cert_path(&self) -> String {
        let t = &self.target_path;
        if let Some(stem) = t.strip_suffix(".pem") {
            format!("{}-renewed.pem", stem)
        } else if let Some(stem) = t.strip_suffix(".crt") {
            format!("{}-renewed.crt", stem)
        } else {
            format!("{}-renewed.pem", t)
        }
    }

    fn derive_renewed_key_path(&self, cert_path: &str) -> String {
        match cert_path
            .strip_suffix(".pem")
            .or_else(|| cert_path.strip_suffix(".crt"))
        {
            Some(stem) => format!("{}-key.pem", stem),
            None => format!("{}-key.pem", cert_path),
        }
    }

    /// Parameters for a renewed certificate: the old certificate's subject
    /// DN, SANs, key usage, extended key usage, and basic constraints, then
    /// the overrides and validity settings from `opts`.
    fn build_renewal_params(
        &self,
        opts: &CertRenewOptions,
        old_der: &[u8],
        key_pair: KeyPair,
        rekeyed: bool,
    ) -> Result<CertificateParams> {
        let (_, old) = X509Certificate::from_der(old_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse old certificate: {}", e))?;
        let alg = key_pair.algorithm();
        let mut params = CertificateParams::from_ca_cert_der(old_der, key_pair).map_err(|e| {
            anyhow::anyhow!("Failed to copy fields from the old certificate: {}", e)
        })?;
        params.alg = alg;
        params.serial_number = Some(random_serial());
        if rekeyed {
            // The old subject key identifier belongs to the old key.
            params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        }

        // Subject
        match (&opts.subject_override, opts.copy_subject) {
            (Some(sub), true) => {
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
                    if values.is_empty() {
                        continue;
                    }
                    params.distinguished_name.remove(ty.clone());
                    for v in values {
                        params.distinguished_name.push(ty.clone(), v);
                    }
                }
            }
            (Some(sub), false) => params.distinguished_name = build_distinguished_name(sub)?,
            (None, true) => {}
            (None, false) => params.distinguished_name = DistinguishedName::new(),
        }

        // SANs
        if let Some(sans) = &opts.sans_override {
            params.subject_alt_names = parse_san_list(sans)?;
        } else if !opts.copy_sans {
            params.subject_alt_names.clear();
        }

        // Key usage and extended key usage
        if let Some(ku) = &opts.key_usage_override {
            params.key_usages = ku.iter().map(rcgen_key_usage).collect();
        } else if !opts.copy_key_usage {
            params.key_usages.clear();
        }
        if let Some(eku) = &opts.extended_key_usage_override {
            params.extended_key_usages = eku.iter().map(rcgen_extended_key_usage).collect();
        } else if !opts.copy_extended_key_usage {
            params.extended_key_usages.clear();
        }

        // Basic constraints
        let constraint = |n: Option<u8>| match n {
            Some(n) => BasicConstraints::Constrained(n),
            None => BasicConstraints::Unconstrained,
        };
        match opts.is_ca {
            Some(true) => {
                let old_len = match &params.is_ca {
                    IsCa::Ca(BasicConstraints::Constrained(n)) => Some(*n),
                    _ => None,
                };
                params.is_ca = IsCa::Ca(constraint(opts.path_len.or(old_len)));
            }
            Some(false) => params.is_ca = IsCa::ExplicitNoCa,
            None => {
                if let (Some(n), IsCa::Ca(_)) = (opts.path_len, &params.is_ca) {
                    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(n));
                }
            }
        }

        // Validity
        let not_before = if opts.carry_over_start {
            NotBeforeSetting::Explicit(
                DateTime::from_timestamp(old.validity().not_before.timestamp(), 0)
                    .unwrap_or_else(Utc::now),
            )
        } else {
            opts.not_before.clone()
        };
        let (start, end) =
            validity_window(&not_before, opts.not_after, opts.not_after_offset_days)?;
        params.not_before = to_offset_datetime(start)?;
        params.not_after = to_offset_datetime(end)?;

        Ok(params)
    }

    fn compute_fingerprints(
        &self,
        der_bytes: &[u8],
        algorithms: &[String],
    ) -> HashMap<String, String> {
        algorithms
            .iter()
            .filter_map(|alg| fingerprint(alg, der_bytes).map(|fp| (alg.clone(), fp)))
            .collect()
    }

    fn parse_name(&self, name: &X509Name) -> HashMap<String, Value> {
        name_to_map(name)
    }

    fn parse_public_key(&self, public_key: &SubjectPublicKeyInfo) -> HashMap<String, Value> {
        let key = describe_spki(public_key);
        let mut key_info = HashMap::new();
        let name = match key.algorithm.as_str() {
            "rsa" => "RSA".to_string(),
            "ecdsa" => "ECDSA".to_string(),
            "ed25519" => "Ed25519".to_string(),
            other => other.to_string(),
        };
        key_info.insert("algorithm".to_string(), json!(name));
        if let Some(bits) = key.bits {
            key_info.insert("key_size".to_string(), json!(bits));
        }
        if let Some(curve) = key.curve {
            key_info.insert("curve".to_string(), json!(curve));
        }
        key_info
    }

    fn parse_extensions(&self, extensions: &[X509Extension]) -> HashMap<String, Value> {
        let mut key_usage = Vec::new();
        let mut eku = Vec::new();
        let mut sans = Vec::new();
        let mut ext_map = HashMap::new();
        for ext in extensions {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
                    let flags = [
                        (ku.digital_signature(), "digitalSignature"),
                        (ku.non_repudiation(), "contentCommitment"),
                        (ku.key_encipherment(), "keyEncipherment"),
                        (ku.data_encipherment(), "dataEncipherment"),
                        (ku.key_agreement(), "keyAgreement"),
                        (ku.key_cert_sign(), "keyCertSign"),
                        (ku.crl_sign(), "cRLSign"),
                        (ku.encipher_only(), "encipherOnly"),
                        (ku.decipher_only(), "decipherOnly"),
                    ];
                    key_usage.extend(
                        flags
                            .iter()
                            .filter(|(set, _)| *set)
                            .map(|(_, n)| n.to_string()),
                    );
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    let flags = [
                        (e.any, "anyExtendedKeyUsage"),
                        (e.server_auth, "serverAuth"),
                        (e.client_auth, "clientAuth"),
                        (e.code_signing, "codeSigning"),
                        (e.email_protection, "emailProtection"),
                        (e.time_stamping, "timeStamping"),
                        (e.ocsp_signing, "ocspSigning"),
                    ];
                    eku.extend(
                        flags
                            .iter()
                            .filter(|(set, _)| *set)
                            .map(|(_, n)| n.to_string()),
                    );
                    eku.extend(e.other.iter().map(|o| o.to_id_string()));
                }
                ParsedExtension::SubjectAlternativeName(san) => {
                    sans.extend(san.general_names.iter().map(general_name_string));
                }
                ParsedExtension::BasicConstraints(bc) => {
                    ext_map.insert(
                        "basic_constraints".to_string(),
                        json!({ "ca": bc.ca, "path_len": bc.path_len_constraint, "critical": ext.critical }),
                    );
                }
                ParsedExtension::SubjectKeyIdentifier(id) => {
                    ext_map.insert("subject_key_id".to_string(), json!(colon_hex(id.0)));
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    if let Some(id) = &aki.key_identifier {
                        ext_map.insert("authority_key_id".to_string(), json!(colon_hex(id.0)));
                    }
                }
                _ => {}
            }
        }
        ext_map.insert("key_usage".to_string(), json!(key_usage));
        ext_map.insert("extended_key_usage".to_string(), json!(eku));
        ext_map.insert("subject_alt_names".to_string(), json!(sans));
        ext_map
    }

    fn is_ca_certificate(&self, extensions: &[X509Extension]) -> bool {
        extensions.iter().any(
            |ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(bc) if bc.ca),
        )
    }

    fn parse_certificate(
        &self,
        cert: &X509Certificate,
        der_bytes: &[u8],
        opts: &CertInfoOptions,
    ) -> Result<CertificateInfo> {
        let serial_hex = hex::encode_upper(cert.tbs_certificate.raw_serial());

        let subject = self.parse_name(&cert.tbs_certificate.subject);
        let issuer = self.parse_name(&cert.tbs_certificate.issuer);

        let not_before = asn1_time_rfc3339(&cert.tbs_certificate.validity.not_before);
        let not_after = asn1_time_rfc3339(&cert.tbs_certificate.validity.not_after);

        let now = Utc::now().timestamp();
        let is_currently_valid = cert.tbs_certificate.validity.not_before.timestamp() <= now
            && now <= cert.tbs_certificate.validity.not_after.timestamp();

        let validity = [
            ("not_before".to_string(), json!(not_before)),
            ("not_after".to_string(), json!(not_after)),
            ("is_currently_valid".to_string(), json!(is_currently_valid)),
        ]
        .into_iter()
        .collect();

        let public_key = self.parse_public_key(&cert.tbs_certificate.subject_pki);
        let extensions = self.parse_extensions(cert.tbs_certificate.extensions());
        let is_ca = self.is_ca_certificate(cert.tbs_certificate.extensions());

        let fingerprints = self.compute_fingerprints(der_bytes, &opts.fingerprint_algs);

        Ok(CertificateInfo {
            kind: CertObjectKind::Certificate,
            version: cert.tbs_certificate.version.0,
            serial_number: serial_hex,
            subject,
            issuer,
            validity,
            public_key,
            fingerprints,
            extensions,
            is_ca,
            pem: if opts.include_pem {
                Some(pem_encode_lf(&Pem::new("CERTIFICATE", der_bytes.to_vec())))
            } else {
                None
            },
            raw_der_base64: if opts.include_raw {
                Some(BASE64_STANDARD.encode(der_bytes))
            } else {
                None
            },
        })
    }

    fn parse_csr_info(&self, der: &[u8], opts: &CertInfoOptions) -> Result<CsrInfo> {
        use x509_parser::certification_request::X509CertificationRequest;
        let (_, csr) = X509CertificationRequest::from_der(der)
            .map_err(|e| anyhow::anyhow!("Failed to parse CSR: {}", e))?;
        let info = &csr.certification_request_info;
        let mut extensions = HashMap::new();
        let mut sans = Vec::new();
        let mut other = 0usize;
        if let Some(exts) = csr.requested_extensions() {
            for ext in exts {
                match ext {
                    ParsedExtension::SubjectAlternativeName(san) => {
                        sans.extend(san.general_names.iter().map(general_name_string))
                    }
                    _ => other += 1,
                }
            }
        }
        extensions.insert("subject_alt_names".to_string(), json!(sans));
        if other > 0 {
            extensions.insert("other_requested_extensions".to_string(), json!(other));
        }
        let mut public_key = self.parse_public_key(&info.subject_pki);
        public_key.insert(
            "signature_valid".to_string(),
            match verify_signature_with_key(
                &csr.signature_algorithm.algorithm.to_id_string(),
                &info.subject_pki,
                info.raw,
                &csr.signature_value.data,
            ) {
                SignatureCheck::Valid => json!(true),
                SignatureCheck::Invalid => json!(false),
                SignatureCheck::Unsupported(_) => Value::Null,
            },
        );
        Ok(CsrInfo {
            kind: CertObjectKind::Csr,
            subject: self.parse_name(&info.subject),
            fingerprints: self.compute_fingerprints(der, &opts.fingerprint_algs),
            public_key,
            extensions,
            pem: if opts.include_pem {
                Some(pem_encode_lf(&Pem::new(
                    "CERTIFICATE REQUEST",
                    der.to_vec(),
                )))
            } else {
                None
            },
        })
    }

    fn private_key_info(
        &self,
        block: &::pem::Pem,
        encoding: &str,
        opts: &CertInfoOptions,
    ) -> PrivateKeyInfo {
        let tag = block.tag();
        let is_encrypted = tag == "ENCRYPTED PRIVATE KEY"
            || block
                .headers()
                .get("Proc-Type")
                .map(|v| v.contains("ENCRYPTED"))
                .unwrap_or(false);
        let (algorithm, key_format) = match tag {
            "RSA PRIVATE KEY" => ("RSA".to_string(), "pkcs1"),
            "EC PRIVATE KEY" => ("ECDSA".to_string(), "sec1"),
            "ENCRYPTED PRIVATE KEY" => ("unknown (encrypted)".to_string(), "pkcs8"),
            _ => {
                let alg = match rcgen_keypair_from_bytes(&pem_encode_lf(block).into_bytes(), "key")
                {
                    Ok(kp) => match signature_algorithm_label(kp.algorithm()) {
                        "rsa" => "RSA".to_string(),
                        "ed25519" => "Ed25519".to_string(),
                        other => other.replace("ecdsa", "ECDSA"),
                    },
                    Err(_) => "Unknown".to_string(),
                };
                (alg, "pkcs8")
            }
        };
        let mut key_info = HashMap::new();
        key_info.insert("key_format".to_string(), json!(key_format));
        PrivateKeyInfo {
            kind: CertObjectKind::PrivateKey,
            algorithm,
            encoding: encoding.to_string(),
            is_encrypted,
            key_info,
            associated_cert_subject: None,
            pem: if opts.include_pem {
                Some(pem_encode_lf(block))
            } else {
                None
            },
        }
    }

    fn parse_pem_content(&self, data: &[u8], opts: &CertInfoOptions) -> Result<CertInfoResponse> {
        let mut objects = Vec::new();
        let mut cert_count = 0;
        for block in pem_blocks(data) {
            match block.tag() {
                "CERTIFICATE" => {
                    let (_, cert) = X509Certificate::from_der(block.contents()).map_err(|e| {
                        anyhow::anyhow!("Failed to parse certificate from PEM data: {}", e)
                    })?;
                    objects.push(CertObject::Certificate(self.parse_certificate(
                        &cert,
                        block.contents(),
                        opts,
                    )?));
                    cert_count += 1;
                }
                "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                    objects.push(CertObject::Csr(
                        self.parse_csr_info(block.contents(), opts)?,
                    ));
                }
                tag if tag.ends_with("PRIVATE KEY") => {
                    objects.push(CertObject::PrivateKey(
                        self.private_key_info(&block, "pem", opts),
                    ));
                }
                "PUBLIC KEY" => {
                    let info = match SubjectPublicKeyInfo::from_der(block.contents()) {
                        Ok((_, spki)) => self.parse_public_key(&spki),
                        Err(_) => HashMap::new(),
                    };
                    let algorithm = info
                        .get("algorithm")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    objects.push(CertObject::PublicKey(PublicKeyInfo {
                        kind: CertObjectKind::PublicKey,
                        algorithm,
                        key_info: info,
                        pem: if opts.include_pem {
                            Some(pem_encode_lf(&block))
                        } else {
                            None
                        },
                    }));
                }
                _ => {}
            }
        }

        if objects.is_empty() {
            bail!("Unrecognized PEM content");
        }

        let cert_type = if cert_count > 1 {
            CertObjectKind::CertificateChain
        } else {
            match &objects[0] {
                CertObject::Certificate(_) => CertObjectKind::Certificate,
                CertObject::PrivateKey(_) => CertObjectKind::PrivateKey,
                CertObject::PublicKey(_) => CertObjectKind::PublicKey,
                CertObject::Csr(_) => CertObjectKind::Csr,
            }
        };

        Ok(CertInfoResponse {
            cert_type,
            encoding: "pem".to_string(),
            objects,
        })
    }

    fn parse_der_content(&self, data: &[u8], opts: &CertInfoOptions) -> Result<CertInfoResponse> {
        // Try to parse as X.509 certificate first
        if let Ok((_, cert)) = X509Certificate::from_der(data) {
            let cert_info = self.parse_certificate(&cert, data, opts)?;

            return Ok(CertInfoResponse {
                cert_type: CertObjectKind::Certificate,
                encoding: "der".to_string(),
                objects: vec![CertObject::Certificate(cert_info)],
            });
        }

        if let Ok(csr) = self.parse_csr_info(data, opts) {
            return Ok(CertInfoResponse {
                cert_type: CertObjectKind::Csr,
                encoding: "der".to_string(),
                objects: vec![CertObject::Csr(csr)],
            });
        }

        if rcgen_keypair_from_bytes(data, "key").is_ok() {
            let block = Pem::new("PRIVATE KEY", data.to_vec());
            let mut info = self.private_key_info(&block, "der", opts);
            if RsaPrivateKey::from_pkcs1_der(data).is_ok() {
                info.algorithm = "RSA".to_string();
                info.key_info
                    .insert("key_format".to_string(), json!("pkcs1"));
            }
            return Ok(CertInfoResponse {
                cert_type: CertObjectKind::PrivateKey,
                encoding: "der".to_string(),
                objects: vec![CertObject::PrivateKey(info)],
            });
        }

        if keyenc::is_encrypted(data) {
            let block = Pem::new(keyenc::ENCRYPTED_LABEL, data.to_vec());
            return Ok(CertInfoResponse {
                cert_type: CertObjectKind::PrivateKey,
                encoding: "der".to_string(),
                objects: vec![CertObject::PrivateKey(
                    self.private_key_info(&block, "der", opts),
                )],
            });
        }

        bail!("not a DER certificate, CSR or private key")
    }
    // Verification methods for the verify verb
    fn verify_certificate_structure(
        &self,
        cert: &X509Certificate,
        opts: &CertVerifyOptions,
    ) -> CheckResult {
        // X509Version is zero-based: 0 = v1, 1 = v2, 2 = v3.
        if cert.tbs_certificate.version.0 > 2 {
            return CheckResult::fail(
                &format!(
                    "Unsupported certificate version: {}",
                    cert.tbs_certificate.version.0 + 1
                ),
                "cert.unsupported_version",
            );
        }

        let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
        if sig_oid != cert.tbs_certificate.signature.algorithm.to_id_string() {
            return CheckResult::fail(
                "Outer signature algorithm does not match the algorithm in the signed certificate body",
                "cert.signature_algorithm_mismatch",
            );
        }

        if is_weak_signature_algorithm(&sig_oid) {
            return CheckResult::fail(
                &format!(
                    "Certificate uses weak signature algorithm {}",
                    signature_algorithm_name(&sig_oid)
                ),
                "cert.weak_signature",
            );
        }

        let key = describe_spki(cert.public_key());
        if key.algorithm == "rsa" {
            let bits = key.bits.unwrap_or(0);
            if bits < opts.min_rsa_bits as usize {
                return CheckResult::fail(
                    &format!(
                        "RSA key is {} bits; policy requires at least {}",
                        bits, opts.min_rsa_bits
                    ),
                    "cert.weak_key",
                );
            }
        }

        CheckResult::ok(&format!(
            "Certificate parsed (X.509 v{}, {}, {}{} key)",
            cert.tbs_certificate.version.0 + 1,
            signature_algorithm_name(&sig_oid),
            key.algorithm,
            key.bits.map(|b| format!(" {}-bit", b)).unwrap_or_default()
        ))
    }

    fn verify_certificate_time(
        &self,
        cert: &X509Certificate,
        opts: &CertVerifyOptions,
    ) -> CheckResult {
        let now = Utc::now().timestamp();
        let not_before = cert.tbs_certificate.validity.not_before.timestamp();
        let not_after = cert.tbs_certificate.validity.not_after.timestamp();

        if now < not_before {
            if opts.allow_not_yet_valid {
                return CheckResult::ok("Certificate not yet valid (allowed by policy)");
            } else {
                return CheckResult::fail("Certificate not yet valid", "cert.not_yet_valid");
            }
        }

        if now > not_after {
            if opts.allow_expired {
                return CheckResult::ok("Certificate expired (allowed by policy)");
            } else {
                return CheckResult::fail("Certificate has expired", "cert.expired");
            }
        }

        CheckResult::ok("Certificate is currently valid")
    }

    fn verify_revocation(&self, _cert: &X509Certificate, opts: &CertVerifyOptions) -> CheckResult {
        match opts.check_revocation {
            RevocationMode::None => {
                CheckResult::skipped("Revocation checking disabled (check_revocation=none)")
            }
            RevocationMode::Soft => CheckResult::not_checked(
                "Revocation was not checked: CRL and OCSP lookups are not implemented (soft mode does not fail)",
            ),
            RevocationMode::Hard => CheckResult::unsupported(
                "Revocation checking (CRL and OCSP) is not implemented, so check_revocation=hard cannot pass",
                "cert.revocation_not_implemented",
            ),
        }
    }
    fn create_policy_json(&self, opts: &CertVerifyOptions) -> serde_json::Value {
        json!({
            "purpose": match opts.purpose {
                Purpose::ServerAuth => "server_auth",
                Purpose::ClientAuth => "client_auth",
                Purpose::CodeSigning => "code_signing",
                Purpose::EmailProtection => "email_protection",
                Purpose::Any => "any",
            },
            "hostname": opts.hostname,
            "trust": match opts.trust {
                TrustMode::System => "system",
                TrustMode::Mount => "mount",
                TrustMode::Inline => "inline",
            },
            "check_revocation": match opts.check_revocation {
                RevocationMode::None => "none",
                RevocationMode::Soft => "soft",
                RevocationMode::Hard => "hard",
            },
            "min_rsa_bits": opts.min_rsa_bits,
            "allow_self_signed": opts.allow_self_signed,
            "allow_expired": opts.allow_expired,
            "allow_not_yet_valid": opts.allow_not_yet_valid,
            "max_chain_depth": opts.max_chain_depth
        })
    }

    fn verify_json(&self, response: &CertVerifyResponse) -> Value {
        let mut checks_json = serde_json::Map::new();
        for (name, check) in &response.checks {
            let check_json = json!({
                "ok": check.ok,
                "status": check.status.as_str(),
                "message": check.message,
                "error_code": check.error_code
            });
            checks_json.insert(name.clone(), check_json);
        }

        let mut chain_report_json = Vec::new();
        for link in &response.chain_report {
            chain_report_json.push(json!({
                "index": link.index,
                "subject": link.subject,
                "issuer": link.issuer,
                "is_ca": link.is_ca,
                "is_trust_anchor": link.is_trust_anchor
            }));
        }

        let response_json = json!({
            "ok": response.ok,
            "target": response.target,
            "type": match response.cert_type {
                CertObjectKind::Certificate => "certificate",
                CertObjectKind::CertificateChain => "certificate_chain",
                CertObjectKind::PrivateKey => "private_key",
                CertObjectKind::PublicKey => "public_key",
                CertObjectKind::Csr => "csr",
                CertObjectKind::Unknown => "unknown",
            },
            "encoding": response.encoding,
            "checks": checks_json,
            "chain_report": chain_report_json,
            "warnings": response.warnings,
            "policy": response.policy
        });

        response_json
    }

    fn format_verify_text(&self, response: &CertVerifyResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Target: {}\n", response.target));
        output.push_str(&format!(
            "Type: {} ({})\n",
            match response.cert_type {
                CertObjectKind::Certificate => "certificate",
                CertObjectKind::CertificateChain => "certificate_chain",
                CertObjectKind::PrivateKey => "private_key",
                CertObjectKind::PublicKey => "public_key",
                CertObjectKind::Csr => "csr",
                CertObjectKind::Unknown => "unknown",
            },
            response.encoding
        ));
        output.push_str(&format!(
            "Overall: {}\n\n",
            if response.ok { "OK" } else { "FAILED" }
        ));

        // Check results
        let check_order = [
            "structure",
            "chain",
            "time",
            "hostname",
            "usage",
            "keypair",
            "revocation",
        ];
        for check_name in &check_order {
            if let Some(check) = response.checks.get(*check_name) {
                output.push_str(&format!("[{}]\n", check_name.to_uppercase()));
                output.push_str(&format!("  {}: {}\n", check.status.label(), check.message));
                if let Some(error_code) = &check.error_code {
                    output.push_str(&format!("  Error Code: {}\n", error_code));
                }
                output.push('\n');
            }
        }

        // Chain report
        if !response.chain_report.is_empty() {
            output.push_str("[Chain Report]\n");
            for link in &response.chain_report {
                output.push_str(&format!(
                    "  {}: {}{}\n",
                    link.index,
                    link.subject,
                    if link.is_trust_anchor {
                        " (TRUSTED)"
                    } else {
                        ""
                    }
                ));
            }
            output.push('\n');
        }

        // Warnings
        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    fn info_json(&self, response: &CertInfoResponse) -> Value {
        let mut json_objects = Vec::new();

        for obj in &response.objects {
            let json_obj = match obj {
                CertObject::Certificate(cert) => {
                    let mut obj = json!({
                        "kind": "certificate",
                        "version": cert.version,
                        "serial_number": cert.serial_number,
                        "subject": cert.subject,
                        "issuer": cert.issuer,
                        "validity": cert.validity,
                        "public_key": cert.public_key,
                        "fingerprints": cert.fingerprints,
                        "extensions": cert.extensions,
                        "is_ca": cert.is_ca
                    });

                    if let Some(pem) = &cert.pem {
                        obj["pem"] = json!(pem);
                    }
                    if let Some(raw) = &cert.raw_der_base64 {
                        obj["raw_der_base64"] = json!(raw);
                    }

                    obj
                }
                CertObject::PrivateKey(key) => {
                    let mut obj = json!({
                        "kind": "private_key",
                        "algorithm": key.algorithm,
                        "encoding": key.encoding,
                        "is_encrypted": key.is_encrypted
                    });

                    for (k, v) in &key.key_info {
                        obj[k] = v.clone();
                    }

                    if let Some(subject) = &key.associated_cert_subject {
                        obj["associated_cert_subject"] = json!(subject);
                    }
                    if let Some(pem) = &key.pem {
                        obj["pem"] = json!(pem);
                    }

                    obj
                }
                CertObject::PublicKey(key) => {
                    let mut obj = json!({
                        "kind": "public_key",
                        "algorithm": key.algorithm
                    });

                    for (k, v) in &key.key_info {
                        obj[k] = v.clone();
                    }

                    if let Some(pem) = &key.pem {
                        obj["pem"] = json!(pem);
                    }

                    obj
                }
                CertObject::Csr(csr) => {
                    let mut obj = json!({
                        "kind": "csr",
                        "subject": csr.subject,
                        "fingerprints": csr.fingerprints,
                        "public_key": csr.public_key,
                        "extensions": csr.extensions
                    });

                    if let Some(pem) = &csr.pem {
                        obj["pem"] = json!(pem);
                    }

                    obj
                }
            };

            json_objects.push(json_obj);
        }

        let response_json = json!({
            "type": format!("{:?}", response.cert_type).to_lowercase(),
            "encoding": response.encoding,
            "objects": json_objects
        });

        response_json
    }

    // Renewal helper methods
    fn parse_der_certificate_for_renewal(&self, data: &[u8]) -> Result<ParsedCertificate> {
        let (_, cert) = X509Certificate::from_der(data)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

        Ok(ParsedCertificate {
            subject: self.extract_subject_info(&cert)?,
            issuer: self.extract_issuer_info(&cert)?,
            validity: self.extract_validity_info(&cert)?,
            is_ca: is_ca_cert(&cert),
            self_issued: is_self_issued(&cert),
            fingerprints: self.calculate_fingerprints(data),
        })
    }

    fn determine_signer_strategy(
        &self,
        opts: &CertRenewOptions,
        old_cert: &ParsedCertificate,
        warnings: &mut Vec<String>,
    ) -> Result<Option<SignerInfo>> {
        match &opts.renewal_mode {
            CertRenewalMode::SelfSigned => Ok(Some(SignerInfo {
                mode: "self_signed".to_string(),
                signer_ca: None,
                signer_key: None,
            })),
            CertRenewalMode::ExplicitSigner => {
                if let (Some(ca), Some(key)) = (&opts.signer_ca, &opts.signer_key) {
                    Ok(Some(SignerInfo {
                        mode: "explicit_signer".to_string(),
                        signer_ca: Some(ca.clone()),
                        signer_key: Some(key.clone()),
                    }))
                } else {
                    warnings.push(
                        "explicit_signer mode requires both signer_ca and signer_key".to_string(),
                    );
                    Ok(None)
                }
            }
            CertRenewalMode::Auto => {
                // Check if old cert is self-signed
                if self.is_self_signed(old_cert) {
                    Ok(Some(SignerInfo {
                        mode: "auto".to_string(),
                        signer_ca: None,
                        signer_key: None,
                    }))
                } else {
                    // Need explicit signer for CA-signed certs
                    if let (Some(ca), Some(key)) = (&opts.signer_ca, &opts.signer_key) {
                        Ok(Some(SignerInfo {
                            mode: "auto".to_string(),
                            signer_ca: Some(ca.clone()),
                            signer_key: Some(key.clone()),
                        }))
                    } else {
                        warnings.push(
                            "Auto mode for CA-signed certificate requires signer_ca and signer_key"
                                .to_string(),
                        );
                        Ok(None)
                    }
                }
            }
        }
    }

    // Utility methods for certificate parsing
    fn extract_subject_info(
        &self,
        cert: &X509Certificate,
    ) -> Result<HashMap<String, serde_json::Value>> {
        Ok(name_to_map(cert.subject()))
    }

    fn extract_issuer_info(
        &self,
        cert: &X509Certificate,
    ) -> Result<HashMap<String, serde_json::Value>> {
        Ok(name_to_map(cert.issuer()))
    }

    fn extract_validity_info(&self, cert: &X509Certificate) -> Result<HashMap<String, String>> {
        let mut validity = HashMap::new();
        validity.insert(
            "not_before".to_string(),
            asn1_time_rfc3339(&cert.validity().not_before),
        );
        validity.insert(
            "not_after".to_string(),
            asn1_time_rfc3339(&cert.validity().not_after),
        );
        Ok(validity)
    }

    fn is_self_signed(&self, cert: &ParsedCertificate) -> bool {
        cert.self_issued
    }
}

// Renewal supporting types
#[derive(Debug)]
struct ParsedCertificate {
    subject: HashMap<String, serde_json::Value>,
    issuer: HashMap<String, serde_json::Value>,
    validity: HashMap<String, String>,
    is_ca: bool,
    self_issued: bool,
    fingerprints: HashMap<String, String>,
}

// Helper types for signing
#[derive(Debug)]
enum SignerKey {
    Rsa(RsaPrivateKey),
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
    Ed25519(Ed25519SigningKey),
}

impl CertHandle {
    fn default_signature_algorithm(&self, key: &SignerKey) -> Result<SignatureAlgorithm> {
        match key {
            SignerKey::Rsa(_) => Ok(SignatureAlgorithm::RsaPssSha256),
            SignerKey::EcdsaP256(_) => Ok(SignatureAlgorithm::EcdsaSha256),
            SignerKey::EcdsaP384(_) => Ok(SignatureAlgorithm::EcdsaSha384),
            SignerKey::Ed25519(_) => Ok(SignatureAlgorithm::Ed25519),
        }
    }

    fn create_signature(
        &self,
        data: &[u8],
        key: &SignerKey,
        algorithm: &SignatureAlgorithm,
    ) -> Result<Vec<u8>> {
        match (key, algorithm) {
            (SignerKey::Rsa(rsa_key), SignatureAlgorithm::RsaPssSha256) => {
                let mut rng = OsRng;
                let hash = sha2::Sha256::digest(data);
                let padding = Pss::new::<sha2::Sha256>();
                let signature = rsa_key.sign_with_rng(&mut rng, padding, &hash)?;
                Ok(signature)
            }
            (SignerKey::Rsa(rsa_key), SignatureAlgorithm::RsaPkcs1Sha256) => {
                let hash = sha2::Sha256::digest(data);
                let padding = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
                Ok(rsa_key.sign(padding, &hash)?)
            }
            (SignerKey::Rsa(rsa_key), SignatureAlgorithm::RsaPssSha384) => {
                let mut rng = OsRng;
                let hash = sha2::Sha384::digest(data);
                let padding = Pss::new::<sha2::Sha384>();
                let signature = rsa_key.sign_with_rng(&mut rng, padding, &hash)?;
                Ok(signature)
            }
            (SignerKey::Rsa(rsa_key), SignatureAlgorithm::RsaPkcs1Sha384) => {
                let hash = sha2::Sha384::digest(data);
                let padding = rsa::Pkcs1v15Sign::new::<sha2::Sha384>();
                Ok(rsa_key.sign(padding, &hash)?)
            }
            (SignerKey::EcdsaP256(ecdsa_key), SignatureAlgorithm::EcdsaSha256) => {
                let signature: P256Signature = ecdsa_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            (SignerKey::EcdsaP384(ecdsa_key), SignatureAlgorithm::EcdsaSha384) => {
                let signature: P384Signature = ecdsa_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            (SignerKey::EcdsaP384(ecdsa_key), SignatureAlgorithm::EcdsaSha512) => {
                // ECDSA over a SHA-512 digest. `sign` would hash with the
                // curve's default SHA-384; sign_prehash takes the SHA-512
                // digest and uses its leftmost 384 bits, as ECDSA specifies
                // for a digest longer than the group order (FIPS 186-5).
                use p384::ecdsa::signature::hazmat::PrehashSigner;
                let digest = sha2::Sha512::digest(data);
                let signature: P384Signature = ecdsa_key.sign_prehash(&digest)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            (SignerKey::Ed25519(ed25519_key), SignatureAlgorithm::Ed25519) => {
                let signature: Ed25519Signature = ed25519_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            _ => bail!(
                "Unsupported key/algorithm combination: a {} key cannot sign with {:?}; nothing was signed",
                signer_key_label(key),
                algorithm
            ),
        }
    }

    /// Builds a DER-encoded CMS (RFC 5652) ContentInfo holding a SignedData
    /// over `data`: one SignerInfo identified by the issuer and serial number
    /// of `signer_cert`, with content-type, message-digest and signing-time
    /// signed attributes, and `signer_cert` in `certificates`. With
    /// `attached` the data is carried as eContent; otherwise the SignedData
    /// is detached. Ed25519 follows RFC 8419 (SHA-512 message digest).
    fn create_cms_signature(
        &self,
        data: &[u8],
        key: &SignerKey,
        algorithm: &SignatureAlgorithm,
        signer_cert: &x509_cert::Certificate,
        attached: bool,
    ) -> Result<Vec<u8>> {
        use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
        use cms::content_info::{CmsVersion, ContentInfo};
        use cms::signed_data::{
            CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
            SignerInfos,
        };
        use const_oid::db::rfc5911::{
            ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNED_DATA, ID_SIGNING_TIME,
        };
        use der::asn1::{OctetString, SetOfVec};
        use der::{Any, Encode};
        use x509_cert::attr::Attribute;

        let (digest_alg, signature_alg) = cms_algorithm_identifiers(key, algorithm)?;
        let message_digest = cms_message_digest(algorithm, data);

        let attribute = |oid, value: Any| -> Result<Attribute> {
            let mut values = SetOfVec::new();
            values.insert(value)?;
            Ok(Attribute { oid, values })
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("System clock is before 1970")?;
        // RFC 5652 section 11.3: UTCTime for 1950-2049, GeneralizedTime after.
        let now = std::time::Duration::from_secs(now.as_secs());
        let signing_time = match der::asn1::UtcTime::from_unix_duration(now) {
            Ok(t) => x509_cert::time::Time::UtcTime(t),
            Err(_) => x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(now)
                    .context("Failed to encode signing-time")?,
            ),
        };
        let signed_attrs = SetOfVec::try_from(vec![
            attribute(ID_CONTENT_TYPE, Any::encode_from(&ID_DATA)?)?,
            attribute(
                ID_MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(message_digest)?)?,
            )?,
            attribute(ID_SIGNING_TIME, Any::encode_from(&signing_time)?)?,
        ])?;

        // RFC 5652 section 5.4: the signature covers the DER encoding of the
        // signed attributes with an explicit SET OF tag.
        let signature = self.create_signature(&signed_attrs.to_der()?, key, algorithm)?;

        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: signer_cert.tbs_certificate.issuer.clone(),
                serial_number: signer_cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: signature_alg,
            signature: OctetString::new(signature)?,
            unsigned_attrs: None,
        };

        let mut certificates = SetOfVec::new();
        certificates.insert(CertificateChoices::Certificate(signer_cert.clone()))?;
        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms.insert(digest_alg)?;
        let mut signer_infos = SetOfVec::new();
        signer_infos.insert(signer_info)?;

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_DATA,
                econtent: if attached {
                    Some(Any::encode_from(&OctetString::new(data)?)?)
                } else {
                    None
                },
            },
            certificates: Some(CertificateSet(certificates)),
            crls: None,
            signer_infos: SignerInfos(signer_infos),
        };

        let content_info = ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data)?,
        };
        Ok(content_info.to_der()?)
    }

    fn encode_signature(
        &self,
        signature: &[u8],
        encoding: &SignatureEncoding,
        pem_label: &str,
    ) -> Result<Vec<u8>> {
        match encoding {
            SignatureEncoding::Base64 => Ok(BASE64_STANDARD.encode(signature).into_bytes()),
            SignatureEncoding::Pem => {
                Ok(pem_encode_lf(&Pem::new(pem_label, signature.to_vec())).into_bytes())
            }
            SignatureEncoding::Der => Ok(signature.to_vec()),
        }
    }

    // Helper methods for csr.sign functionality (simplified implementation)
}

impl Handle for CertHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "info",
            "verify",
            "chain.info",
            "generate",
            "csr.create",
            "sign",
            "csr.sign",
            "renew",
            "help",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&CERT_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help: cert://--help, cert://--help=<verb>, or the help verb
        // (optionally with verb=<verb>).
        let help_verb = if verb == "help" || help::is_help_flag(verb) {
            Some(args.get("verb").map(String::as_str))
        } else {
            verb.strip_prefix("--help=").map(Some)
        };
        if let Some(topic) = help_verb {
            let text = help::render_legacy("cert", &CERT_HELP, self.verbs(), topic);
            write!(io.stdout, "{}", text).with_context(|| "Failed to write help text to stdout")?;
            return Ok(Status::ok());
        }

        let json = args.get("format").map(String::as_str) != Some("text");
        let (result, warnings) = self.dispatch(verb, args, &mut *io.stdin);
        for w in &warnings {
            writeln!(io.stderr, "{w}")?;
        }
        let status = match result {
            Ok(done) => {
                match done.out {
                    verbs::Out::Json(v) => {
                        writeln!(io.stdout, "{}", serde_json::to_string_pretty(&v)?)?
                    }
                    verbs::Out::Text(t) => write!(io.stdout, "{}", t)?,
                }
                done.status
            }
            Err(e) => {
                if json {
                    let v = json!({
                        "ok": false,
                        "target": self.target_path,
                        "error": e.to_json(),
                    });
                    writeln!(io.stdout, "{}", serde_json::to_string_pretty(&v)?)?;
                }
                Status::coded(e.exit, e.code, &e.message)
            }
        };
        io.stdout.flush()?;
        // main prints the error line only when the handle wrote nothing to
        // stderr; after a warning it is printed here.
        if !status.ok && !warnings.is_empty() {
            writeln!(
                io.stderr,
                "Error: {}",
                status.reason.as_deref().unwrap_or("")
            )?;
        }
        Ok(status)
    }
}

// ---------------------------------------------------------------------------
// X.509 helpers shared by info, verify, generate, sign, and renew
// ---------------------------------------------------------------------------

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";

/// Fingerprint algorithms accepted by `fingerprint_algs`.
const FINGERPRINT_ALGS: &[&str] = &["sha1", "sha256", "sha384", "sha512"];

fn encode_rsa_private_key(
    key: &RsaPrivateKey,
    format: &KeyFormat,
    encoding: &Encoding,
) -> Result<Vec<u8>> {
    match (format, encoding) {
        (KeyFormat::Pkcs8, Encoding::Pem) => {
            let pkcs8_der = key
                .to_pkcs8_der()
                .with_context(|| "Failed to encode RSA key as PKCS8")?;
            let pem = Pem::new("PRIVATE KEY", pkcs8_der.as_bytes());
            Ok(pem_encode_lf(&pem).into_bytes())
        }
        (KeyFormat::Pkcs1, Encoding::Pem) => {
            let pkcs1_der = key
                .to_pkcs1_der()
                .with_context(|| "Failed to encode RSA key as PKCS1")?;
            let pem = Pem::new("RSA PRIVATE KEY", pkcs1_der.as_bytes());
            Ok(pem_encode_lf(&pem).into_bytes())
        }
        (KeyFormat::Pkcs8, Encoding::Der) => {
            let pkcs8_der = key
                .to_pkcs8_der()
                .with_context(|| "Failed to encode RSA key as PKCS8")?;
            Ok(pkcs8_der.as_bytes().to_vec())
        }
        (KeyFormat::Pkcs1, Encoding::Der) => {
            let pkcs1_der = key
                .to_pkcs1_der()
                .with_context(|| "Failed to encode RSA key as PKCS1")?;
            Ok(pkcs1_der.as_bytes().to_vec())
        }
        _ => bail!(
            "Unsupported RSA key encoding combination: {:?} {:?}",
            format,
            encoding
        ),
    }
}

fn encode_key_pair(
    keypair: &KeyPair,
    algorithm: &CertAlgorithm,
    format: &KeyFormat,
    encoding: &Encoding,
) -> Result<Vec<u8>> {
    match algorithm {
        CertAlgorithm::Rsa => {
            let rsa_key = RsaPrivateKey::from_pkcs8_der(&keypair.serialize_der())
                .with_context(|| "Failed to parse generated RSA key")?;
            encode_rsa_private_key(&rsa_key, format, encoding)
        }
        CertAlgorithm::Ecdsa | CertAlgorithm::Ed25519 => {
            let key_der = keypair.serialize_der();
            match (format, encoding) {
                (KeyFormat::Pkcs8, Encoding::Pem) => {
                    Ok(pem_encode_lf(&Pem::new("PRIVATE KEY", key_der)).into_bytes())
                }
                (KeyFormat::Pkcs8, Encoding::Der) => Ok(key_der),
                (KeyFormat::Sec1, enc) if matches!(algorithm, CertAlgorithm::Ecdsa) => {
                    let sec1 = sec1_with_curve(&key_der)?;
                    Ok(match enc {
                        Encoding::Pem => {
                            pem_encode_lf(&Pem::new("EC PRIVATE KEY", sec1)).into_bytes()
                        }
                        Encoding::Der => sec1,
                    })
                }
                _ => bail!(
                    "Unsupported {:?} key format/encoding combination: {:?} {:?}",
                    algorithm,
                    format,
                    encoding
                ),
            }
        }
    }
}

/// The SEC1 `ECPrivateKey` of a PKCS#8 EC key, with the named curve in
/// its parameters (RFC 5915), as OpenSSL needs to read it.
fn sec1_with_curve(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    use der::{Decode, Encode};
    let info = Pkcs8PrivateKeyInfo::try_from(pkcs8_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse the EC key: {}", e))?;
    let curve = info
        .algorithm
        .parameters_oid()
        .map_err(|e| anyhow::anyhow!("EC key without a named curve: {}", e))?;
    let mut ec = sec1::EcPrivateKey::from_der(info.private_key)
        .map_err(|e| anyhow::anyhow!("Failed to parse the EC key: {}", e))?;
    ec.parameters = Some(sec1::EcParameters::NamedCurve(curve));
    ec.to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode SEC1 key: {}", e))
}

/// PEM text with LF line endings (the pem crate defaults to CRLF).
fn pem_encode_lf(p: &::pem::Pem) -> String {
    ::pem::encode_config(
        p,
        ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
    )
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Colon-separated uppercase hex digest of `der`, or None for an unknown algorithm.
fn fingerprint(alg: &str, der: &[u8]) -> Option<String> {
    let algorithm = match alg {
        "sha1" => &SHA1_FOR_LEGACY_USE_ONLY,
        "sha256" => &SHA256,
        "sha384" => &digest::SHA384,
        "sha512" => &digest::SHA512,
        _ => return None,
    };
    Some(colon_hex(digest(algorithm, der).as_ref()))
}

fn looks_like_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

/// All PEM blocks in `data` (empty if it is not PEM text).
fn pem_blocks(data: &[u8]) -> Vec<::pem::Pem> {
    std::str::from_utf8(data)
        .ok()
        .and_then(|s| ::pem::parse_many(s).ok())
        .unwrap_or_default()
}

/// DER bytes of every certificate in `data`: each CERTIFICATE block of a PEM
/// bundle, or `data` itself when it is a single DER certificate.
fn certificate_ders(data: &[u8]) -> Vec<Vec<u8>> {
    if looks_like_pem(data) {
        pem_blocks(data)
            .into_iter()
            .filter(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.contents().to_vec())
            .filter(|der| X509Certificate::from_der(der).is_ok())
            .collect()
    } else if X509Certificate::from_der(data).is_ok() {
        vec![data.to_vec()]
    } else {
        Vec::new()
    }
}

/// Raw DER of the issuer name of a certificate (empty if it cannot be parsed).
fn issuer_raw(der: &[u8]) -> Vec<u8> {
    X509Certificate::from_der(der)
        .map(|(_, c)| c.issuer().as_raw().to_vec())
        .unwrap_or_default()
}

/// Raw DER of the subject name of a certificate (empty if it cannot be parsed).
fn subject_raw(der: &[u8]) -> Vec<u8> {
    X509Certificate::from_der(der)
        .map(|(_, c)| c.subject().as_raw().to_vec())
        .unwrap_or_default()
}

/// Bit length of a big-endian RSA modulus.
fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    let m: &[u8] = {
        let start = modulus
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(modulus.len());
        &modulus[start..]
    };
    match m.first() {
        None => 0,
        Some(first) => (m.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    }
}

/// Algorithm, size, and curve of a public key.
#[derive(Debug, Clone, PartialEq)]
struct KeyDescription {
    /// "rsa", "ecdsa", "ed25519", or the algorithm OID when unknown.
    algorithm: String,
    bits: Option<usize>,
    /// "P-256", "P-384", "P-521", "secp256k1", or the curve OID.
    curve: Option<String>,
}

fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256".to_string(),
        "1.3.132.0.34" => "P-384".to_string(),
        "1.3.132.0.35" => "P-521".to_string(),
        "1.3.132.0.10" => "secp256k1".to_string(),
        other => other.to_string(),
    }
}

fn describe_spki(spki: &SubjectPublicKeyInfo) -> KeyDescription {
    let oid = spki.algorithm.algorithm.to_id_string();
    match oid.as_str() {
        OID_RSA_ENCRYPTION => {
            let bits = match spki.parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
                    Some(rsa_modulus_bits(rsa.modulus))
                }
                _ => None,
            };
            KeyDescription {
                algorithm: "rsa".to_string(),
                bits,
                curve: None,
            }
        }
        OID_EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| curve_name(&o.to_id_string()));
            let bits = match curve.as_deref() {
                Some("P-256") | Some("secp256k1") => Some(256),
                Some("P-384") => Some(384),
                Some("P-521") => Some(521),
                _ => None,
            };
            KeyDescription {
                algorithm: "ecdsa".to_string(),
                bits,
                curve,
            }
        }
        OID_ED25519 => KeyDescription {
            algorithm: "ed25519".to_string(),
            bits: Some(256),
            curve: None,
        },
        _ => KeyDescription {
            algorithm: oid,
            bits: None,
            curve: None,
        },
    }
}

fn spki_key_bytes<'a>(spki: &'a SubjectPublicKeyInfo) -> &'a [u8] {
    &spki.subject_public_key.data
}

/// Human-readable name of a signature algorithm OID.
fn signature_algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.3" => "md4WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "dsa-with-SHA1",
        OID_ED25519 => "Ed25519",
        _ => "unknown",
    }
}

/// Signature algorithms considered weak (MD2, MD4, MD5, SHA-1).
fn is_weak_signature_algorithm(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.2"
            | "1.2.840.113549.1.1.3"
            | "1.2.840.113549.1.1.4"
            | "1.2.840.113549.1.1.5"
            | "1.3.14.3.2.29"
            | "1.2.840.10045.4.1"
            | "1.2.840.10040.4.3"
    )
}

#[derive(Debug, Clone, PartialEq)]
enum SignatureCheck {
    Valid,
    Invalid,
    Unsupported(String),
}

/// Verifies `signature` over `message` with `signer`'s public key, for RSA
/// PKCS#1 v1.5 with SHA-256/384/512, ECDSA P-256/P-384 with SHA-256/384, and
/// Ed25519. Other algorithms report Unsupported.
fn verify_signature_with_key(
    signature_oid: &str,
    signer: &SubjectPublicKeyInfo,
    message: &[u8],
    signature: &[u8],
) -> SignatureCheck {
    use ring::signature as rs;
    let key = describe_spki(signer);
    let alg: &'static dyn rs::VerificationAlgorithm = match (signature_oid, key.algorithm.as_str())
    {
        ("1.2.840.113549.1.1.11", "rsa")
        | ("1.2.840.113549.1.1.12", "rsa")
        | ("1.2.840.113549.1.1.13", "rsa")
            if key.bits.unwrap_or(0) < 2048 =>
        {
            return SignatureCheck::Unsupported(format!(
                "RSA signer keys under 2048 bits are not supported ({} bits)",
                key.bits.unwrap_or(0)
            ));
        }
        ("1.2.840.113549.1.1.11", "rsa") => &rs::RSA_PKCS1_2048_8192_SHA256,
        ("1.2.840.113549.1.1.12", "rsa") => &rs::RSA_PKCS1_2048_8192_SHA384,
        ("1.2.840.113549.1.1.13", "rsa") => &rs::RSA_PKCS1_2048_8192_SHA512,
        ("1.2.840.10045.4.3.2", "ecdsa") | ("1.2.840.10045.4.3.3", "ecdsa") => {
            match (signature_oid, key.curve.as_deref()) {
                ("1.2.840.10045.4.3.2", Some("P-256")) => &rs::ECDSA_P256_SHA256_ASN1,
                ("1.2.840.10045.4.3.3", Some("P-256")) => &rs::ECDSA_P256_SHA384_ASN1,
                ("1.2.840.10045.4.3.2", Some("P-384")) => &rs::ECDSA_P384_SHA256_ASN1,
                ("1.2.840.10045.4.3.3", Some("P-384")) => &rs::ECDSA_P384_SHA384_ASN1,
                (_, curve) => {
                    return SignatureCheck::Unsupported(format!(
                        "ECDSA curve {} is not supported for signature verification",
                        curve.unwrap_or("unknown")
                    ));
                }
            }
        }
        (OID_ED25519, "ed25519") => &rs::ED25519,
        _ => {
            return SignatureCheck::Unsupported(format!(
                "signature algorithm {} ({}) with a {} key is not supported for verification",
                signature_algorithm_name(signature_oid),
                signature_oid,
                key.algorithm
            ));
        }
    };
    match rs::UnparsedPublicKey::new(alg, spki_key_bytes(signer)).verify(message, signature) {
        Ok(()) => SignatureCheck::Valid,
        Err(_) => SignatureCheck::Invalid,
    }
}

/// CMS digestAlgorithm and signatureAlgorithm identifiers for a SignerInfo
/// made with `key` and `algorithm` (RFC 5754, RFC 4056, RFC 8419). The
/// digest parameters are absent, as RFC 5754 prefers.
fn cms_algorithm_identifiers(
    key: &SignerKey,
    algorithm: &SignatureAlgorithm,
) -> Result<(
    spki::AlgorithmIdentifierOwned,
    spki::AlgorithmIdentifierOwned,
)> {
    use const_oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_SHA_256, ID_SHA_384,
        ID_SHA_512, RSA_ENCRYPTION,
    };
    use spki::AlgorithmIdentifierOwned as AlgId;
    let plain = |oid| AlgId {
        oid,
        parameters: None,
    };
    let rsa_pkcs1 = || AlgId {
        oid: RSA_ENCRYPTION,
        parameters: Some(der::Any::null()),
    };
    Ok(match (key, algorithm) {
        (SignerKey::Rsa(_), SignatureAlgorithm::RsaPssSha256) => (
            plain(ID_SHA_256),
            rsa::pss::get_default_pss_signature_algo_id::<sha2::Sha256>()?,
        ),
        (SignerKey::Rsa(_), SignatureAlgorithm::RsaPssSha384) => (
            plain(ID_SHA_384),
            rsa::pss::get_default_pss_signature_algo_id::<sha2::Sha384>()?,
        ),
        (SignerKey::Rsa(_), SignatureAlgorithm::RsaPkcs1Sha256) => (plain(ID_SHA_256), rsa_pkcs1()),
        (SignerKey::Rsa(_), SignatureAlgorithm::RsaPkcs1Sha384) => (plain(ID_SHA_384), rsa_pkcs1()),
        (SignerKey::EcdsaP256(_), SignatureAlgorithm::EcdsaSha256) => {
            (plain(ID_SHA_256), plain(ECDSA_WITH_SHA_256))
        }
        (SignerKey::EcdsaP384(_), SignatureAlgorithm::EcdsaSha384) => {
            (plain(ID_SHA_384), plain(ECDSA_WITH_SHA_384))
        }
        (SignerKey::EcdsaP384(_), SignatureAlgorithm::EcdsaSha512) => {
            (plain(ID_SHA_512), plain(ECDSA_WITH_SHA_512))
        }
        (SignerKey::Ed25519(_), SignatureAlgorithm::Ed25519) => (
            plain(ID_SHA_512),
            plain(const_oid::db::rfc8410::ID_ED_25519),
        ),
        // The same pairs create_signature refuses; checked here first so no
        // CMS structure is built for them.
        (_, algorithm) => bail!(
            "Unsupported key/algorithm combination: a {} key cannot sign with {:?}; nothing was signed",
            signer_key_label(key),
            algorithm
        ),
    })
}

/// The CMS message-digest of `data` for `algorithm`: SHA-256, SHA-384 or
/// SHA-512 as the signature algorithm names, and SHA-512 for Ed25519
/// (RFC 8419 section 3).
fn cms_message_digest(algorithm: &SignatureAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        SignatureAlgorithm::RsaPssSha256
        | SignatureAlgorithm::RsaPkcs1Sha256
        | SignatureAlgorithm::EcdsaSha256 => sha2::Sha256::digest(data).to_vec(),
        SignatureAlgorithm::RsaPssSha384
        | SignatureAlgorithm::RsaPkcs1Sha384
        | SignatureAlgorithm::EcdsaSha384 => sha2::Sha384::digest(data).to_vec(),
        SignatureAlgorithm::EcdsaSha512 | SignatureAlgorithm::Ed25519 => {
            sha2::Sha512::digest(data).to_vec()
        }
    }
}

fn signer_key_label(key: &SignerKey) -> &'static str {
    match key {
        SignerKey::Rsa(_) => "RSA",
        SignerKey::EcdsaP256(_) => "P-256 ECDSA",
        SignerKey::EcdsaP384(_) => "P-384 ECDSA",
        SignerKey::Ed25519(_) => "Ed25519",
    }
}

/// Parses the first certificate in `data` (PEM or DER) for use as a CMS
/// signer certificate.
fn parse_cms_signer_cert(data: &[u8], label: &str) -> Result<x509_cert::Certificate> {
    use der::Decode;
    let ders = certificate_ders(data);
    let der = ders
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in signer_cert {}", label))?;
    x509_cert::Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse signer_cert {}: {}", label, e))
}

/// Whether the public key of `cert` is the public half of `key`.
fn signer_key_matches_cert(key: &SignerKey, cert: &x509_cert::Certificate) -> bool {
    use rsa::pkcs1::EncodeRsaPublicKey;
    let cert_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    match key {
        SignerKey::Rsa(k) => k
            .to_public_key()
            .to_pkcs1_der()
            .map(|d| d.as_bytes() == cert_key)
            .unwrap_or(false),
        SignerKey::EcdsaP256(k) => k.verifying_key().to_encoded_point(false).as_bytes() == cert_key,
        SignerKey::EcdsaP384(k) => k.verifying_key().to_encoded_point(false).as_bytes() == cert_key,
        SignerKey::Ed25519(k) => k.verifying_key().as_bytes().as_slice() == cert_key,
    }
}

/// Verifies that `cert` was signed by the key in `issuer_spki`.
fn verify_cert_signed_by(
    cert: &X509Certificate,
    issuer_spki: &SubjectPublicKeyInfo,
) -> SignatureCheck {
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    if oid != cert.tbs_certificate.signature.algorithm.to_id_string() {
        return SignatureCheck::Invalid;
    }
    verify_signature_with_key(
        &oid,
        issuer_spki,
        cert.tbs_certificate.as_ref(),
        &cert.signature_value.data,
    )
}

fn is_self_issued(cert: &X509Certificate) -> bool {
    cert.tbs_certificate.subject.as_raw() == cert.tbs_certificate.issuer.as_raw()
}

/// Basic constraints (cA flag and path length) of a certificate.
fn basic_constraints_of(cert: &X509Certificate) -> (bool, Option<u32>) {
    match cert.basic_constraints() {
        Ok(Some(bc)) => (bc.value.ca, bc.value.path_len_constraint),
        _ => (false, None),
    }
}

fn is_ca_cert(cert: &X509Certificate) -> bool {
    basic_constraints_of(cert).0
}

fn key_usage_names(cert: &X509Certificate) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(ku)) = cert.key_usage() {
        let ku = ku.value;
        let flags = [
            (ku.digital_signature(), "digitalSignature"),
            (ku.non_repudiation(), "contentCommitment"),
            (ku.key_encipherment(), "keyEncipherment"),
            (ku.data_encipherment(), "dataEncipherment"),
            (ku.key_agreement(), "keyAgreement"),
            (ku.key_cert_sign(), "keyCertSign"),
            (ku.crl_sign(), "cRLSign"),
            (ku.encipher_only(), "encipherOnly"),
            (ku.decipher_only(), "decipherOnly"),
        ];
        out.extend(
            flags
                .iter()
                .filter(|(set, _)| *set)
                .map(|(_, n)| n.to_string()),
        );
    }
    out
}

fn extended_key_usage_names(cert: &X509Certificate) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        let e = eku.value;
        let flags = [
            (e.any, "anyExtendedKeyUsage"),
            (e.server_auth, "serverAuth"),
            (e.client_auth, "clientAuth"),
            (e.code_signing, "codeSigning"),
            (e.email_protection, "emailProtection"),
            (e.time_stamping, "timeStamping"),
            (e.ocsp_signing, "ocspSigning"),
        ];
        out.extend(
            flags
                .iter()
                .filter(|(set, _)| *set)
                .map(|(_, n)| n.to_string()),
        );
        out.extend(e.other.iter().map(|o| o.to_id_string()));
    }
    out
}

fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => hex::encode(bytes),
    }
}

fn general_name_string(gn: &GeneralName) -> String {
    match gn {
        GeneralName::DNSName(s) => format!("DNS:{}", s),
        GeneralName::IPAddress(b) => format!("IP:{}", format_ip_bytes(b)),
        GeneralName::RFC822Name(s) => format!("EMAIL:{}", s),
        GeneralName::URI(s) => format!("URI:{}", s),
        GeneralName::DirectoryName(n) => format!("DirName:{}", n),
        other => format!("{:?}", other),
    }
}

/// SANs of a certificate as "DNS:x", "IP:x", "EMAIL:x", "URI:x" strings.
fn san_strings(cert: &X509Certificate) -> Vec<String> {
    match cert.subject_alternative_name() {
        Ok(Some(san)) => san
            .value
            .general_names
            .iter()
            .map(general_name_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Subject or issuer name as a JSON-friendly map.
fn name_to_map(name: &X509Name) -> HashMap<String, Value> {
    fn values<'a>(it: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> Vec<String> {
        it.filter_map(|a| a.as_str().ok().map(|s| s.to_string()))
            .collect()
    }
    let mut map = HashMap::new();
    map.insert("raw_dn".to_string(), json!(name.to_string()));
    if let Some(cn) = values(name.iter_common_name()).into_iter().next() {
        map.insert("common_name".to_string(), json!(cn));
    }
    let lists = [
        ("organization", values(name.iter_organization())),
        (
            "organizational_unit",
            values(name.iter_organizational_unit()),
        ),
        ("country", values(name.iter_country())),
        ("state_or_province", values(name.iter_state_or_province())),
        ("locality", values(name.iter_locality())),
    ];
    for (key, vals) in lists {
        if !vals.is_empty() {
            map.insert(key.to_string(), json!(vals));
        }
    }
    map
}

fn asn1_time_rfc3339(t: &ASN1Time) -> String {
    DateTime::from_timestamp(t.timestamp(), 0)
        .unwrap_or_default()
        .to_rfc3339()
}

/// True if `pattern` (a DNS SAN or CN) matches `host`. A wildcard is allowed
/// only as the entire leftmost label ("*.example.com"), matches exactly one
/// label, and needs at least two labels after it.
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if rest.contains('*') || !rest.contains('.') {
            return false;
        }
        match host.split_once('.') {
            Some((label, host_rest)) => !label.is_empty() && host_rest == rest,
            None => false,
        }
    } else {
        !pattern.contains('*') && pattern == host
    }
}

/// Checks extended key usage and key usage against a purpose. A missing
/// extension does not restrict usage.
fn check_purpose(cert: &X509Certificate, purpose: &Purpose) -> CheckResult {
    let (eku_needed, label): (fn(&x509_parser::extensions::ExtendedKeyUsage) -> bool, &str) =
        match purpose {
            Purpose::Any => return CheckResult::skipped("No purpose requested (purpose=any)"),
            Purpose::ServerAuth => (|e| e.server_auth, "serverAuth"),
            Purpose::ClientAuth => (|e| e.client_auth, "clientAuth"),
            Purpose::CodeSigning => (|e| e.code_signing, "codeSigning"),
            Purpose::EmailProtection => (|e| e.email_protection, "emailProtection"),
        };

    let eku = match cert.extended_key_usage() {
        Ok(e) => e,
        Err(e) => {
            return CheckResult::fail(
                &format!("Extended key usage could not be parsed: {}", e),
                "cert.eku_parse_failed",
            );
        }
    };
    let ku = match cert.key_usage() {
        Ok(k) => k,
        Err(e) => {
            return CheckResult::fail(
                &format!("Key usage could not be parsed: {}", e),
                "cert.key_usage_parse_failed",
            );
        }
    };

    let mut notes = Vec::new();
    if let Some(eku) = eku {
        if !(eku.value.any || eku_needed(eku.value)) {
            return CheckResult::fail(
                &format!(
                    "Extended key usage ({}) does not include {}",
                    extended_key_usage_names(cert).join(", "),
                    label
                ),
                "cert.eku_mismatch",
            );
        }
        notes.push(format!("extended key usage allows {}", label));
    } else {
        notes.push("no extended key usage extension".to_string());
    }

    if let Some(ku) = ku {
        let k = ku.value;
        let allowed = match purpose {
            Purpose::ServerAuth => {
                k.digital_signature() || k.key_encipherment() || k.key_agreement()
            }
            Purpose::ClientAuth => k.digital_signature() || k.key_agreement(),
            Purpose::CodeSigning => k.digital_signature(),
            Purpose::EmailProtection => {
                k.digital_signature() || k.non_repudiation() || k.key_encipherment()
            }
            Purpose::Any => true,
        };
        if !allowed {
            return CheckResult::fail(
                &format!(
                    "Key usage ({}) does not permit {}",
                    key_usage_names(cert).join(", "),
                    label
                ),
                "cert.key_usage_mismatch",
            );
        }
        notes.push(format!("key usage permits {}", label));
    } else {
        notes.push("no key usage extension".to_string());
    }

    CheckResult::ok(&format!("Purpose {}: {}", label, notes.join("; ")))
}

/// PKCS#8 v1 document for a raw Ed25519 seed.
fn ed25519_pkcs8_from_seed(seed: &[u8; 32]) -> Result<Vec<u8>> {
    use der::Encode;
    let algorithm = spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc8410::ID_ED_25519,
        parameters: None,
    };
    // The PKCS#8 privateKey for Ed25519 is itself an OCTET STRING (RFC 8410).
    let inner = der::asn1::OctetStringRef::new(seed)
        .map_err(|e| anyhow::anyhow!("Failed to encode Ed25519 key: {}", e))?
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode Ed25519 key: {}", e))?;
    Pkcs8PrivateKeyInfo::new(algorithm, &inner)
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode Ed25519 key as PKCS#8: {}", e))
}

/// Parses an unencrypted private key (PKCS#8, PKCS#1 RSA, SEC1 EC, or a raw
/// 32-byte Ed25519 seed; PEM or DER) into an rcgen KeyPair.
fn rcgen_keypair_from_bytes(data: &[u8], label: &str) -> Result<KeyPair> {
    fn from_pkcs1(der: &[u8]) -> Option<KeyPair> {
        let key = RsaPrivateKey::from_pkcs1_der(der).ok()?;
        let pkcs8 = key.to_pkcs8_der().ok()?;
        KeyPair::from_der(pkcs8.as_bytes()).ok()
    }
    fn from_sec1(der: &[u8]) -> Option<KeyPair> {
        if let Ok(k) = p256::SecretKey::from_sec1_der(der) {
            let k = P256SigningKey::from(k);
            return KeyPair::from_der(k.to_pkcs8_der().ok()?.as_bytes()).ok();
        }
        if let Ok(k) = p384::SecretKey::from_sec1_der(der) {
            let k = P384SigningKey::from(k);
            return KeyPair::from_der(k.to_pkcs8_der().ok()?.as_bytes()).ok();
        }
        None
    }

    if looks_like_pem(data) {
        for block in pem_blocks(data) {
            let parsed = match block.tag() {
                "PRIVATE KEY" => KeyPair::from_der(block.contents()).ok(),
                "RSA PRIVATE KEY" => from_pkcs1(block.contents()),
                "EC PRIVATE KEY" => from_sec1(block.contents()),
                "ENCRYPTED PRIVATE KEY" => {
                    bail!(
                        "Private key {} is encrypted; encrypted keys are not supported here",
                        label
                    )
                }
                _ => None,
            };
            if let Some(kp) = parsed {
                return Ok(kp);
            }
        }
        bail!(
            "No supported private key found in {} (PKCS#8, PKCS#1 RSA, SEC1 P-256/P-384)",
            label
        );
    }

    if let Ok(kp) = KeyPair::from_der(data) {
        return Ok(kp);
    }
    if let Some(kp) = from_pkcs1(data).or_else(|| from_sec1(data)) {
        return Ok(kp);
    }
    if let Ok(seed) = <[u8; 32]>::try_from(data) {
        return Ok(KeyPair::from_der(&ed25519_pkcs8_from_seed(&seed)?)?);
    }
    bail!("Unable to parse private key from {}", label)
}

/// rcgen signature algorithm used for a subject public key.
fn rcgen_alg_for_key(key: &KeyDescription) -> Result<&'static rcgen::SignatureAlgorithm> {
    match (key.algorithm.as_str(), key.curve.as_deref()) {
        ("rsa", _) => Ok(&rcgen::PKCS_RSA_SHA256),
        ("ecdsa", Some("P-256")) => Ok(&rcgen::PKCS_ECDSA_P256_SHA256),
        ("ecdsa", Some("P-384")) => Ok(&rcgen::PKCS_ECDSA_P384_SHA384),
        ("ed25519", _) => Ok(&rcgen::PKCS_ED25519),
        (alg, curve) => bail!(
            "Unsupported public key: {}{}",
            alg,
            curve.map(|c| format!(" ({})", c)).unwrap_or_default()
        ),
    }
}

/// A key pair that holds only a public key, for issuing a certificate to a
/// key whose private half is not available (signing uses the issuer's key).
struct PublicKeyOnly {
    raw: Vec<u8>,
    alg: &'static rcgen::SignatureAlgorithm,
}

impl rcgen::RemoteKeyPair for PublicKeyOnly {
    fn public_key(&self) -> &[u8] {
        &self.raw
    }
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.alg
    }
}

/// Short key algorithm name for an rcgen signature algorithm.
fn signature_algorithm_label(alg: &rcgen::SignatureAlgorithm) -> &'static str {
    if alg == &rcgen::PKCS_ED25519 {
        "ed25519"
    } else if alg == &rcgen::PKCS_ECDSA_P256_SHA256 {
        "ecdsa P-256"
    } else if alg == &rcgen::PKCS_ECDSA_P384_SHA384 {
        "ecdsa P-384"
    } else {
        "rsa"
    }
}

/// A random positive 128-bit serial number.
fn random_serial() -> rcgen::SerialNumber {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7F;
    if bytes[0] == 0 {
        bytes[0] = 0x01;
    }
    rcgen::SerialNumber::from(bytes.to_vec())
}

fn to_offset_datetime(dt: DateTime<Utc>) -> Result<::time::OffsetDateTime> {
    ::time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
        .map_err(|e| anyhow::anyhow!("Invalid timestamp {}: {}", dt, e))
}

fn rcgen_key_usage(ku: &CertKeyUsage) -> rcgen::KeyUsagePurpose {
    match ku {
        CertKeyUsage::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
        CertKeyUsage::ContentCommitment => rcgen::KeyUsagePurpose::ContentCommitment,
        CertKeyUsage::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
        CertKeyUsage::DataEncipherment => rcgen::KeyUsagePurpose::DataEncipherment,
        CertKeyUsage::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
        CertKeyUsage::KeyCertSign => rcgen::KeyUsagePurpose::KeyCertSign,
        CertKeyUsage::CrlSign => rcgen::KeyUsagePurpose::CrlSign,
        CertKeyUsage::EncipherOnly => rcgen::KeyUsagePurpose::EncipherOnly,
        CertKeyUsage::DecipherOnly => rcgen::KeyUsagePurpose::DecipherOnly,
    }
}

fn rcgen_extended_key_usage(eku: &CertExtendedKeyUsage) -> rcgen::ExtendedKeyUsagePurpose {
    match eku {
        CertExtendedKeyUsage::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        CertExtendedKeyUsage::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        CertExtendedKeyUsage::CodeSigning => rcgen::ExtendedKeyUsagePurpose::CodeSigning,
        CertExtendedKeyUsage::EmailProtection => rcgen::ExtendedKeyUsagePurpose::EmailProtection,
        CertExtendedKeyUsage::TimeStamping => rcgen::ExtendedKeyUsagePurpose::TimeStamping,
        CertExtendedKeyUsage::OcspSigning => rcgen::ExtendedKeyUsagePurpose::OcspSigning,
    }
}

fn encode_cert_der(der: &[u8], encoding: &Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Pem => pem_encode_lf(&Pem::new("CERTIFICATE", der.to_vec())).into_bytes(),
        Encoding::Der => der.to_vec(),
    }
}

/// Details of an issued certificate, read back from its DER encoding.
#[derive(Debug, Clone)]
struct IssuedCertSummary {
    subject: HashMap<String, Value>,
    issuer: HashMap<String, Value>,
    serial_hex: String,
    not_before: String,
    not_after: String,
    is_ca: bool,
    path_len: Option<u8>,
    sans: Vec<String>,
    key_usage: Vec<String>,
    extended_key_usage: Vec<String>,
    fingerprints: HashMap<String, String>,
}

fn summarize_cert_der(der: &[u8]) -> Result<IssuedCertSummary> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse issued certificate: {}", e))?;
    let (is_ca, path_len) = basic_constraints_of(&cert);
    let mut fingerprints = HashMap::new();
    for alg in ["sha1", "sha256"] {
        if let Some(fp) = fingerprint(alg, der) {
            fingerprints.insert(alg.to_string(), fp);
        }
    }
    Ok(IssuedCertSummary {
        subject: name_to_map(cert.subject()),
        issuer: name_to_map(cert.issuer()),
        serial_hex: hex::encode_upper(cert.tbs_certificate.raw_serial()),
        not_before: asn1_time_rfc3339(&cert.validity().not_before),
        not_after: asn1_time_rfc3339(&cert.validity().not_after),
        is_ca,
        path_len: path_len.and_then(|p| u8::try_from(p).ok()),
        sans: san_strings(&cert),
        key_usage: key_usage_names(&cert),
        extended_key_usage: extended_key_usage_names(&cert),
        fingerprints,
    })
}

/// A CA certificate and key loaded for signing.
struct CaSigner {
    cert: rcgen::Certificate,
}

/// Loads a CA certificate and its private key for signing. Fails if the key
/// does not belong to the certificate or the certificate is not a CA.
fn load_ca_signer(
    ca_cert_data: &[u8],
    ca_label: &str,
    key_data: &[u8],
    key_label: &str,
) -> Result<CaSigner> {
    let ders = certificate_ders(ca_cert_data);
    let ca_der = ders
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in signer CA {}", ca_label))?;
    let (_, ca) = X509Certificate::from_der(ca_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse signer CA {}: {}", ca_label, e))?;
    if !is_ca_cert(&ca) {
        bail!(
            "Signer certificate {} is not a CA (basicConstraints cA is not set)",
            ca_label
        );
    }
    let key_pair = rcgen_keypair_from_bytes(key_data, key_label)?;
    if key_pair.public_key_raw() != spki_key_bytes(ca.public_key()) {
        bail!(
            "Signer key {} does not match the public key of signer CA {}",
            key_label,
            ca_label
        );
    }
    let alg = key_pair.algorithm();
    let mut params = CertificateParams::from_ca_cert_der(ca_der, key_pair)
        .map_err(|e| anyhow::anyhow!("Failed to load signer CA {}: {}", ca_label, e))?;
    // Sign with the algorithm of the CA's own key, not the one that signed the CA.
    params.alg = alg;
    let cert = Certificate::from_params(params)
        .map_err(|e| anyhow::anyhow!("Failed to prepare signer CA {}: {}", ca_label, e))?;
    Ok(CaSigner { cert })
}

/// Validity window from a not_before setting, an explicit not_after, and an
/// offset in days.
fn validity_window(
    not_before: &NotBeforeSetting,
    not_after: Option<DateTime<Utc>>,
    offset_days: i64,
) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let start = match not_before {
        NotBeforeSetting::Now => Utc::now(),
        NotBeforeSetting::Explicit(dt) => *dt,
    };
    let end = not_after.unwrap_or_else(|| start + chrono::Duration::days(offset_days));
    if end <= start {
        bail!(
            "not_after ({}) must be later than not_before ({})",
            end.to_rfc3339(),
            start.to_rfc3339()
        );
    }
    Ok((start, end))
}

/// Subject, SANs, and key of a CSR.
struct CsrDescription {
    subject: HashMap<String, Value>,
    sans: Vec<String>,
    public_key: KeyDescription,
}

fn describe_csr(der: &[u8]) -> Result<CsrDescription> {
    use x509_parser::certification_request::X509CertificationRequest;
    let (_, csr) = X509CertificationRequest::from_der(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse CSR: {}", e))?;
    let info = &csr.certification_request_info;
    let mut sans = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                sans.extend(san.general_names.iter().map(general_name_string));
            }
        }
    }
    Ok(CsrDescription {
        subject: name_to_map(&info.subject),
        sans,
        public_key: describe_spki(&info.subject_pki),
    })
}

/// DER bytes of a CSR given as PEM or DER, and the encoding found.
fn csr_der_from_bytes(data: &[u8], hint: &EncodingHint) -> Result<(Vec<u8>, &'static str)> {
    let pem = match hint {
        EncodingHint::Pem => true,
        EncodingHint::Der => false,
        EncodingHint::Auto => looks_like_pem(data),
    };
    if pem {
        pem_blocks(data)
            .into_iter()
            .find(|b| b.tag() == "CERTIFICATE REQUEST" || b.tag() == "NEW CERTIFICATE REQUEST")
            .map(|b| (b.contents().to_vec(), "pem"))
            .ok_or_else(|| anyhow::anyhow!("No CERTIFICATE REQUEST block found in the CSR"))
    } else {
        Ok((data.to_vec(), "der"))
    }
}

fn build_distinguished_name(subject: &CertSubject) -> Result<DistinguishedName> {
    let mut dn = DistinguishedName::new();
    if let Some(cn) = &subject.common_name {
        dn.push(rcgen::DnType::CommonName, cn.as_str());
    }
    for v in &subject.organization {
        dn.push(rcgen::DnType::OrganizationName, v.as_str());
    }
    for v in &subject.organizational_unit {
        dn.push(rcgen::DnType::OrganizationalUnitName, v.as_str());
    }
    for v in &subject.country {
        dn.push(rcgen::DnType::CountryName, v.as_str());
    }
    for v in &subject.state_or_province {
        dn.push(rcgen::DnType::StateOrProvinceName, v.as_str());
    }
    for v in &subject.locality {
        dn.push(rcgen::DnType::LocalityName, v.as_str());
    }
    Ok(dn)
}

fn parse_san_list(sans: &[String]) -> Result<Vec<SanType>> {
    let mut out = Vec::new();
    for s in sans {
        let s = s.trim();
        if let Some(v) = s.strip_prefix("DNS:") {
            out.push(SanType::DnsName(v.to_string()));
        } else if let Some(v) = s.strip_prefix("IP:") {
            out.push(SanType::IpAddress(
                v.parse()
                    .with_context(|| format!("Invalid IP SAN: {}", s))?,
            ));
        } else if let Some(v) = s.strip_prefix("EMAIL:") {
            out.push(SanType::Rfc822Name(v.to_string()));
        } else if let Some(v) = s.strip_prefix("URI:") {
            out.push(SanType::URI(v.to_string()));
        } else {
            bail!(
                "Invalid SAN format: {}. Must be DNS:, IP:, EMAIL:, or URI:",
                s
            );
        }
    }
    Ok(out)
}

/// Parses a boolean option value ("true"/"false", "1"/"0", "yes"/"no").
fn parse_bool_arg(name: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("Invalid {} '{}'. Use true or false", name, value),
    }
}

/// A JSON boolean, or a string holding one (CLI values arrive as strings).
fn json_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => parse_bool_arg("value", s).ok(),
        _ => None,
    }
}

/// Stage 6B: `signature_algorithm` is honoured exactly; an ECDSA signature
/// is never silently made with a different digest.
#[cfg(test)]
mod ecdsa_algorithm_tests {
    use super::*;
    use p384::ecdsa::VerifyingKey as P384VerifyingKey;
    use p384::ecdsa::signature::hazmat::PrehashVerifier;

    fn handle() -> CertHandle {
        CertHandle {
            target_path: "./sig".to_string(),
        }
    }

    /// Verifies with ring, an independent implementation (it supports
    /// P-384 with SHA-384 only).
    fn ring_p384_sha384_ok(vk: &P384VerifyingKey, data: &[u8], der: &[u8]) -> bool {
        let point = vk.to_encoded_point(false);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P384_SHA384_ASN1,
            point.as_bytes(),
        )
        .verify(data, der)
        .is_ok()
    }

    #[test]
    fn p384_sha512_uses_a_sha512_digest() {
        let key = P384SigningKey::random(&mut OsRng);
        let vk = *key.verifying_key();
        let data = b"resh stage 6b signing fixture";
        let der = handle()
            .create_signature(
                data,
                &SignerKey::EcdsaP384(key),
                &SignatureAlgorithm::EcdsaSha512,
            )
            .unwrap();
        let sig = P384Signature::from_der(&der).unwrap();
        assert!(vk.verify_prehash(&sha2::Sha512::digest(data), &sig).is_ok());
        // Before the fix this was a SHA-384 signature.
        assert!(!ring_p384_sha384_ok(&vk, data, &der));
    }

    #[test]
    fn p384_sha384_is_unchanged() {
        let key = P384SigningKey::random(&mut OsRng);
        let vk = *key.verifying_key();
        let data = b"resh stage 6b signing fixture";
        let der = handle()
            .create_signature(
                data,
                &SignerKey::EcdsaP384(key),
                &SignatureAlgorithm::EcdsaSha384,
            )
            .unwrap();
        assert!(ring_p384_sha384_ok(&vk, data, &der));
    }

    #[test]
    fn mismatched_curve_and_digest_is_refused() {
        let key = SignerKey::EcdsaP256(P256SigningKey::random(&mut OsRng));
        for alg in [
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
        ] {
            let err = handle().create_signature(b"x", &key, &alg).unwrap_err();
            assert!(
                err.to_string().contains("P-256 ECDSA key cannot sign"),
                "{err}"
            );
        }
    }
}

/// `cert sign` data signing end to end through the verb: every key type,
/// signature algorithm, signature_format and signature_encoding, with raw
/// signatures and CMS SignedData verified independently of the signer.
#[cfg(test)]
mod sign_verb_tests {
    use super::*;
    use cms::content_info::ContentInfo;
    use cms::signed_data::{SignedData, SignerIdentifier};
    use der::{Decode, Encode};
    use rsa::pkcs1::DecodeRsaPublicKey;
    use std::fs;
    use std::path::Path;
    use std::sync::OnceLock;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Kind {
        Rsa,
        P256,
        P384,
        Ed25519,
    }

    const KINDS: [Kind; 4] = [Kind::Rsa, Kind::P256, Kind::P384, Kind::Ed25519];

    const ALGORITHMS: [&str; 8] = [
        "rsa_pss_sha256",
        "rsa_pkcs1_sha256",
        "rsa_pss_sha384",
        "rsa_pkcs1_sha384",
        "ecdsa_sha256",
        "ecdsa_sha384",
        "ecdsa_sha512",
        "ed25519",
    ];

    /// The (key, algorithm) pairs `cert sign` implements.
    fn supported(kind: Kind, alg: &str) -> bool {
        match kind {
            Kind::Rsa => alg.starts_with("rsa_"),
            Kind::P256 => alg == "ecdsa_sha256",
            Kind::P384 => alg == "ecdsa_sha384" || alg == "ecdsa_sha512",
            Kind::Ed25519 => alg == "ed25519",
        }
    }

    /// PKCS#8 PEM key and self-signed certificate PEM for each key type,
    /// generated once (RSA key generation is slow in debug builds).
    fn material(kind: Kind) -> &'static (String, String) {
        static MATERIAL: OnceLock<Vec<(String, String)>> = OnceLock::new();
        let all = MATERIAL.get_or_init(|| {
            KINDS
                .iter()
                .map(|kind| {
                    let key_pem = match kind {
                        Kind::Rsa => RsaPrivateKey::new(&mut OsRng, 2048)
                            .unwrap()
                            .to_pkcs8_pem(pkcs8::LineEnding::LF)
                            .unwrap()
                            .to_string(),
                        Kind::P256 => P256SigningKey::random(&mut OsRng)
                            .to_pkcs8_pem(pkcs8::LineEnding::LF)
                            .unwrap()
                            .to_string(),
                        Kind::P384 => P384SigningKey::random(&mut OsRng)
                            .to_pkcs8_pem(pkcs8::LineEnding::LF)
                            .unwrap()
                            .to_string(),
                        Kind::Ed25519 => {
                            let mut seed = [0u8; 32];
                            OsRng.fill_bytes(&mut seed);
                            pem_encode_lf(&Pem::new(
                                "PRIVATE KEY",
                                ed25519_pkcs8_from_seed(&seed).unwrap(),
                            ))
                        }
                    };
                    let key_pair = KeyPair::from_pem(&key_pem).unwrap();
                    let mut params = CertificateParams::new(vec![]);
                    params.distinguished_name = DistinguishedName::new();
                    params
                        .distinguished_name
                        .push(rcgen::DnType::CommonName, format!("{:?} signer", kind));
                    params.alg = key_pair.algorithm();
                    params.key_pair = Some(key_pair);
                    let cert_pem = Certificate::from_params(params)
                        .unwrap()
                        .serialize_pem()
                        .unwrap();
                    (key_pem, cert_pem)
                })
                .collect()
        });
        &all[KINDS.iter().position(|k| *k == kind).unwrap()]
    }

    /// Writes the key and certificate of `kind` into `dir`.
    fn write_signer(dir: &Path, kind: Kind) -> (String, String) {
        let (key_pem, cert_pem) = material(kind);
        let key = dir.join(format!("{:?}-key.pem", kind));
        let cert = dir.join(format!("{:?}-cert.pem", kind));
        fs::write(&key, key_pem).unwrap();
        fs::write(&cert, cert_pem).unwrap();
        (
            key.to_string_lossy().into_owned(),
            cert.to_string_lossy().into_owned(),
        )
    }

    fn sign_verb(args: &[(&str, &str)]) -> (i32, Value) {
        let handle = CertHandle {
            target_path: "./signer".to_string(),
        };
        let args: Args = args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut stdin = std::io::empty();
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let status = {
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut out,
                stderr: &mut err,
            };
            handle.call("sign", &args, &mut io).unwrap()
        };
        let json: Value = serde_json::from_slice(&out)
            .unwrap_or_else(|e| panic!("non-JSON output {:?}: {e}", String::from_utf8_lossy(&out)));
        (status.exit_code(), json)
    }

    fn error_code(json: &Value) -> &str {
        json["error"]["code"].as_str().unwrap_or("")
    }

    /// Decodes a signature file written with `encoding`, checking the PEM label.
    fn decode_output(bytes: &[u8], encoding: &str, pem_label: &str) -> Vec<u8> {
        match encoding {
            "der" => bytes.to_vec(),
            "base64" => BASE64_STANDARD
                .decode(std::str::from_utf8(bytes).unwrap().trim())
                .unwrap(),
            "pem" => {
                let text = std::str::from_utf8(bytes).unwrap();
                let block = ::pem::parse(text).unwrap();
                assert_eq!(block.tag(), pem_label);
                assert!(text.lines().all(|l| l.len() <= 64), "PEM lines over 64");
                block.contents().to_vec()
            }
            other => panic!("unknown encoding {other}"),
        }
    }

    fn digest_for(alg: &str, data: &[u8]) -> Vec<u8> {
        if alg.ends_with("sha256") {
            sha2::Sha256::digest(data).to_vec()
        } else if alg.ends_with("sha384") {
            sha2::Sha384::digest(data).to_vec()
        } else {
            // ecdsa_sha512, and ed25519 in CMS (RFC 8419)
            sha2::Sha512::digest(data).to_vec()
        }
    }

    /// Verifies `signature` over `message` with the public key of `cert`,
    /// using verifier-side APIs only.
    fn verify_raw(cert: &x509_cert::Certificate, alg: &str, message: &[u8], signature: &[u8]) {
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let ok = match alg {
            "rsa_pss_sha256" | "rsa_pss_sha384" | "rsa_pkcs1_sha256" | "rsa_pkcs1_sha384" => {
                let public = rsa::RsaPublicKey::from_pkcs1_der(spki).unwrap();
                let hash = digest_for(alg, message);
                match alg {
                    "rsa_pss_sha256" => {
                        public.verify(rsa::Pss::new::<sha2::Sha256>(), &hash, signature)
                    }
                    "rsa_pss_sha384" => {
                        public.verify(rsa::Pss::new::<sha2::Sha384>(), &hash, signature)
                    }
                    "rsa_pkcs1_sha256" => {
                        public.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash, signature)
                    }
                    _ => public.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha384>(), &hash, signature),
                }
                .is_ok()
            }
            "ecdsa_sha256" => {
                use p256::ecdsa::signature::Verifier;
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(spki).unwrap();
                vk.verify(message, &P256Signature::from_der(signature).unwrap())
                    .is_ok()
            }
            "ecdsa_sha384" | "ecdsa_sha512" => {
                use p384::ecdsa::signature::hazmat::PrehashVerifier;
                let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(spki).unwrap();
                let sig = P384Signature::from_der(signature).unwrap();
                vk.verify_prehash(&digest_for(alg, message), &sig).is_ok()
            }
            "ed25519" => {
                use ed25519_dalek::Verifier;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(spki.try_into().unwrap()).unwrap();
                vk.verify(message, &Ed25519Signature::from_slice(signature).unwrap())
                    .is_ok()
            }
            other => panic!("unknown algorithm {other}"),
        };
        assert!(ok, "{alg} signature does not verify");
    }

    fn expected_algorithm_oids(alg: &str) -> (&'static str, &'static str) {
        match alg {
            "rsa_pss_sha256" => ("2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.10"),
            "rsa_pss_sha384" => ("2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.10"),
            "rsa_pkcs1_sha256" => ("2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.1"),
            "rsa_pkcs1_sha384" => ("2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.1"),
            "ecdsa_sha256" => ("2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2"),
            "ecdsa_sha384" => ("2.16.840.1.101.3.4.2.2", "1.2.840.10045.4.3.3"),
            "ecdsa_sha512" => ("2.16.840.1.101.3.4.2.3", "1.2.840.10045.4.3.4"),
            "ed25519" => ("2.16.840.1.101.3.4.2.3", "1.3.101.112"),
            other => panic!("unknown algorithm {other}"),
        }
    }

    /// Parses a CMS ContentInfo and checks it is a SignedData over `data` by
    /// the key of `cert`, as RFC 5652 (and RFC 8419 for Ed25519) define.
    fn verify_cms(cms_der: &[u8], cert_pem: &str, alg: &str, data: &[u8], attached: bool) {
        use const_oid::db::rfc5911::{
            ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNED_DATA, ID_SIGNING_TIME,
        };
        let cert = parse_cms_signer_cert(cert_pem.as_bytes(), "test").unwrap();
        let ci = ContentInfo::from_der(cms_der).unwrap();
        assert_eq!(ci.content_type, ID_SIGNED_DATA);
        let sd: SignedData = ci.content.decode_as().unwrap();

        // Content: attached carries the data, detached carries none.
        assert_eq!(sd.encap_content_info.econtent_type, ID_DATA);
        match (&sd.encap_content_info.econtent, attached) {
            (Some(any), true) => {
                let content: der::asn1::OctetString = any.decode_as().unwrap();
                assert_eq!(content.as_bytes(), data, "attached content round trip");
            }
            (None, false) => {}
            (econtent, _) => panic!("attached={attached} but eContent={econtent:?}"),
        }

        // The signer certificate is included.
        let certs = sd.certificates.as_ref().expect("certificates");
        assert!(certs.0.iter().any(|c| matches!(
            c,
            cms::cert::CertificateChoices::Certificate(c) if c == &cert
        )));

        let (digest_oid, sig_oid) = expected_algorithm_oids(alg);
        assert_eq!(sd.digest_algorithms.len(), 1);
        assert_eq!(
            sd.digest_algorithms.get(0).unwrap().oid.to_string(),
            digest_oid
        );
        assert_eq!(sd.signer_infos.0.len(), 1);
        let si = sd.signer_infos.0.get(0).unwrap();
        match &si.sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                assert_eq!(ias.issuer, cert.tbs_certificate.issuer);
                assert_eq!(ias.serial_number, cert.tbs_certificate.serial_number);
            }
            other => panic!("unexpected sid {other:?}"),
        }
        assert_eq!(si.digest_alg.oid.to_string(), digest_oid);
        assert_eq!(si.signature_algorithm.oid.to_string(), sig_oid);

        let attrs = si.signed_attrs.as_ref().expect("signed attributes");
        let attr = |oid| {
            attrs
                .iter()
                .find(|a| a.oid == oid)
                .unwrap_or_else(|| panic!("missing attribute {oid}"))
                .values
                .get(0)
                .unwrap()
                .clone()
        };
        let content_type: const_oid::ObjectIdentifier = attr(ID_CONTENT_TYPE).decode_as().unwrap();
        assert_eq!(content_type, ID_DATA);
        let md: der::asn1::OctetString = attr(ID_MESSAGE_DIGEST).decode_as().unwrap();
        assert_eq!(md.as_bytes(), digest_for(alg, data), "message-digest");
        let signing_time =
            x509_cert::time::Time::from_der(&attr(ID_SIGNING_TIME).to_der().unwrap()).unwrap();
        let age = std::time::SystemTime::now()
            .duration_since(signing_time.to_system_time())
            .unwrap();
        assert!(age.as_secs() < 600, "signing-time is not now");

        // The signature covers the DER signed attributes (SET OF tag).
        verify_raw(
            &cert,
            alg,
            &attrs.to_der().unwrap(),
            si.signature.as_bytes(),
        );
    }

    /// Every key type x algorithm x signature_format x signature_encoding:
    /// supported pairs produce a verifiable raw or CMS signature, both in
    /// the output file and in bytes_base64; unsupported pairs fail with
    /// cert.sign_failed and write nothing.
    #[test]
    fn sign_verb_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let data_path = dir.path().join("data.bin");
        let data: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        fs::write(&data_path, &data).unwrap();
        let data_source = data_path.to_string_lossy().into_owned();

        for kind in KINDS {
            let (key, cert) = write_signer(dir.path(), kind);
            let cert_pem = &material(kind).1;
            let parsed_cert = parse_cms_signer_cert(cert_pem.as_bytes(), "test").unwrap();
            for alg in ALGORITHMS {
                for format in ["raw", "cms_detached", "cms_attached"] {
                    for encoding in ["der", "pem", "base64"] {
                        let case = format!("{kind:?} {alg} {format} {encoding}");
                        let out = dir
                            .path()
                            .join(format!("{kind:?}-{alg}-{format}.{encoding}"));
                        let out_s = out.to_string_lossy().into_owned();
                        let mut args = vec![
                            ("signer_key", key.as_str()),
                            ("data_source", data_source.as_str()),
                            ("signature_algorithm", alg),
                            ("signature_format", format),
                            ("signature_encoding", encoding),
                            ("signature_output_path", out_s.as_str()),
                            ("include_signature_bytes", "true"),
                        ];
                        if format != "raw" {
                            args.push(("signer_cert", cert.as_str()));
                        }
                        let (code, json) = sign_verb(&args);

                        if !supported(kind, alg) {
                            assert_eq!(code, 1, "{case}: {json}");
                            assert_eq!(error_code(&json), "cert.sign_failed", "{case}");
                            assert!(
                                json["error"]["message"]
                                    .as_str()
                                    .unwrap()
                                    .contains("Unsupported key/algorithm combination"),
                                "{case}: {json}"
                            );
                            assert!(!out.exists(), "{case}: wrote a signature");
                            continue;
                        }

                        assert_eq!(code, 0, "{case}: {json}");
                        assert_eq!(json["ok"], true, "{case}");
                        let expected_format = match format {
                            "raw" => "Raw",
                            "cms_detached" => "CmsDetached",
                            _ => "CmsAttached",
                        };
                        assert_eq!(json["signature_format"], expected_format, "{case}");
                        let label = if format == "raw" { "SIGNATURE" } else { "CMS" };
                        let written = decode_output(&fs::read(&out).unwrap(), encoding, label);
                        let included = BASE64_STANDARD
                            .decode(json["signature"]["bytes_base64"].as_str().unwrap())
                            .unwrap();
                        assert_eq!(written, included, "{case}");

                        if format == "raw" {
                            assert!(json["warnings"].as_array().unwrap().is_empty(), "{case}");
                            verify_raw(&parsed_cert, alg, &data, &written);
                        } else {
                            verify_cms(&written, cert_pem, alg, &data, format == "cms_attached");
                        }
                    }
                }
            }
        }
    }

    /// Each key type's default algorithm also works with CMS.
    #[test]
    fn cms_uses_the_default_algorithm_of_each_key() {
        let dir = tempfile::tempdir().unwrap();
        for (kind, alg) in [
            (Kind::Rsa, "rsa_pss_sha256"),
            (Kind::P256, "ecdsa_sha256"),
            (Kind::P384, "ecdsa_sha384"),
            (Kind::Ed25519, "ed25519"),
        ] {
            let (key, cert) = write_signer(dir.path(), kind);
            let (code, json) = sign_verb(&[
                ("signer_key", &key),
                ("signer_cert", &cert),
                ("data_bytes_base64", "aGVsbG8gY21z"),
                ("signature_format", "cms_attached"),
                ("include_signature_bytes", "true"),
            ]);
            assert_eq!(code, 0, "{kind:?}: {json}");
            let cms = BASE64_STANDARD
                .decode(json["signature"]["bytes_base64"].as_str().unwrap())
                .unwrap();
            verify_cms(&cms, &material(kind).1, alg, b"hello cms", true);
        }
    }

    #[test]
    fn cms_without_signer_cert_is_refused_before_signing() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = write_signer(dir.path(), Kind::P256);
        let out = dir.path().join("sig.der");
        for format in ["cms_detached", "cms_attached"] {
            let (code, json) = sign_verb(&[
                ("signer_key", &key),
                ("data_bytes_base64", "aGVsbG8="),
                ("signature_format", format),
                ("signature_output_path", &out.to_string_lossy()),
            ]);
            assert_eq!(code, 2, "{format}: {json}");
            assert_eq!(error_code(&json), "cert.invalid_argument", "{format}");
            assert!(
                json["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("needs signer_cert"),
                "{json}"
            );
            assert!(!out.exists());
        }
    }

    #[test]
    fn cms_with_a_certificate_for_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = write_signer(dir.path(), Kind::P256);
        let (_, other_cert) = write_signer(dir.path(), Kind::P384);
        let out = dir.path().join("sig.der");
        let (code, json) = sign_verb(&[
            ("signer_key", &key),
            ("signer_cert", &other_cert),
            ("data_bytes_base64", "aGVsbG8="),
            ("signature_format", "cms_detached"),
            ("signature_output_path", &out.to_string_lossy()),
        ]);
        assert_eq!(code, 1, "{json}");
        assert_eq!(error_code(&json), "cert.keypair_mismatch");
        assert!(!out.exists());
    }

    #[test]
    fn cms_with_an_unreadable_signer_cert_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = write_signer(dir.path(), Kind::P256);
        let not_a_cert = dir.path().join("junk.pem");
        fs::write(&not_a_cert, "not a certificate").unwrap();
        for cert in [
            not_a_cert.to_string_lossy().into_owned(),
            dir.path()
                .join("missing.pem")
                .to_string_lossy()
                .into_owned(),
        ] {
            let (code, json) = sign_verb(&[
                ("signer_key", &key),
                ("signer_cert", &cert),
                ("data_bytes_base64", "aGVsbG8="),
                ("signature_format", "cms_attached"),
                ("include_signature_bytes", "true"),
            ]);
            assert_eq!(code, 1, "{json}");
            assert_eq!(error_code(&json), "cert.signer_load_failed", "{json}");
        }
    }

    #[test]
    fn cms_accepts_a_der_signer_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = write_signer(dir.path(), Kind::Ed25519);
        let cert_pem = &material(Kind::Ed25519).1;
        let der_path = dir.path().join("cert.der");
        fs::write(&der_path, ::pem::parse(cert_pem).unwrap().contents()).unwrap();
        let (code, json) = sign_verb(&[
            ("signer_key", &key),
            ("signer_cert", &der_path.to_string_lossy()),
            ("data_bytes_base64", "aGVsbG8="),
            ("signature_format", "cms_detached"),
            ("include_signature_bytes", "true"),
        ]);
        assert_eq!(code, 0, "{json}");
        let cms = BASE64_STANDARD
            .decode(json["signature"]["bytes_base64"].as_str().unwrap())
            .unwrap();
        verify_cms(&cms, cert_pem, "ed25519", b"hello", false);
    }

    /// Cross-checks the verb's CMS output with `openssl cms -verify` for
    /// every key type and algorithm; skipped when openssl is not installed.
    #[test]
    fn cms_output_verifies_with_openssl() {
        if std::process::Command::new("openssl")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skipping: openssl not found on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let data_path = dir.path().join("data.bin");
        fs::write(&data_path, b"openssl interop \x00\x01\xff payload").unwrap();
        for kind in KINDS {
            let (key, cert) = write_signer(dir.path(), kind);
            for alg in ALGORITHMS.iter().filter(|a| supported(kind, a)) {
                for format in ["cms_detached", "cms_attached"] {
                    let out = dir.path().join(format!("{kind:?}-{alg}-{format}.der"));
                    let (code, json) = sign_verb(&[
                        ("signer_key", &key),
                        ("signer_cert", &cert),
                        ("data_source", &data_path.to_string_lossy()),
                        ("signature_algorithm", alg),
                        ("signature_format", format),
                        ("signature_encoding", "der"),
                        ("signature_output_path", &out.to_string_lossy()),
                    ]);
                    assert_eq!(code, 0, "{json}");
                    let recovered = dir.path().join("recovered.bin");
                    let mut cmd = std::process::Command::new("openssl");
                    cmd.args([
                        "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any",
                    ])
                    .arg("-in")
                    .arg(&out)
                    .arg("-CAfile")
                    .arg(&cert)
                    .arg("-out")
                    .arg(&recovered);
                    if format == "cms_detached" {
                        cmd.arg("-content").arg(&data_path);
                    }
                    let result = cmd.output().unwrap();
                    assert!(
                        result.status.success(),
                        "openssl rejected {kind:?} {alg} {format}: {}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                    assert_eq!(
                        fs::read(&recovered).unwrap(),
                        fs::read(&data_path).unwrap(),
                        "{kind:?} {alg} {format}"
                    );
                }
            }
        }
    }

    /// Raw RSA PKCS#1 v1.5 signatures (previously refused) verify with ring,
    /// an independent implementation.
    #[test]
    fn raw_rsa_pkcs1_verifies_with_ring() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = write_signer(dir.path(), Kind::Rsa);
        let cert = parse_cms_signer_cert(material(Kind::Rsa).1.as_bytes(), "test").unwrap();
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        for (alg, ring_alg) in [
            (
                "rsa_pkcs1_sha256",
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            ),
            (
                "rsa_pkcs1_sha384",
                &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            ),
        ] {
            let (code, json) = sign_verb(&[
                ("signer_key", &key),
                ("data_bytes_base64", "aGVsbG8="),
                ("signature_algorithm", alg),
                ("include_signature_bytes", "true"),
            ]);
            assert_eq!(code, 0, "{json}");
            let sig = BASE64_STANDARD
                .decode(json["signature"]["bytes_base64"].as_str().unwrap())
                .unwrap();
            ring::signature::UnparsedPublicKey::new(ring_alg, &spki)
                .verify(b"hello", &sig)
                .unwrap_or_else(|_| panic!("{alg} does not verify with ring"));
        }
    }
}
