//! Reading private keys (PKCS#8, PKCS#1 RSA, SEC1 EC, raw Ed25519 seeds;
//! PEM or DER; encrypted PKCS#8 with a passphrase) and encoding generated
//! keys, encrypted when a passphrase is given.

use ::pem::Pem;
use pkcs8::DecodePrivateKey;
use rcgen::KeyPair;
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;

use super::errors::{CResult, CertError};
use super::{CertAlgorithm, EcdsaCurve, Encoding, KeyFormat, SignerKey};

/// A private key loaded from a file, as unencrypted PKCS#8 DER.
pub struct LoadedKey {
    pub pkcs8_der: Vec<u8>,
    /// "rsa", "ecdsa" or "ed25519".
    pub algorithm: &'static str,
    pub curve: Option<&'static str>,
    pub rsa_bits: Option<usize>,
    /// "pkcs8", "pkcs1", "sec1" or "raw".
    pub format: &'static str,
    /// "pem", "der" or "raw".
    pub encoding: &'static str,
    pub encrypted: bool,
    pub warning: Option<String>,
}

impl LoadedKey {
    pub fn key_pair(&self) -> CResult<KeyPair> {
        KeyPair::from_der(&self.pkcs8_der).map_err(|e| {
            CertError::failed("cert.key_load_failed", format!("unusable private key: {e}"))
        })
    }

    pub fn signer(&self) -> CResult<SignerKey> {
        let bad =
            |e: &dyn std::fmt::Display| CertError::failed("cert.key_load_failed", e.to_string());
        Ok(match (self.algorithm, self.curve) {
            ("rsa", _) => {
                SignerKey::Rsa(RsaPrivateKey::from_pkcs8_der(&self.pkcs8_der).map_err(|e| bad(&e))?)
            }
            ("ecdsa", Some("P-256")) => SignerKey::EcdsaP256(
                p256::ecdsa::SigningKey::from_pkcs8_der(&self.pkcs8_der).map_err(|e| bad(&e))?,
            ),
            ("ecdsa", Some("P-384")) => SignerKey::EcdsaP384(
                p384::ecdsa::SigningKey::from_pkcs8_der(&self.pkcs8_der).map_err(|e| bad(&e))?,
            ),
            ("ed25519", _) => {
                let info = pkcs8::PrivateKeyInfo::try_from(self.pkcs8_der.as_slice())
                    .map_err(|e| bad(&e))?;
                let seed = match info.private_key {
                    [0x04, 0x20, seed @ ..] => <[u8; 32]>::try_from(seed).ok(),
                    _ => None,
                }
                .ok_or_else(|| bad(&"malformed Ed25519 private key"))?;
                SignerKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed))
            }
            (alg, _) => return Err(bad(&format!("unsupported {alg} key"))),
        })
    }

    /// Short description for messages and output.
    pub fn describe(&self) -> String {
        match (self.algorithm, self.curve, self.rsa_bits) {
            ("rsa", _, Some(bits)) => format!("RSA {bits}-bit"),
            ("ecdsa", Some(c), _) => format!("ECDSA {c}"),
            ("ed25519", _, _) => "Ed25519".to_string(),
            (a, _, _) => a.to_string(),
        }
    }
}

/// Reads and parses the private key at `source`. `what` names it in
/// messages; `passphrase_arg` is the option that supplies the passphrase of
/// an encrypted key.
pub fn load_key(
    what: &str,
    source: &str,
    passphrase: Option<&str>,
    passphrase_arg: &str,
) -> CResult<LoadedKey> {
    let data = super::fileio::read_input(what, source)?;
    let label = format!("{what} {source}");
    parse_key(&data, &label, passphrase, passphrase_arg)
}

/// Parses private key bytes (see [`load_key`]).
pub fn parse_key(
    data: &[u8],
    label: &str,
    passphrase: Option<&str>,
    passphrase_arg: &str,
) -> CResult<LoadedKey> {
    let unlocked = super::keyenc::unlock(data, passphrase, passphrase_arg, label)?;
    let bytes = &unlocked.bytes;
    let (format, encoding) = if unlocked.encrypted {
        (
            "pkcs8",
            if super::looks_like_pem(data) {
                "pem"
            } else {
                "der"
            },
        )
    } else if super::looks_like_pem(bytes) {
        let tag = super::pem_blocks(bytes)
            .into_iter()
            .map(|b| b.tag().to_string())
            .find(|t| t.ends_with("PRIVATE KEY"));
        match tag.as_deref() {
            Some("RSA PRIVATE KEY") => ("pkcs1", "pem"),
            Some("EC PRIVATE KEY") => ("sec1", "pem"),
            Some(_) => ("pkcs8", "pem"),
            None => {
                return Err(CertError::failed(
                    "cert.key_load_failed",
                    format!("{label}: no private key found (expected a PRIVATE KEY PEM block)"),
                ));
            }
        }
    } else if bytes.len() == 32 {
        ("raw", "raw")
    } else if pkcs8::PrivateKeyInfo::try_from(bytes.as_slice()).is_ok() {
        ("pkcs8", "der")
    } else if rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(bytes)
        .map(|_: RsaPrivateKey| ())
        .is_ok()
    {
        ("pkcs1", "der")
    } else {
        ("sec1", "der")
    };
    let key_pair = super::rcgen_keypair_from_bytes(bytes, label).map_err(|e| {
        CertError::failed(
            "cert.key_load_failed",
            format!(
                "{e:#} (supported: RSA PKCS#8/PKCS#1, ECDSA P-256/P-384 PKCS#8/SEC1, Ed25519 \
                 PKCS#8 or a raw 32-byte seed; PEM or DER; encrypted PKCS#8)"
            ),
        )
    })?;
    let pkcs8_der = key_pair.serialize_der();
    let (algorithm, curve) = match super::signature_algorithm_label(key_pair.algorithm()) {
        "ed25519" => ("ed25519", None),
        "ecdsa P-256" => ("ecdsa", Some("P-256")),
        "ecdsa P-384" => ("ecdsa", Some("P-384")),
        _ => ("rsa", None),
    };
    let rsa_bits = (algorithm == "rsa")
        .then(|| RsaPrivateKey::from_pkcs8_der(&pkcs8_der).ok())
        .flatten()
        .map(|k| k.size() * 8);
    Ok(LoadedKey {
        pkcs8_der,
        algorithm,
        curve,
        rsa_bits,
        format,
        encoding,
        encrypted: unlocked.encrypted,
        warning: unlocked.warning,
    })
}

/// Generates a key pair.
pub fn generate_key(
    algorithm: &CertAlgorithm,
    rsa_bits: u16,
    curve: &EcdsaCurve,
) -> CResult<KeyPair> {
    let failed = |e: &dyn std::fmt::Display| {
        CertError::failed(
            "cert.generation_failed",
            format!("key generation failed: {e}"),
        )
    };
    let der: Vec<u8> = match algorithm {
        CertAlgorithm::Rsa => {
            let key = RsaPrivateKey::new(&mut rand::thread_rng(), usize::from(rsa_bits))
                .map_err(|e| failed(&e))?;
            pkcs8::EncodePrivateKey::to_pkcs8_der(&key)
                .map_err(|e| failed(&e))?
                .as_bytes()
                .to_vec()
        }
        CertAlgorithm::Ecdsa => match curve {
            EcdsaCurve::P256 => {
                let k = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                pkcs8::EncodePrivateKey::to_pkcs8_der(&k)
                    .map_err(|e| failed(&e))?
                    .as_bytes()
                    .to_vec()
            }
            EcdsaCurve::P384 => {
                let k = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
                pkcs8::EncodePrivateKey::to_pkcs8_der(&k)
                    .map_err(|e| failed(&e))?
                    .as_bytes()
                    .to_vec()
            }
        },
        CertAlgorithm::Ed25519 => {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            super::ed25519_pkcs8_from_seed(&seed).map_err(|e| failed(&e))?
        }
    };
    KeyPair::from_der(&der).map_err(|e| failed(&e))
}

/// Encodes a key pair in `format` and `encoding`; with a passphrase, as an
/// encrypted PKCS#8 key (`format` must be pkcs8).
pub fn encode_key(
    key_pair: &KeyPair,
    algorithm: &CertAlgorithm,
    format: &KeyFormat,
    encoding: &Encoding,
    passphrase: Option<(&str, u32)>,
) -> CResult<Vec<u8>> {
    let failed = |e: &dyn std::fmt::Display| {
        CertError::failed(
            "cert.generation_failed",
            format!("cannot encode the key: {e:#}"),
        )
    };
    if let Some((pass, iterations)) = passphrase {
        let enc = super::keyenc::encrypt_pkcs8(&key_pair.serialize_der(), pass, iterations)?;
        return Ok(match encoding {
            Encoding::Pem => {
                super::pem_encode_lf(&Pem::new(super::keyenc::ENCRYPTED_LABEL, enc)).into_bytes()
            }
            Encoding::Der => enc,
        });
    }
    super::encode_key_pair(key_pair, algorithm, format, encoding).map_err(|e| failed(&e))
}
