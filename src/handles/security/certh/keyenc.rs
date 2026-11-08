//! Encrypted private keys: PKCS#8 `EncryptedPrivateKeyInfo` with PBES2
//! (RFC 8018): PBKDF2 with HMAC-SHA-1/224/256/384/512 and AES-128/192/256
//! in CBC mode. This is what `openssl pkcs8 -topk8 -v2 aes-256-cbc` and
//! `openssl genpkey -aes256` write. Keys are written with PBKDF2-HMAC-SHA256
//! and AES-256-CBC, a random 16-byte salt and IV.
//!
//! Passphrases never appear in messages.

use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use der::{Decode, Encode};
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::pkcs5::EncryptionScheme;
use pkcs8::pkcs5::pbes2::{self, Kdf, Pbkdf2Prf};
use rand::RngCore;

use super::errors::{CResult, CertError};
use crate::core::status::exit;

/// PEM label of an encrypted PKCS#8 key.
pub const ENCRYPTED_LABEL: &str = "ENCRYPTED PRIVATE KEY";

/// Smallest and largest PBKDF2 iteration counts written (`key_kdf_iterations`).
pub const MIN_ITERATIONS: u64 = 10_000;
pub const MAX_ITERATIONS: u64 = 10_000_000;
/// Default `key_kdf_iterations`.
pub const DEFAULT_ITERATIONS: u32 = 100_000;

fn cbc_encrypt<C: BlockEncrypt>(cipher: &C, iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    // PKCS#7 padding: always 1..=16 bytes.
    let pad = 16 - plain.len() % 16;
    let mut data = plain.to_vec();
    data.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
        prev.copy_from_slice(chunk);
    }
    data
}

fn cbc_decrypt<C: BlockDecrypt>(cipher: &C, iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let mut out = data.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_mut(16) {
        let mut this = [0u8; 16];
        this.copy_from_slice(chunk);
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = this;
    }
    let pad = *out.last()? as usize;
    if pad == 0 || pad > 16 || out[out.len() - pad..].iter().any(|b| *b as usize != pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

fn derive_key(prf: Pbkdf2Prf, pass: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) -> bool {
    match prf {
        Pbkdf2Prf::HmacWithSha1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pass, salt, rounds, out),
        Pbkdf2Prf::HmacWithSha224 => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pass, salt, rounds, out),
        Pbkdf2Prf::HmacWithSha256 => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, salt, rounds, out),
        Pbkdf2Prf::HmacWithSha384 => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, salt, rounds, out),
        Pbkdf2Prf::HmacWithSha512 => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, salt, rounds, out),
        _ => return false,
    }
    true
}

/// Encrypts a plain PKCS#8 `PrivateKeyInfo` (DER) as an
/// `EncryptedPrivateKeyInfo` (DER) with PBKDF2-HMAC-SHA256 and AES-256-CBC.
pub fn encrypt_pkcs8(plain_der: &[u8], passphrase: &str, iterations: u32) -> CResult<Vec<u8>> {
    let fail = |e: &dyn std::fmt::Display| {
        CertError::failed(
            "cert.generation_failed",
            format!("cannot encrypt the private key: {e}"),
        )
    };
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let mut key = [0u8; 32];
    derive_key(
        Pbkdf2Prf::HmacWithSha256,
        passphrase.as_bytes(),
        &salt,
        iterations,
        &mut key,
    );
    let cipher = Aes256::new(GenericArray::from_slice(&key));
    let encrypted = cbc_encrypt(&cipher, &iv, plain_der);
    let params =
        pbes2::Parameters::pbkdf2_sha256_aes256cbc(iterations, &salt, &iv).map_err(|e| fail(&e))?;
    EncryptedPrivateKeyInfo {
        encryption_algorithm: EncryptionScheme::Pbes2(params),
        encrypted_data: &encrypted,
    }
    .to_der()
    .map_err(|e| fail(&e))
}

/// Decrypts an `EncryptedPrivateKeyInfo` (DER) into the plain PKCS#8 DER.
pub fn decrypt_pkcs8(enc_der: &[u8], passphrase: &str, label: &str) -> CResult<Vec<u8>> {
    let unsupported =
        |what: String| CertError::failed("cert.key_unsupported", format!("{label}: {what}"));
    let info = EncryptedPrivateKeyInfo::from_der(enc_der).map_err(|e| {
        CertError::failed(
            "cert.key_load_failed",
            format!("{label}: not a valid encrypted PKCS#8 key ({e})"),
        )
    })?;
    let EncryptionScheme::Pbes2(params) = &info.encryption_algorithm else {
        return Err(unsupported(
            "PBES1 encryption (DES/RC2 with MD5/SHA-1) is not supported; re-encrypt with \
             `openssl pkcs8 -topk8 -v2 aes-256-cbc`"
                .into(),
        ));
    };
    let Kdf::Pbkdf2(kdf) = &params.kdf else {
        return Err(unsupported(
            "scrypt key derivation is not supported; use PBKDF2 (`openssl pkcs8 -topk8 -v2 \
             aes-256-cbc`)"
                .into(),
        ));
    };
    if u64::from(kdf.iteration_count) > MAX_ITERATIONS {
        return Err(unsupported(format!(
            "{} PBKDF2 iterations is more than the {MAX_ITERATIONS} supported",
            kdf.iteration_count
        )));
    }
    let (key_len, iv) = match &params.encryption {
        pbes2::EncryptionScheme::Aes128Cbc { iv } => (16, *iv),
        pbes2::EncryptionScheme::Aes192Cbc { iv } => (24, *iv),
        pbes2::EncryptionScheme::Aes256Cbc { iv } => (32, *iv),
        _ => {
            return Err(unsupported(
                "only AES-128/192/256-CBC encrypted keys are supported".into(),
            ));
        }
    };
    if let Some(len) = kdf.key_length
        && usize::from(len) != key_len
    {
        return Err(unsupported(format!(
            "PBKDF2 key length {len} does not match the cipher"
        )));
    }
    let mut key = vec![0u8; key_len];
    if !derive_key(
        kdf.prf,
        passphrase.as_bytes(),
        kdf.salt,
        kdf.iteration_count,
        &mut key,
    ) {
        return Err(unsupported("unsupported PBKDF2 hash".into()));
    }
    let plain = match key_len {
        16 => cbc_decrypt(
            &Aes128::new(GenericArray::from_slice(&key)),
            iv,
            info.encrypted_data,
        ),
        24 => cbc_decrypt(
            &Aes192::new(GenericArray::from_slice(&key)),
            iv,
            info.encrypted_data,
        ),
        _ => cbc_decrypt(
            &Aes256::new(GenericArray::from_slice(&key)),
            iv,
            info.encrypted_data,
        ),
    };
    // A wrong passphrase almost always breaks the padding; if it does not,
    // the result is not a PrivateKeyInfo.
    match plain {
        Some(p) if pkcs8::PrivateKeyInfo::from_der(&p).is_ok() => Ok(p),
        _ => Err(CertError::failed(
            "cert.key_decrypt_failed",
            format!("{label}: cannot decrypt the private key (wrong passphrase?)"),
        )),
    }
}

/// An unencrypted private key read from a file.
pub struct Unlocked {
    /// The key as found (PEM or DER), or, for an encrypted key, the
    /// decrypted PKCS#8 DER.
    pub bytes: Vec<u8>,
    pub encrypted: bool,
    /// Set when a passphrase was given for a key that is not encrypted.
    pub warning: Option<String>,
}

/// Decrypts `data` if it holds an encrypted private key. `passphrase_arg`
/// names the option that supplies the passphrase, for messages.
pub fn unlock(
    data: &[u8],
    passphrase: Option<&str>,
    passphrase_arg: &str,
    label: &str,
) -> CResult<Unlocked> {
    let need = || {
        CertError::new(
            exit::USAGE,
            "cert.passphrase_required",
            format!("{label} is encrypted; pass {passphrase_arg}=<passphrase>"),
        )
    };
    let encrypted_der: Option<Vec<u8>> = if super::looks_like_pem(data) {
        let blocks = super::pem_blocks(data);
        if let Some(b) = blocks.iter().find(|b| b.tag() == ENCRYPTED_LABEL) {
            Some(b.contents().to_vec())
        } else if blocks.iter().any(|b| {
            b.tag().ends_with("PRIVATE KEY")
                && b.headers()
                    .get("Proc-Type")
                    .is_some_and(|v| v.contains("ENCRYPTED"))
        }) || String::from_utf8_lossy(data).contains("Proc-Type: 4,ENCRYPTED")
        {
            return Err(CertError::failed(
                "cert.key_unsupported",
                format!(
                    "{label} uses legacy OpenSSL PEM encryption (Proc-Type: 4,ENCRYPTED), which \
                     is not supported; convert it with `openssl pkcs8 -topk8 -v2 aes-256-cbc`"
                ),
            ));
        } else {
            None
        }
    } else if EncryptedPrivateKeyInfo::from_der(data).is_ok() {
        Some(data.to_vec())
    } else {
        None
    };
    match (encrypted_der, passphrase) {
        (Some(der), Some(pass)) => Ok(Unlocked {
            bytes: decrypt_pkcs8(&der, pass, label)?,
            encrypted: true,
            warning: None,
        }),
        (Some(_), None) => Err(need()),
        (None, pass) => Ok(Unlocked {
            bytes: data.to_vec(),
            encrypted: false,
            warning: pass
                .map(|_| format!("{label} is not encrypted; {passphrase_arg} was not needed")),
        }),
    }
}

/// True if `data` holds an encrypted PKCS#8 key (PEM or DER).
pub fn is_encrypted(data: &[u8]) -> bool {
    if super::looks_like_pem(data) {
        super::pem_blocks(data)
            .iter()
            .any(|b| b.tag() == ENCRYPTED_LABEL || b.headers().get("Proc-Type").is_some())
    } else {
        EncryptedPrivateKeyInfo::from_der(data).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_passphrase() {
        let key = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let plain = key.serialize_der();
        let enc = encrypt_pkcs8(&plain, "s3cret pass", 10_000).unwrap();
        assert_eq!(decrypt_pkcs8(&enc, "s3cret pass", "k").unwrap(), plain);
        let err = decrypt_pkcs8(&enc, "xyzzy-not-it", "k").unwrap_err();
        assert_eq!(err.code, "cert.key_decrypt_failed");
        assert!(!err.message.contains("xyzzy"), "{}", err.message);
    }

    #[test]
    fn cbc_padding_is_checked() {
        let cipher = Aes128::new(GenericArray::from_slice(&[7u8; 16]));
        let iv = [1u8; 16];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 100] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let enc = cbc_encrypt(&cipher, &iv, &plain);
            assert_eq!(enc.len() % 16, 0);
            assert!(enc.len() > plain.len());
            assert_eq!(cbc_decrypt(&cipher, &iv, &enc).unwrap(), plain);
        }
        assert!(cbc_decrypt(&cipher, &iv, &[0u8; 15]).is_none());
    }

    #[test]
    fn unlock_requires_the_passphrase_and_warns_when_unneeded() {
        let key = rcgen::KeyPair::generate(&rcgen::PKCS_ED25519).unwrap();
        let enc = encrypt_pkcs8(&key.serialize_der(), "pw", 10_000).unwrap();
        let pem = super::super::pem_encode_lf(&::pem::Pem::new(ENCRYPTED_LABEL, enc));
        let e = unlock(pem.as_bytes(), None, "key_passphrase", "k.pem")
            .err()
            .unwrap();
        assert_eq!((e.exit, e.code), (2, "cert.passphrase_required"));
        let u = unlock(pem.as_bytes(), Some("pw"), "key_passphrase", "k.pem").unwrap();
        assert!(u.encrypted);
        assert_eq!(u.bytes, key.serialize_der());
        let plain = key.serialize_pem();
        let u = unlock(plain.as_bytes(), Some("pw"), "key_passphrase", "k.pem").unwrap();
        assert!(!u.encrypted && u.warning.is_some());
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: \
                      AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        let e = unlock(legacy.as_bytes(), Some("pw"), "key_passphrase", "k")
            .err()
            .unwrap();
        assert_eq!(e.code, "cert.key_unsupported");
    }
}
