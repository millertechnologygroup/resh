//! Publisher signatures for registry artifacts, and the trusted keys.
//!
//! A registry artifact is signed with Ed25519 over the ASCII bytes
//!
//! ```text
//! resh-plugin-v1:<plugin-id>:<version>:<sha256>
//! ```
//!
//! where `<sha256>` is the artifact's SHA-256 in lower-case hex. The
//! registry gives the signature (`signature`, base64 of the 64 signature
//! bytes) and the signing key's id (`key_id`) next to `sha256`. A key id is
//! the first 16 hex digits of the SHA-256 of the 32-byte raw public key.
//!
//! Trusted keys: the built-in official key ([`OFFICIAL_KEY`], empty until
//! the project owner sets it), the user's trust store
//! `$XDG_CONFIG_HOME/resh/plugin-trusted-keys.json` (managed by `keys.add`,
//! `keys.list` and `keys.delete`) and `trust_key=<base64>` for one call.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::common::{IO_ERROR, PResult, PluginError, SIGNATURE_INVALID, SIGNATURE_REQUIRED};
use super::paths;

/// THE OFFICIAL PUBLISHER KEY: base64 of the 32-byte raw Ed25519 public key
/// that signs the official registry's artifacts, trusted by every resh.
///
/// EMPTY ON PURPOSE: no key is compiled in until the project owner sets
/// one (see plugin.md, "Setting the official key"). While it is empty, only
/// keys in the user's trust store or given with `trust_key=` are trusted.
pub const OFFICIAL_KEY: &str = "";

/// Trust store file name under `$XDG_CONFIG_HOME/resh`.
const STORE_FILE: &str = "plugin-trusted-keys.json";
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// The bytes a publisher signs.
pub fn signed_message(id: &str, version: &str, sha256: &str) -> String {
    format!("resh-plugin-v1:{id}:{version}:{sha256}")
}

/// A public key given as base64 of its 32 raw bytes.
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, String> {
    let raw = B64
        .decode(b64.trim())
        .map_err(|e| format!("not base64: {e}"))?;
    let raw: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        format!(
            "{} bytes, expected the 32 raw bytes of an Ed25519 key",
            v.len()
        )
    })?;
    VerifyingKey::from_bytes(&raw).map_err(|e| format!("not an Ed25519 public key: {e}"))
}

/// The key id of a public key.
pub fn key_id(key: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(key.as_bytes()))[..16].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustStore {
    #[serde(default)]
    pub keys: Vec<TrustedKey>,
}

fn store_dir(create: bool) -> PResult<Option<std::path::PathBuf>> {
    let loc = paths::locations()?;
    if create {
        paths::ensure_dir(&loc.config, &["resh"], 0o700).map(Some)
    } else {
        paths::existing_dir(&loc.config, &["resh"])
    }
}

/// The trust store path, whether or not it exists.
pub fn store_path() -> PResult<std::path::PathBuf> {
    Ok(paths::locations()?.config.join("resh").join(STORE_FILE))
}

pub fn load_store() -> PResult<TrustStore> {
    let Some(dir) = store_dir(false)? else {
        return Ok(TrustStore::default());
    };
    match paths::read_file(&dir, STORE_FILE, MAX_STORE_BYTES)? {
        None => Ok(TrustStore::default()),
        Some(d) => serde_json::from_slice(&d).map_err(|e| {
            PluginError::failed(
                IO_ERROR,
                format!("{} is not valid: {e}", dir.join(STORE_FILE).display()),
            )
        }),
    }
}

pub fn save_store(store: &TrustStore) -> PResult<()> {
    let dir = store_dir(true)?.expect("created");
    let data = serde_json::to_vec_pretty(store)
        .map_err(|e| PluginError::failed(IO_ERROR, e.to_string()))?;
    paths::write_file_atomic(&dir, STORE_FILE, &data, 0o600)
}

/// A key the verification may use, and where it came from.
pub struct Trusted {
    pub key: VerifyingKey,
    pub origin: &'static str,
}

/// Every trusted key: official, trust store, and `trust_key` of this call.
pub fn trusted_keys(extra: Option<&VerifyingKey>) -> PResult<Vec<Trusted>> {
    let mut out = Vec::new();
    if !OFFICIAL_KEY.is_empty() {
        let key = parse_public_key(OFFICIAL_KEY).expect("OFFICIAL_KEY must be a valid key");
        out.push(Trusted {
            key,
            origin: "official",
        });
    }
    for k in load_store()?.keys {
        if let Ok(key) = parse_public_key(&k.public_key) {
            out.push(Trusted {
                key,
                origin: "trust_store",
            });
        }
    }
    if let Some(k) = extra {
        out.push(Trusted {
            key: *k,
            origin: "trust_key",
        });
    }
    Ok(out)
}

/// Checks the registry's signature of artifact `sha256` of `id` `version`.
/// Returns the key id and where the key came from.
pub fn verify(
    id: &str,
    version: &str,
    sha256: &str,
    signature: Option<&str>,
    key_id_given: Option<&str>,
    keys: &[Trusted],
) -> PResult<(String, &'static str)> {
    let (Some(sig), Some(kid)) = (signature.filter(|s| !s.is_empty()), key_id_given) else {
        return Err(PluginError::failed(
            SIGNATURE_REQUIRED,
            format!(
                "the registry gives no signature (signature and key_id) for plugin {id} {version}; \
                 refusing to install an unsigned artifact (allow_unsigned=true overrides)"
            ),
        ));
    };
    let invalid = |why: String| {
        PluginError::failed(
            SIGNATURE_INVALID,
            format!(
                "the signature of plugin {id} {version} is not valid: {why}; nothing was installed"
            ),
        )
    };
    let raw = B64
        .decode(sig.trim())
        .map_err(|e| invalid(format!("not base64: {e}")))?;
    let sig = Signature::from_slice(&raw).map_err(|e| invalid(e.to_string()))?;
    let Some(t) = keys.iter().find(|t| key_id(&t.key) == kid) else {
        return Err(invalid(format!(
            "it was made with key {kid}, which is not trusted (add it with \
             plugin://keys.add, or pass trust_key=)"
        )));
    };
    t.key
        .verify(signed_message(id, version, sha256).as_bytes(), &sig)
        .map_err(|_| invalid(format!("it does not match key {kid}")))?;
    Ok((kid.to_string(), t.origin))
}

/// `keys.add`: adds `key` (base64) with an optional name. Returns the entry
/// and whether the store changed.
pub fn add_key(b64: &str, name: Option<&str>) -> PResult<(TrustedKey, bool)> {
    let key = parse_public_key(b64)
        .map_err(|e| PluginError::usage(format!("invalid key: {e}; nothing was done")))?;
    let id = key_id(&key);
    let mut store = load_store()?;
    if let Some(k) = store.keys.iter().find(|k| k.key_id == id) {
        return Ok((k.clone(), false));
    }
    let entry = TrustedKey {
        key_id: id,
        public_key: B64.encode(key.as_bytes()),
        name: name.map(String::from),
        added_at: Utc::now().to_rfc3339(),
    };
    store.keys.push(entry.clone());
    save_store(&store)?;
    Ok((entry, true))
}

/// `keys.delete`: removes the key with id `id`; `None` when there is none.
pub fn remove_key(id: &str) -> PResult<Option<TrustedKey>> {
    let mut store = load_store()?;
    let Some(pos) = store.keys.iter().position(|k| k.key_id == id) else {
        return Ok(None);
    };
    let k = store.keys.remove(pos);
    save_store(&store)?;
    Ok(Some(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signatures_cover_id_version_and_digest() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let kid = key_id(&vk);
        assert_eq!(kid.len(), 16);
        let sha = "ab".repeat(32);
        let sig = B64.encode(
            sk.sign(signed_message("demo", "1.0.0", &sha).as_bytes())
                .to_bytes(),
        );
        let keys = vec![Trusted {
            key: vk,
            origin: "trust_key",
        }];
        assert!(verify("demo", "1.0.0", &sha, Some(&sig), Some(&kid), &keys).is_ok());
        // Another plugin, version or digest: invalid.
        for (id, v, s) in [
            ("other", "1.0.0", sha.clone()),
            ("demo", "2.0.0", sha.clone()),
            ("demo", "1.0.0", "cd".repeat(32)),
        ] {
            let e = verify(id, v, &s, Some(&sig), Some(&kid), &keys).unwrap_err();
            assert_eq!(e.code, SIGNATURE_INVALID);
        }
        assert_eq!(
            verify("demo", "1.0.0", &sha, None, Some(&kid), &keys)
                .unwrap_err()
                .code,
            SIGNATURE_REQUIRED
        );
        assert_eq!(
            verify(
                "demo",
                "1.0.0",
                &sha,
                Some(&sig),
                Some("0000000000000000"),
                &keys
            )
            .unwrap_err()
            .code,
            SIGNATURE_INVALID
        );
        assert_eq!(
            verify("demo", "1.0.0", &sha, Some("!!"), Some(&kid), &keys)
                .unwrap_err()
                .code,
            SIGNATURE_INVALID
        );
        assert!(parse_public_key("AAAA").is_err());
        assert!(parse_public_key(&B64.encode(vk.as_bytes())).is_ok());
    }

    #[test]
    fn official_key_slot_is_empty_or_valid() {
        assert!(OFFICIAL_KEY.is_empty() || parse_public_key(OFFICIAL_KEY).is_ok());
    }
}
