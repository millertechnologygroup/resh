//! Resolving install and update sources to an artifact.
//!
//! A registry serves `GET <registry>/v1/plugins/<id>` (a [`RegistryEntry`])
//! and the artifacts at `<registry>/v1/artifacts/<id>/<version>/<bin>`.

use std::fs;

use super::store::{component_problem, is_safe_component};
use super::types::{ArtifactCandidate, RegistryEntry, RequestedVersion, SourceSpec, VerifyMode};
use crate::handles::pluginh::common::{
    CATALOG_INVALID, NOT_FOUND, PLATFORM_UNSUPPORTED, PResult, PluginError, VERIFY_FAILED,
    io_error, version_sort_key_cmp,
};
use crate::handles::pluginh::net::Fetcher;

/// Default registry for install and update.
pub const DEFAULT_REGISTRY: &str = "https://plugins.reshshell.dev";

/// Largest registry entry read.
const MAX_ENTRY_BYTES: u64 = 4 * 1024 * 1024;

/// Parse a SHA-256 given as 64 hexadecimal digits (either case) and return
/// it in lower case. Anything else is an error; nothing is trimmed.
pub fn parse_sha256(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// The SHA-256 of `data` in lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

fn artifact_kind(name: &str) -> &'static str {
    if name.ends_with(".tar.gz") {
        "tar.gz"
    } else {
        "binary"
    }
}

/// The `<os>-<arch>` key of this system (`linux-x86_64`).
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Resolves `source` to one artifact. Registry sources are fetched (through
/// `fetcher`); url and file sources are only described.
pub fn resolve(
    plugin_id: &str,
    source: &SourceSpec,
    requested: &RequestedVersion,
    verify: VerifyMode,
    fetcher: Option<&Fetcher>,
) -> PResult<ArtifactCandidate> {
    match source {
        SourceSpec::Registry { url } => {
            let fetcher = fetcher.expect("a registry source needs a fetcher");
            resolve_registry(plugin_id, url, requested, verify, fetcher)
        }
        SourceSpec::Url { url } => Ok(ArtifactCandidate {
            kind: artifact_kind(url.path()).to_string(),
            url: Some(url.clone()),
            path: None,
            sha256: None,
            version: "unknown".to_string(),
            signature: None,
            key_id: None,
        }),
        SourceSpec::File { path } => {
            match fs::metadata(path) {
                Ok(m) if m.is_file() => {}
                Ok(_) => {
                    return Err(PluginError::failed(
                        NOT_FOUND,
                        format!("plugin artifact {path} is not a regular file"),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PluginError::failed(
                        NOT_FOUND,
                        format!("plugin artifact {path} does not exist"),
                    ));
                }
                Err(e) => return Err(io_error(&format!("cannot read {path}"), &e)),
            }
            Ok(ArtifactCandidate {
                kind: artifact_kind(path).to_string(),
                url: None,
                path: Some(path.clone()),
                sha256: None,
                version: "local".to_string(),
                signature: None,
                key_id: None,
            })
        }
    }
}

fn resolve_registry(
    plugin_id: &str,
    registry: &url::Url,
    requested: &RequestedVersion,
    verify: VerifyMode,
    fetcher: &Fetcher,
) -> PResult<ArtifactCandidate> {
    let base = registry.as_str().trim_end_matches('/');
    let entry_url = url::Url::parse(&format!("{base}/v1/plugins/{plugin_id}")).map_err(|e| {
        PluginError::usage(format!(
            "invalid registry {registry}: {e}; nothing was done"
        ))
    })?;
    let what = format!("registry entry of plugin {plugin_id}");
    let body = fetcher.get(&entry_url, MAX_ENTRY_BYTES, &what)?;
    let invalid = |why: String| {
        PluginError::failed(
            CATALOG_INVALID,
            format!("the {what} at {entry_url} is invalid: {why}"),
        )
    };
    let entry: RegistryEntry = serde_json::from_slice(&body).map_err(|e| invalid(e.to_string()))?;
    if entry.plugin_id != plugin_id {
        return Err(invalid(format!(
            "it describes plugin {:?}",
            entry.plugin_id
        )));
    }
    let version = match requested {
        RequestedVersion::Specific(v) => {
            if !entry.versions.contains_key(v) {
                return Err(PluginError::failed(
                    NOT_FOUND,
                    format!("version {v} of plugin {plugin_id} is not in the registry {registry}"),
                ));
            }
            v.clone()
        }
        RequestedVersion::Latest => entry
            .versions
            .keys()
            .max_by(|a, b| version_sort_key_cmp(a, b))
            .cloned()
            .ok_or_else(|| {
                PluginError::failed(
                    NOT_FOUND,
                    format!("plugin {plugin_id} has no versions in the registry {registry}"),
                )
            })?,
    };
    if let Some(p) = component_problem(&version) {
        return Err(invalid(format!("version {version:?} {p}")));
    }
    let manifest = &entry.versions[&version];
    let platform = platform_key();
    let spec = manifest.platforms.get(&platform).ok_or_else(|| {
        PluginError::failed(
            PLATFORM_UNSUPPORTED,
            format!("plugin {plugin_id} {version} has no artifact for {platform}"),
        )
    })?;
    if !is_safe_component(&spec.bin) {
        return Err(invalid(format!(
            "artifact name {:?} is not a plain file name",
            spec.bin
        )));
    }
    let sha256 = match (verify, spec.sha256.as_deref()) {
        (VerifyMode::None, s) => s.and_then(parse_sha256),
        (VerifyMode::Sha256, Some(s)) => Some(parse_sha256(s).ok_or_else(|| {
            PluginError::failed(
                VERIFY_FAILED,
                format!(
                    "the registry gives no valid SHA-256 for plugin {plugin_id} {version} \
                     ({s:?} is not 64 hexadecimal digits); refusing to install an unverifiable artifact"
                ),
            )
        })?),
        (VerifyMode::Sha256, None) => {
            return Err(PluginError::failed(
                VERIFY_FAILED,
                format!(
                    "the registry gives no SHA-256 for plugin {plugin_id} {version}; \
                     refusing to install an unverifiable artifact"
                ),
            ));
        }
    };
    let url = url::Url::parse(&format!(
        "{base}/v1/artifacts/{plugin_id}/{version}/{}",
        spec.bin
    ))
    .map_err(|e| invalid(e.to_string()))?;
    Ok(ArtifactCandidate {
        kind: artifact_kind(&spec.bin).to_string(),
        url: Some(url),
        path: None,
        sha256,
        version,
        signature: spec.signature.clone(),
        key_id: spec.key_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_parsing_is_strict() {
        let good = "A".repeat(64);
        assert_eq!(parse_sha256(&good), Some("a".repeat(64)));
        for bad in [
            "",
            "abc",
            &"g".repeat(64),
            &format!(" {}", "a".repeat(63)),
            &"a".repeat(65),
        ] {
            assert_eq!(parse_sha256(bad), None, "{bad:?}");
        }
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn local_and_url_sources_are_described() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("demo.tar.gz");
        fs::write(&f, b"x").unwrap();
        let c = resolve(
            "demo",
            &SourceSpec::File {
                path: f.to_string_lossy().into(),
            },
            &RequestedVersion::Latest,
            VerifyMode::Sha256,
            None,
        )
        .unwrap();
        assert_eq!((c.kind.as_str(), c.version.as_str()), ("tar.gz", "local"));
        let e = resolve(
            "demo",
            &SourceSpec::File {
                path: t.path().join("none").to_string_lossy().into(),
            },
            &RequestedVersion::Latest,
            VerifyMode::Sha256,
            None,
        )
        .unwrap_err();
        assert_eq!(e.code, NOT_FOUND);
        let e = resolve(
            "demo",
            &SourceSpec::File {
                path: t.path().to_string_lossy().into(),
            },
            &RequestedVersion::Latest,
            VerifyMode::Sha256,
            None,
        )
        .unwrap_err();
        assert_eq!(e.code, NOT_FOUND);
        let c = resolve(
            "demo",
            &SourceSpec::Url {
                url: url::Url::parse("https://example.org/tool").unwrap(),
            },
            &RequestedVersion::Latest,
            VerifyMode::None,
            None,
        )
        .unwrap();
        assert_eq!((c.kind.as_str(), c.version.as_str()), ("binary", "unknown"));
    }
}
