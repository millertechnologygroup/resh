//! Hashing verbs: md5, sha1, sha256, sha512, hash, verify.

use super::FileHandle;
use super::common::{Code, Deadline, Fail, Opts, emit, fail, invalid};
use crate::core::{IoStreams, Status};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Files larger than this are refused by every hashing verb.
pub(crate) const MAX_HASH_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Algorithms accepted by `hash algo=` and `verify algo=`.
pub(crate) const ALGOS: &[&str] = &["sha256", "sha512", "sha1", "md5", "blake3"];

/// Streams a regular file through the algorithm. Returns the lowercase hex
/// digest and the number of bytes hashed.
pub(crate) fn hash_file(path: &Path, algo: &str, deadline: Deadline) -> Result<(String, u64)> {
    let meta = fs::metadata(path).with_context(|| format!("hash {}", path.display()))?;
    if meta.is_dir() {
        return Err(fail(
            Code::IsADirectory,
            format!("{} is a directory", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(fail(
            Code::NotAFile,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.len() > MAX_HASH_SIZE {
        return Err(fail(
            Code::TooLarge,
            format!(
                "{} is {} bytes; files over {MAX_HASH_SIZE} bytes are not hashed",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut file = File::open(path).with_context(|| format!("hash {}", path.display()))?;
    let ctx = || format!("read {}", path.display());
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    let size = meta.len();
    let mut feed = |update: &mut dyn FnMut(&[u8])| -> Result<()> {
        loop {
            deadline.check(|| {
                format!(
                    "{total} of {size} bytes of {} were hashed; no digest was produced",
                    path.display()
                )
            })?;
            let n = file.read(&mut buf).with_context(ctx)?;
            if n == 0 {
                return Ok(());
            }
            update(&buf[..n]);
            total += n as u64;
        }
    };
    let hex = match algo {
        "md5" => {
            let mut c = md5::Context::new();
            feed(&mut |b| c.consume(b))?;
            format!("{:x}", c.compute())
        }
        "sha1" => {
            use sha1::Digest;
            let mut h = sha1::Sha1::new();
            feed(&mut |b| h.update(b))?;
            format!("{:x}", h.finalize())
        }
        "sha256" => {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            feed(&mut |b| h.update(b))?;
            format!("{:x}", h.finalize())
        }
        "sha512" => {
            use sha2::Digest;
            let mut h = sha2::Sha512::new();
            feed(&mut |b| h.update(b))?;
            format!("{:x}", h.finalize())
        }
        "blake3" => {
            let mut h = blake3::Hasher::new();
            feed(&mut |b| {
                h.update(b);
            })?;
            h.finalize().to_hex().to_string()
        }
        other => return Err(invalid(format!("unsupported algorithm: {other}"))),
    };
    Ok((hex, total))
}

/// Length in hex digits of a digest.
fn hex_len(algo: &str) -> usize {
    match algo {
        "md5" => 32,
        "sha1" => 40,
        "sha512" => 128,
        _ => 64,
    }
}

/// A user-supplied digest: hex of the algorithm's length (spaces ignored).
fn parse_digest(key: &str, raw: &str, algo: &str) -> Result<String> {
    let d: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if d.len() != hex_len(algo) || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "invalid value for {key}: {raw:?} (expected {} hex digits for {algo})",
            hex_len(algo)
        )));
    }
    Ok(d)
}

impl FileHandle {
    /// md5, sha1, sha256, sha512: `{"path","algorithm","hash","size"}`.
    pub(super) fn verb_fixed_hash(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let algo = o.verb();
        let (hash, size) = hash_file(&self.path, algo, o.deadline()?)?;
        emit(
            io,
            &json!({
                "path": self.path.to_string_lossy(),
                "algorithm": algo,
                "hash": hash,
                "size": size
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_hash(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let algo = o.choice("algo", ALGOS)?.unwrap_or("sha256");
        let deadline = o.deadline()?;
        let (hash, size) = hash_file(&self.path, algo, deadline)?;
        emit(
            io,
            &json!({
                "path": self.path.display().to_string(),
                "algo": algo,
                "hash_hex": hash,
                "size_bytes": size
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_verify(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let algo = o.choice("algo", ALGOS)?.unwrap_or("sha256");
        let expected = o
            .get("expected")
            .map(|e| parse_digest("expected", e, algo))
            .transpose()?;
        let expected_any: Vec<String> = match o.get("expected_any") {
            None => Vec::new(),
            Some(list) => {
                let v = list
                    .split(';')
                    .filter(|d| !d.trim().is_empty())
                    .map(|d| parse_digest("expected_any", d, algo))
                    .collect::<Result<Vec<_>>>()?;
                if v.is_empty() {
                    return Err(invalid("expected_any= must list at least one digest"));
                }
                v
            }
        };
        let expected_size = o.number::<u64>("size", 0)?;
        let deadline = o.deadline()?;

        let report = |digest: Option<&str>,
                      size: Option<u64>,
                      hash_match: bool,
                      size_match: bool,
                      error: Option<Value>| {
            json!({
                "path": self.path.display().to_string(),
                "algorithm": algo,
                "digest": digest,
                "size": size,
                "expected": expected,
                "expected_any": expected_any,
                "match": hash_match,
                "size_match": size_match,
                "verified": error.is_none() && hash_match && size_match,
                "error": error
            })
        };

        let (digest, size) = match hash_file(&self.path, algo, deadline) {
            Ok(r) => r,
            Err(e) => {
                let err = super::common::error_json_of(&e);
                emit(io, &report(None, None, false, false, Some(err)))?;
                return Err(e);
            }
        };
        let hash_match = (expected.is_none() && expected_any.is_empty())
            || expected.as_deref() == Some(digest.as_str())
            || expected_any.contains(&digest);
        let size_match = expected_size.is_none_or(|s| s == size);
        let value: Value = report(Some(&digest), Some(size), hash_match, size_match, None);
        emit(io, &value)?;
        if hash_match && size_match {
            Ok(Status::ok())
        } else {
            let what = match (hash_match, size_match) {
                (false, false) => "digest and size do not match",
                (false, true) => "digest does not match",
                _ => "size does not match",
            };
            Err(Fail {
                code: Code::VerifyFailed,
                msg: format!("{}: {what}", self.path.display()),
            }
            .into())
        }
    }
}
