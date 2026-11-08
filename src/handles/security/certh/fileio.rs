//! File input and output for the cert verbs, and the `timeout_ms` deadline.
//!
//! - Inputs (certificates, keys, CSRs, bundles) are read with a size limit,
//!   so the verbs that only read them finish at once.
//! - Outputs never follow a symlink planted at the path: a symlink there is
//!   refused. Data is written to a fresh temporary file in the same
//!   directory and renamed into place. Private keys are 0600 from the start;
//!   certificates, CSRs and signatures 0644.
//! - Work that can take long (key generation, reading data to sign) runs in
//!   a worker thread. It must call [`Gate::commit`] before its first write;
//!   once the deadline has passed, `commit` fails, so a timed-out run writes
//!   nothing.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use super::errors::{CResult, CertError, read_error};

/// Largest certificate, key, CSR or bundle file read (16 MiB).
pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Strips the `file://` and `cert://` prefixes accepted on path options.
pub fn plain_path(path: &str) -> &str {
    path.strip_prefix("file://")
        .or_else(|| path.strip_prefix("cert://"))
        .unwrap_or(path)
}

/// Reads an input file of at most [`MAX_INPUT_BYTES`]. `what` names it in
/// messages ("certificate", "signer key", ...). A `string:<text>` source is
/// the text itself.
pub fn read_input(what: &str, source: &str) -> CResult<Vec<u8>> {
    if let Some(text) = source.strip_prefix("string:") {
        return Ok(text.as_bytes().to_vec());
    }
    let path = plain_path(source);
    let f = fs::File::open(path).map_err(|e| read_error(what, path, &e))?;
    let meta = f.metadata().map_err(|e| read_error(what, path, &e))?;
    if meta.is_dir() {
        return Err(CertError::failed(
            "cert.read_failed",
            format!("{what} {path} is a directory"),
        ));
    }
    let mut data = Vec::new();
    f.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| read_error(what, path, &e))?;
    if data.len() as u64 > MAX_INPUT_BYTES {
        return Err(CertError::failed(
            "cert.read_failed",
            format!(
                "{what} {path} is larger than {} MiB",
                MAX_INPUT_BYTES / 1024 / 1024
            ),
        ));
    }
    Ok(data)
}

/// True if anything exists at `path`, a dangling symlink included.
pub fn exists(path: &str) -> bool {
    crate::core::secure_fs::entry_exists(Path::new(plain_path(path)))
}

/// Refuses every existing path in `paths` unless `overwrite`, and a symlink
/// at any of them in every case. Run before anything is written.
pub fn check_outputs(paths: &[&str], overwrite: bool) -> CResult<()> {
    let mut existing = Vec::new();
    for p in paths {
        let path = plain_path(p);
        if let Ok(m) = fs::symlink_metadata(path) {
            if m.file_type().is_symlink() {
                return Err(CertError::failed(
                    "cert.symlink_refused",
                    format!("refusing to write through the symlink at {path}"),
                ));
            }
            existing.push(path.to_string());
        }
    }
    if !overwrite && !existing.is_empty() {
        return Err(CertError::failed(
            "cert.target_exists",
            format!(
                "output already exists: {} (pass overwrite=true to replace it)",
                existing.join(", ")
            ),
        )
        .with_details(serde_json::json!({ "existing_paths": existing })));
    }
    Ok(())
}

/// Writes `data` to `path` with `mode`, through a temporary sibling that is
/// renamed into place; a symlink at `path` is refused.
fn write_atomic(path: &str, data: &[u8], mode: u32, overwrite: bool) -> CResult<()> {
    let path = plain_path(path);
    check_outputs(&[path], overwrite)?;
    let target = Path::new(path);
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name,
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let failed = |e: std::io::Error| {
        CertError::failed("cert.write_failed", format!("cannot write {path}: {e}"))
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(failed)?;
    let result = f
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| f.write_all(data))
        .and_then(|_| f.sync_all())
        .and_then(|_| {
            // Without overwrite, never replace an entry that appeared since
            // the check: link(2) fails if the name exists.
            if overwrite {
                fs::rename(&tmp, target)
            } else {
                fs::hard_link(&tmp, target).and_then(|_| fs::remove_file(&tmp))
            }
        });
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(CertError::failed(
                "cert.target_exists",
                format!("output already exists: {path} (pass overwrite=true to replace it)"),
            ));
        }
        return Err(failed(e));
    }
    Ok(())
}

/// Writes a private key: mode 0600 from the moment the file exists.
pub fn write_private(path: &str, data: &[u8], overwrite: bool) -> CResult<()> {
    write_atomic(path, data, 0o600, overwrite)
}

/// Writes a certificate, CSR or signature: mode 0644.
pub fn write_public(path: &str, data: &[u8], overwrite: bool) -> CResult<()> {
    write_atomic(path, data, 0o644, overwrite)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GateState {
    Running,
    Committed,
    Cancelled,
}

/// Lets a worker check, right before its first write, that the deadline has
/// not passed, and stops the deadline from passing while it writes.
#[derive(Clone)]
pub struct Gate(Arc<Mutex<GateState>>);

impl Gate {
    /// Call before writing anything: fails with `cert.timeout` if the
    /// deadline has passed.
    pub fn commit(&self) -> CResult<()> {
        let mut s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match *s {
            GateState::Cancelled => Err(CertError::timeout(
                "timeout_ms reached before anything was written",
            )),
            _ => {
                *s = GateState::Committed;
                Ok(())
            }
        }
    }
}

/// Runs `work` in a worker thread and waits at most `timeout`. If the
/// deadline passes before the worker called [`Gate::commit`], the result is
/// `cert.timeout` (exit 124) and nothing is written; if the worker is
/// already writing, its writes are waited for.
pub fn run_with_deadline<T, F>(timeout: Duration, work: F) -> CResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Gate) -> CResult<T> + Send + 'static,
{
    let state = Arc::new(Mutex::new(GateState::Running));
    let gate = Gate(state.clone());
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("cert-worker".into())
        .spawn(move || {
            let _ = tx.send(work(&gate));
        })
        .map_err(|e| {
            CertError::failed(
                "cert.generation_failed",
                format!("cannot start worker: {e}"),
            )
        })?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            {
                let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
                if *s == GateState::Running {
                    *s = GateState::Cancelled;
                    return Err(CertError::timeout(format!(
                        "timeout_ms={} reached; nothing was written",
                        timeout.as_millis()
                    )));
                }
            }
            rx.recv().unwrap_or_else(|_| {
                Err(CertError::failed(
                    "cert.generation_failed",
                    "the worker stopped unexpectedly",
                ))
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(CertError::failed(
            "cert.generation_failed",
            "the worker stopped unexpectedly",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_refuse_symlinks_and_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.pem");
        let t = target.to_str().unwrap();
        write_public(t, b"one", false).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            write_public(t, b"two", false).unwrap_err().code,
            "cert.target_exists"
        );
        write_public(t, b"two", true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");

        let victim = dir.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        for overwrite in [false, true] {
            let e = write_private(link.to_str().unwrap(), b"x", overwrite).unwrap_err();
            assert_eq!(e.code, "cert.symlink_refused");
        }
        assert_eq!(fs::read(&victim).unwrap(), b"keep");

        let key = dir.path().join("k.pem");
        write_private(key.to_str().unwrap(), b"secret", false).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // No temporary files are left behind.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }

    #[test]
    fn deadline_cancels_before_commit() {
        let r: CResult<()> = run_with_deadline(Duration::from_millis(20), |gate| {
            std::thread::sleep(Duration::from_millis(200));
            gate.commit()
        });
        assert_eq!(r.unwrap_err().code, "cert.timeout");
        let r = run_with_deadline(Duration::from_secs(5), |gate| {
            gate.commit()?;
            Ok(7)
        });
        assert_eq!(r.unwrap(), 7);
    }
}
