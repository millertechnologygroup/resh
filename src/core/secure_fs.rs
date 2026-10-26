//! File writes that must not be redirected through a planted symlink and must
//! not expose their content through a permissive mode, even briefly.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to write through a symlink: {}", path.display()),
        )),
        _ => Ok(()),
    }
}

/// True if anything exists at `path`, including a dangling symlink.
pub fn entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// An unpredictable sibling of `path`, created with `O_EXCL | O_NOFOLLOW`
/// and the given mode from the start.
fn create_sibling_temp(path: &Path, mode: u32) -> io::Result<(PathBuf, File)> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name,
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    Ok((tmp, file))
}

/// Writes secret data (a private key) so that the file is mode 0600 from the
/// moment it exists and a symlink at `path` is never followed.
///
/// Without `overwrite`, an existing entry at `path` (a dangling symlink
/// included) is an error. With `overwrite`, the data goes to a fresh temp
/// file that is renamed over `path`; a symlink at `path` is still refused.
pub fn write_private_file(path: &Path, data: &[u8], overwrite: bool) -> io::Result<()> {
    refuse_symlink(path)?;
    if !overwrite {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // The umask can only remove bits from 0600; set it exactly anyway.
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        let written = f.write_all(data).and_then(|_| f.sync_all());
        if written.is_err() {
            let _ = fs::remove_file(path);
        }
        return written;
    }
    let (tmp, mut f) = create_sibling_temp(path, 0o600)?;
    let result = f
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|_| f.write_all(data))
        .and_then(|_| f.sync_all())
        .and_then(|_| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Copies `src` to `dest` as a backup without following a symlink at
/// `dest`: an existing symlink is refused, the copy is written to a fresh
/// temp file with the source's permission bits (without setuid/setgid/sticky),
/// and the temp file is renamed over `dest`.
pub fn copy_no_follow(src: &Path, dest: &Path) -> io::Result<u64> {
    refuse_symlink(dest)?;
    let mut input = File::open(src)?;
    let mode = input.metadata()?.permissions().mode() & 0o777;
    let (tmp, mut out) = create_sibling_temp(dest, 0o600)?;
    let result = io::copy(&mut input, &mut out).and_then(|n| {
        out.set_permissions(fs::Permissions::from_mode(mode))?;
        out.sync_all()?;
        fs::rename(&tmp, dest)?;
        Ok(n)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn private_file_is_0600_and_new() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.pem");
        write_private_file(&p, b"secret", false).unwrap();
        assert_eq!(mode(&p), 0o600);
        assert_eq!(fs::read(&p).unwrap(), b"secret");
        assert!(write_private_file(&p, b"again", false).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"secret");
    }

    #[test]
    fn private_file_overwrite_replaces_and_stays_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.pem");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&p, b"new", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn private_file_refuses_symlinks_including_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        let link = dir.path().join("k.pem");
        symlink(&victim, &link).unwrap();
        for overwrite in [false, true] {
            assert!(write_private_file(&link, b"secret", overwrite).is_err());
            assert!(!victim.exists());
        }
        fs::write(&victim, b"keep").unwrap();
        for overwrite in [false, true] {
            assert!(write_private_file(&link, b"secret", overwrite).is_err());
            assert_eq!(fs::read(&victim).unwrap(), b"keep");
        }
    }

    #[test]
    fn copy_refuses_symlink_and_keeps_target() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("app.conf");
        fs::write(&src, b"content").unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        let bak = dir.path().join("app.conf.bak");
        symlink(&victim, &bak).unwrap();
        assert!(copy_no_follow(&src, &bak).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(mode(&victim), 0o600);

        let dangling = dir.path().join("other.bak");
        let created = dir.path().join("created");
        symlink(&created, &dangling).unwrap();
        assert!(copy_no_follow(&src, &dangling).is_err());
        assert!(!created.exists());
    }

    #[test]
    fn copy_writes_content_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("app.conf");
        fs::write(&src, b"content").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o640)).unwrap();
        let bak = dir.path().join("app.conf.bak");
        fs::write(&bak, b"stale").unwrap();
        assert_eq!(copy_no_follow(&src, &bak).unwrap(), 7);
        assert_eq!(fs::read(&bak).unwrap(), b"content");
        assert_eq!(mode(&bak), 0o640);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
