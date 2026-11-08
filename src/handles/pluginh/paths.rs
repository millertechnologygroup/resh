//! Where the plugin verbs keep their files, and safe ways to use them.
//!
//! Every directory resh creates or uses below an XDG base directory
//! (`<base>/resh/plugins/...`) must be a real directory (not a symlink),
//! owned by the user running resh and not writable by group or others. The
//! base directory itself must belong to that user, or to root. So running
//! as root with another user's `HOME`/`XDG_*` (for example `sudo -E`) is
//! refused instead of acting on files that user controls.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::common::{IO_ERROR, PResult, PluginError, UNSAFE_PATH, io_error};

/// The base directories of the current user.
#[derive(Debug, Clone)]
pub struct Locations {
    /// `$XDG_DATA_HOME` (`~/.local/share`): the plugin store.
    pub data: PathBuf,
    /// `$XDG_STATE_HOME` (`~/.local/state`): user enable state, search cache.
    pub state: PathBuf,
    /// `$XDG_CACHE_HOME` (`~/.cache`): `available.info` index cache.
    pub cache: PathBuf,
    /// `$XDG_CONFIG_HOME` (`~/.config`): per-plugin config (purged only).
    pub config: PathBuf,
    /// Base of the system enable state (`/var/lib`; the state is in
    /// `resh/plugins` below it).
    pub system_state: PathBuf,
}

#[cfg(test)]
thread_local! {
    /// Test-only seam: every location of this thread under one directory.
    static TEST_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Puts every location of the current thread under `root` until the guard
/// is dropped (tests only).
#[cfg(test)]
pub fn test_root(root: &Path) -> TestRootGuard {
    TEST_ROOT.with(|r| *r.borrow_mut() = Some(root.to_path_buf()));
    TestRootGuard
}

#[cfg(test)]
pub struct TestRootGuard;

#[cfg(test)]
impl Drop for TestRootGuard {
    fn drop(&mut self) {
        TEST_ROOT.with(|r| *r.borrow_mut() = None);
    }
}

pub fn locations() -> PResult<Locations> {
    #[cfg(test)]
    if let Some(root) = TEST_ROOT.with(|r| r.borrow().clone()) {
        return Ok(Locations {
            data: root.join("data"),
            state: root.join("state"),
            cache: root.join("cache"),
            config: root.join("config"),
            system_state: root.join("system"),
        });
    }
    let need = |d: Option<PathBuf>, what: &str| {
        d.ok_or_else(|| {
            PluginError::failed(
                IO_ERROR,
                format!("cannot determine the {what} directory (HOME is not set)"),
            )
        })
    };
    Ok(Locations {
        data: need(dirs::data_local_dir(), "data")?,
        state: need(dirs::state_dir(), "state")?,
        cache: need(dirs::cache_dir(), "cache")?,
        config: need(dirs::config_dir(), "config")?,
        system_state: system_state_dir(),
    })
}

fn system_state_dir() -> PathBuf {
    // Debug builds only: lets the binary tests use a temporary directory
    // for scope=system. Release builds always use /var/lib.
    #[cfg(debug_assertions)]
    if let Some(d) = std::env::var_os("RESH_TEST_PLUGIN_SYSTEM_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from("/var/lib")
}

impl Locations {
    /// The plugin store: `<data>/resh/plugins`.
    pub fn store(&self) -> (PathBuf, [&'static str; 2]) {
        (self.data.clone(), ["resh", "plugins"])
    }
}

fn euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn unsafe_path(path: &Path, why: &str) -> PluginError {
    PluginError::failed(
        UNSAFE_PATH,
        format!(
            "refusing to use {}: {why}; run plugin verbs as the user who owns these \
             directories, with that user's own HOME and XDG_* variables",
            path.display()
        ),
    )
}

/// Checks the XDG base directory `base` (when it exists): a directory owned
/// by the current user or by root, and when owned by root, the current user
/// must be root too unless it is a system location.
fn check_base(base: &Path) -> PResult<bool> {
    match fs::metadata(base) {
        Ok(m) => {
            if !m.is_dir() {
                return Err(unsafe_path(base, "it is not a directory"));
            }
            let me = euid();
            if m.uid() != me && m.uid() != 0 {
                return Err(unsafe_path(
                    base,
                    &format!("it belongs to uid {}, not to uid {me}", m.uid()),
                ));
            }
            if m.uid() != me && m.mode() & 0o002 != 0 && m.mode() & 0o1000 == 0 {
                return Err(unsafe_path(base, "it is writable by every user"));
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(&format!("cannot inspect {}", base.display()), &e)),
    }
}

/// Checks one directory resh uses: a real directory (not a symlink), owned
/// by the current user or by root, not writable by group or others. `Ok(false)` when it
/// does not exist.
fn check_own_dir(path: &Path) -> PResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(unsafe_path(path, "it is a symbolic link")),
        Ok(m) if !m.is_dir() => Err(unsafe_path(path, "it is not a directory")),
        Ok(m) => {
            let me = euid();
            if m.uid() != me && m.uid() != 0 {
                return Err(unsafe_path(
                    path,
                    &format!("it belongs to uid {}, not to uid {me} or root", m.uid()),
                ));
            }
            if m.mode() & 0o022 != 0 {
                return Err(unsafe_path(path, "it is writable by group or others"));
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(&format!("cannot inspect {}", path.display()), &e)),
    }
}

/// `base/rel...` if every part that exists passes the checks; `None` when
/// some part does not exist yet. Nothing is created.
pub fn existing_dir(base: &Path, rel: &[&str]) -> PResult<Option<PathBuf>> {
    if !check_base(base)? {
        return Ok(None);
    }
    let mut cur = base.to_path_buf();
    for c in rel {
        cur.push(c);
        if !check_own_dir(&cur)? {
            return Ok(None);
        }
    }
    Ok(Some(cur))
}

/// `base/rel...`, creating missing parts with `mode` (the base itself with
/// 0700), after checking every part that already exists.
pub fn ensure_dir(base: &Path, rel: &[&str], mode: u32) -> PResult<PathBuf> {
    if !check_base(base)? {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base)
            .map_err(|e| io_error(&format!("cannot create {}", base.display()), &e))?;
        check_base(base)?;
    }
    let mut cur = base.to_path_buf();
    for c in rel {
        cur.push(c);
        if !check_own_dir(&cur)? {
            match fs::DirBuilder::new().mode(mode).create(&cur) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(io_error(&format!("cannot create {}", cur.display()), &e));
                }
            }
            // The umask may have narrowed the mode; never widen beyond it.
            let _ = fs::set_permissions(&cur, fs::Permissions::from_mode(mode));
            check_own_dir(&cur)?;
        }
    }
    Ok(cur)
}

/// Reads `dir/name` without following a symlink at `name`; `None` when it
/// does not exist.
pub fn read_file(dir: &Path, name: &str, max: u64) -> PResult<Option<Vec<u8>>> {
    use std::io::Read;
    let path = dir.join(name);
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path);
    let f = match f {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(unsafe_path(&path, "it is a symbolic link"));
        }
        Err(e) => return Err(io_error(&format!("cannot read {}", path.display()), &e)),
    };
    let meta = f
        .metadata()
        .map_err(|e| io_error(&format!("cannot read {}", path.display()), &e))?;
    if !meta.is_file() {
        return Err(unsafe_path(&path, "it is not a regular file"));
    }
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_error(&format!("cannot read {}", path.display()), &e))?;
    if buf.len() as u64 > max {
        return Err(PluginError::failed(
            IO_ERROR,
            format!("{} is larger than {max} bytes", path.display()),
        ));
    }
    Ok(Some(buf))
}

/// Writes `dir/name` atomically with `mode`: a new temporary file in `dir`
/// is written, synced and renamed over `name`. A symlink planted at `name`
/// is replaced, never written through.
pub fn write_file_atomic(dir: &Path, name: &str, data: &[u8], mode: u32) -> PResult<()> {
    let tmp = dir.join(format!(".{name}.tmp-{}", uuid::Uuid::new_v4().simple()));
    let target = dir.join(name);
    let result = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, &target)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io_error(&format!("cannot write {}", target.display()), &e));
    }
    Ok(())
}

/// Holds an exclusive `flock` on a lock file until dropped.
pub struct FileLock {
    _file: fs::File,
}

/// Takes an exclusive lock on `dir/name`, waiting until `until`. `Ok(None)`
/// when another process still holds it then.
pub fn lock(dir: &Path, name: &str, until: std::time::Instant) -> PResult<Option<FileLock>> {
    use std::os::fd::AsRawFd;
    let path = dir.join(name);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                unsafe_path(&path, "it is a symbolic link")
            } else {
                io_error(&format!("cannot open lock {}", path.display()), &e)
            }
        })?;
    loop {
        // SAFETY: flock on a descriptor this function owns.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(FileLock { _file: file }));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(io_error(&format!("cannot lock {}", path.display()), &err));
        }
        if std::time::Instant::now() >= until {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlinked_or_shared_dirs_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let base = t.path().join("base");
        let dir = ensure_dir(&base, &["resh", "plugins"], 0o755).unwrap();
        assert!(dir.is_dir());
        assert_eq!(
            fs::metadata(&base).unwrap().mode() & 0o777,
            0o700,
            "a created base is private"
        );
        // A symlinked component is refused, never followed.
        let other = t.path().join("other");
        fs::create_dir(&other).unwrap();
        fs::remove_dir(&dir).unwrap();
        symlink(&other, &dir).unwrap();
        let e = ensure_dir(&base, &["resh", "plugins"], 0o755).unwrap_err();
        assert_eq!(e.code, UNSAFE_PATH);
        assert_eq!(
            existing_dir(&base, &["resh", "plugins"]).unwrap_err().code,
            UNSAFE_PATH
        );
        // A group-writable directory is refused.
        fs::remove_file(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            existing_dir(&base, &["resh", "plugins"]).unwrap_err().code,
            UNSAFE_PATH
        );
        // Missing parts: nothing is created by existing_dir.
        assert!(existing_dir(&base, &["nope"]).unwrap().is_none());
        assert!(!base.join("nope").exists());
    }

    #[test]
    fn atomic_write_replaces_a_planted_symlink() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, t.path().join("state.json")).unwrap();
        assert_eq!(
            read_file(t.path(), "state.json", 100).unwrap_err().code,
            UNSAFE_PATH
        );
        write_file_atomic(t.path(), "state.json", b"{}", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        let m = fs::symlink_metadata(t.path().join("state.json")).unwrap();
        assert!(m.is_file());
        assert_eq!(m.mode() & 0o777, 0o600);
        assert_eq!(
            read_file(t.path(), "state.json", 100).unwrap().unwrap(),
            b"{}"
        );
        assert!(read_file(t.path(), "none", 100).unwrap().is_none());
        assert_eq!(
            read_file(t.path(), "state.json", 1).unwrap_err().code,
            IO_ERROR
        );
    }

    #[test]
    fn locks_exclude_each_other() {
        let t = tempfile::tempdir().unwrap();
        let now = std::time::Instant::now();
        let a = lock(t.path(), "x.lock", now).unwrap();
        assert!(a.is_some());
        // A second open file description cannot take it while `a` holds it.
        let b = lock(
            t.path(),
            "x.lock",
            now + std::time::Duration::from_millis(50),
        )
        .unwrap();
        assert!(b.is_none());
        drop(a);
        assert!(lock(t.path(), "x.lock", now).unwrap().is_some());
    }
}
