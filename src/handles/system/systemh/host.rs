//! The system handle's view of the host: every `/proc`, `/sys` and `/etc`
//! read, `statvfs`, the process environment and the pause between CPU
//! samples go through [`Host`]. Production uses the real root (`/`); tests
//! point it at a fixture directory laid out like a root filesystem, which is
//! the seam that lets cgroup v1/v2, missing files and odd formats be tested
//! without touching the machine.

use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why a file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadKind {
    NotFound,
    Denied,
    Other,
}

/// A failed read of `path` (the path as seen on the host, for example
/// `/proc/meminfo`, never the fixture path).
#[derive(Debug, Clone)]
pub struct ReadError {
    pub path: String,
    pub kind: ReadKind,
    pub detail: String,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot read {}: {}", self.path, self.detail)
    }
}

/// Capacity and inode counts of one filesystem, from `statvfs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStats {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub inodes_total: u64,
    pub inodes_used: u64,
    pub inodes_free: u64,
}

type Pause = Arc<dyn Fn(u64) + Send + Sync>;
type StatHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Where the handle reads host information from.
#[derive(Clone)]
pub struct Host {
    root: PathBuf,
    /// The environment reported for the resh process itself (tests only).
    env: Option<Vec<(String, String)>>,
    /// Waits between the two CPU samples (a real sleep in production).
    pause: Pause,
    /// Runs before each `statvfs` (tests use it to simulate a hung mount).
    stat_hook: Option<StatHook>,
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").field("root", &self.root).finish()
    }
}

impl Host {
    /// The real host. Debug builds honor `RESH_TEST_SYSTEM_ROOT=<dir>` so
    /// the binary tests can run against fixture trees; release builds always
    /// read `/`.
    pub fn real() -> Host {
        #[cfg(debug_assertions)]
        if let Some(dir) = std::env::var_os("RESH_TEST_SYSTEM_ROOT") {
            return Host::at(dir);
        }
        Host::at("/")
    }

    /// A host rooted at `root` (a fixture directory in tests).
    pub fn at(root: impl Into<PathBuf>) -> Host {
        Host {
            root: root.into(),
            env: None,
            pause: Arc::new(|ms| std::thread::sleep(Duration::from_millis(ms))),
            stat_hook: None,
        }
    }

    /// True when this is the machine's own root.
    pub fn is_real_root(&self) -> bool {
        self.root == Path::new("/")
    }

    #[cfg(test)]
    pub fn with_env(mut self, env: &[(&str, &str)]) -> Host {
        self.env = Some(
            env.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        self
    }

    #[cfg(test)]
    pub fn with_pause(mut self, pause: impl Fn(u64) + Send + Sync + 'static) -> Host {
        self.pause = Arc::new(pause);
        self
    }

    #[cfg(test)]
    pub fn with_stat_hook(mut self, hook: impl Fn(&str) + Send + Sync + 'static) -> Host {
        self.stat_hook = Some(Arc::new(hook));
        self
    }

    /// The real location of the host path `abs` (an absolute path).
    pub fn path(&self, abs: &str) -> PathBuf {
        let rel = abs.trim_start_matches('/');
        if rel.is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    fn read_error(abs: &str, e: &std::io::Error) -> ReadError {
        let kind = match e.kind() {
            ErrorKind::NotFound => ReadKind::NotFound,
            ErrorKind::PermissionDenied => ReadKind::Denied,
            _ if e.raw_os_error() == Some(libc::ESRCH) => ReadKind::NotFound,
            _ => ReadKind::Other,
        };
        ReadError {
            path: abs.to_string(),
            kind,
            detail: e.to_string(),
        }
    }

    /// Reads the host file `abs` as text (invalid UTF-8 is replaced).
    pub fn read(&self, abs: &str) -> Result<String, ReadError> {
        self.read_bytes(abs)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn read_bytes(&self, abs: &str) -> Result<Vec<u8>, ReadError> {
        std::fs::read(self.path(abs)).map_err(|e| Self::read_error(abs, &e))
    }

    /// Reads `abs` and trims it; `None` if it cannot be read.
    pub fn read_trim(&self, abs: &str) -> Option<String> {
        self.read(abs).ok().map(|s| s.trim().to_string())
    }

    pub fn exists(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }

    /// Names in the host directory `abs`.
    pub fn list_dir(&self, abs: &str) -> Result<Vec<String>, ReadError> {
        let rd = std::fs::read_dir(self.path(abs)).map_err(|e| Self::read_error(abs, &e))?;
        Ok(rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect())
    }

    /// The host path `abs` with symlinks resolved, as a host path.
    pub fn canonical(&self, abs: &str) -> Option<String> {
        let real = std::fs::canonicalize(self.path(abs)).ok()?;
        let root = std::fs::canonicalize(&self.root).ok()?;
        let rel = real.strip_prefix(&root).ok()?;
        Some(format!("/{}", rel.to_string_lossy()))
    }

    /// The device number (`st_dev`) of the filesystem holding `abs`.
    pub fn device_of(&self, abs: &str) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(self.path(abs)).ok()?.dev();
        Some((libc::major(dev) as u64, libc::minor(dev) as u64))
    }

    pub fn stat_hook(&self) -> Option<StatHook> {
        self.stat_hook.clone()
    }

    pub fn now_unix_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    pub fn pause(&self, ms: u64) {
        (self.pause)(ms)
    }

    pub fn pid(&self) -> i64 {
        std::process::id() as i64
    }

    /// The environment of the resh process itself.
    pub fn own_env(&self) -> Vec<(String, String)> {
        match &self.env {
            Some(env) => env.clone(),
            None => std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
        }
    }

    /// The hardware name the kernel reports (`uname -m`): from
    /// `/proc/sys/kernel/arch` when present, else `uname(2)` on the real
    /// root.
    pub fn machine(&self) -> Option<String> {
        if let Some(arch) = self
            .read_trim("/proc/sys/kernel/arch")
            .filter(|s| !s.is_empty())
        {
            return Some(arch);
        }
        if !self.is_real_root() {
            return None;
        }
        // SAFETY: uname fills the zeroed struct; each field is a
        // NUL-terminated C string within its array.
        unsafe {
            let mut u: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut u) != 0 {
                return None;
            }
            let s = std::ffi::CStr::from_ptr(u.machine.as_ptr());
            Some(s.to_string_lossy().into_owned())
        }
    }

    /// Clock ticks per second (`USER_HZ`) for `/proc` tick counters.
    pub fn clock_ticks(&self) -> u64 {
        // SAFETY: sysconf has no preconditions.
        let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if t > 0 { t as u64 } else { 100 }
    }
}

/// `statvfs` of `path` (a real path, see [`Host::path`]).
pub fn statvfs_at(path: &Path) -> Result<FsStats, String> {
    let st = nix::sys::statvfs::statvfs(path).map_err(|e| e.desc().to_string())?;
    // f_blocks, f_bfree and f_bavail count fragments of f_frsize bytes.
    let unit = if st.fragment_size() > 0 {
        st.fragment_size()
    } else {
        st.block_size()
    } as u64;
    let blocks = st.blocks() as u64;
    let free = st.blocks_free() as u64;
    let avail = st.blocks_available() as u64;
    let files = st.files() as u64;
    let ffree = st.files_free() as u64;
    Ok(FsStats {
        total_bytes: blocks.saturating_mul(unit),
        used_bytes: blocks.saturating_sub(free).saturating_mul(unit),
        free_bytes: free.saturating_mul(unit),
        avail_bytes: avail.saturating_mul(unit),
        inodes_total: files,
        inodes_used: files.saturating_sub(ffree),
        inodes_free: ffree,
    })
}

/// Undoes the octal escapes the kernel uses in `/proc/*/mounts` and
/// `mountinfo` fields (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash). Other text is kept as is.
pub fn unescape_octal(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let v = (bytes[i + 1] - b'0') as u32 * 64
                + (bytes[i + 2] - b'0') as u32 * 8
                + (bytes[i + 3] - b'0') as u32;
            if v <= 0xff {
                out.push(v as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
