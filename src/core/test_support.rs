//! Helpers shared by unit tests.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Create an executable script at `path` through a child process.
///
/// A test that writes a file itself holds a write descriptor while it does
/// so; a `fork` in another test thread copies that descriptor into a child
/// that keeps it until its `exec`. Executing the script in that window
/// fails with ETXTBSY ("Text file busy"). Writing from a child means this
/// process never holds such a descriptor.
pub fn write_executable(path: &Path, contents: &str) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "cannot write {}",
        path.display()
    );
}

/// Waits (up to 30 s) until this process has an inotify watch on `path`
/// (or, for a file, on its directory), then runs `f` in a new thread. A test that
/// changes a file for a watcher started by the code under test uses it
/// instead of a fixed sleep, which loses the change when the watcher is
/// slow to start on a busy machine.
pub fn when_watched(path: &Path, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    use std::os::unix::fs::MetadataExt;
    let mut inodes = Vec::new();
    let dir = path.parent().filter(|_| !path.is_dir());
    for p in [Some(path), dir].into_iter().flatten() {
        if let Ok(m) = std::fs::metadata(p) {
            inodes.push(format!("ino:{:x} ", m.ino()));
        }
    }
    std::thread::spawn(move || {
        wait_for(|| {
            std::fs::read_dir("/proc/self/fdinfo")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                .any(|info| {
                    info.lines()
                        .any(|l| l.starts_with("inotify") && inodes.iter().any(|i| l.contains(i)))
                })
        });
        f()
    })
}

/// Waits (up to 30 s) until this process has `path` open, lets it read
/// for a moment, then runs `f` in a new thread: for changes to a file that
/// the code under test follows.
pub fn when_open(path: &Path, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    std::thread::spawn(move || {
        wait_for(|| {
            std::fs::read_dir("/proc/self/fd")
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| std::fs::read_link(e.path()).is_ok_and(|l| l == want))
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        f()
    })
}

fn wait_for(mut ready: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready() && std::time::Instant::now() < end {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The option names a help usage lists (`name=` words, after `[`, `|`, `(`
/// or whitespace), sorted and without duplicates. Templated names such as
/// `header_<Name>=` are left out.
pub fn usage_option_names(usage: &str) -> Vec<&str> {
    let mut names: Vec<&str> = usage
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | '|' | '('))
        .filter_map(|w| w.split_once('=').map(|(k, _)| k))
        .filter(|k| {
            k.starts_with(|c: char| c.is_ascii_lowercase())
                && k.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}
