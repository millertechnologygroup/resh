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
