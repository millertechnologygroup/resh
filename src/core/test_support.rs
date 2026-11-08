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
