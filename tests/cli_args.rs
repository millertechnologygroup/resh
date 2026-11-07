//! Command-line `key=value` arguments reach the handle exactly as the shell
//! passed them: surrounding spaces in a value are data, not noise.

use tempfile::TempDir;

#[test]
fn value_whitespace_is_preserved() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("out.txt");
    let url = format!("file://{}.write", path.display());
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .args([url.as_str(), "data=  indented line  "])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "  indented line  ");
}

#[test]
fn key_whitespace_is_still_ignored() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("out.txt");
    let url = format!("file://{}.write", path.display());
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .args([url.as_str(), " data =x"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
}
