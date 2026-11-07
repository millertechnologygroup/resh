//! Every help spelling works for every handle and verb, and unknown names
//! fail clearly. See docs/cli_help_format.md.

use resh::{Registry, handles};

fn resh(args: &[&str]) -> (i32, String, String) {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn registry() -> Registry {
    let mut reg = Registry::default();
    handles::register_all(&mut reg);
    reg
}

/// Each (handle, verb) pair listed in the handle's help.
fn handles_and_verbs() -> Vec<(String, Vec<String>)> {
    let reg = registry();
    reg.list_schemes()
        .into_iter()
        .map(|s| {
            let (code, out, err) = resh(&[s.as_str(), "--help"]);
            assert_eq!(code, 0, "{s} --help: {err}");
            let verbs = out
                .split("Available Verbs:\n")
                .nth(1)
                .unwrap()
                .split("\n\n")
                .next()
                .unwrap()
                .lines()
                .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
                .map(|l| l.split_whitespace().next().unwrap().to_string())
                .collect();
            (s.to_string(), verbs)
        })
        .collect()
}

#[test]
fn every_help_spelling_gives_the_same_handle_help() {
    for (handle, _) in handles_and_verbs() {
        let (_, expected, _) = resh(&[&handle, "--help"]);
        assert!(expected.starts_with(&format!("Handle: {handle}\n")));
        for args in [
            vec![handle.as_str(), "-h"],
            vec![handle.as_str(), "help"],
            vec!["help", handle.as_str()],
        ] {
            let (code, out, err) = resh(&args);
            assert_eq!(code, 0, "{args:?}: {err}");
            assert_eq!(out, expected, "{args:?}");
            assert!(err.is_empty(), "{args:?}: {err}");
        }
    }
}

#[test]
fn every_help_spelling_gives_the_same_verb_help() {
    for (handle, verbs) in handles_and_verbs() {
        assert!(!verbs.is_empty(), "{handle} lists no verbs");
        for verb in &verbs {
            let (code, expected, err) = resh(&[&handle, verb, "--help"]);
            assert_eq!(code, 0, "{handle} {verb} --help: {err}");
            assert!(
                expected.starts_with(&format!("Handle: {handle}\nVerb: {verb}\n")),
                "{handle} {verb}: {expected}"
            );
            assert!(
                expected.lines().all(|l| l.chars().count() <= 80),
                "{handle} {verb}: line over 80 columns"
            );
            for args in [
                vec![handle.as_str(), verb.as_str(), "-h"],
                vec![handle.as_str(), verb.as_str(), "help"],
                vec!["help", handle.as_str(), verb.as_str()],
            ] {
                let (code, out, _) = resh(&args);
                assert_eq!(code, 0, "{args:?}");
                assert_eq!(out, expected, "{args:?}");
            }
        }
    }
}

#[test]
fn unknown_handle_is_an_error_with_a_suggestion() {
    for args in [
        vec!["fiel", "--help"],
        vec!["fiel", "-h"],
        vec!["help", "fiel"],
    ] {
        let (code, out, err) = resh(&args);
        assert_eq!(code, 2, "{args:?}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains("unknown handle 'fiel'"), "{err}");
        assert!(err.contains("Did you mean 'file'?"), "{err}");
        assert!(err.contains("resh --list-schemas"), "{err}");
    }
    let (code, _, err) = resh(&["zzzzzz", "--help"]);
    assert_eq!(code, 2);
    assert!(!err.contains("Did you mean"), "{err}");
}

#[test]
fn unknown_verb_is_an_error_listing_the_verbs() {
    let (code, out, err) = resh(&["file", "reed", "--help"]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(
        err.contains("unknown verb 'reed' for handle 'file'"),
        "{err}"
    );
    assert!(err.contains("Did you mean 'read'?"), "{err}");
    assert!(err.contains("Available verbs: read,"), "{err}");
    assert!(err.contains("resh file --help"), "{err}");
    assert!(err.lines().all(|l| l.chars().count() <= 80), "{err}");
}

#[test]
fn bare_handle_name_is_not_a_stage() {
    for args in [vec!["file"], vec!["file", "read"]] {
        let (code, _, err) = resh(&args);
        assert_eq!(code, 2, "{args:?}");
        assert!(
            err.contains("'file' is a handle name, not a stage"),
            "{err}"
        );
        assert!(err.contains("file://<target>.<verb>"), "{err}");
    }
}

#[test]
fn bare_help_is_global_help() {
    let (code, out, _) = resh(&["help"]);
    let (_, global, _) = resh(&["--help"]);
    assert_eq!(code, 0);
    assert_eq!(out, global);
}
