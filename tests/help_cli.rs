//! CLI tests for `resh <handle> --help` and `resh <handle> <verb> --help`.

use assert_cmd::Command;
use resh::core::parse::parse_stage;
use resh::{Registry, handles};

fn resh() -> Command {
    Command::cargo_bin("resh").unwrap()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = resh().args(args).output().unwrap();
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

/// Operation verbs registered by svc, excluding help aliases.
fn svc_registered_verbs() -> Vec<&'static str> {
    let h = registry().instantiate("svc").unwrap().unwrap();
    h.verbs()
        .iter()
        .copied()
        .filter(|v| !["help", "--help", "-h"].contains(v))
        .collect()
}

/// Verb names in the "Available Verbs:" section, one per line.
fn listed_verbs(out: &str) -> Vec<String> {
    out.split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect()
}

fn assert_plain_text(out: &str) {
    assert!(!out.contains('\x1b'), "ANSI escape in output");
    assert!(out.is_ascii(), "non-ASCII in output");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
    }
}

// --- handle-level help -----------------------------------------------------

#[test]
fn handle_help_matches_golden() {
    let (code, out, err) = run(&["svc", "--help"]);
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_eq!(out, include_str!("golden/svc_help.txt"));
}

#[test]
fn handle_help_names_handle_and_has_description() {
    let (_, out, _) = run(&["svc", "--help"]);
    assert!(out.starts_with("Handle: svc\n"));
    let desc = out
        .split("Description:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap();
    assert!(desc.lines().all(|l| l.starts_with("  ")));
    assert!(
        desc.matches(". ").count() >= 1,
        "description should be a paragraph"
    );
    assert!(out.contains("Usage:\n  resh svc://<service-name>.<verb>"));
    assert!(out.contains("For help with a specific verb:\n  resh svc <verb> --help\n"));
}

#[test]
fn handle_help_lists_exactly_the_registered_verbs() {
    let (_, out, _) = run(&["svc", "--help"]);
    let mut listed = listed_verbs(&out);
    let mut registered: Vec<String> = svc_registered_verbs()
        .iter()
        .map(|s| s.to_string())
        .collect();
    listed.sort();
    registered.sort();
    assert_eq!(listed, registered);
    for absent in ["list", "invalidverb", "help", "--help", "-h"] {
        assert!(
            !listed.iter().any(|v| v == absent),
            "{absent} should not be listed"
        );
    }
}

// --- verb-level help -------------------------------------------------------

#[test]
fn verb_help_matches_golden() {
    let (code, out, err) = run(&["svc", "status", "--help"]);
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_eq!(out, include_str!("golden/svc_status_help.txt"));
}

#[test]
fn verb_help_has_labels_in_order() {
    let (_, out, _) = run(&["svc", "status", "--help"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "Handle: svc");
    assert_eq!(lines[1], "Verb: status");
    assert!(lines[2].starts_with("Definition: "));
    let pos = |label: &str| out.find(label).unwrap_or_else(|| panic!("missing {label}"));
    assert!(pos("Definition: ") < pos("\nUsage:\n"));
    assert!(pos("\nUsage:\n") < pos("\nExample:\n"));
}

#[test]
fn verb_help_example_is_a_valid_stage() {
    let (_, out, _) = run(&["svc", "status", "--help"]);
    let example = out
        .split("Example:\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim();
    let stage = example
        .strip_prefix("resh ")
        .expect("example should start with resh");
    let parsed = parse_stage(stage).unwrap();
    assert_eq!(parsed.verb, "status");
    assert!(parsed.args.is_empty());
    let handle = registry().resolve(&parsed.target).unwrap();
    assert!(handle.verbs().contains(&"status"));
}

#[test]
fn verb_help_example_output_matches_systemd_status_shape() {
    let (_, out, _) = run(&["svc", "status", "--help"]);
    assert!(out.find("\nExample:\n").unwrap() < out.find("\nExample Output:\n").unwrap());

    // Strip section indentation and take the JSON block.
    let section = out.split("Example Output:\n").nth(1).unwrap();
    let json_text: String = section
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .map(|l| format!("{}\n", l.strip_prefix("  ").unwrap()))
        .collect();
    let v: serde_json::Value = serde_json::from_str(&json_text).unwrap();

    // Exactly the fields built by SvcHandle::status_systemd_dbus.
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "active_state",
            "backend",
            "description",
            "exit_status",
            "name",
            "pid",
            "sub_state",
            "timestamps"
        ]
    );
    let mut ts: Vec<&str> = v["timestamps"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    ts.sort();
    assert_eq!(ts, ["active_enter", "active_exit", "inactive_enter"]);
    assert_eq!(v["backend"], "systemd");
    assert_eq!(v["name"], "nginx.service");

    // Byte-for-byte what --json-pretty prints for this value.
    assert_eq!(serde_json::to_string_pretty(&v).unwrap() + "\n", json_text);
}

// --- side effects and environment -----------------------------------------

#[test]
fn help_does_not_execute_or_need_external_tools() {
    // With an empty PATH no service manager tools can be found; help must
    // still render identically to the golden output.
    let empty = tempfile::tempdir().unwrap();
    for (args, golden) in [
        (&["svc", "--help"][..], include_str!("golden/svc_help.txt")),
        (
            &["svc", "status", "--help"][..],
            include_str!("golden/svc_status_help.txt"),
        ),
    ] {
        let out = resh()
            .args(args)
            .env_clear()
            .env("PATH", empty.path())
            .env("HOME", empty.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(stdout, golden);
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn help_output_is_plain_text() {
    assert_plain_text(&run(&["svc", "--help"]).1);
    assert_plain_text(&run(&["svc", "status", "--help"]).1);
}

// --- preserved behavior ----------------------------------------------------

#[test]
fn global_help_unchanged() {
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage: resh [OPTIONS] [STAGE] [ARGS]..."));
}

#[test]
fn unknown_handle_help_falls_back_to_global_help() {
    let global = run(&["--help"]);
    assert_eq!(run(&["invalidhandle", "--help"]), global);
}

#[test]
fn unknown_verb_help_falls_back_to_global_help() {
    let global = run(&["--help"]);
    assert_eq!(run(&["svc", "invalidverb", "--help"]), global);
    // Help aliases are not operations and get no verb-level help.
    assert_eq!(run(&["svc", "help", "--help"]), global);
}

#[test]
fn every_handle_help_renders_from_cli() {
    let reg = registry();
    for scheme in reg.list_schemes() {
        let (code, out, err) = run(&[&scheme, "--help"]);
        assert_eq!(code, 0, "{scheme}");
        assert_eq!(err, "", "{scheme}");
        assert!(out.starts_with(&format!("Handle: {scheme}\n")), "{scheme}");
        assert_plain_text(&out);
    }
}

#[test]
fn unknown_handle_and_verb_errors_unchanged() {
    let (code, _, err) = run(&["invalidhandle://x.status"]);
    assert_eq!(code, 1);
    assert!(err.contains("Unknown scheme: invalidhandle"));

    let (code, _, err) = run(&["svc://resh-help-test.invalidverb"]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown verb for svc://: invalidverb"));
}

#[test]
fn normal_status_execution_unchanged() {
    // Read-only query of a service that does not exist. Help interception
    // must not affect it: the handle runs and prints its status object.
    // Since Stage 2 (FUNC-02) a missing service is a failure, with a reason
    // on stderr, instead of exit 0.
    let (code, out, err) = run(&["svc://resh-help-test-nonexistent.status"]);
    assert_eq!(code, 1);
    assert!(
        err.starts_with("Error: svc status resh-help-test-nonexistent"),
        "{err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v.get("name").is_some());
    assert!(v.get("backend").is_some());
}

#[test]
fn legacy_url_help_shows_approved_help() {
    let (code, out, _) = run(&["svc://--help"]);
    assert_eq!(code, 0);
    assert_eq!(out, include_str!("golden/svc_help.txt"));
}
