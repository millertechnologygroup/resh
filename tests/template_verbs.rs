//! Binary tests for every `template://` verb and its help. Each test runs
//! the real `resh` binary in its own temporary working directory.

use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn resh(dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

/// Runs resh in `dir`; returns (exit code, stdout, stderr).
fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = resh(dir).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).unwrap_or_else(|e| panic!("not JSON ({e}): {out}"))
}

/// The help examples' fixture: welcome.txt and its default test cases.
fn welcome() -> TempDir {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("welcome.txt"), "Hello, {{ name }}!").unwrap();
    std::fs::write(
        tmp.path().join("welcome.tests.json"),
        r#"[{"name":"alice","context":{"name":"alice"},"expected":"Hello, alice!"}]"#,
    )
    .unwrap();
    tmp
}

const SLOW: &str = "template={% for i in range(end=50000000) %}{{ i }}{% endfor %}";

// --- render ------------------------------------------------------------------

#[test]
fn render_file_inline_and_context_file() {
    let tmp = welcome();
    std::fs::write(tmp.path().join("ctx.json"), r#"{"name":"bob"}"#).unwrap();
    let (code, out, _) = run(
        tmp.path(),
        &["template://welcome.txt.render", "context_file=ctx.json"],
    );
    assert_eq!(code, 0);
    assert_eq!(json(&out)["body"]["value"], "Hello, bob!");

    let (code, out, _) = run(
        tmp.path(),
        &[
            "template://inline.render",
            r#"template={"port": {{ port }}}"#,
            r#"context={"port":8080}"#,
            "format=json",
            "timeout_ms=10000",
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(json(&out)["body"]["value"]["port"], 8080);
}

#[test]
fn render_errors() {
    let tmp = welcome();
    for (args, code, kind) in [
        (
            &["template://missing.txt.render"][..],
            1,
            "template_not_found",
        ),
        (&["template://inline.render"][..], 2, "template_not_found"),
        (
            &["template://welcome.txt.render", "contxt={}"][..],
            2,
            "invalid_argument",
        ),
        (
            &["template://welcome.txt.render", "context={"][..],
            1,
            "context_parse",
        ),
        (&["template://welcome.txt.render"][..], 1, "render"),
        (
            &["template://inline.render", "template=x", "format=json"][..],
            1,
            "json_parse",
        ),
        (
            &["template://welcome.txt.render", "format=xml"][..],
            2,
            "invalid_format",
        ),
        (
            &["template://welcome.txt.render", "timeout_ms=x"][..],
            2,
            "invalid_argument",
        ),
        (
            &["template://welcome.txt.render", "strict=true"][..],
            2,
            "invalid_argument",
        ),
    ] {
        let (c, out, err) = run(tmp.path(), args);
        assert_eq!(c, code, "{args:?}: {out} {err}");
        let v = json(&out);
        assert_eq!(v["ok"], false);
        assert_eq!(v["errors"][0]["kind"], kind, "{args:?}");
    }
    let (c, _, err) = run(
        tmp.path(),
        &["template://welcome.txt.render", "dry_run=true"],
    );
    assert_eq!(c, 2);
    assert!(err.contains("does not support dry_run"), "{err}");
    let (c, out, _) = run(tmp.path(), &["template://welcome.txt.render", "contxt={}"]);
    assert_eq!(c, 2);
    assert!(out.contains("did you mean `context`?"), "{out}");
}

/// A macro that calls itself without end is stopped with an error; before,
/// it overflowed the stack and aborted resh (exit 134).
#[test]
fn unbounded_macro_recursion_fails_cleanly() {
    let tmp = TempDir::new().unwrap();
    let (code, out, err) = run(
        tmp.path(),
        &[
            "template://inline.render",
            "template={% macro m(n) %}{{ self::m(n=n+1) }}{% endmacro m %}{{ self::m(n=1) }}",
        ],
    );
    assert_eq!(code, 1, "{err}");
    let v = json(&out);
    assert_eq!(v["errors"][0]["kind"], "render");
    assert!(
        v["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("nested deeper than 200 levels")
    );
}

#[test]
fn render_timeout_ms_is_enforced() {
    let tmp = TempDir::new().unwrap();
    let started = Instant::now();
    let (code, out, err) = run(
        tmp.path(),
        &["template://inline.render", SLOW, "timeout_ms=200"],
    );
    assert_eq!(code, 124, "{err}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(json(&out)["errors"][0]["kind"], "timeout");
}

// --- validate ----------------------------------------------------------------

#[test]
fn validate_template_argument_context_file_and_strict() {
    let tmp = welcome();
    std::fs::write(tmp.path().join("ctx.json"), r#"{"name":"bob"}"#).unwrap();
    let (code, out, _) = run(
        tmp.path(),
        &[
            "template://inline.validate",
            "template=Hi {{ name }}",
            "context_file=ctx.json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = run(
        tmp.path(),
        &["template://welcome.txt.validate", "strict=false"],
    );
    assert_eq!(code, 0);
    assert_eq!(json(&out)["warnings"][0]["kind"], "missing_variable");
}

#[test]
fn validate_errors() {
    let tmp = welcome();
    for (args, code, kind) in [
        (
            &["template://welcome.txt.validate"][..],
            1,
            "missing_variable",
        ),
        (&["template://missing.txt.validate"][..], 1, "file_read"),
        (
            &["template://inline.validate", "from={% if %}"][..],
            1,
            "syntax",
        ),
        (
            &["template://inline.validate", "from=x", "context={"][..],
            1,
            "context_parse",
        ),
        (
            &["template://welcome.txt.validate", "strict=ture"][..],
            2,
            "invalid_argument",
        ),
        (
            &["template://welcome.txt.validate", "encoding=latin1"][..],
            2,
            "encoding",
        ),
        (
            &["template://inline.validate", SLOW, "timeout_ms=200"][..],
            124,
            "timeout",
        ),
    ] {
        let (c, out, err) = run(tmp.path(), args);
        assert_eq!(c, code, "{args:?}: {out} {err}");
        assert_eq!(json(&out)["errors"][0]["kind"], kind, "{args:?}");
    }
}

// --- test --------------------------------------------------------------------

#[test]
fn test_inline_cases_and_options() {
    let tmp = TempDir::new().unwrap();
    let (code, out, _) = run(
        tmp.path(),
        &[
            "template://inline.test",
            "template=Hi {{ n }}",
            r#"cases=[{"name":"one","context":{"n":1},"expected":"Hi 1"},{"name":"two","context":{"n":2},"expected":"Hi 3"},{"name":"three","context":{"n":3},"contains":"3"}]"#,
            "stop_on_first_fail=true",
            "capture_output=full",
        ],
    );
    assert_eq!(code, 1);
    let v = json(&out);
    assert_eq!(
        (v["total"].as_u64(), v["failed"].as_u64()),
        (Some(2), Some(1))
    );
    assert_eq!(v["cases"][1]["rendered"], "Hi 2");
}

#[test]
fn test_errors() {
    let tmp = welcome();
    std::fs::write(tmp.path().join("bare.txt"), "x").unwrap();
    for (args, code) in [
        (&["template://missing.txt.test"][..], 1),
        (&["template://inline.test", "cases=[]"][..], 2),
        (&["template://bare.txt.test", "cases_file=nope.json"][..], 1),
        (&["template://bare.txt.test"][..], 2),
        (&["template://bare.txt.test", "cases=nope"][..], 2),
        (&["template://bare.txt.test", "cases=[]"][..], 1),
        (
            &["template://welcome.txt.test", "capture_output=all"][..],
            2,
        ),
        (
            &["template://welcome.txt.test", "stop_on_first_fail=2"][..],
            2,
        ),
        (&["template://welcome.txt.test", "context={}"][..], 2),
    ] {
        let (c, out, err) = run(tmp.path(), args);
        assert_eq!(c, code, "{args:?}: {out} {err}");
        let v = json(&out);
        assert_eq!(v["ok"], false);
        assert!(v["error"].is_string(), "{args:?}: {v}");
    }
    let (c, out, _) = run(
        tmp.path(),
        &[
            "template://inline.test",
            SLOW,
            r#"cases=[{"name":"a","context":{}}]"#,
            "timeout_ms=200",
        ],
    );
    assert_eq!(c, 124);
    assert!(
        json(&out)["error"]
            .as_str()
            .unwrap()
            .contains("timeout_ms=200")
    );
}

// --- help --------------------------------------------------------------------

const VERBS: [&str; 3] = ["render", "validate", "test"];

fn golden(name: &str) -> &'static str {
    match name {
        "template" => include_str!("golden/template_help.txt"),
        "render" => include_str!("golden/template_render_help.txt"),
        "validate" => include_str!("golden/template_validate_help.txt"),
        "test" => include_str!("golden/template_test_help.txt"),
        _ => unreachable!(),
    }
}

/// The options each verb parses (kept in step with `verb_args` in
/// src/handles/automation/templateh.rs; a unit test there checks the usage).
fn options(verb: &str) -> Vec<&'static str> {
    let mut v = match verb {
        "render" => vec![
            "template",
            "from",
            "context",
            "context_file",
            "format",
            "timeout_ms",
        ],
        "validate" => vec![
            "template",
            "from",
            "inline",
            "context",
            "context_file",
            "strict",
            "encoding",
            "timeout_ms",
        ],
        "test" => vec![
            "template",
            "from",
            "cases",
            "cases_file",
            "stop_on_first_fail",
            "capture_output",
            "timeout_ms",
        ],
        _ => unreachable!(),
    };
    v.sort();
    v
}

fn section<'a>(help: &'a str, name: &str) -> &'a str {
    help.split(&format!("\n{name}:\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("no {name} section"))
        .split("\n\n")
        .next()
        .unwrap()
}

fn assert_plain(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

/// Minimal shell word splitting for the help examples (single quotes only).
fn words(example: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in example.trim().chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

#[test]
fn handle_help_matches_golden_and_lists_verbs() {
    let tmp = TempDir::new().unwrap();
    let (code, out, err) = run(tmp.path(), &["template", "--help"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, golden("template"));
    assert_plain(&out);
    let mut listed: Vec<&str> = section(&out, "Available Verbs")
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    listed.sort();
    let mut verbs = VERBS.to_vec();
    verbs.sort();
    assert_eq!(listed, verbs);
    let (code, out, _) = run(tmp.path(), &["template://--help"]);
    assert_eq!((code, out.as_str()), (0, golden("template")));
}

#[test]
fn verb_help_matches_golden_and_lists_parsed_options() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        let (code, out, err) = run(tmp.path(), &["template", verb, "--help"]);
        assert_eq!((code, err.as_str()), (0, ""), "{verb}");
        assert_eq!(out, golden(verb), "{verb}");
        assert_plain(&out);
        assert!(out.starts_with(&format!("Handle: template\nVerb: {verb}\nDefinition: ")));
        let usage = section(&out, "Usage");
        let mut listed: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        listed.sort();
        assert_eq!(listed, options(verb), "{verb} usage options");
    }
}

/// Each verb's help example, run as written in the welcome.txt fixture,
/// prints exactly the JSON shown under "Example Output:".
#[test]
fn verb_help_examples_run_and_match_their_output() {
    let tmp = welcome();
    for verb in VERBS {
        let help = golden(verb);
        let example = section(help, "Example");
        let argv = words(example);
        assert_eq!(argv[0], "resh");
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        let (code, out, err) = run(tmp.path(), &args);
        assert_eq!(code, 0, "{verb}: {err}");
        let shown: String = help
            .split("\nExample Output:\n")
            .nth(1)
            .unwrap()
            .lines()
            .take_while(|l| !l.is_empty())
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(json(&out), json(&shown), "{verb}");
    }
}
