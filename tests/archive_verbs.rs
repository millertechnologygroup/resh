//! Integration tests for `archive://`: every verb run through the built
//! `resh` binary in a temporary directory, for every supported format, plus
//! exit codes, help output (golden files) and the help examples.

use resh::handles::filesystem::archiveh::archive_args::options_for;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::TempDir;

const VERBS: &[&str] = &["list", "info", "test", "create", "extract", "add", "remove"];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

fn resh(dir: &Path, args: &[&str]) -> Run {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(dir)
        .env_remove("SSH_AUTH_SOCK")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn ok(r: &Run) -> &Value {
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["ok"], true, "{}", r.stdout);
    &r.json
}

fn fixture() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let d = tmp.path();
    fs::create_dir_all(d.join("data/sub")).unwrap();
    fs::write(d.join("data/a.txt"), "hello\n").unwrap();
    fs::write(d.join("data/sub/b.txt"), "world\n").unwrap();
    symlink("a.txt", d.join("data/link")).unwrap();
    fs::write(d.join("new.txt"), "new\n").unwrap();
    tmp
}

fn names(r: &Run) -> Vec<String> {
    let mut v: Vec<String> = r.json["manifest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            m["path"]
                .as_str()
                .unwrap()
                .trim_end_matches('/')
                .to_string()
        })
        .collect();
    v.sort();
    v
}

/// create -> list -> test -> info -> extract -> add -> remove for each
/// format the handle writes.
#[test]
fn every_verb_on_every_format() {
    for name in [
        "t.tar",
        "t.tar.gz",
        "t.tgz",
        "t.tar.xz",
        "t.tar.zst",
        "t.zip",
    ] {
        let tmp = fixture();
        let d = tmp.path();
        let a = format!("archive={name}");
        ok(&resh(
            d,
            &[
                "archive://.create",
                &format!("output={name}"),
                r#"sources=["data"]"#,
            ],
        ));

        let r = resh(d, &["archive://.list", &a]);
        ok(&r);
        assert_eq!(
            names(&r),
            [
                "data",
                "data/a.txt",
                "data/link",
                "data/sub",
                "data/sub/b.txt"
            ],
            "{name}"
        );
        assert_eq!(
            ok(&resh(d, &["archive://.test", &a]))["summary"]["valid"],
            true
        );
        let info = resh(d, &["archive://.info", &a]);
        assert_eq!(ok(&info)["summary"]["entries_total"], 5, "{name}");

        ok(&resh(d, &["archive://.extract", &a, "destination=out"]));
        assert_eq!(
            fs::read_to_string(d.join("out/data/sub/b.txt")).unwrap(),
            "world\n"
        );
        assert_eq!(
            fs::read_link(d.join("out/data/link")).unwrap(),
            Path::new("a.txt")
        );

        let r = resh(d, &["archive://.add", &a, r#"inputs=["new.txt"]"#]);
        assert_eq!(ok(&r)["summary"]["entries_after"], 6, "{name}");
        let r = resh(d, &["archive://.remove", &a, r#"paths=["data/a.txt"]"#]);
        assert_eq!(
            ok(&r)["details"]["removed"],
            serde_json::json!(["data/a.txt"])
        );
        let r = resh(d, &["archive://.list", &a]);
        assert_eq!(
            names(&r),
            ["data", "data/link", "data/sub", "data/sub/b.txt", "new.txt"],
            "{name}"
        );
    }
}

#[test]
fn gzip_and_raw_streams() {
    let tmp = fixture();
    let d = tmp.path();
    ok(&resh(
        d,
        &[
            "archive://.create",
            "output=a.txt.gz",
            "format=gzip",
            r#"sources=["data/a.txt"]"#,
        ],
    ));
    let r = resh(d, &["archive://.list", "archive=a.txt.gz"]);
    assert_eq!(ok(&r)["manifest"][0]["size"], 6);
    assert_eq!(
        ok(&resh(d, &["archive://.info", "archive=a.txt.gz"]))["summary"]["format"],
        "raw"
    );
    ok(&resh(d, &["archive://.test", "archive=a.txt.gz"]));
    ok(&resh(
        d,
        &["archive://.extract", "archive=a.txt.gz", "destination=out"],
    ));
    assert_eq!(fs::read_to_string(d.join("out/a.txt")).unwrap(), "hello\n");
    let r = resh(
        d,
        &[
            "archive://.add",
            "archive=a.txt.gz",
            r#"inputs=["new.txt"]"#,
        ],
    );
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.starts_with("[archive.add_unsupported_for_raw] "),
        "{}",
        r.stderr
    );
}

#[test]
fn usage_errors_exit_2_with_a_suggestion_and_do_nothing() {
    let tmp = fixture();
    let d = tmp.path();
    for verb in VERBS {
        let r = resh(
            d,
            &[
                &format!("archive://.{verb}"),
                "archive=x.tar",
                "output=o.tar",
                "verbos=1",
            ],
        );
        assert_eq!(r.code, 2, "{verb}: {}", r.stderr);
        assert!(r.stdout.is_empty(), "{verb}");
        assert!(
            r.stderr.starts_with(&format!(
                "[archive.{verb}_invalid_argument] unknown option "
            )),
            "{verb}: {}",
            r.stderr
        );
    }
    let r = resh(
        d,
        &["archive://.extract", "archive=t.tar", "destnation=out"],
    );
    assert!(
        r.stderr.contains("did you mean \"destination\"?"),
        "{}",
        r.stderr
    );
    let r = resh(d, &["archive://.list", "archive=t.tar", "dry_run"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    let r = resh(
        d,
        &[
            "archive://.create",
            "output=o.tar",
            r#"sources=["data"]"#,
            "overwrite=perhaps",
        ],
    );
    assert_eq!(r.code, 2);
    assert!(!d.join("o.tar").exists());
}

#[test]
fn runtime_failures_exit_1_with_a_report() {
    let tmp = fixture();
    let d = tmp.path();
    let r = resh(d, &["archive://.list", "archive=missing.tar"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error"][0], "archive.list_missing_archive");
    assert_eq!(
        r.stderr,
        "Error: [archive.list_missing_archive] Archive 'missing.tar' does not exist.\n"
    );
    fs::write(d.join("x.tar"), "x").unwrap();
    let r = resh(
        d,
        &["archive://.create", "output=x.tar", r#"sources=["data"]"#],
    );
    assert_eq!(r.code, 1);
    assert_eq!(r.json["error"][0], "archive.create_output_exists");
    assert_eq!(fs::read(d.join("x.tar")).unwrap(), b"x");
}

#[test]
fn timeout_exits_124() {
    let tmp = fixture();
    let d = tmp.path();
    let mut data = Vec::with_capacity(8 << 20);
    let mut x: u32 = 7;
    while data.len() < 8 << 20 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.extend_from_slice(&x.to_le_bytes());
    }
    fs::write(d.join("data/big.bin"), data).unwrap();
    let r = resh(
        d,
        &[
            "archive://.create",
            "output=b.tar.xz",
            r#"sources=["data"]"#,
            "compression_level=9",
            "timeout_ms=1",
        ],
    );
    assert_eq!(r.code, 124, "{}", r.stderr);
    assert_eq!(r.json["error"][0], "archive.create_timeout");
    assert!(!d.join("b.tar.xz").exists());
}

#[test]
fn text_reports_are_plain_text() {
    let tmp = fixture();
    let d = tmp.path();
    ok(&resh(
        d,
        &["archive://.create", "output=t.zip", r#"sources=["data"]"#],
    ));
    for (verb, extra) in [
        ("list", vec![]),
        ("info", vec![]),
        ("test", vec![]),
        ("extract", vec!["destination=o"]),
        ("add", vec![r#"inputs=["new.txt"]"#]),
        ("remove", vec![r#"paths=["new.txt"]"#]),
    ] {
        let mut args = vec![
            format!("archive://.{verb}"),
            "archive=t.zip".to_string(),
            "format_output=text".to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = resh(d, &argv);
        assert_eq!(r.code, 0, "{verb}: {}", r.stderr);
        assert!(r.json.is_null(), "{verb} printed JSON");
        assert!(r.stdout.starts_with("Archive "), "{verb}: {}", r.stdout);
        assert!(r.stdout.is_ascii(), "{verb}");
    }
}

// ------------------------------------------------------------------ help --

fn assert_plain(out: &str) {
    assert!(out.is_ascii(), "non-ASCII");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

#[test]
fn handle_help_matches_golden() {
    let tmp = TempDir::new().unwrap();
    let r = resh(tmp.path(), &["archive", "--help"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.stderr, "");
    assert_plain(&r.stdout);
    assert_eq!(r.stdout, include_str!("golden/archive_help.txt"));
    let listed: Vec<&str> = r
        .stdout
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, VERBS);
    // The in-URL form shows the same text.
    assert_eq!(resh(tmp.path(), &["archive://--help"]).stdout, r.stdout);
}

fn golden(verb: &str) -> &'static str {
    match verb {
        "list" => include_str!("golden/archive_list_help.txt"),
        "info" => include_str!("golden/archive_info_help.txt"),
        "test" => include_str!("golden/archive_test_help.txt"),
        "create" => include_str!("golden/archive_create_help.txt"),
        "extract" => include_str!("golden/archive_extract_help.txt"),
        "add" => include_str!("golden/archive_add_help.txt"),
        "remove" => include_str!("golden/archive_remove_help.txt"),
        _ => unreachable!(),
    }
}

/// The `Usage:` section of a verb help text.
fn usage_section(out: &str) -> &str {
    out.split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
}

fn usage_options(usage: &str) -> Vec<String> {
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.contains(':'))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn verb_help_matches_golden_and_lists_every_option() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        let r = resh(tmp.path(), &["archive", verb, "--help"]);
        assert_eq!(r.code, 0, "{verb}");
        assert_eq!(r.stderr, "");
        assert_plain(&r.stdout);
        assert!(
            r.stdout
                .starts_with(&format!("Handle: archive\nVerb: {verb}\nDefinition: "))
        );
        for section in ["\nUsage:\n", "\nExample:\n", "\nExample Output:\n"] {
            assert!(r.stdout.contains(section), "{verb}: {section:?}");
        }
        assert_eq!(r.stdout, golden(verb), "{verb}: help differs from golden");
        let mut want: Vec<String> = options_for(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        assert_eq!(usage_options(usage_section(&r.stdout)), want, "{verb}");
        // In-URL help forms show the same text.
        assert_eq!(
            resh(tmp.path(), &[&format!("archive://--help={verb}")]).stdout,
            r.stdout
        );
        assert_eq!(
            resh(tmp.path(), &[&format!("archive://.{verb}(help=1)")]).stdout,
            r.stdout
        );
    }
}

/// The keys of a JSON value, recursively (array items merged).
fn shape(v: &Value, prefix: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let p = format!("{prefix}.{k}");
                out.push(p.clone());
                shape(v, &p, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                shape(v, &format!("{prefix}[]"), out);
            }
        }
        _ => {}
    }
}

fn shape_of(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    shape(v, "", &mut out);
    out.sort();
    out.dedup();
    out
}

fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Every help example runs (in order, in one directory holding app.log and
/// db.log) and prints a report with the same fields as the example output.
#[test]
fn help_examples_run_and_match_their_sample_output() {
    let tmp = TempDir::new().unwrap();
    let d = tmp.path();
    fs::write(d.join("app.log"), "hello archive\n").unwrap();
    fs::write(d.join("db.log"), "db ready.\n").unwrap();
    for verb in ["create", "list", "info", "test", "extract", "add", "remove"] {
        let help = resh(d, &["archive", verb, "--help"]).stdout;
        let example = help
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim();
        let words = shell_words(example);
        assert_eq!(words[0], "resh");
        let argv: Vec<&str> = words[1..].iter().map(String::as_str).collect();
        let r = resh(d, &argv);
        assert_eq!(r.code, 0, "{verb}: {example}: {}", r.stderr);
        let sample: String = help
            .split("Example Output:\n")
            .nth(1)
            .unwrap()
            .split("\n\n  Shown with")
            .next()
            .unwrap()
            .lines()
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        let sample: Value = serde_json::from_str(&sample).unwrap();
        assert_eq!(shape_of(&r.json), shape_of(&sample), "{verb}");
        assert_eq!(r.json["query"], sample["query"], "{verb}: query differs");
    }
    assert_eq!(
        fs::read_to_string(d.join("restore/app.log")).unwrap(),
        "hello archive\n"
    );
}
