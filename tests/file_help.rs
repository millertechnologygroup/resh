//! Help for the file handle: `resh file --help`, `resh file <verb> --help`
//! and the in-URL help forms render the approved format, match the golden
//! files, list exactly the options each verb parses, and every example
//! actually runs (inside a temporary directory, with the example's absolute
//! paths moved below it).

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const VERBS: &[&str] = &[
    "read", "exists", "stat", "preview", "summary", "analyze", "schema", "tail", "grep", "find",
    "watch", "md5", "sha1", "sha256", "sha512", "hash", "verify", "write", "append", "replace",
    "copy", "rename", "move", "mv", "delete", "remove", "chmod", "chown", "ea.get", "ea.set",
    "tag.add", "tag.rm",
];

fn resh() -> Command {
    assert_cmd::cargo::cargo_bin_cmd!("resh")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = resh().args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn golden_name(verb: Option<&str>) -> PathBuf {
    let name = match verb {
        None => "file_help.txt".to_string(),
        Some(v) => format!("file_{v}_help.txt"),
    };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn assert_plain_text(out: &str) {
    assert!(!out.contains('\x1b'), "ANSI escape in output");
    assert!(out.is_ascii(), "non-ASCII in output");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
    }
}

fn section<'a>(out: &'a str, label: &str) -> &'a str {
    out.split(&format!("{label}:\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("missing {label}"))
        .split("\n\n")
        .next()
        .unwrap()
}

/// Option names (`name=`) in a usage block.
fn usage_options(usage: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in usage.split_whitespace() {
        let w = word.trim_start_matches('[');
        if let Some((name, _)) = w.split_once('=')
            && !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            && !out.contains(&name.to_string())
        {
            out.push(name.to_string());
        }
    }
    out
}

#[test]
fn handle_help_matches_golden_and_lists_every_verb() {
    let (code, out, err) = run(&["file", "--help"]);
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_plain_text(&out);
    assert_eq!(out, std::fs::read_to_string(golden_name(None)).unwrap());
    assert!(out.starts_with("Handle: file\n\nDescription:\n"));
    let listed: Vec<&str> = section(&out, "Available Verbs")
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, VERBS);
    assert!(out.contains("Usage:\n  resh file://<path>.<verb>[(key=value,...)]\n"));
    assert!(out.ends_with("For help with a specific verb:\n  resh file <verb> --help\n"));
}

#[test]
fn verb_help_matches_golden_and_format() {
    for verb in VERBS {
        let (code, out, err) = run(&["file", verb, "--help"]);
        assert_eq!(code, 0, "{verb}");
        assert_eq!(err, "", "{verb}");
        assert_plain_text(&out);
        let golden = std::fs::read_to_string(golden_name(Some(verb))).unwrap();
        assert_eq!(out, golden, "{verb} help differs from its golden file");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Handle: file");
        assert_eq!(lines[1], format!("Verb: {verb}"));
        assert!(lines[2].starts_with("Definition: "));
        let pos = |l: &str| out.find(l).unwrap_or_else(|| panic!("{verb}: missing {l}"));
        assert!(pos("Definition: ") < pos("\nUsage:\n"));
        assert!(pos("\nUsage:\n") < pos("\nExample:\n"));
        let usage = section(&out, "Usage");
        assert!(
            usage.trim_start().starts_with("resh file://<"),
            "{verb}: {usage}"
        );
        assert!(usage.contains(&format!(".{verb}")), "{verb}: {usage}");
    }
}

#[test]
fn unknown_verb_help_is_not_rendered() {
    let (_, out, _) = run(&["file", "nosuchverb", "--help"]);
    assert!(!out.contains("Handle: file"), "{out}");
}

#[test]
fn in_url_help_forms_show_the_same_text() {
    let (_, handle_help, _) = run(&["file", "--help"]);
    for form in ["file://--help", "file://-h"] {
        let (code, out, _) = run(&[form]);
        assert_eq!(code, 0, "{form}");
        assert_eq!(out, handle_help, "{form}");
    }
    let (code, out, _) = run(&["file:///etc/hosts.help"]);
    assert_eq!(code, 0);
    assert_eq!(out, handle_help);
    let (_, grep_help, _) = run(&["file", "grep", "--help"]);
    let (code, out, _) = run(&["file:///etc/hosts.help", "verb=grep"]);
    assert_eq!(code, 0);
    assert_eq!(out, grep_help);
}

/// The usage lists exactly the options the verb parses: each listed option
/// is accepted (an invalid value is refused for its value, not as unknown),
/// and an option outside the list is refused as unknown.
#[test]
fn usage_options_are_exactly_the_parsed_options() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join("f.txt");
    for verb in VERBS {
        std::fs::write(&f, "content\n").unwrap();
        let (_, out, _) = run(&["file", verb, "--help"]);
        let opts = usage_options(section(&out, "Usage"));
        let stage = format!("file://{}.{verb}", f.display());
        for opt in &opts {
            std::fs::write(&f, "content\n").unwrap();
            let arg = format!("{opt}=\u{1}bad");
            let o = resh()
                .current_dir(tmp.path())
                .args([stage.as_str(), arg.as_str()])
                .output()
                .unwrap();
            let err = String::from_utf8_lossy(&o.stderr);
            assert!(
                !err.contains("unknown argument"),
                "{verb} rejects listed {opt}: {err}"
            );
        }
        std::fs::write(&f, "content\n").unwrap();
        let o = resh()
            .current_dir(tmp.path())
            .args([stage.as_str(), "not_an_option=1"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{verb}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(
            err.contains("unknown argument \"not_an_option\""),
            "{verb}: {err}"
        );
        let accepted = if opts.is_empty() {
            format!("file {verb} takes no arguments")
        } else {
            format!("file {verb} accepts: {}", opts.join(", "))
        };
        assert!(err.contains(&accepted), "{verb}: {err} / {accepted}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "content\n", "{verb}");
    }
}

// --- the examples run --------------------------------------------------------

const USERS_CSV: &str = "id,name,joined\n1,alice,2026-01-05\n2,bob,2026-02-11\n";
const APP_LOG: &str = "INFO start\nERROR disk full\nINFO ok\nerror again\n";
const SYSLOG: &str = "Oct 16 09:10:00 web01 kernel: boot\n\
Oct 16 09:12:44 web01 systemd[1]: Started nginx.service.\n\
Oct 16 09:13:02 web01 CRON[2211]: (root) CMD (run-parts /etc/cron.hourly)\n";

/// POSIX-style word splitting with single and double quotes.
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

fn put(root: &Path, abs: &str, content: &str) -> PathBuf {
    let p = root.join(abs.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, content).unwrap();
    p
}

fn xattrs_supported(root: &Path) -> bool {
    let p = root.join(".probe");
    std::fs::write(&p, "").unwrap();
    let ok = xattr::set(&p, "user.resh_probe", b"1").is_ok();
    std::fs::remove_file(&p).unwrap();
    ok
}

/// Same keys at every object level (arrays compared by their first item).
fn same_shape(a: &Value, b: &Value, at: &str) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut kx: Vec<_> = x.keys().collect();
            let mut ky: Vec<_> = y.keys().collect();
            kx.sort();
            ky.sort();
            assert_eq!(kx, ky, "keys at {at}");
            for k in x.keys() {
                same_shape(&x[k], &y[k], &format!("{at}.{k}"));
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if let (Some(p), Some(q)) = (x.first(), y.first()) {
                same_shape(p, q, &format!("{at}[0]"));
            }
        }
        _ => {}
    }
}

/// The example output's JSON (the part before the explanatory note).
fn example_json(sample: &str) -> Option<Value> {
    let body = sample.split("\n\n").next()?;
    serde_json::from_str(body).ok()
}

fn strip_volatile(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        for k in ["path", "modified", "from", "to"] {
            m.remove(k);
        }
    }
    v
}

#[test]
fn every_example_runs_and_matches_its_output() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let xattrs = xattrs_supported(root);
    for verb in VERBS {
        if *verb == "chown" {
            // Needs users alice and www and root: see tests/file_e2e_docker.rs.
            continue;
        }
        if verb.starts_with("ea.") || verb.starts_with("tag.") {
            if !xattrs {
                eprintln!("skipped {verb}: no user xattrs");
                continue;
            }
        }
        let (_, help, _) = run(&["file", verb, "--help"]);
        let example = section(&help, "Example").trim().to_string();
        let sample = help.split("Example Output:\n").nth(1).map(|s| {
            s.lines()
                .map(|l| l.strip_prefix("  ").unwrap_or(l))
                .collect::<Vec<_>>()
                .join("\n")
        });

        let words = shell_words(&example);
        assert_eq!(words[0], "resh", "{verb}");
        let mut argv: Vec<String> = Vec::new();
        let mut stage_path = String::new();
        for w in &words[1..] {
            if let Some(rest) = w.strip_prefix("file://") {
                let path = rest.strip_suffix(&format!(".{verb}")).unwrap();
                stage_path = path.to_string();
                argv.push(format!(
                    "file://{}/{}.{verb}",
                    root.display(),
                    path.trim_start_matches('/')
                ));
            } else if let Some(to) = w.strip_prefix("to=/") {
                argv.push(format!("to={}/{to}", root.display()));
            } else {
                argv.push(w.clone());
            }
        }

        // Fixtures for the example's paths.
        let target = root.join(stage_path.trim_start_matches('/'));
        match *verb {
            "read" => {
                put(root, &stage_path, "web01\n");
            }
            "exists" | "stat" | "preview" => {
                put(
                    root,
                    &stage_path,
                    "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 web01\n",
                );
            }
            "summary" | "schema" | "md5" | "sha1" | "sha256" | "sha512" | "hash" | "verify" => {
                put(root, &stage_path, USERS_CSV);
            }
            "analyze" | "grep" => {
                put(root, &stage_path, APP_LOG);
            }
            "tail" => {
                put(root, &stage_path, SYSLOG);
            }
            "find" => {
                put(root, &format!("{stage_path}/index.html"), "<html>");
                put(root, &format!("{stage_path}/style.css"), "body{}");
            }
            "watch" | "copy" | "rename" | "move" | "mv" | "chmod" | "replace" => {
                put(root, &stage_path, "listen 8080;\nport 8080\n");
                if matches!(*verb, "move" | "mv") {
                    std::fs::create_dir_all(root.join("srv/reports")).unwrap();
                }
            }
            "delete" => {
                put(root, &format!("{stage_path}/obj/a.o"), "x");
            }
            "remove" | "write" | "append" => {}
            "ea.get" | "ea.set" => {
                let p = put(root, &stage_path, "%PDF");
                xattr::set(&p, "user.comment", b"reviewed by alice").unwrap();
            }
            "tag.add" => {
                put(root, &stage_path, "%PDF");
            }
            "tag.rm" => {
                let p = put(root, &stage_path, "%PDF");
                xattr::set(&p, "user.resh.tags", b"q3,work").unwrap();
            }
            other => panic!("no fixture for {other}"),
        }

        let watcher = (*verb == "watch").then(|| {
            let t = target.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(700));
                std::fs::write(&t, "changed").unwrap();
            })
        });
        let out = resh()
            .args(&argv)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap();
        if let Some(w) = watcher {
            w.join().unwrap();
        }
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "{verb}: example {example:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Effects of the changing examples.
        match *verb {
            "write" => assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello world"),
            "append" => assert_eq!(std::fs::read_to_string(&target).unwrap(), "job finished"),
            "copy" => assert!(root.join("etc/nginx/nginx.conf.bak").exists()),
            "rename" => assert!(root.join("srv/data/new.csv").exists() && !target.exists()),
            "move" => assert!(root.join("srv/reports/report.pdf").exists() && !target.exists()),
            "mv" => assert!(root.join("srv/reports/q3.pdf").exists() && !target.exists()),
            "delete" => assert!(!target.exists()),
            "chmod" => {
                use std::os::unix::fs::PermissionsExt;
                let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
                assert_eq!(m, 0o755);
            }
            "replace" => assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "listen 9090;\nport 9090\n"
            ),
            "watch" => {
                let v: Value = serde_json::from_str(stdout.trim()).unwrap();
                assert_eq!(v["event"], "modify");
            }
            _ => {}
        }

        let Some(sample) = sample else {
            if *verb != "watch" {
                assert_eq!(stdout, "", "{verb} prints nothing per its help");
            }
            continue;
        };
        match example_json(&sample) {
            Some(expected) => {
                let actual: Value = serde_json::from_str(stdout.trim())
                    .unwrap_or_else(|e| panic!("{verb}: {e}: {stdout}"));
                same_shape(&expected, &actual, verb);
                let exact = [
                    "exists", "summary", "md5", "sha1", "sha256", "verify", "write", "append",
                    "ea.get", "ea.set", "tag.add", "tag.rm", "rename",
                ];
                if exact.contains(verb) {
                    assert_eq!(
                        strip_volatile(expected.clone()),
                        strip_volatile(actual.clone()),
                        "{verb}: output differs from the help's example output"
                    );
                }
                if *verb == "hash" || *verb == "sha512" {
                    let key = if *verb == "hash" { "hash_hex" } else { "hash" };
                    let shown = expected[key].as_str().unwrap();
                    let prefix = shown.split("...").next().unwrap();
                    assert!(actual[key].as_str().unwrap().starts_with(prefix), "{verb}");
                }
            }
            None => {
                // Text examples (read, tail, grep): the lines before the note.
                let body = sample.split("\n\n").next().unwrap();
                assert_eq!(stdout.trim_end(), body, "{verb}");
            }
        }
    }
}
