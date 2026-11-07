//! Help for the git handle: `resh git --help`, `resh git <verb> --help` and
//! the in-URL help forms render the approved format, match the golden files,
//! list exactly the arguments each verb accepts, and every example runs
//! (against a repository in a temporary directory).
//!
//! Regenerate the goldens with `RESH_UPDATE_GOLDEN=1 cargo test --test git_help`.

use assert_cmd::Command;
use git2::{Repository, RepositoryInitOptions, Signature};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const VERBS: &[&str] = &[
    "clone",
    "pull",
    "push",
    "status",
    "branch",
    "commit",
    "diff",
    "tag",
    "merge",
    "rebase",
    "sync",
    "status_summary",
    "status_short",
];

fn resh(home: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.join("gitconfig"))
        .env_remove("SSH_AUTH_SOCK");
    cmd
}

fn run_in(home: &Path, args: &[&str]) -> (i32, String, String) {
    let out = resh(home).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn run(args: &[&str]) -> (i32, String, String) {
    let home = TempDir::new().unwrap();
    run_in(home.path(), args)
}

fn golden(verb: Option<&str>) -> PathBuf {
    let name = match verb {
        None => "git_help.txt".to_string(),
        Some(v) => format!("git_{v}_help.txt"),
    };
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn check_golden(verb: Option<&str>, out: &str) {
    let path = golden(verb);
    if std::env::var_os("RESH_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, out).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {}", path.display()));
    assert_eq!(out, want, "{} differs from its golden file", path.display());
}

fn assert_plain_text(out: &str) {
    assert!(!out.contains('\x1b'), "ANSI escape in output");
    for line in out.lines() {
        assert!(line.chars().count() <= 80, "line over 80 columns: {line:?}");
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

/// Argument names (`name=`) in a usage block.
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
    out.sort();
    out
}

#[test]
fn handle_help_matches_golden_and_lists_every_verb() {
    let (code, out, err) = run(&["git", "--help"]);
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_plain_text(&out);
    check_golden(None, &out);
    assert!(out.starts_with("Handle: git\n\nDescription:\n"));
    let listed: Vec<&str> = section(&out, "Available Verbs")
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    let mut want: Vec<&str> = VERBS.to_vec();
    let mut got = listed.clone();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    assert!(out.contains("timeout_ms"), "{out}");
}

#[test]
fn verb_help_matches_golden_and_format() {
    for verb in VERBS {
        let (code, out, err) = run(&["git", verb, "--help"]);
        assert_eq!(code, 0, "{verb}");
        assert_eq!(err, "", "{verb}");
        assert_plain_text(&out);
        check_golden(Some(verb), &out);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Handle: git");
        assert_eq!(lines[1], format!("Verb: {verb}"));
        assert!(lines[2].starts_with("Definition: "));
        let pos = |l: &str| out.find(l).unwrap_or_else(|| panic!("{verb}: missing {l}"));
        assert!(pos("Definition: ") < pos("\nUsage:\n"));
        assert!(pos("\nUsage:\n") < pos("\nExample:\n"));
        let usage = section(&out, "Usage");
        assert!(
            usage.contains(&format!("git://<alias>.{verb} ")),
            "{verb}: {usage}"
        );
        assert!(usage.contains("[timeout_ms=<ms>]"), "{verb}: {usage}");
    }
}

#[test]
fn help_aliases_and_in_url_forms_show_the_same_text() {
    let (_, handle_help, _) = run(&["git", "--help"]);
    for form in ["git://--help", "git://-h"] {
        let (code, out, _) = run(&[form]);
        assert_eq!(code, 0, "{form}");
        assert_eq!(out, handle_help, "{form}");
    }
    for alias in ["-h", "help"] {
        let (code, out, _) = run(&["git", alias]);
        assert_eq!(code, 0, "{alias}");
        assert_eq!(out, handle_help, "{alias}");
    }
    let (_, sync_help, _) = run(&["git", "sync", "--help"]);
    for args in [
        vec!["git", "sync", "-h"],
        vec!["git://main.sync", "help=sync"],
    ] {
        let (code, out, _) = run(&args);
        assert_eq!(code, 0, "{args:?}");
        assert_eq!(out, sync_help, "{args:?}");
    }
}

/// The usage lists exactly the arguments the verb accepts: the refusal of
/// an unknown argument names the accepted list, which must equal the usage.
#[test]
fn usage_options_are_exactly_the_accepted_arguments() {
    let tmp = TempDir::new().unwrap();
    for verb in VERBS {
        let (_, out, _) = run(&["git", verb, "--help"]);
        let opts = usage_options(section(&out, "Usage"));
        let stage = format!("git://main.{verb}");
        let (code, stdout, err) = run_in(
            tmp.path(),
            &[&stage, "path=/nonexistent", "not_an_option=1"],
        );
        assert_eq!(code, 2, "{verb}: {err}");
        assert_eq!(stdout, "");
        assert!(
            err.contains("unknown argument \"not_an_option\""),
            "{verb}: {err}"
        );
        let accepted = err
            .split("accepted arguments: ")
            .nth(1)
            .unwrap_or_else(|| panic!("{verb}: {err}"))
            .trim();
        let mut accepted: Vec<String> = accepted.split(", ").map(str::to_string).collect();
        accepted.sort();
        assert_eq!(
            accepted, opts,
            "{verb}: usage and accepted arguments differ"
        );
    }
}

// --- the examples run --------------------------------------------------------

fn sig() -> Signature<'static> {
    Signature::now("Resh Test", "test@example.invalid").unwrap()
}

fn commit(repo: &Repository, file: &str, content: &str) {
    let wd = repo.workdir().unwrap();
    std::fs::write(wd.join(file), content).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new(file)).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let parents: Vec<&git2::Commit> = parent.iter().collect();
    repo.commit(Some("HEAD"), &sig(), &sig(), file, &tree, &parents)
        .unwrap();
}

/// `/srv/app` of the examples: a repository on main with a `feature` branch
/// one commit ahead, an `origin` remote (bare, file://) and a modified file.
fn example_world(tmp: &Path) -> (PathBuf, String) {
    let app = tmp.join("app");
    let repo =
        Repository::init_opts(&app, RepositoryInitOptions::new().initial_head("main")).unwrap();
    let mut cfg = repo.config().unwrap();
    cfg.set_str("user.name", "Resh Test").unwrap();
    cfg.set_str("user.email", "test@example.invalid").unwrap();
    commit(&repo, "README.md", "hello\n");
    let origin = tmp.join("origin.git");
    Repository::init_opts(
        &origin,
        RepositoryInitOptions::new().bare(true).initial_head("main"),
    )
    .unwrap();
    let url = format!("file://{}", origin.display());
    repo.remote("origin", &url).unwrap();
    repo.find_remote("origin")
        .unwrap()
        .push(&["refs/heads/main:refs/heads/main"], None)
        .unwrap();
    repo.find_branch("main", git2::BranchType::Local)
        .unwrap()
        .set_upstream(Some("origin/main"))
        .unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    repo.branch("feature", &head, false).unwrap();
    repo.set_head("refs/heads/feature").unwrap();
    commit(&repo, "feature.txt", "f\n");
    repo.set_head("refs/heads/main").unwrap();
    repo.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))
        .unwrap();
    std::fs::write(app.join("README.md"), "hello, world\n").unwrap();
    (app, url)
}

#[test]
fn every_example_runs() {
    for verb in VERBS {
        let tmp = TempDir::new().unwrap();
        let (app, origin) = example_world(tmp.path());
        let (_, out, _) = run(&["git", verb, "--help"]);
        let example = section(&out, "Example").trim();
        let mut words: Vec<String> = example
            .split_whitespace()
            .map(|w| w.trim_matches('\'').to_string())
            .collect();
        assert_eq!(words[0], "resh", "{verb}: {example}");
        words.remove(0);
        // commit: the example message is quoted with a space inside
        let joined = words
            .join(" ")
            .replace("message=Fix typo", "message=Fix\u{0}typo");
        let mut args: Vec<String> = joined.split(' ').map(|w| w.replace('\u{0}', " ")).collect();
        for a in args.iter_mut() {
            if *a == "path=/srv/app" {
                *a = if *verb == "clone" {
                    format!("path={}", tmp.path().join("clone").display())
                } else {
                    format!("path={}", app.display())
                };
            }
            if a.starts_with("url=") {
                *a = format!("url={origin}");
            }
        }
        if *verb == "commit" {
            // the example commits staged changes
            let repo = Repository::open(&app).unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("README.md")).unwrap();
            index.write().unwrap();
        }
        if *verb == "rebase" || *verb == "merge" || *verb == "sync" {
            std::fs::write(app.join("README.md"), "hello\n").unwrap();
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, stdout, err) = run_in(tmp.path(), &refs);
        assert_eq!(code, 0, "{verb}: {example}\n{err}");
        let v: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{verb}: {e}: {stdout}"));
        assert_eq!(v["alias"], "main", "{verb}: {v}");
    }
}
