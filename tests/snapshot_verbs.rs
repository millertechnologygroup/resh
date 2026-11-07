//! `snapshot://` verbs and help, run through the real `resh` binary. Each
//! test works in its own temporary directory (also the working directory)
//! with HOME and XDG_STATE_HOME pointed inside it, so the snapshot store is
//! private to the test. Nothing outside the temporary directory is touched.

use resh::handles::filesystem::snapshot::{
    CREATE_OPTIONS, DIFF_OPTIONS, EXIT_TIMEOUT, LS_OPTIONS, RESTORE_OPTIONS,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "stdout: {}\nstderr: {}", self.out, self.err);
        self
    }

    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.code, exit,
            "stdout: {}\nstderr: {}",
            self.out, self.err
        );
        let v = self.json();
        assert_eq!(v["error"], code, "{}", self.out);
        assert!(self.err.starts_with("Error: "), "{}", self.err);
        self
    }
}

struct Env {
    tmp: TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            tmp: TempDir::new().unwrap(),
        }
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    fn run(&self, args: &[&str]) -> Run {
        let d = self.dir();
        let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
            .current_dir(d)
            .env("HOME", d)
            .env("XDG_STATE_HOME", d.join("state"))
            .env("XDG_CONFIG_HOME", d.join("config"))
            .env("XDG_DATA_HOME", d.join("data"))
            .env("XDG_CACHE_HOME", d.join("cache"))
            .args(args)
            .output()
            .unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8(out.stdout).unwrap(),
            err: String::from_utf8(out.stderr).unwrap(),
        }
    }

    fn store(&self) -> PathBuf {
        self.path("state/resh/snapshots")
    }

    /// `srv/app` with two files.
    fn app(&self) -> PathBuf {
        let app = self.path("srv/app");
        fs::create_dir_all(app.join("conf")).unwrap();
        fs::write(app.join("conf/main.conf"), "v1").unwrap();
        fs::write(app.join("README"), "readme").unwrap();
        app
    }
}

fn url(target: &Path, verb: &str) -> String {
    format!("snapshot://{}.{verb}", target.display())
}

// --- create ---------------------------------------------------------------

#[test]
fn create_writes_snapshot_under_xdg_state_home() {
    let env = Env::new();
    let app = env.app();
    let r = env
        .run(&[
            "--json-pretty",
            &url(&app, "create"),
            "name=backup-v1",
            "ttl=86400",
            "description=before upgrade",
            "tags=nightly",
        ])
        .ok();
    assert!(
        r.out.starts_with("{\n  \"backend\": \"local\""),
        "{}",
        r.out
    );
    let v = r.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["skipped"], false);
    assert!(v["expires_at"].is_string());
    let path = PathBuf::from(v["path"].as_str().unwrap());
    assert!(path.starts_with(env.store()));
    assert_eq!(
        fs::read_to_string(path.join("content/conf/main.conf")).unwrap(),
        "v1"
    );
}

#[test]
fn create_relative_target_works_with_ls_and_diff() {
    let env = Env::new();
    env.app();
    env.run(&["snapshot://srv/app.create", "name=rel"]).ok();
    // The absolute and relative forms name the same target.
    let abs = env.run(&[&url(&env.path("srv/app"), "ls")]).ok().json();
    assert_eq!(abs[0]["name"], "rel");
    let rel = env.run(&["snapshot://srv/app.ls"]).ok().json();
    assert_eq!(rel[0]["name"], "rel");
    let d = env
        .run(&["snapshot://srv/app.diff", "from=rel", "to=live"])
        .ok()
        .json();
    assert_eq!(d["summary"]["unchanged"], 3);
}

#[test]
fn create_errors() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create")])
        .fails(2, "missing_argument");
    env.run(&[&url(&app, "create"), "name=-bad"])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "create"), "name=v1", "ttl=soon"])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "create"), "name=v1", "backend=btrfs"])
        .fails(2, "unsupported_backend");
    env.run(&[&url(&env.path("nope"), "create"), "name=v1"])
        .fails(1, "target_not_found");
    // dry_run=true is refused by the dispatcher: create has no dry run.
    let r = env.run(&[&url(&app, "create"), "name=v1", "dry_run=true"]);
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(!env.store().exists());
    env.run(&[&url(&app, "create"), "name=v1"]).ok();
    env.run(&[&url(&app, "create"), "name=v1"])
        .fails(1, "snapshot_exists");
    let r = env
        .run(&[&url(&app, "create"), "name=v1", "if_exists=skip"])
        .ok();
    assert_eq!(r.json()["skipped"], true);
}

#[test]
fn create_timeout_exits_5_and_leaves_nothing() {
    let env = Env::new();
    let app = env.app();
    let bulk = app.join("bulk");
    fs::create_dir(&bulk).unwrap();
    for i in 0..3000 {
        fs::write(bulk.join(format!("f{i}")), "x").unwrap();
    }
    env.run(&[&url(&app, "create"), "name=v1", "timeout_ms=1"])
        .fails(EXIT_TIMEOUT, "timeout");
    let ls = env.run(&[&url(&app, "ls")]).ok();
    assert_eq!(ls.out, "[]\n");
}

// --- ls -------------------------------------------------------------------

#[test]
fn ls_lists_and_filters() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create"), "name=deploy-1", "tags=nightly"])
        .ok();
    env.run(&[
        &url(&app, "create"),
        "name=manual-1",
        "description=hand made",
    ])
    .ok();
    let all = env.run(&[&url(&app, "ls")]).ok().json();
    let names: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["manual-1", "deploy-1"]);
    assert_eq!(all[0]["description"], "hand made");
    assert_eq!(all[0]["state"], "complete");

    let one = env.run(&[&url(&app, "ls"), "limit=1"]).ok().json();
    assert_eq!(one.as_array().unwrap().len(), 1);
    let tagged = env.run(&[&url(&app, "ls"), "tag=nightly"]).ok().json();
    assert_eq!(tagged[0]["name"], "deploy-1");
    let pre = env
        .run(&[&url(&app, "ls"), "name_prefix=deploy-", "state=complete"])
        .ok()
        .json();
    assert_eq!(pre.as_array().unwrap().len(), 1);
    let none = env
        .run(&[&url(&app, "ls"), "since=2999-01-01T00:00:00Z"])
        .ok();
    assert_eq!(none.out, "[]\n");
    let pretty = env.run(&[&url(&app, "ls"), "json_pretty=true"]).ok();
    assert!(pretty.out.starts_with("[\n  {"));
    assert_eq!(env.run(&[&url(&env.path("x"), "ls")]).ok().out, "[]\n");
}

#[test]
fn ls_errors() {
    let env = Env::new();
    let app = env.app();
    for a in [
        "limit=0",
        "since=yesterday",
        "until=x",
        "json_pretty=maybe",
        "timeout_ms=x",
        "bogus=1",
    ] {
        env.run(&[&url(&app, "ls"), a]).fails(2, "invalid_argument");
    }
}

// --- diff -----------------------------------------------------------------

#[test]
fn diff_reports_changes_in_json_and_summary() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create"), "name=backup-v1"]).ok();
    fs::write(app.join("conf/main.conf"), "v2!").unwrap();
    fs::write(app.join("new"), "n").unwrap();
    let v = env
        .run(&[&url(&app, "diff"), "from=backup-v1", "to=live"])
        .ok()
        .json();
    assert_eq!(v["summary"]["added"], 1);
    assert_eq!(v["summary"]["modified"], 1);
    let s = env
        .run(&[
            &url(&app, "diff"),
            "from=backup-v1",
            "to=live",
            "format=summary",
        ])
        .ok();
    assert!(
        s.out
            .contains("from: backup-v1 (snapshot)\nto:   live (live)\n"),
        "{}",
        s.out
    );
    assert!(
        s.out
            .ends_with("added: 1\nremoved: 0\nmodified: 1\nunchanged: 2\n"),
        "{}",
        s.out
    );
    // path= restricts the comparison.
    let p = env
        .run(&[&url(&app, "diff"), "from=backup-v1", "path=conf"])
        .ok()
        .json();
    assert_eq!(p["summary"]["added"], 0);
}

#[test]
fn diff_errors() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create"), "name=v1"]).ok();
    env.run(&[&url(&app, "diff")]).fails(2, "invalid_argument");
    env.run(&[&url(&app, "diff"), "from=live", "to=live"])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "diff"), "from=v1", "format=yaml"])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "diff"), "from=v1", "path=../.."])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "diff"), "from=v1", "to=v1"])
        .fails(2, "invalid_argument");
    env.run(&[&url(&app, "diff"), "from=v9"])
        .fails(1, "snapshot_not_found");
}

// --- restore --------------------------------------------------------------

#[test]
fn restore_dry_run_then_real() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create"), "name=backup-v1"]).ok();
    fs::write(app.join("conf/main.conf"), "broken").unwrap();
    let target = format!("target={}", app.display());

    env.run(&["snapshot://backup-v1.restore", &target])
        .fails(1, "target_not_empty");
    let dry = env
        .run(&[
            "snapshot://backup-v1.restore",
            &target,
            "force=true",
            "dry_run",
        ])
        .ok()
        .json();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "broken"
    );

    let r = env
        .run(&[
            "--json-pretty",
            "snapshot://backup-v1.restore",
            &target,
            "force=true",
        ])
        .ok();
    assert_eq!(
        r.out,
        format!(
            "{{\n  \"mode\": \"overwrite\",\n  \"snapshot\": \"backup-v1\",\n  \"status\": \"ok\",\n  \"target\": \"{}\"\n}}\n",
            app.display()
        )
    );
    assert_eq!(
        fs::read_to_string(app.join("conf/main.conf")).unwrap(),
        "v1"
    );
}

#[test]
fn restore_relative_target_and_errors() {
    let env = Env::new();
    let app = env.app();
    env.run(&[&url(&app, "create"), "name=v1"]).ok();
    env.run(&["snapshot://v1.restore", "target=copy"]).ok();
    assert_eq!(
        fs::read_to_string(env.path("copy/conf/main.conf")).unwrap(),
        "v1"
    );
    env.run(&["snapshot://v1.restore"])
        .fails(2, "missing_argument");
    env.run(&["snapshot://v1.restore", "target=x", "mode=merge"])
        .fails(2, "unsupported_mode");
    env.run(&["snapshot://v1.restore", "target=x", "force=perhaps"])
        .fails(2, "invalid_argument");
    env.run(&["snapshot://nope.restore", "target=x"])
        .fails(1, "snapshot_not_found");
    fs::write(env.path("file"), "keep").unwrap();
    env.run(&["snapshot://v1.restore", "target=file"])
        .fails(1, "target_exists");
    assert!(!env.path("x").exists());
}

// --- help -----------------------------------------------------------------

const VERBS: [&str; 4] = ["ls", "diff", "create", "restore"];

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/snapshot_help.txt"),
        Some("ls") => include_str!("golden/snapshot_ls_help.txt"),
        Some("diff") => include_str!("golden/snapshot_diff_help.txt"),
        Some("create") => include_str!("golden/snapshot_create_help.txt"),
        Some("restore") => include_str!("golden/snapshot_restore_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

#[test]
fn handle_help_matches_golden_and_lists_registered_verbs() {
    let env = Env::new();
    let r = env.run(&["snapshot", "--help"]).ok();
    assert_eq!(r.err, "");
    assert_eq!(r.out, golden(None));
    assert_plain_text(&r.out);
    let listed: Vec<&str> = r
        .out
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
    // In-URL forms render the same text.
    for form in [
        "snapshot://--help",
        "snapshot://-h",
        "snapshot:///srv/app.help",
    ] {
        assert_eq!(env.run(&[form]).ok().out, golden(None), "{form}");
    }
}

#[test]
fn verb_help_matches_golden_for_every_verb() {
    let env = Env::new();
    for verb in VERBS {
        let r = env.run(&["snapshot", verb, "--help"]).ok();
        assert_eq!(r.err, "");
        assert_eq!(r.out, golden(Some(verb)), "{verb}");
        assert_plain_text(&r.out);
        for section in [
            "Handle: snapshot\n",
            &format!("Verb: {verb}\n"),
            "Definition: ",
            "\nUsage:\n  resh snapshot://",
            "\nExample:\n  resh ",
            "\nExample Output:\n",
        ] {
            assert!(r.out.contains(section), "{verb} help lacks {section:?}");
        }
        let in_url = env.run(&[&format!("snapshot://--help={verb}")]).ok();
        assert_eq!(in_url.out, r.out, "snapshot://--help={verb}");
    }
}

/// The options shown in each verb's usage are exactly those it accepts.
#[test]
fn verb_help_lists_exactly_the_accepted_options() {
    let env = Env::new();
    for (verb, opts) in [
        ("ls", LS_OPTIONS),
        ("diff", DIFF_OPTIONS),
        ("create", CREATE_OPTIONS),
        ("restore", RESTORE_OPTIONS),
    ] {
        let out = env.run(&["snapshot", verb, "--help"]).ok().out;
        let usage = out
            .split("Usage:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        let mut listed: Vec<&str> = usage
            .split(|c: char| c.is_whitespace() || c == '[')
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .filter(|k| !k.is_empty() && !k.contains("://"))
            .collect();
        listed.sort_unstable();
        let mut expected = opts.to_vec();
        expected.sort_unstable();
        assert_eq!(listed, expected, "{verb}");
        // Every listed option is accepted (not rejected as unknown).
        let stage = if verb == "restore" {
            "snapshot://nope.restore".to_string()
        } else {
            format!("snapshot:///nonexistent-resh-target.{verb}")
        };
        for o in opts {
            let r = env.run(&[&stage, &format!("{o}=x")]);
            assert!(!r.err.contains("unknown argument"), "{verb} {o}: {}", r.err);
        }
        let r = env.run(&[&stage, "not_an_option=x"]);
        assert!(r.err.contains("unknown argument"), "{verb}: {}", r.err);
    }
}

/// The help examples run as shown, with /srv/app replaced by a temporary
/// directory, and produce output of the documented shape.
#[test]
fn help_examples_run() {
    let env = Env::new();
    let app = env.app();
    let a = app.display().to_string();
    let example = |verb: &str| -> Vec<String> {
        let line = golden(Some(verb))
            .split("Example:\n  ")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .replace("/srv/app", &a);
        line.split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect()
    };
    let run = |args: Vec<String>| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        env.run(&refs)
    };

    let c = run(example("create")).ok().json();
    for k in [
        "backend",
        "created_at",
        "expires_at",
        "id",
        "name",
        "ok",
        "path",
        "skipped",
        "target",
    ] {
        assert!(c.get(k).is_some(), "create output lacks {k}");
    }
    let l = run(example("ls")).ok().json();
    assert_eq!(l[0]["name"], "backup-v1");
    fs::write(app.join("README"), "changed").unwrap();
    let d = run(example("diff")).ok();
    assert!(
        d.out
            .starts_with(&format!("snapshot: {a}\nfrom: backup-v1 (snapshot)\n"))
    );
    assert!(d.out.contains("modified: 1\n"));
    let r = run(example("restore")).ok().json();
    assert_eq!(r["status"], "ok");
    assert_eq!(fs::read_to_string(app.join("README")).unwrap(), "readme");
}
