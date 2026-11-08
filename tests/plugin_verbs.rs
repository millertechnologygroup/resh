//! Binary tests of every `plugin` verb. Each test runs the built `resh`
//! with its own temporary HOME and XDG directories and talks only to a
//! local HTTPS registry (`tests/plugin_support/registry.rs`). The help
//! output of the handle and of every verb is compared with its golden file,
//! and every help example runs here.

#[path = "plugin_support/registry.rs"]
mod fake;

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};

use fake::{FakeRegistry, plugin_tar_gz, raw_tar_gz, sha256_hex};
use serde_json::Value;
use tempfile::TempDir;

const VERBS: &[&str] = &[
    "available.list",
    "available.search",
    "available.info",
    "installed.list",
    "install",
    "update",
    "remove",
    "enable",
    "disable",
];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Value {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.stderr);
        assert!(
            self.stderr
                .lines()
                .any(|l| l.starts_with(&format!("Error: [{code}] "))),
            "want {code}: {}",
            self.stderr
        );
        if exit == 2 {
            assert!(
                self.stdout.is_empty(),
                "refused call printed {}",
                self.stdout
            );
        } else {
            assert_eq!(self.json["ok"], false, "{}", self.stdout);
            assert_eq!(self.json["code"], exit);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
        &self.json
    }
}

/// A throwaway HOME with its own XDG directories.
struct Home {
    t: TempDir,
    env: Vec<(String, String)>,
}

impl Home {
    fn new() -> Self {
        let t = TempDir::new().unwrap();
        let h = t.path().join("home");
        fs::create_dir(&h).unwrap();
        let hs = h.to_string_lossy().into_owned();
        let env = vec![
            ("HOME".into(), hs.clone()),
            ("XDG_DATA_HOME".into(), format!("{hs}/.local/share")),
            ("XDG_STATE_HOME".into(), format!("{hs}/.local/state")),
            ("XDG_CACHE_HOME".into(), format!("{hs}/.cache")),
            ("XDG_CONFIG_HOME".into(), format!("{hs}/.config")),
            (
                "RESH_TEST_PLUGIN_SYSTEM_DIR".into(),
                t.path().join("varlib").to_string_lossy().into_owned(),
            ),
        ];
        Home { t, env }
    }

    fn path(&self) -> &Path {
        self.t.path()
    }

    fn home(&self) -> PathBuf {
        self.t.path().join("home")
    }

    fn store(&self) -> PathBuf {
        self.home().join(".local/share/resh/plugins")
    }

    fn with(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    fn file(&self, name: &str, data: &[u8]) -> String {
        let p = self.path().join(name);
        fs::write(&p, data).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn ca(&self, reg: &FakeRegistry) -> String {
        self.file("ca.pem", reg.ca_pem.as_bytes())
    }

    fn run(&self, args: &[&str]) -> Run {
        self.run_in(&self.home(), args)
    }

    fn run_in(&self, cwd: &Path, args: &[&str]) -> Run {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(cwd).args(args).env_remove("SSH_AUTH_SOCK");
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(stdout.trim()).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn current(&self, id: &str) -> Option<String> {
        fs::read_link(self.store().join(id).join("current"))
            .ok()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
    }

    fn nothing_installed(&self, id: &str) -> bool {
        let staging_empty = fs::read_dir(self.store().join(".staging"))
            .map(|d| d.count() == 0)
            .unwrap_or(true);
        !self.store().join(id).exists() && staging_empty
    }
}

fn reg_args<'a>(reg: &'a str, ca: &'a str) -> [String; 2] {
    [format!("registry={reg}"), format!("ca_file={ca}")]
}

// --- install / update ----------------------------------------------------------

#[test]
fn install_update_and_remove_through_a_local_registry() {
    let h = Home::new();
    let reg = FakeRegistry::start();
    let ca = h.ca(&reg);
    let [r, c] = reg_args(&reg.base(), &ca);
    reg.publish_ok("demo", "1.0.0");
    let j = h
        .run(&["plugin://demo.install", &r, &c, "dry_run=true"])
        .ok()
        .clone();
    assert_eq!(j["result"]["version"], "1.0.0");
    assert!(!h.store().exists());
    let j = h.run(&["plugin://demo.install", &r, &c]).ok().clone();
    assert_eq!(j["result"]["installed"], true);
    assert_eq!(h.current("demo").as_deref(), Some("1.0.0"));
    let bin = h.store().join("demo/versions/1.0.0/bin/plugin");
    assert_eq!(fs::metadata(&bin).unwrap().mode() & 0o777, 0o755);
    // update: no-op, strict error, then a real update.
    let j = h.run(&["plugin://demo.update", &r, &c]).ok().clone();
    assert_eq!(j["result"]["changed"], false);
    h.run(&["plugin://demo.update", &r, &c, "strict=true"])
        .fails(1, "plugin.no_update_available");
    reg.publish_ok("demo", "1.10.0");
    reg.publish_ok("demo", "1.9.0");
    let j = h.run(&["plugin://demo.update", &r, &c]).ok().clone();
    assert_eq!(j["result"]["version"], "1.10.0");
    assert_eq!(j["result"]["previous_version"], "1.0.0");
    assert_eq!(h.current("demo").as_deref(), Some("1.10.0"));
    // remove
    let j = h
        .run(&["plugin://demo.remove", "dry_run=true"])
        .ok()
        .clone();
    assert_eq!(j["result"]["removed"], false);
    let j = h.run(&["plugin://demo.remove"]).ok().clone();
    assert_eq!(j["result"]["removed"], true);
    assert!(h.nothing_installed("demo"));
    h.run(&["plugin://demo.remove"])
        .fails(1, "plugin.not_installed");
    h.run(&["plugin://demo.update", &r, &c])
        .fails(1, "plugin.not_installed");
}

#[test]
fn tampered_artifact_is_refused() {
    let h = Home::new();
    let reg = FakeRegistry::start();
    let ca = h.ca(&reg);
    let [r, c] = reg_args(&reg.base(), &ca);
    let data = plugin_tar_gz("x");
    let mut tampered = data.clone();
    let n = tampered.len();
    tampered[n - 20] ^= 0xff;
    reg.publish(
        "demo",
        "1.0.0",
        "p.tar.gz",
        &tampered,
        Some(&sha256_hex(&data)),
    );
    h.run(&["plugin://demo.install", &r, &c])
        .fails(1, "plugin.verify_failed");
    assert!(h.nothing_installed("demo"));
    // Without the private CA the registry is not trusted at all.
    h.run(&["plugin://demo.install", &r])
        .fails(1, "plugin.download_failed");
    // Plain http is refused before any connection.
    let http = format!("registry=http://127.0.0.1:{}", reg.port);
    let before = reg.hits().len();
    h.run(&["plugin://demo.install", &http])
        .fails(2, "plugin.invalid_argument");
    assert_eq!(reg.hits().len(), before);
}

#[test]
fn timeout_mid_download_exits_124_and_installs_nothing() {
    let h = Home::new();
    let reg = FakeRegistry::start();
    let ca = h.ca(&reg);
    let [r, c] = reg_args(&reg.base(), &ca);
    let data = plugin_tar_gz("slow");
    reg.publish(
        "demo",
        "1.0.0",
        "slow.tar.gz",
        &data,
        Some(&sha256_hex(&data)),
    );
    reg.slow("/v1/artifacts/demo/1.0.0/slow.tar.gz");
    let start = std::time::Instant::now();
    let run = h.run(&["plugin://demo.install", &r, &c, "timeout_ms=800"]);
    run.fails(124, "plugin.timeout");
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert!(
        run.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nothing was installed")
    );
    assert!(h.nothing_installed("demo"));
}

#[test]
fn path_traversal_archive_is_refused() {
    let h = Home::new();
    for (i, name) in [
        "../escape",
        "../../../../tmp/escape",
        "/tmp/plugin-escape-abs",
    ]
    .iter()
    .enumerate()
    {
        let p = h.file(&format!("evil{i}.tar.gz"), &raw_tar_gz(name, b"x"));
        h.run(&["plugin://evil.install", "source=file", &format!("path={p}")])
            .fails(1, "plugin.extract_failed");
        assert!(h.nothing_installed("evil"));
    }
    assert!(!h.home().join(".local/share/resh/escape").exists());
    assert!(!Path::new("/tmp/plugin-escape-abs").exists());
}

#[test]
fn url_source_needs_verify_none_and_https() {
    let h = Home::new();
    let reg = FakeRegistry::start();
    let ca = h.ca(&reg);
    reg.set("/tool", 200, b"#!/bin/sh\necho tool\n".to_vec());
    let url = format!("url={}/tool", reg.base());
    let c = format!("ca_file={ca}");
    h.run(&["plugin://tool.install", "source=url", &url, &c])
        .fails(2, "plugin.invalid_argument");
    let j = h
        .run(&[
            "plugin://tool.install",
            "source=url",
            &url,
            &c,
            "verify=none",
        ])
        .ok()
        .clone();
    assert_eq!(j["result"]["version"], "unknown");
    assert!(j["warnings"][0].as_str().unwrap().contains("verify=none"));
}

// --- enable / disable / installed.list ----------------------------------------

#[test]
fn enable_disable_and_installed_list_share_state() {
    let h = Home::new();
    h.run(&["plugin://aws.enable"])
        .fails(1, "plugin.not_installed");
    let p = h.file("aws-plugin", b"#!/bin/sh\necho aws\n");
    h.run(&["plugin://aws.install", "source=file", &format!("path={p}")])
        .ok();
    let j = h
        .run(&["plugin://aws.enable", "reason=deploy jobs"])
        .ok()
        .clone();
    assert_eq!(j["result"]["enabled"], true);
    let state = h.home().join(".local/state/resh/plugins/state.json");
    assert_eq!(fs::metadata(&state).unwrap().mode() & 0o777, 0o600);
    let l = h
        .run(&["plugin://installed.list", "format=summary"])
        .ok()
        .clone();
    assert_eq!(l["result"]["items"][0]["enabled"], true);
    assert_eq!(l["result"]["items"][0]["source"]["type"], "file");
    let j = h.run(&["plugin://aws.disable"]).ok().clone();
    assert_eq!(j["result"]["was_enabled"], true);
    let l = h
        .run(&["plugin://installed.list", "enabled=true"])
        .ok()
        .clone();
    assert_eq!(l["result"]["total"], 0);
    // System scope (a temporary directory in debug builds).
    let j = h.run(&["plugin://aws.enable", "scope=system"]).ok().clone();
    assert_eq!(j["result"]["scope"], "system");
    assert!(h.path().join("varlib/resh/plugins/state.json").is_file());
    h.run(&["plugin://aws.enable", "timeout_ms=100"])
        .fails(2, "plugin.invalid_argument");
    h.run(&["plugin://aws.enable", "scope=global"])
        .fails(2, "plugin.invalid_argument");
    h.run(&["plugin://installed.list", "sort=size"])
        .fails(2, "plugin.invalid_argument");
    h.run(&["plugin://installed.list", "dry_run=true"])
        .fails(2, "plugin.invalid_argument");
}

#[test]
fn another_users_home_is_refused() {
    // A plugin store that is writable by others (as when a user's directory
    // is shared) is refused instead of being used.
    let h = Home::new();
    let p = h.file("aws-plugin", b"#!/bin/sh\n");
    let store = h.store();
    fs::create_dir_all(&store).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o777)).unwrap();
    h.run(&["plugin://aws.install", "source=file", &format!("path={p}")])
        .fails(1, "plugin.unsafe_path");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    // A planted state.json symlink is never written through.
    h.run(&["plugin://aws.install", "source=file", &format!("path={p}")])
        .ok();
    let victim = h.file("victim", b"keep");
    let sd = h.home().join(".local/state/resh/plugins");
    fs::create_dir_all(&sd).unwrap();
    symlink(&victim, sd.join("state.json")).unwrap();
    h.run(&["plugin://aws.enable"])
        .fails(1, "plugin.unsafe_path");
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
}

// --- catalogs ------------------------------------------------------------------

#[test]
fn available_list_search_and_info() {
    let reg = FakeRegistry::start();
    let h = Home::new()
        .with(
            "RESH_TEST_PLUGIN_OFFICIAL_URL",
            &format!("{}/official", reg.base()),
        )
        .with(
            "RESH_TEST_PLUGIN_COMMUNITY_URL",
            &format!("{}/community", reg.base()),
        );
    let ca = h.ca(&reg);
    let c = format!("ca_file={ca}");
    // available.list: the built-in catalog, from any directory.
    let j = h
        .run(&["plugin://available.list", "query=docker", "limit=1"])
        .ok()
        .clone();
    assert_eq!(j["result"]["items"][0]["id"], "resh.docker");
    h.run(&["plugin://available.list", "source=file:/nonexistent"])
        .fails(1, "plugin.not_found");
    h.run(&["plugin://available.list", "limt=1"])
        .fails(2, "plugin.invalid_argument");
    // available.search against a local index.
    reg.set(
        "/index.json",
        200,
        r#"{"plugins":[{"id":"resh.docker","display_name":"Docker","description":"d","version":"1.0.0","publisher":"acme","tags":["docker"]}]}"#,
    );
    let src = format!("source={}/index.json", reg.base());
    h.run(&["plugin://available.search", &src, "offline=true"])
        .fails(1, "plugin.not_found");
    let j = h
        .run(&["plugin://available.search", &src, &c, "q=docker"])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 1);
    let j = h
        .run(&[
            "plugin://available.search",
            &src,
            "offline=true",
            "q=docker",
        ])
        .ok()
        .clone();
    assert_eq!(j["result"]["source"]["mode"], "cache");
    reg.slow("/index.json");
    h.run(&[
        "plugin://available.search",
        &src,
        &c,
        "refresh=true",
        "timeout_ms=300",
    ])
    .fails(124, "plugin.timeout");
    // available.info against local official/community indexes.
    let idx = |name: &str| {
        serde_json::json!({"version": 1, "generated_at": "x", "plugins": [{
            "id": name, "name": name, "display_name": name, "version": "1.2.0",
            "description": "d", "compatibility": {"resh_min": "0.1"}}]})
        .to_string()
    };
    reg.set("/official/index-stable.json", 200, idx("resh.docker"));
    reg.set("/community/index-stable.json", 200, idx("other"));
    let j = h
        .run(&["plugin://available.info", "name=resh.docker", &c])
        .ok()
        .clone();
    assert_eq!(j["result"]["plugin"]["version"], "1.2.0");
    let j = h
        .run(&["plugin://available.info", "name=other", "offline=true"])
        .ok()
        .clone();
    assert_eq!(j["result"]["plugin"]["name"], "other");
    h.run(&["plugin://available.info", "name=missing", "offline=true"])
        .fails(1, "plugin.not_found");
    h.run(&["plugin://available.info"])
        .fails(2, "plugin.invalid_argument");
}

// --- targets and verbs -----------------------------------------------------------

#[test]
fn targets_and_unknown_verbs() {
    let h = Home::new();
    h.run(&["plugin://install"])
        .fails(2, "plugin.invalid_target");
    h.run(&["plugin://acme/tool.install"])
        .fails(2, "plugin.invalid_target");
    h.run(&["plugin://aws.instal"])
        .fails(2, "plugin.unknown_verb");
    assert!(
        h.run(&["plugin://aws.instal"])
            .stderr
            .contains("did you mean `install`")
    );
    h.run(&["plugin://aws.available.list"])
        .fails(2, "plugin.invalid_target");
    // The older doubled forms still work.
    h.run(&["plugin://available.available.list", "limit=1"])
        .ok();
    h.run(&["plugin://installed.installed.list"]).ok();
}

// --- help ------------------------------------------------------------------------

fn golden(verb: &str) -> String {
    let name = format!("tests/golden/plugin_{}_help.txt", verb.replace('.', "_"));
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap()
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let h = Home::new();
    let want = include_str!("golden/plugin_help.txt");
    for args in [
        &["plugin", "--help"][..],
        &["plugin", "-h"],
        &["plugin", "help"],
        &["help", "plugin"],
        &["plugin://--help"],
        &["plugin://help"],
    ] {
        let r = h.run(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden_in_every_form() {
    let h = Home::new();
    for verb in VERBS {
        let want = golden(verb);
        assert!(want.lines().all(|l| l.len() <= 80), "{verb}");
        let stage = if verb.contains('.') {
            format!("plugin://{verb}")
        } else {
            format!("plugin://aws.{verb}")
        };
        let q = format!("{stage}?help");
        let eq = format!("plugin://--help={verb}");
        for args in [
            vec!["plugin", verb, "--help"],
            vec!["plugin", verb, "-h"],
            vec!["help", "plugin", verb],
            vec![stage.as_str(), "--help"],
            vec![stage.as_str(), "-h"],
            vec![q.as_str()],
            vec![eq.as_str()],
        ] {
            let r = h.run(&args);
            assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
            assert_eq!(r.stdout, want, "{args:?}: help differs from golden");
        }
    }
    let r = h.run(&["plugin", "instal", "--help"]);
    assert_eq!(r.code, 2);
}

/// Every help example runs: in a fresh HOME, with what it needs prepared.
#[test]
fn help_examples_run() {
    let reg = FakeRegistry::start();
    let h = Home::new()
        .with(
            "RESH_TEST_PLUGIN_OFFICIAL_URL",
            &format!("{}/official", reg.base()),
        )
        .with(
            "RESH_TEST_PLUGIN_COMMUNITY_URL",
            &format!("{}/community", reg.base()),
        );
    let ca = h.ca(&reg);
    // Caches for the offline examples.
    reg.set(
        "/official/index-stable.json",
        200,
        r#"{"version":1,"generated_at":"x","plugins":[{"id":"resh.docker","name":"resh.docker","display_name":"Docker","version":"0.1.0","description":"d","compatibility":{"resh_min":"0.1"}}]}"#,
    );
    reg.set(
        "/community/index-stable.json",
        200,
        r#"{"version":1,"generated_at":"x","plugins":[]}"#,
    );
    h.run(&[
        "plugin://available.info",
        "name=resh.docker",
        &format!("ca_file={ca}"),
    ])
    .ok();
    let state = h.home().join(".local/state/resh/plugins");
    fs::create_dir_all(&state).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for d in [
        h.home().join(".local/state"),
        h.home().join(".local/state/resh"),
        state.clone(),
    ] {
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        state.join("index-cache.json"),
        r#"{"source_url":"https://plugins.reshshell.dev/index.json","fetched_at":"x","plugins":[{"id":"resh.docker","display_name":"Docker","description":"d","version":"0.1.0","publisher":"p","tags":["docker"]}]}"#,
    )
    .unwrap();
    fs::write(h.home().join("aws-plugin"), b"#!/bin/sh\necho aws\n").unwrap();
    let help = |verb: &str| -> String {
        golden(verb)
            .lines()
            .skip_while(|l| *l != "Example:")
            .nth(1)
            .unwrap()
            .trim()
            .to_string()
    };
    let words =
        |ex: &str| -> Vec<String> { ex.split_whitespace().skip(1).map(String::from).collect() };
    let run = |verb: &str| {
        let w = words(&help(verb));
        let a: Vec<&str> = w.iter().map(String::as_str).collect();
        h.run(&a)
    };
    for verb in [
        "available.list",
        "available.search",
        "available.info",
        "installed.list",
    ] {
        run(verb).ok();
    }
    // install (a dry run) works on a fresh home; update needs an installed
    // plugin and would contact the default registry, so its example is run
    // where it fails before any network access.
    run("install").ok();
    run("update").fails(1, "plugin.not_installed");
    h.run(&["plugin://aws.install", "source=file", "path=./aws-plugin"])
        .ok();
    for verb in ["remove", "enable", "disable"] {
        let j = run(verb).ok().clone();
        assert_eq!(j["args"]["dry_run"], true, "{verb}");
    }
}
