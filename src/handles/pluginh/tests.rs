//! Handle-level tests of the plugin verbs: every verb is called through
//! `PluginHandle::call` with all locations in a temporary directory and a
//! local HTTPS registry (`tests/plugin_support/registry.rs`).

#[path = "../../../tests/plugin_support/registry.rs"]
mod fake;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use serde_json::Value;
use tempfile::TempDir;

use super::common::*;
use super::paths;
use crate::core::registry::{Args, Handle, IoStreams};
use crate::core::status::Status;
use crate::handles::automation::pluginh::PluginHandle;
use fake::{
    FakeRegistry, add_file, b64, key_id, new_key, plugin_tar_gz, raw_tar_gz, sha256_hex, sign,
    tar_gz,
};

struct Env {
    t: TempDir,
    _guard: paths::TestRootGuard,
}

impl Env {
    fn new() -> Self {
        let t = TempDir::new().unwrap();
        let guard = paths::test_root(t.path());
        Env { t, _guard: guard }
    }
    fn root(&self) -> &Path {
        self.t.path()
    }
    fn store(&self) -> PathBuf {
        self.root().join("data/resh/plugins")
    }
    fn plugin(&self, id: &str) -> PathBuf {
        self.store().join(id)
    }
    /// The registry's CA file; also trusts the registry's publisher key.
    fn ca(&self, reg: &FakeRegistry) -> String {
        super::sign::add_key(&reg.public_key(), Some("test registry")).unwrap();
        let p = self.root().join("ca.pem");
        fs::write(&p, &reg.ca_pem).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn file(&self, name: &str, data: &[u8]) -> String {
        let p = self.root().join(name);
        fs::write(&p, data).unwrap();
        p.to_string_lossy().into_owned()
    }
    fn current(&self, id: &str) -> Option<String> {
        fs::read_link(self.plugin(id).join("current"))
            .ok()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
    }
    /// True if the store holds no files for `id` and staging is empty.
    fn nothing_installed(&self, id: &str) -> bool {
        let staging_empty = fs::read_dir(self.store().join(".staging"))
            .map(|d| d.count() == 0)
            .unwrap_or(true);
        !self.plugin(id).exists() && staging_empty
    }
}

struct Out {
    status: Status,
    json: Value,
    stdout: String,
}

impl Out {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert!(self.status.ok, "{:?}\n{}", self.status, self.stdout);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        assert_eq!(self.json["code"], 0);
        &self.json
    }
    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Value {
        assert!(!self.status.ok, "expected failure: {}", self.stdout);
        assert_eq!(self.status.exit_code(), exit, "{:?}", self.status);
        let reason = self.status.reason.clone().unwrap_or_default();
        assert!(
            reason.starts_with(&format!("[{code}] ")),
            "{reason} (want {code})"
        );
        if !self.stdout.is_empty() {
            assert_eq!(self.json["ok"], false);
            assert_eq!(self.json["code"], exit);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
        &self.json
    }
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Calls `verb` on `plugin://<host>` the way dispatch does.
fn call(host: &str, verb: &str, pairs: &[(&str, &str)]) -> Out {
    let url = url::Url::parse(&format!("plugin://{host}")).unwrap();
    let h = PluginHandle::new(&url).unwrap();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let status = h.call(verb, &args(pairs), &mut io).unwrap();
    let stdout = String::from_utf8(o).unwrap();
    let json = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    Out {
        status,
        json,
        stdout,
    }
}

fn install(id: &str, pairs: &[(&str, &str)]) -> Out {
    call(id, "install", pairs)
}

fn install_file(env: &Env, id: &str, body: &[u8]) -> Out {
    let p = env.file(&format!("{id}-artifact"), body);
    install(id, &[("source", "file"), ("path", &p)])
}

// --- install ---------------------------------------------------------------

#[test]
fn install_from_a_local_binary_and_tar() {
    let env = Env::new();
    let r = install_file(&env, "demo", b"#!/bin/sh\necho hi\n");
    let j = r.ok();
    assert_eq!(j["result"]["installed"], true);
    assert_eq!(j["result"]["version"], "local");
    assert_eq!(j["target"]["version"], "local");
    assert_eq!(env.current("demo").as_deref(), Some("local"));
    let bin = env.plugin("demo").join("versions/local/demo");
    assert_eq!(j["target"]["bin_path"], bin.to_string_lossy().as_ref());
    assert_eq!(fs::metadata(&bin).unwrap().mode() & 0o777, 0o755);
    let types: Vec<_> = j["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["type"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        types,
        [
            "check_installed",
            "resolve",
            "download",
            "verify",
            "extract",
            "install",
            "activate",
            "cleanup"
        ]
    );
    // The store directories are not writable by others.
    assert_eq!(fs::metadata(env.store()).unwrap().mode() & 0o022, 0);
    // A .tar.gz with setuid and world-writable modes is sanitized.
    let data = tar_gz(|b| {
        add_file(b, "bin/plugin", b"#!/bin/sh\n", 0o4777);
        add_file(b, "doc/readme", b"x", 0o666);
    });
    let p = env.file("t.tar.gz", &data);
    let j = install("tool", &[("source", "file"), ("path", &p)])
        .ok()
        .clone();
    let v = env.plugin("tool").join("versions/local");
    assert_eq!(
        fs::metadata(v.join("bin/plugin")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(v.join("doc/readme")).unwrap().mode() & 0o7777,
        0o644
    );
    assert_eq!(
        j["target"]["bin_path"],
        v.join("bin/plugin").to_string_lossy().as_ref()
    );
    let meta: Value = serde_json::from_slice(&fs::read(v.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(meta["source"], "file");
    assert_eq!(meta["sha256"], sha256_hex(&data));
}

#[test]
fn install_dry_run_writes_nothing() {
    let env = Env::new();
    let p = env.file("a", b"x");
    let j = install(
        "demo",
        &[("source", "file"), ("path", &p), ("dry_run", "true")],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["installed"], false);
    assert_eq!(j["result"]["changed"], false);
    let last = j["actions"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["details"]["dry_run"], true);
    assert_eq!(last["details"]["to_version"], "local");
    assert!(
        !env.root().join("data").exists(),
        "dry run created the store"
    );
}

#[test]
fn install_from_registry_verifies_and_uses_ca_file() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    reg.publish_ok("demo", "1.0.0");
    let ca = env.ca(&reg);
    let base = reg.base();
    // Without the private CA, the certificate is not trusted.
    install("demo", &[("registry", &base)]).fails(1, DOWNLOAD_FAILED);
    assert!(env.nothing_installed("demo"));
    let j = install("demo", &[("registry", &base), ("ca_file", &ca)])
        .ok()
        .clone();
    assert_eq!(j["result"]["version"], "1.0.0");
    assert_eq!(j["args"]["registry"], format!("{base}/"));
    let verify = j["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["type"] == "verify")
        .unwrap()
        .clone();
    assert_eq!(verify["ok"], true);
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    assert!(
        env.plugin("demo")
            .join("versions/1.0.0/bin/plugin")
            .is_file()
    );
    // Installing the same version again is a no-op; force reinstalls.
    let j = install("demo", &[("registry", &base), ("ca_file", &ca)])
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], false);
    let j = install(
        "demo",
        &[("registry", &base), ("ca_file", &ca), ("force", "yes")],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(j["result"]["previous_version"], "1.0.0");
}

#[test]
fn tampered_or_unverifiable_artifacts_are_refused() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    let base = reg.base();
    let a = [("registry", base.as_str()), ("ca_file", ca.as_str())];
    let good = plugin_tar_gz("x");
    // Tampered: the checksum belongs to other bytes.
    reg.publish(
        "demo",
        "1.0.0",
        "p.tar.gz",
        &good,
        Some(&sha256_hex(b"other")),
    );
    let j = install("demo", &a).fails(1, VERIFY_FAILED).clone();
    let v = j["actions"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        (v["type"].as_str(), v["ok"].as_bool()),
        (Some("verify"), Some(false))
    );
    assert!(env.nothing_installed("demo"));
    // No checksum, or a malformed one: refused before the download.
    for (id, sha) in [
        ("nosum", None),
        ("badsum", Some("abc")),
        ("hexish", Some(&"g".repeat(64)[..])),
    ] {
        reg.publish(id, "1.0.0", "p.tar.gz", &good, sha);
        install(id, &a).fails(1, VERIFY_FAILED);
        assert!(
            !reg.hits()
                .iter()
                .any(|h| h.starts_with(&format!("/v1/artifacts/{id}"))),
            "{id}: artifact fetched"
        );
        assert!(env.nothing_installed(id));
    }
    // verify=none installs without a checksum, with a warning.
    let mut a2 = a.to_vec();
    a2.push(("verify", "none"));
    let j = install("nosum", &a2).ok().clone();
    assert!(j["warnings"][0].as_str().unwrap().contains("verify=none"));
    // verify accepts only sha256 and none.
    for bad in ["md5", "NONE", "off", ""] {
        install("demo", &[("registry", &base), ("verify", bad)]).fails(2, INVALID_ARGUMENT);
    }
}

#[test]
fn url_and_http_sources_need_https_and_explicit_verify_none() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    reg.set("/tool", 200, b"#!/bin/sh\n".to_vec());
    let url = format!("{}/tool", reg.base());
    install(
        "tool",
        &[("source", "url"), ("url", &url), ("ca_file", &ca)],
    )
    .fails(2, INVALID_ARGUMENT);
    assert!(reg.hits().is_empty());
    let j = install(
        "tool",
        &[
            ("source", "url"),
            ("url", &url),
            ("ca_file", &ca),
            ("verify", "none"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["version"], "unknown");
    // Plain http, other schemes, credentials: refused before any connection.
    for bad in [
        format!("http://127.0.0.1:{}/tool", reg.port),
        "ftp://x/y".to_string(),
        format!("https://u:p@127.0.0.1:{}/tool", reg.port),
    ] {
        install("x", &[("source", "url"), ("url", &bad), ("verify", "none")])
            .fails(2, INVALID_ARGUMENT);
        install("x", &[("registry", &bad)]).fails(2, INVALID_ARGUMENT);
        call("x", "update", &[("registry", &bad)]).fails(2, INVALID_ARGUMENT);
    }
    // A redirect to plain http is refused.
    reg.redirect(
        "/v1/plugins/redir",
        &format!("http://127.0.0.1:{}/x", reg.port),
    );
    install("redir", &[("registry", &reg.base()), ("ca_file", &ca)]).fails(1, DOWNLOAD_FAILED);
}

#[test]
fn registry_resolution_errors() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    let base = reg.base();
    let a = |extra: &[(&'static str, &'static str)]| {
        let mut v: Vec<(String, String)> = vec![
            ("registry".into(), base.clone()),
            ("ca_file".into(), ca.clone()),
        ];
        v.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        v
    };
    let run = |id: &str, extra: &[(&'static str, &'static str)]| {
        let v = a(extra);
        let p: Vec<(&str, &str)> = v.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        install(id, &p)
    };
    // Unknown plugin, unknown version.
    run("ghost", &[]).fails(1, NOT_FOUND);
    reg.publish_ok("demo", "1.9.0");
    reg.publish_ok("demo", "1.10.0");
    run("demo", &[("version", "3.0.0")]).fails(1, NOT_FOUND);
    // "Latest" is the highest version, numerically.
    let j = run("demo", &[("dry_run", "true")]).ok().clone();
    assert_eq!(j["result"]["version"], "1.10.0");
    // No artifact for this platform.
    reg.set(
        "/v1/plugins/other",
        200,
        r#"{"plugin_id":"other","versions":{"1.0.0":{"platforms":{"plan9-mips":{"bin":"p","sha256":"00"}}}}}"#,
    );
    run("other", &[]).fails(1, PLATFORM_UNSUPPORTED);
    // Malformed entries.
    reg.set("/v1/plugins/broken", 200, "{not json");
    run("broken", &[]).fails(1, CATALOG_INVALID);
    reg.set(
        "/v1/plugins/liar",
        200,
        r#"{"plugin_id":"someone-else","versions":{}}"#,
    );
    run("liar", &[]).fails(1, CATALOG_INVALID);
    let plat = fake::platform();
    reg.set(
        "/v1/plugins/sneaky",
        200,
        format!(
            r#"{{"plugin_id":"sneaky","versions":{{"1.0.0":{{"platforms":{{"{plat}":{{"bin":"../../x","sha256":"{}"}}}}}}}}}}"#,
            "0".repeat(64)
        ),
    );
    run("sneaky", &[]).fails(1, CATALOG_INVALID);
    reg.set(
        "/v1/plugins/badver",
        200,
        format!(
            r#"{{"plugin_id":"badver","versions":{{"../../x":{{"platforms":{{"{plat}":{{"bin":"p","sha256":"{}"}}}}}}}}}}"#,
            "0".repeat(64)
        ),
    );
    run("badver", &[]).fails(1, CATALOG_INVALID);
    reg.set("/v1/plugins/err", 500, "oops");
    run("err", &[]).fails(1, DOWNLOAD_FAILED);
    for id in [
        "ghost", "demo", "other", "broken", "liar", "sneaky", "badver", "err",
    ] {
        assert!(env.nothing_installed(id), "{id}");
    }
    // Downgrades need allow_downgrade (or force).
    run("demo", &[]).ok();
    run("demo", &[("version", "1.9.0")]).fails(1, DOWNGRADE_REFUSED);
    assert_eq!(env.current("demo").as_deref(), Some("1.10.0"));
    let j = run("demo", &[("version", "1.9.0"), ("allow_downgrade", "true")])
        .ok()
        .clone();
    assert_eq!(j["result"]["previous_version"], "1.10.0");
    assert_eq!(env.current("demo").as_deref(), Some("1.9.0"));
    // The current and one previous version are kept.
    let mut v: Vec<_> = fs::read_dir(env.plugin("demo").join("versions"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    assert_eq!(v, ["1.10.0", "1.9.0"]);
}

#[test]
fn timeout_mid_download_installs_nothing_and_keeps_the_old_version() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    let base = reg.base();
    reg.publish_ok("demo", "1.0.0");
    install("demo", &[("registry", &base), ("ca_file", &ca)]).ok();
    let data = plugin_tar_gz("2");
    reg.publish(
        "demo",
        "2.0.0",
        "slow.tar.gz",
        &data,
        Some(&sha256_hex(&data)),
    );
    reg.slow("/v1/artifacts/demo/2.0.0/slow.tar.gz");
    let start = std::time::Instant::now();
    let r = install(
        "demo",
        &[("registry", &base), ("ca_file", &ca), ("timeout_ms", "700")],
    );
    r.fails(124, TIMEOUT);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    assert_eq!(
        fs::read_dir(env.plugin("demo").join("versions"))
            .unwrap()
            .count(),
        1
    );
    let r = call(
        "demo",
        "update",
        &[("registry", &base), ("ca_file", &ca), ("timeout_ms", "500")],
    );
    r.fails(124, TIMEOUT);
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    // A fresh install that times out leaves nothing behind.
    reg.publish(
        "fresh",
        "1.0.0",
        "slow.tar.gz",
        &data,
        Some(&sha256_hex(&data)),
    );
    reg.slow("/v1/artifacts/fresh/1.0.0/slow.tar.gz");
    install(
        "fresh",
        &[("registry", &base), ("ca_file", &ca), ("timeout_ms", "500")],
    )
    .fails(124, TIMEOUT);
    assert!(env.nothing_installed("fresh"));
}

#[test]
fn malicious_archives_are_refused_and_nothing_escapes() {
    let env = Env::new();
    let victim = env.root().join("victim");
    fs::create_dir(&victim).unwrap();
    let outside = env.root().join("data/resh/evil");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("dotdot", raw_tar_gz("../evil", b"x")),
        ("deep", raw_tar_gz("a/../../../../evil", b"x")),
        ("abs", raw_tar_gz("/tmp/resh-plugin-evil-abs", b"x")),
        (
            "link",
            tar_gz(|b| {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_cksum();
                b.append_link(&mut h, "bin/plugin", "/etc/passwd").unwrap();
            }),
        ),
        (
            "hard",
            tar_gz(|b| {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Link);
                h.set_size(0);
                h.set_cksum();
                b.append_link(&mut h, "plugin", "/etc/shadow").unwrap();
            }),
        ),
        (
            "fifo",
            tar_gz(|b| {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Fifo);
                h.set_size(0);
                h.set_cksum();
                b.append_data(&mut h, "pipe", &[][..]).unwrap();
            }),
        ),
        ("garbage", b"not a gzip stream".to_vec()),
    ];
    for (id, data) in &cases {
        let p = env.file(&format!("{id}.tar.gz"), data);
        install(id, &[("source", "file"), ("path", &p)]).fails(1, EXTRACT_FAILED);
        assert!(env.nothing_installed(id), "{id}");
    }
    assert!(!outside.exists());
    assert!(!Path::new("/tmp/resh-plugin-evil-abs").exists());
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    // A failed reinstall leaves the installed version untouched.
    install_file(&env, "keep", b"#!/bin/sh\n").ok();
    let p = env.file("keep-bad.tar.gz", &cases[0].1);
    install(
        "keep",
        &[("source", "file"), ("path", &p), ("force", "true")],
    )
    .fails(1, EXTRACT_FAILED);
    assert!(env.plugin("keep").join("versions/local/keep").is_file());
}

#[test]
fn oversized_tar_headers_are_refused() {
    // More than 1 MiB of PAX header data before one member (v1.0.5-beta).
    let env = Env::new();
    let mut pax = Vec::new();
    let value = "a".repeat(1100 * 1024);
    let rec = format!("comment={value}\n");
    let len = rec.len() + 8;
    let len = len + (len.to_string().len() - 1);
    pax.extend_from_slice(format!("{len} {rec}").as_bytes());
    let data = tar_gz(|b| {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::XHeader);
        h.set_size(pax.len() as u64);
        h.set_cksum();
        b.append_data(&mut h, "pax", &pax[..]).unwrap();
        add_file(b, "plugin", b"x", 0o755);
    });
    let p = env.file("pax.tar.gz", &data);
    install("pax", &[("source", "file"), ("path", &p)]).fails(1, EXTRACT_FAILED);
    assert!(env.nothing_installed("pax"));
}

#[test]
fn install_argument_errors_do_nothing() {
    let env = Env::new();
    let p = env.file("a", b"x");
    let bad: &[&[(&str, &str)]] = &[
        &[("verfy", "none")],
        &[("source", "ftp")],
        &[("source", "file")],
        &[("source", "url")],
        &[("source", "file"), ("path", &p), ("registry", "https://x")],
        &[("source", "file"), ("path", &p), ("version", "1.0")],
        &[
            ("source", "file"),
            ("path", &p),
            ("ca_file", "/nonexistent.pem"),
        ],
        &[("source", "file"), ("path", &p), ("force", "maybe")],
        &[("source", "file"), ("path", &p), ("dry_run", "2")],
        &[("source", "file"), ("path", &p), ("timeout_ms", "0")],
        &[("source", "file"), ("path", &p), ("timeout_ms", "abc")],
        &[("version", "../x")],
        &[("registry", "")],
        &[("registry", "/srv/registry.json")],
        &[("ca_file", &p)],
    ];
    for a in bad {
        let r = install("demo", a);
        r.fails(2, INVALID_ARGUMENT);
        assert!(r.stdout.is_empty(), "{a:?}");
    }
    for id in ["-x", "locks", ".hidden", "a/b"] {
        call(id, "install", &[("source", "file"), ("path", &p)]).fails(2, INVALID_TARGET);
    }
    call("install", "install", &[]).fails(2, INVALID_TARGET);
    install("demo", &[("source", "file"), ("path", "/nonexistent")]).fails(1, NOT_FOUND);
    assert!(!env.root().join("data").exists());
}

#[test]
fn unsafe_store_locations_are_refused() {
    let env = Env::new();
    // A symlink planted at the plugin directory is never followed.
    let victim = env.root().join("victim");
    fs::create_dir(&victim).unwrap();
    fs::create_dir_all(env.store()).unwrap();
    symlink(&victim, env.plugin("demo")).unwrap();
    install_file(&env, "demo", b"x").fails(1, UNSAFE_PATH);
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    fs::remove_file(env.plugin("demo")).unwrap();
    // A store others can write to is refused.
    fs::set_permissions(env.store(), fs::Permissions::from_mode(0o777)).unwrap();
    install_file(&env, "demo", b"x").fails(1, UNSAFE_PATH);
    call("installed.list", "installed.list", &[]).fails(1, UNSAFE_PATH);
    fs::set_permissions(env.store(), fs::Permissions::from_mode(0o755)).unwrap();
    // A symlinked store is refused too.
    fs::rename(env.store(), env.root().join("elsewhere")).unwrap();
    symlink(env.root().join("elsewhere"), env.store()).unwrap();
    install_file(&env, "demo", b"x").fails(1, UNSAFE_PATH);
}

// --- update ----------------------------------------------------------------

#[test]
fn update_installs_the_newest_version() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    let base = reg.base();
    let a = [("registry", base.as_str()), ("ca_file", ca.as_str())];
    // Not installed: nothing is fetched.
    call("demo", "update", &a).fails(1, NOT_INSTALLED);
    assert!(reg.hits().is_empty());
    reg.publish_ok("demo", "1.0.0");
    install("demo", &a).ok();
    // Up to date: a no-op, or an error with strict=true.
    let j = call("demo", "update", &a).ok().clone();
    assert_eq!(j["result"]["changed"], false);
    let mut strict = a.to_vec();
    strict.push(("strict", "true"));
    call("demo", "update", &strict).fails(1, NO_UPDATE_AVAILABLE);
    reg.publish_ok("demo", "1.1.0");
    let mut dry = a.to_vec();
    dry.push(("dry_run", "true"));
    let j = call("demo", "update", &dry).ok().clone();
    assert_eq!(j["result"]["version"], "1.1.0");
    assert_eq!(j["result"]["previous_version"], "1.0.0");
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    // A tampered new version fails and the old one stays active.
    reg.publish(
        "demo",
        "1.2.0",
        "x.tar.gz",
        b"bad",
        Some(&sha256_hex(b"good")),
    );
    call("demo", "update", &a).fails(1, VERIFY_FAILED);
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    reg.publish_ok("demo", "1.2.0");
    let j = call("demo", "update", &a).ok().clone();
    assert_eq!(j["result"]["previous_version"], "1.0.0");
    assert_eq!(j["result"]["version"], "1.2.0");
    assert_eq!(env.current("demo").as_deref(), Some("1.2.0"));
    assert!(
        env.plugin("demo").join("versions/1.0.0").is_dir(),
        "kept as previous"
    );
    // installed_at is kept; updated_at changes.
    let list = call("installed.list", "installed.list", &[]).ok().clone();
    let item = &list["result"]["items"][0];
    assert_ne!(item["installed_at"], item["updated_at"]);
    // A url update needs verify=none and always installs.
    reg.set("/raw", 200, b"#!/bin/sh\n".to_vec());
    let url = format!("{base}/raw");
    call("demo", "update", &[("url", &url), ("ca_file", &ca)]).fails(2, INVALID_ARGUMENT);
    call("demo", "update", &[("url", &url), ("registry", &base)]).fails(2, INVALID_ARGUMENT);
    let j = call(
        "demo",
        "update",
        &[("url", &url), ("ca_file", &ca), ("verify", "none")],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["version"], "unknown");
    call("demo", "update", &[("version", "1.0.0")]).fails(2, INVALID_ARGUMENT);
    call("demo", "update", &[("strict", "sure")]).fails(2, INVALID_ARGUMENT);
}

// --- remove ----------------------------------------------------------------

#[test]
fn remove_dry_run_purge_and_errors() {
    let env = Env::new();
    call("demo", "remove", &[]).fails(1, NOT_INSTALLED);
    install_file(&env, "demo", b"#!/bin/sh\n").ok();
    let j = call("demo", "remove", &[("dry_run", "true"), ("purge", "true")])
        .ok()
        .clone();
    assert_eq!(j["result"]["removed"], false);
    assert!(env.plugin("demo").exists());
    // purge deletes the plugin's own data directories and its state entry.
    call("demo", "enable", &[]).ok();
    let data = [
        env.root().join("state/resh/plugins/demo"),
        env.root().join("cache/resh/plugins/demo"),
        env.root().join("config/resh/plugins/demo"),
    ];
    for d in &data {
        fs::create_dir_all(d).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
    }
    let j = call("demo", "remove", &[("purge", "true")]).ok().clone();
    assert_eq!(j["result"]["removed"], true);
    assert_eq!(j["result"]["purged"], true);
    assert_eq!(j["result"]["previous_version"], "local");
    assert!(env.nothing_installed("demo"));
    for d in &data {
        assert!(!d.exists(), "{}", d.display());
    }
    let st: Value = serde_json::from_slice(
        &fs::read(env.root().join("state/resh/plugins/state.json")).unwrap(),
    )
    .unwrap();
    assert!(st["enabled_plugins"].get("demo").is_none());
    call("demo", "remove", &[]).fails(1, NOT_INSTALLED);
    // A symlinked purge directory is refused before anything is removed.
    install_file(&env, "demo", b"#!/bin/sh\n").ok();
    let victim = env.root().join("victim");
    fs::create_dir(&victim).unwrap();
    fs::write(victim.join("keep"), b"x").unwrap();
    symlink(&victim, &data[1]).unwrap();
    call("demo", "remove", &[("purge", "true")]).fails(1, UNSAFE_PATH);
    assert!(victim.join("keep").exists());
    assert!(env.plugin("demo").exists());
    // Without purge the plugin data is kept.
    call("demo", "remove", &[]).ok();
    assert!(victim.join("keep").exists());
    for a in [
        &[("purge", "x")][..],
        &[("timeout_ms", "-1")],
        &[("verify", "none")],
    ] {
        call("demo", "remove", a).fails(2, INVALID_ARGUMENT);
    }
}

/// Installs a copy of `/bin/sh` as plugin `id` and starts it, blocked
/// reading its stdin, so a process runs the plugin binary.
fn run_plugin(env: &Env, id: &str) -> std::process::Child {
    let sh = fs::read("/bin/sh").unwrap();
    let p = env.file(&format!("{id}-sh"), &sh);
    install(id, &[("source", "file"), ("path", &p)]).ok();
    let bin = env.plugin(id).join("versions/local").join(id);
    // Another test's fork may briefly hold a write descriptor (ETXTBSY).
    let mut tries = 0;
    let child = loop {
        match std::process::Command::new(&bin)
            .args(["-c", "read x"])
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("cannot start {}: {e}", bin.display()),
        }
    };
    // Wait until the child runs the plugin binary (exec done), however
    // slow the machine is.
    let exe = format!("/proc/{}/exe", child.id());
    let bin = fs::canonicalize(&bin).unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while fs::read_link(&exe).ok().as_deref() != Some(bin.as_path())
        && std::time::Instant::now() < end
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child
}

#[test]
fn running_plugins_are_not_removed_or_disabled_without_force() {
    let env = Env::new();
    let mut child = run_plugin(&env, "busy");
    call("busy", "enable", &[]).ok();
    let j = call("busy", "disable", &[]).fails(1, IN_USE).clone();
    assert!(
        j["error"]["message"]
            .as_str()
            .unwrap()
            .contains("force=true")
    );
    call("busy", "remove", &[]).fails(1, IN_USE);
    assert!(env.plugin("busy").exists());
    call("busy", "disable", &[("force", "true")]).ok();
    let j = call("busy", "remove", &[("force", "true")]).ok().clone();
    assert_eq!(j["result"]["removed"], true);
    child.kill().ok();
    child.wait().ok();
}

// --- enable / disable --------------------------------------------------------

#[test]
fn enable_and_disable_record_state() {
    let env = Env::new();
    call("demo", "enable", &[]).fails(1, NOT_INSTALLED);
    call("demo", "disable", &[]).fails(1, NOT_INSTALLED);
    install_file(&env, "demo", b"#!/bin/sh\n").ok();
    let j = call("demo", "enable", &[("dry_run", "true")]).ok().clone();
    assert_eq!(j["result"]["changed"], false);
    let state = env.root().join("state/resh/plugins/state.json");
    assert!(!state.exists());
    let j = call("demo", "enable", &[("reason", "needed for deploys")])
        .ok()
        .clone();
    assert_eq!(j["result"]["enabled"], true);
    assert_eq!(j["result"]["was_enabled"], false);
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(fs::metadata(&state).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(state.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    let st: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(st["enabled_plugins"]["demo"], true);
    assert_eq!(st["changes"]["demo"]["reason"], "needed for deploys");
    // Already enabled: no change; force rewrites the entry.
    let j = call("demo", "enable", &[]).ok().clone();
    assert_eq!(j["result"]["changed"], false);
    let j = call("demo", "enable", &[("force", "true"), ("reason", "again")])
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], true);
    // installed.list reads the same state.
    let l = call("installed.list", "installed.list", &[("enabled", "true")])
        .ok()
        .clone();
    assert_eq!(l["result"]["total"], 1);
    let j = call("demo", "disable", &[]).ok().clone();
    assert_eq!(j["result"]["enabled"], false);
    assert_eq!(j["result"]["was_enabled"], true);
    let l = call("installed.list", "installed.list", &[("enabled", "true")])
        .ok()
        .clone();
    assert_eq!(l["result"]["total"], 0);
    // System scope: its own file, readable by everyone.
    let j = call("demo", "enable", &[("scope", "system")]).ok().clone();
    assert_eq!(j["result"]["scope"], "system");
    let sys = env.root().join("system/resh/plugins/state.json");
    assert_eq!(fs::metadata(&sys).unwrap().mode() & 0o777, 0o644);
    // The user entry (disabled) wins over the system entry.
    let l = call("installed.list", "installed.list", &[("format", "summary")])
        .ok()
        .clone();
    assert_eq!(l["result"]["items"][0]["enabled"], false);
    // Keys written by other versions are kept.
    let mut st: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    st["installed_plugins"] = serde_json::json!({"demo": {"version": "local"}});
    fs::write(&state, serde_json::to_vec(&st).unwrap()).unwrap();
    call("demo", "enable", &[]).ok();
    let st: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(st["installed_plugins"]["demo"]["version"], "local");
}

#[test]
fn enable_errors() {
    let env = Env::new();
    install_file(&env, "demo", b"#!/bin/sh\n").ok();
    for a in [
        &[("scope", "global")][..],
        &[("timeout_ms", "1000")],
        &[("force", "nope")],
        &[("reson", "x")],
    ] {
        call("demo", "enable", a).fails(2, INVALID_ARGUMENT);
    }
    let long = "x".repeat(201);
    call("demo", "enable", &[("reason", &long)]).fails(2, INVALID_ARGUMENT);
    call("demo", "disable", &[("reason", "a\nb")]).fails(2, INVALID_ARGUMENT);
    call("demo", "enable", &[("reason", &"é".repeat(200))]).ok();
    // A corrupt state file is an error, not silently replaced.
    let state = env.root().join("state/resh/plugins/state.json");
    fs::write(&state, b"{oops").unwrap();
    call("demo", "disable", &[]).fails(1, IO_ERROR);
    assert_eq!(fs::read(&state).unwrap(), b"{oops");
    // A planted symlink is refused, and its target is never written.
    let victim = env.root().join("victim.json");
    fs::write(&victim, b"{}").unwrap();
    fs::remove_file(&state).unwrap();
    symlink(&victim, &state).unwrap();
    call("demo", "disable", &[]).fails(1, UNSAFE_PATH);
    assert_eq!(fs::read(&victim).unwrap(), b"{}");
    // Every lifecycle verb needs a plugin id.
    for verb in ["enable", "disable", "remove", "update"] {
        call(verb, verb, &[]).fails(2, INVALID_TARGET);
    }
}

// --- installed.list ----------------------------------------------------------

#[test]
fn installed_list_filters_sorts_and_reports_damage() {
    let env = Env::new();
    let empty = call("installed.list", "installed.list", &[]).ok().clone();
    assert_eq!(empty["result"]["total"], 0);
    assert!(
        !env.root().join("data").exists(),
        "listing created the store"
    );
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    reg.publish_ok("zeta", "1.0.0");
    install("zeta", &[("registry", &reg.base()), ("ca_file", &ca)]).ok();
    install_file(&env, "Alpha", b"#!/bin/sh\n").ok();
    install_file(&env, "beta", b"#!/bin/sh\n").ok();
    call("beta", "enable", &[]).ok();
    let names = |a: &[(&str, &str)]| -> Vec<String> {
        let mut v = vec![("format", "names")];
        v.extend_from_slice(a);
        call("installed.list", "installed.list", &v).ok()["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names(&[]), ["Alpha", "beta", "zeta"]);
    assert_eq!(names(&[("order", "desc")]), ["zeta", "beta", "Alpha"]);
    assert_eq!(names(&[("enabled", "true")]), ["beta"]);
    assert_eq!(names(&[("enabled", "no")]), ["Alpha", "zeta"]);
    assert_eq!(names(&[("source", "registry")]), ["zeta"]);
    assert_eq!(names(&[("source", "file")]), ["Alpha", "beta"]);
    assert_eq!(names(&[("prefix", "be")]), ["beta"]);
    assert_eq!(names(&[("name", "zeta")]), ["zeta"]);
    assert_eq!(names(&[("tag", "demo")]), ["zeta"]);
    assert_eq!(names(&[("limit", "1"), ("offset", "1")]), ["beta"]);
    assert_eq!(names(&[("sort", "installed_at")]).len(), 3);
    let full = call("installed.list", "installed.list", &[("name", "zeta")])
        .ok()
        .clone();
    let z = &full["result"]["items"][0];
    assert_eq!(z["health"], "ok");
    assert_eq!(z["manifest"]["tags"][0], "demo");
    assert_eq!(z["source"]["type"], "registry");
    // A damaged entry is listed as broken.
    fs::remove_file(env.plugin("beta").join("versions/local/metadata.json")).unwrap();
    let l = call("installed.list", "installed.list", &[("name", "beta")])
        .ok()
        .clone();
    assert_eq!(l["result"]["items"][0]["health"], "broken");
    for a in [
        &[("enabled", "maybe")][..],
        &[("limit", "0")],
        &[("limit", "501")],
        &[("offset", "-1")],
        &[("sort", "size")],
        &[("order", "up")],
        &[("format", "xml")],
        &[("source", "git")],
        &[("timeout_ms", "100")],
        &[("dry_run", "true")],
    ] {
        call("installed.list", "installed.list", a).fails(2, INVALID_ARGUMENT);
    }
    call("aws", "installed.list", &[]).fails(2, INVALID_TARGET);
}

// --- available.list ----------------------------------------------------------

#[test]
fn available_list_reads_builtin_and_file_catalogs() {
    let env = Env::new();
    // The built-in catalog works from any directory.
    let j = call(
        "available.list",
        "available.list",
        &[("query", "docker"), ("limit", "1")],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["count"], 1);
    assert_eq!(j["result"]["items"][0]["id"], "resh.docker");
    let j = call("available", "available.list", &[("platform", "plan9-mips")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 0);
    let cat = env.file(
        "cat.json",
        br#"{"version":2,"generated_at":"x","plugins":[
          {"id":"b","name":"B","version":"1.10.0","platforms":["linux-x86_64","linux-aarch64"],"tags":["Net"]},
          {"id":"b","name":"B","version":"1.9.0","platforms":["linux-x86_64","linux-aarch64"],"tags":["net"]},
          {"id":"a","name":"A","version":"2.0.0-rc.1","platforms":["linux-x86_64","linux-aarch64"]}]}"#,
    );
    let src = format!("file:{cat}");
    let j = call("available.list", "available.list", &[("source", &src)])
        .ok()
        .clone();
    let vers: Vec<_> = j["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["version"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(vers, ["1.10.0", "1.9.0"], "prerelease hidden, newest first");
    let j = call(
        "available.list",
        "available.list",
        &[
            ("source", &src),
            ("include_prerelease", "true"),
            ("tags", "NET"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["count"], 2);
    let j = call(
        "available.list",
        "available.list",
        &[
            ("source", &src),
            ("format", "full"),
            ("include_prerelease", "on"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(j["result"]["items"][0]["id"], "a");
    call(
        "available.list",
        "available.list",
        &[("source", "file:/nonexistent.json")],
    )
    .fails(1, NOT_FOUND);
    let bad = env.file("bad.json", b"[1,2]");
    call(
        "available.list",
        "available.list",
        &[("source", &format!("file:{bad}"))],
    )
    .fails(1, CATALOG_INVALID);
    for a in [
        &[("source", "url:https://x")][..],
        &[("source", "file:")],
        &[("limit", "0")],
        &[("limit", "1001")],
        &[("format", "xml")],
        &[("platform", "linux")],
        &[("include_prerelease", "si")],
        &[("timeout_ms", "100")],
    ] {
        call("available.list", "available.list", a).fails(2, INVALID_ARGUMENT);
    }
    call("aws", "available.list", &[]).fails(2, INVALID_TARGET);
}

// --- available.search --------------------------------------------------------

const INDEX: &str = r#"{"plugins":[
  {"id":"resh.docker","display_name":"Docker","description":"containers","version":"1.10.0","publisher":"acme","tags":["container","docker"]},
  {"id":"resh.k8s","display_name":"Kubernetes","description":"clusters","version":"1.2.0","publisher":"acme","tags":["container"]},
  {"id":"resh.backup","display_name":"Backup","description":"backups","version":"0.9.0","publisher":"other","tags":["storage","backup"]}]}"#;

#[test]
fn available_search_fetches_caches_and_filters() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    reg.set("/index.json", 200, INDEX);
    let src = format!("{}/index.json", reg.base());
    let search = |a: &[(&str, &str)]| call("available.search", "available.search", a);
    // No cache yet: offline fails.
    search(&[("source", &src), ("offline", "true")]).fails(1, NOT_FOUND);
    search(&[("source", &src)]).fails(1, DOWNLOAD_FAILED);
    let j = search(&[("source", &src), ("ca_file", &ca), ("q", "docker")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 1);
    assert_eq!(j["result"]["source"]["mode"], "online");
    assert_eq!(j["result"]["items"][0]["id"], "resh.docker");
    // The cache is private.
    let cache_dir = env.root().join("state/resh/plugins");
    let cache = fs::read_dir(&cache_dir)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("cache-"))
        .unwrap()
        .path();
    assert_eq!(fs::metadata(&cache).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&cache_dir).unwrap().mode() & 0o777, 0o700);
    // Offline and default runs use the cache, without contacting the server.
    reg.set("/index.json", 500, "down");
    let hits = reg.hits().len();
    let j = search(&[("source", &src), ("offline", "true"), ("tags", "container")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 2);
    assert_eq!(j["result"]["source"]["mode"], "cache");
    let j = search(&[("source", &src), ("min_version", "1.9.0")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 1, "1.10.0 >= 1.9.0 numerically");
    let j = search(&[("source", &src), ("owner", "other")]).ok().clone();
    assert_eq!(j["result"]["items"][0]["id"], "resh.backup");
    let j = search(&[("source", &src), ("name", "resh.k8s")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 1);
    let j = search(&[("source", &src), ("q", "nomatch")]).ok().clone();
    assert_eq!(j["result"]["count"], 0);
    let j = search(&[("source", &src), ("max_results", "1")])
        .ok()
        .clone();
    assert_eq!(j["result"]["count"], 1);
    assert_eq!(reg.hits().len(), hits);
    // refresh=true fetches again (and the server now fails).
    search(&[("source", &src), ("ca_file", &ca), ("refresh", "true")]).fails(1, DOWNLOAD_FAILED);
    reg.set("/index.json", 200, "{bad");
    search(&[("source", &src), ("ca_file", &ca), ("refresh", "true")]).fails(1, CATALOG_INVALID);
    reg.slow("/index.json");
    search(&[
        ("source", &src),
        ("ca_file", &ca),
        ("refresh", "1"),
        ("timeout_ms", "400"),
    ])
    .fails(124, TIMEOUT);
    for a in [
        &[("offline", "true"), ("refresh", "true")][..],
        &[("offline", "true"), ("ca_file", &ca)],
        &[("source", "http://x/index.json")],
        &[("min_version", "new")],
        &[("max_results", "0")],
        &[("max_results", "201")],
        &[("timeout_ms", "0")],
        &[("offline", "TRUEISH")],
        &[("dry_run", "true")],
    ] {
        search(a).fails(2, INVALID_ARGUMENT);
    }
}

// --- available.info ----------------------------------------------------------

fn info_index(name: &str, versions: &[(&str, &str)]) -> String {
    let plugins: Vec<Value> = versions
        .iter()
        .map(|(v, min)| {
            serde_json::json!({
                "id": format!("{name}.id"), "name": name, "display_name": name,
                "version": v, "channel": "stable", "description": "d",
                "compatibility": {"resh_min": min, "os": ["linux"]},
                "assets": [{"kind": "tar.gz", "os": "linux", "arch": "x86_64",
                            "url": "https://x/a.tar.gz", "size": 1, "sha256": "00"}]
            })
        })
        .collect();
    serde_json::json!({"version": 1, "generated_at": "x", "plugins": plugins}).to_string()
}

#[test]
fn available_info_selects_from_indexes() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    super::available::index::TEST_INDEX_BASE.with(|b| *b.borrow_mut() = Some(reg.base()));
    let info = |a: &[(&str, &str)]| call("available.info", "available.info", a);
    reg.set(
        "/official/index-stable.json",
        200,
        info_index(
            "resh.docker",
            &[("1.9.0", "0.1"), ("1.10.0", "0.1"), ("9.0.0", "999.0")],
        ),
    );
    reg.set(
        "/community/index-stable.json",
        200,
        info_index("community.tool", &[("0.1.0", "0.1")]),
    );
    info(&[("name", "resh.docker"), ("offline", "true")]).fails(1, NOT_FOUND);
    info(&[("name", "resh.docker")]).fails(1, DOWNLOAD_FAILED);
    let j = info(&[("name", "resh.docker"), ("ca_file", &ca)])
        .ok()
        .clone();
    assert_eq!(
        j["result"]["plugin"]["version"], "1.10.0",
        "9.0.0 needs a newer resh"
    );
    let j = info(&[("id", "community.tool.id"), ("offline", "true")])
        .ok()
        .clone();
    assert_eq!(j["result"]["plugin"]["name"], "community.tool");
    let j = info(&[
        ("name", "resh.docker"),
        ("version", "1.9"),
        ("offline", "yes"),
    ])
    .ok()
    .clone();
    assert_eq!(j["result"]["plugin"]["version"], "1.9.0");
    info(&[
        ("name", "resh.docker"),
        ("channel", "beta"),
        ("source", "official"),
        ("ca_file", &ca),
    ])
    .fails(1, NOT_FOUND);
    info(&[
        ("name", "resh.docker"),
        ("os", "windows"),
        ("offline", "true"),
    ])
    .fails(1, NOT_FOUND);
    info(&[("name", "nothing"), ("offline", "true")]).fails(1, NOT_FOUND);
    // One index failing is a warning when the other loads.
    let cache = env.root().join("cache/resh/plugin-indexes");
    assert_eq!(fs::metadata(&cache).unwrap().mode() & 0o777, 0o700);
    fs::remove_dir_all(&cache).unwrap();
    reg.set("/community/index-stable.json", 500, "down");
    let j = info(&[("name", "resh.docker"), ("ca_file", &ca)])
        .ok()
        .clone();
    assert!(j["warnings"][0].as_str().unwrap().contains("community"));
    reg.set("/official/index-stable.json", 200, "{bad");
    fs::remove_dir_all(&cache).unwrap();
    info(&[
        ("name", "resh.docker"),
        ("source", "official"),
        ("ca_file", &ca),
    ])
    .fails(1, CATALOG_INVALID);
    reg.slow("/official/index-stable.json");
    info(&[
        ("name", "resh.docker"),
        ("source", "official"),
        ("ca_file", &ca),
        ("timeout_ms", "300"),
    ])
    .fails(124, TIMEOUT);
    for a in [
        &[][..],
        &[("name", "x"), ("version", "1")],
        &[("name", "x"), ("channel", "edge")],
        &[("name", "x"), ("source", "https://x")],
        &[("name", "x"), ("timeout_ms", "x")],
        &[("name", "x"), ("offline", "true"), ("ca_file", &ca)],
        &[("name", "x"), ("include", "core")],
    ] {
        info(a).fails(2, INVALID_ARGUMENT);
    }
    super::available::index::TEST_INDEX_BASE.with(|b| *b.borrow_mut() = None);
}

// --- help and codes ----------------------------------------------------------

/// Option names in a usage text (`[key=...]` and `key=...`).
fn usage_keys(usage: &str) -> Vec<String> {
    let mut keys: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == '|')
        .filter_map(|w| w.split_once('='))
        .map(|(k, _)| k.trim_start_matches('[').to_string())
        .filter(|k| !k.is_empty() && !k.starts_with('<'))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

#[test]
fn help_usage_lists_exactly_the_accepted_arguments() {
    let help = crate::handles::automation::pluginh::plugin_help();
    for verb in VERBS {
        let h = help.verbs.iter().find(|v| v.name == *verb).unwrap();
        let mut want: Vec<String> = verb_args(verb).iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(usage_keys(h.detail.as_ref().unwrap().usage), want, "{verb}");
    }
}

#[test]
fn every_code_is_documented() {
    let doc = include_str!("../../../docs/Automation_Utilities/plugin.md");
    for c in CODES {
        assert!(crate::core::status::is_valid_error_code(c), "{c}");
        assert!(doc.contains(&format!("`{c}`")), "{c} is not documented");
    }
}

#[test]
fn a_damaged_plugin_can_still_be_removed() {
    let env = Env::new();
    install_file(&env, "demo", b"#!/bin/sh\n").ok();
    let cur = env.plugin("demo").join("current");
    fs::remove_file(&cur).unwrap();
    symlink("../../elsewhere", &cur).unwrap();
    call("demo", "enable", &[]).fails(1, IO_ERROR);
    let j = call("demo", "remove", &[]).ok().clone();
    assert!(j["warnings"][0].as_str().unwrap().contains("damaged"));
    assert!(env.nothing_installed("demo"));
}

// --- signatures, keys, rollback, progress -------------------------------------

#[test]
fn unsigned_or_untrusted_artifacts_are_refused() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca_path = env.root().join("ca.pem");
    fs::write(&ca_path, &reg.ca_pem).unwrap();
    let ca = ca_path.to_string_lossy().into_owned();
    let base = reg.base();
    let a = [("registry", base.as_str()), ("ca_file", ca.as_str())];
    let data = plugin_tar_gz("x");
    let sha = sha256_hex(&data);
    // Signed by the registry's key, which is not trusted yet.
    reg.publish("demo", "1.0.0", "p.tar.gz", &data, Some(&sha));
    let j = install("demo", &a).fails(1, SIGNATURE_INVALID).clone();
    assert!(
        j["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not trusted")
    );
    assert!(
        !reg.hits().iter().any(|h| h.starts_with("/v1/artifacts/")),
        "artifact fetched before the signature was checked"
    );
    assert!(env.nothing_installed("demo"));
    // trust_key= for one call.
    let pk = reg.public_key();
    let mut t = a.to_vec();
    t.push(("trust_key", pk.as_str()));
    let j = install("demo", &t).ok().clone();
    let sig = j["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["type"] == "signature")
        .unwrap()
        .clone();
    assert_eq!(sig["details"]["key_origin"], "trust_key");
    // Unsigned: refused unless allow_unsigned=true (with a warning).
    reg.publish_with(
        "bare",
        "1.0.0",
        "p.tar.gz",
        &data,
        Some(&sha),
        serde_json::json!({}),
    );
    install("bare", &t).fails(1, SIGNATURE_REQUIRED);
    let mut u = t.clone();
    u.push(("allow_unsigned", "true"));
    let j = install("bare", &u).ok().clone();
    assert!(
        j["warnings"][0]
            .as_str()
            .unwrap()
            .contains("allow_unsigned")
    );
    // A signature by a trusted key that does not match is always refused.
    let other = sign(&reg.signer, "bare", "9.9.9", &sha);
    reg.publish_with(
        "forged",
        "1.0.0",
        "p.tar.gz",
        &data,
        Some(&sha),
        serde_json::json!({"signature": other, "key_id": key_id(&reg.signer.verifying_key())}),
    );
    install("forged", &u).fails(1, SIGNATURE_INVALID);
    // A key that is not trusted is accepted with allow_unsigned=true only.
    let stranger = new_key();
    reg.publish_with(
        "stranger",
        "1.0.0",
        "p.tar.gz",
        &data,
        Some(&sha),
        serde_json::json!({
            "signature": sign(&stranger, "stranger", "1.0.0", &sha),
            "key_id": key_id(&stranger.verifying_key()),
        }),
    );
    install("stranger", &t).fails(1, SIGNATURE_INVALID);
    install("stranger", &u).ok();
    // Garbage signatures.
    reg.publish_with(
        "junk",
        "1.0.0",
        "p.tar.gz",
        &data,
        Some(&sha),
        serde_json::json!({"signature": "!!!", "key_id": key_id(&reg.signer.verifying_key())}),
    );
    install("junk", &t).fails(1, SIGNATURE_INVALID);
    // verify=none skips checksum and signature; file sources have none.
    let mut n = t.clone();
    n.push(("verify", "none"));
    install("bare", &n).ok();
    // Bad trust_key values are usage errors.
    for bad in ["", "abc", &b64(&[1u8; 31])] {
        install("demo", &[("registry", &base), ("trust_key", bad)]).fails(2, INVALID_ARGUMENT);
    }
}

#[test]
fn keys_add_list_remove() {
    let env = Env::new();
    let list = || call("keys.list", "keys.list", &[]).ok().clone();
    let j = list();
    assert_eq!(j["result"]["count"], 0);
    assert_eq!(j["result"]["official_key_set"], false);
    let k = new_key();
    let pk = b64(k.verifying_key().as_bytes());
    let kid = key_id(&k.verifying_key());
    let j = call("keys.add", "keys.add", &[("key", &pk), ("name", "acme")])
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(j["result"]["key"]["key_id"], kid.as_str());
    let j = call("keys.add", "keys.add", &[("key", &pk)]).ok().clone();
    assert_eq!(j["result"]["changed"], false);
    let store = env.root().join("config/resh/plugin-trusted-keys.json");
    assert_eq!(fs::metadata(&store).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(store.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    let j = list();
    assert_eq!(j["result"]["items"][0]["name"], "acme");
    assert_eq!(j["result"]["items"][0]["origin"], "trust_store");
    call("keys.delete", "keys.delete", &[("key_id", &kid)]).ok();
    call("keys.delete", "keys.delete", &[("key_id", &kid)]).fails(1, NOT_FOUND);
    assert_eq!(list()["result"]["count"], 0);
    for (verb, a) in [
        ("keys.add", &[][..]),
        ("keys.add", &[("key", "nope")]),
        ("keys.add", &[("key", pk.as_str()), ("nmae", "x")]),
        ("keys.delete", &[]),
        ("keys.list", &[("verbose", "true")]),
    ] {
        call(verb, verb, a).fails(2, INVALID_ARGUMENT);
    }
    call("aws", "keys.list", &[]).fails(2, INVALID_TARGET);
    // A planted symlink at the trust store is never written through.
    let victim = env.root().join("victim");
    fs::write(&victim, b"keep").unwrap();
    fs::remove_file(&store).unwrap();
    symlink(&victim, &store).unwrap();
    call("keys.add", "keys.add", &[("key", &pk)]).fails(1, UNSAFE_PATH);
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
}

#[test]
fn rollback_switches_to_the_kept_previous_version() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    let base = reg.base();
    let a = [("registry", base.as_str()), ("ca_file", ca.as_str())];
    call("demo", "rollback", &[]).fails(1, NOT_INSTALLED);
    reg.publish_ok("demo", "1.0.0");
    install("demo", &a).ok();
    call("demo", "rollback", &[]).fails(1, NO_PREVIOUS_VERSION);
    reg.publish_ok("demo", "2.0.0");
    call("demo", "update", &a).ok();
    let l = call("installed.list", "installed.list", &[("format", "summary")])
        .ok()
        .clone();
    assert_eq!(l["result"]["items"][0]["previous_version"], "1.0.0");
    let j = call("demo", "rollback", &[("dry_run", "true")])
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], false);
    assert_eq!(env.current("demo").as_deref(), Some("2.0.0"));
    let j = call("demo", "rollback", &[]).ok().clone();
    assert_eq!(j["result"]["version"], "1.0.0");
    assert_eq!(j["result"]["previous_version"], "2.0.0");
    assert_eq!(j["target"]["version"], "1.0.0");
    assert_eq!(env.current("demo").as_deref(), Some("1.0.0"));
    // Rolling back again returns to 2.0.0.
    call("demo", "rollback", &[]).ok();
    assert_eq!(env.current("demo").as_deref(), Some("2.0.0"));
    // A third version: only it and the one it replaced are kept.
    reg.publish_ok("demo", "3.0.0");
    call("demo", "update", &a).ok();
    let mut v: Vec<_> = fs::read_dir(env.plugin("demo").join("versions"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    assert_eq!(v, ["2.0.0", "3.0.0"]);
    for bad in [
        &[("force", "true")][..],
        &[("timeout_ms", "0")],
        &[("dry_run", "x")],
    ] {
        call("demo", "rollback", bad).fails(2, INVALID_ARGUMENT);
    }
    // remove deletes both versions.
    call("demo", "remove", &[]).ok();
    assert!(env.nothing_installed("demo"));
}

#[test]
fn progress_streams_json_lines_before_the_result() {
    let env = Env::new();
    let reg = FakeRegistry::start();
    let ca = env.ca(&reg);
    // A large artifact so several download events are written.
    let big: Vec<u8> = (0..900_000u32).map(|i| (i % 251) as u8).collect();
    let data = tar_gz(|b| {
        add_file(b, "plugin", b"#!/bin/sh\n", 0o755);
        add_file(b, "blob", &big, 0o644);
    });
    reg.publish("demo", "1.0.0", "p.tar.gz", &data, Some(&sha256_hex(&data)));
    let r = install(
        "demo",
        &[
            ("registry", &reg.base()),
            ("ca_file", &ca),
            ("progress", "true"),
        ],
    );
    assert!(r.status.ok, "{}", r.stdout);
    let lines: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let (events, last) = lines.split_at(lines.len() - 1);
    assert_eq!(last[0]["op"], "plugin.install");
    let steps: Vec<&str> = events.iter().map(|e| e["step"].as_str().unwrap()).collect();
    assert_eq!(steps.first(), Some(&"resolve"));
    assert!(steps.contains(&"signature"));
    assert!(steps.iter().filter(|s| **s == "download").count() >= 1);
    for s in ["verify", "extract", "activate"] {
        assert!(steps.contains(&s), "{s} missing: {steps:?}");
    }
    let dl: Vec<&Value> = events.iter().filter(|e| e["step"] == "download").collect();
    let lastdl = dl.last().unwrap();
    assert_eq!(lastdl["bytes"], data.len());
    assert_eq!(lastdl["total"], data.len());
    for e in events {
        assert_eq!(e["event"], "progress");
        assert_eq!(e["handle"], "plugin");
        assert_eq!(e["verb"], "install");
    }
    // Without progress, one JSON object only.
    reg.publish_ok("demo", "1.1.0");
    let r = call(
        "demo",
        "update",
        &[("registry", &reg.base()), ("ca_file", &ca)],
    );
    assert_eq!(r.stdout.lines().count(), 1);
    install("demo", &[("progress", "maybe")]).fails(2, INVALID_ARGUMENT);
}
