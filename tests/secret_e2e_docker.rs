//! `secret://` against real backends in throwaway Docker containers:
//! - `local` with a real OS keyring: gnome-keyring as the Secret Service
//!   on a private D-Bus session in a Debian container (the same image as
//!   the mail keyring test);
//! - `vault` with a real HashiCorp Vault dev server, published on
//!   127.0.0.1 only, over plain HTTP and over TLS with its own CA
//!   (`ca_file=`).
//!
//! The host's keyring is never used. Run with
//! `cargo test --features e2e-docker --test secret_e2e_docker`.
#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

const KEYRING_IMAGE: &str = "resh-mail-keyring:1";
const VAULT_IMAGE: &str = "hashicorp/vault:1.18.5";

fn ensure_keyring_image() {
    let have = Command::new("docker")
        .args(["image", "inspect", KEYRING_IMAGE])
        .output()
        .unwrap();
    if have.status.success() {
        return;
    }
    let mut child = Command::new("docker")
        .args(["build", "-q", "-t", KEYRING_IMAGE, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"FROM debian:13-slim\nRUN apt-get update && apt-get install -y --no-install-recommends dbus dbus-x11 gnome-keyring libsecret-tools ca-certificates && rm -rf /var/lib/apt/lists/*\n",
        )
        .unwrap();
    assert!(child.wait().unwrap().success(), "image build failed");
}

/// Runs `script` (bash) in the keyring image with this build's `resh` at
/// /usr/local/bin/resh and returns its KEY=value lines.
fn in_keyring_container(script: &str) -> impl Fn(&str) -> String {
    ensure_keyring_image();
    let bin = Path::new(env!("CARGO_BIN_EXE_resh"));
    let out = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/usr/local/bin/resh:ro", bin.display()))
        .args([KEYRING_IMAGE, "bash", "-c", script])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    move |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("no {k} in {text}\n{err}"))
            .to_string()
    }
}

/// The real OS keyring: values go to gnome-keyring under service
/// `resh-secret`, the index holds names only, legacy plaintext is moved in,
/// and without a session bus every keyring operation is refused.
#[test]
fn local_scope_uses_the_real_keyring() {
    let get = in_keyring_container(
        r#"
set -u
export HOME=/tmp/h; mkdir -p $HOME/.local/state/resh/secrets
IDX=$HOME/.local/state/resh/secrets/local.json
echo '{"legacy/token":"old-plain"}' > $IDX
dbus-run-session -- bash -c '
  IDX='"$IDX"'
  echo -n unlock | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
  sleep 1
  echo "LEGACYGET=$(resh secret://local/legacy/token.get 2>/tmp/lw | tr -d "\n ")"
  echo "LEGACYWARN=$(grep -c "^Warning: " /tmp/lw)"
  export DBPW=s3cr3t-pw
  resh secret://local/app/db.set from_env=DBPW >/dev/null; echo "SET=$?"
  echo "LOOKUP=$(secret-tool lookup service resh-secret username app/db)"
  echo "MIGRATED=$(secret-tool lookup service resh-secret username legacy/token)"
  echo "INDEX=$(tr -d "\n " < $IDX)"
  echo "MODE=$(stat -c %a $IDX)"
  echo "GET=$(resh secret://local/app/db.get | tr -d "\n ")"
  echo "LS=$(resh secret://local/.ls | tr -d "\n ")"
  resh secret://local/app/db.rotate strategy=aes length=128 >/tmp/rot.json; echo "ROT=$?"
  echo "ROTATED=$(secret-tool lookup service resh-secret username app/db)"
  echo "ROTOUT=$(tr -d "\n " < /tmp/rot.json)"
  echo "RM=$(resh secret://local/app/db.rm | tr -d "\n ")"
  echo "AFTER=$(secret-tool lookup service resh-secret username app/db)"
'
env -u DBUS_SESSION_BUS_ADDRESS resh secret://local/x.set value=y > /tmp/nokr.json 2>/dev/null; echo "NOKR=$?"
echo "NOKRCODE=$(grep -o "secret\.[a-z_]*" /tmp/nokr.json | head -1)"
echo "NOKRLS=$(env -u DBUS_SESSION_BUS_ADDRESS resh secret://local/.ls | tr -d "\n ")"
"#,
    );
    let v: Value = serde_json::from_str(&get("LEGACYGET")).unwrap();
    assert_eq!(v["value"], "old-plain");
    assert!(v["warnings"].is_array(), "{v}");
    assert_eq!(get("LEGACYWARN"), "1");
    assert_eq!(get("SET"), "0");
    assert_eq!(get("LOOKUP"), "s3cr3t-pw");
    assert_eq!(get("MIGRATED"), "old-plain");
    let index = get("INDEX");
    assert!(
        !index.contains("s3cr3t") && !index.contains("old-plain"),
        "{index}"
    );
    assert!(
        index.contains(r#""app/db":"keyring:resh-secret/app/db""#),
        "{index}"
    );
    assert_eq!(get("MODE"), "600");
    let v: Value = serde_json::from_str(&get("GET")).unwrap();
    assert_eq!(v["value"], "s3cr3t-pw");
    let v: Value = serde_json::from_str(&get("LS")).unwrap();
    assert_eq!(v["keys"], json!(["app/db", "legacy/token"]));
    assert_eq!(get("ROT"), "0");
    let rotated = get("ROTATED");
    assert_eq!(rotated.len(), 32, "{rotated}");
    assert!(!get("ROTOUT").contains(&rotated));
    let v: Value = serde_json::from_str(&get("RM")).unwrap();
    assert_eq!(v["removed"], true);
    assert_eq!(get("AFTER"), "");
    assert_eq!(get("NOKR"), "1");
    assert_eq!(get("NOKRCODE"), "secret.keyring_unavailable");
    let v: Value = serde_json::from_str(&get("NOKRLS")).unwrap();
    assert_eq!(v["keys"], json!(["legacy/token"]));
}

/// A Vault dev server container, removed on drop.
struct VaultServer {
    id: String,
    addr: String,
    _dir: TempDir,
    ca: Option<std::path::PathBuf>,
}

const ROOT: &str = "root-token";

impl VaultServer {
    fn start(tls: bool) -> Self {
        let mut args = vec![
            "run".to_string(),
            "-d".into(),
            "--rm".into(),
            "--cap-add=IPC_LOCK".into(),
            "-p".into(),
            "127.0.0.1::8200".into(),
            "-e".into(),
            "SKIP_SETCAP=1".into(),
            VAULT_IMAGE.into(),
            "server".into(),
            "-dev".into(),
            format!("-dev-root-token-id={ROOT}"),
            "-dev-listen-address=0.0.0.0:8200".into(),
        ];
        if tls {
            args.push("-dev-tls".into());
            args.push("-dev-tls-cert-dir=/tmp".into());
        }
        let out = Command::new("docker").args(&args).output().expect("docker");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let o = Command::new("docker")
            .args(["port", &id, "8200/tcp"])
            .output()
            .unwrap();
        let port: u16 = String::from_utf8(o.stdout)
            .unwrap()
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("port");
        let scheme = if tls { "https" } else { "http" };
        let dir = TempDir::new().unwrap();
        let mut server = Self {
            addr: format!("{scheme}://127.0.0.1:{port}"),
            id,
            _dir: dir,
            ca: None,
        };
        for _ in 0..150 {
            std::thread::sleep(Duration::from_millis(200));
            if tls && server.ca.is_none() {
                let dest = server._dir.path().join("vault-ca.pem");
                let ok = Command::new("docker")
                    .args(["cp", &format!("{}:/tmp/vault-ca.pem", server.id)])
                    .arg(&dest)
                    .output()
                    .unwrap()
                    .status
                    .success();
                if ok {
                    server.ca = Some(dest);
                } else {
                    continue;
                }
            }
            if server.health() {
                return server;
            }
        }
        panic!("vault did not start");
    }

    fn client(&self) -> reqwest::blocking::Client {
        let mut b = reqwest::blocking::Client::builder();
        if let Some(ca) = &self.ca {
            for c in reqwest::Certificate::from_pem_bundle(&std::fs::read(ca).unwrap()).unwrap() {
                b = b.add_root_certificate(c);
            }
        }
        b.build().unwrap()
    }

    fn health(&self) -> bool {
        self.client()
            .get(format!("{}/v1/sys/health", self.addr))
            .send()
            .is_ok_and(|r| r.status().is_success())
    }

    /// Calls the Vault API as root.
    fn api(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let mut r = self
            .client()
            .request(method, format!("{}/v1/{path}", self.addr))
            .header("X-Vault-Token", ROOT);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().unwrap();
        assert!(resp.status().is_success(), "{path}: {}", resp.status());
        resp.json().unwrap_or(Value::Null)
    }
}

impl Drop for VaultServer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn resh(home: &Path, vars: &[(&str, &str)], args: &[&str]) -> (i32, Value, String) {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(home)
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        // Never the host's OS keyring.
        .env("RESH_TEST_KEYRING", "unavailable")
        .env_remove("VAULT_ADDR")
        .env_remove("VAULT_TOKEN")
        .env_remove("VAULT_CACERT")
        .env_remove("VAULT_NAMESPACE");
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd.args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn vault_scope_against_a_real_vault() {
    let v = VaultServer::start(false);
    let home = TempDir::new().unwrap();
    let env = [("VAULT_ADDR", v.addr.as_str()), ("VAULT_TOKEN", ROOT)];
    let run = |args: &[&str]| resh(home.path(), &env, args);

    let (code, out, err) = run(&["secret://vault/app/db.set", "value=pw1"]);
    assert_eq!(code, 0, "{out} {err}");
    let data = v.api(reqwest::Method::GET, "secret/data/app/db", None);
    assert_eq!(data["data"]["data"], json!({"value": "pw1"}));

    // A second field is kept when value changes.
    v.api(
        reqwest::Method::POST,
        "secret/data/app/db",
        Some(json!({"data": {"value": "pw1", "username": "app"}})),
    );
    let (code, out, err) = run(&["secret://vault/app/db.set", "value=pw2"]);
    assert_eq!(code, 0, "{out} {err}");
    let data = v.api(reqwest::Method::GET, "secret/data/app/db", None);
    assert_eq!(
        data["data"]["data"],
        json!({"value": "pw2", "username": "app"})
    );
    assert_eq!(data["data"]["metadata"]["version"], 3);

    let (code, out, _) = run(&["secret://vault/app/db.get"]);
    assert_eq!((code, out["value"].clone()), (0, json!("pw2")));
    let (_, out, _) = run(&["secret://vault/app/db.get", "field=username"]);
    assert_eq!(out["value"], "app");
    let (code, out, _) = run(&["secret://vault/app/db.get", "field=nope"]);
    assert_eq!(code, 1);
    assert_eq!(out["error"]["code"], "secret.vault_field_missing");
    let (code, out, _) = run(&["secret://vault/app/none.get"]);
    assert_eq!((code, out["exists"].clone()), (0, json!(false)));

    run(&["secret://vault/app/nested/deep.set", "value=x"]);
    run(&["secret://vault/app.set", "value=y"]);
    run(&["secret://vault/other.set", "value=z"]);
    let (_, out, _) = run(&["secret://vault/app.ls"]);
    assert_eq!(out["keys"], json!(["app", "app/db", "app/nested/deep"]));
    let (_, out, _) = run(&["secret://vault/.ls"]);
    assert_eq!(
        out["keys"],
        json!(["app", "app/db", "app/nested/deep", "other"])
    );

    let (code, out, err) = run(&[
        "secret://vault/svc/key.rotate",
        "strategy=rsa",
        "length=2048",
    ]);
    assert_eq!(code, 0, "{out} {err}");
    assert!(out["public_key"].as_str().unwrap().contains("PUBLIC KEY"));
    let data = v.api(reqwest::Method::GET, "secret/data/svc/key", None);
    let pem = data["data"]["data"]["value"].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!out.to_string().contains("PRIVATE"));

    let (code, out, _) = run(&["secret://vault/app/db.rm"]);
    assert_eq!((code, out["removed"].clone()), (0, json!(true)));
    let (_, out, _) = run(&["secret://vault/app/db.rm"]);
    assert_eq!(out["removed"], false);
    let (_, out, _) = run(&["secret://vault/app/db.get"]);
    assert_eq!(out["exists"], false);

    // Another KV v2 mount, nested.
    v.api(
        reqwest::Method::POST,
        "sys/mounts/kv/team",
        Some(json!({"type": "kv", "options": {"version": "2"}})),
    );
    let (code, out, err) = run(&["secret://vault/t.set", "value=tv", "mount=kv/team"]);
    assert_eq!(code, 0, "{out} {err}");
    let (_, out, _) = run(&["secret://vault/t.get", "mount=kv/team"]);
    assert_eq!(out["value"], "tv");
    // A mount that does not exist is an error, not a missing secret.
    let (code, out, _) = run(&["secret://vault/t.get", "mount=nope"]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["error"]["code"], "secret.vault_error");

    let bad = [("VAULT_ADDR", v.addr.as_str()), ("VAULT_TOKEN", "wrong")];
    let (code, out, _) = resh(home.path(), &bad, &["secret://vault/t.get"]);
    assert_eq!(code, 1);
    assert_eq!(out["error"]["code"], "secret.vault_denied");
}

#[test]
fn vault_over_tls_needs_its_ca() {
    let v = VaultServer::start(true);
    let home = TempDir::new().unwrap();
    let env = [("VAULT_ADDR", v.addr.as_str()), ("VAULT_TOKEN", ROOT)];
    // The dev server's own CA is not trusted by default.
    let (code, out, _) = resh(home.path(), &env, &["secret://vault/k.set", "value=v"]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["error"]["code"], "secret.vault_error");
    let ca = v.ca.as_ref().unwrap().display().to_string();
    let ca_arg = format!("ca_file={ca}");
    let (code, out, err) = resh(
        home.path(),
        &env,
        &["secret://vault/k.set", "value=v", &ca_arg],
    );
    assert_eq!(code, 0, "{out} {err}");
    // VAULT_CACERT is the default for ca_file.
    let env2 = [
        ("VAULT_ADDR", v.addr.as_str()),
        ("VAULT_TOKEN", ROOT),
        ("VAULT_CACERT", ca.as_str()),
    ];
    let (code, out, _) = resh(home.path(), &env2, &["secret://vault/k.get"]);
    assert_eq!((code, out["value"].clone()), (0, json!("v")));
}
