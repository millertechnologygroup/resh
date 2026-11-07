//! `secret://` verbs through the real `resh` binary. Each test uses its own
//! temporary directory as HOME and XDG_STATE_HOME, and the debug-build test
//! keyring (`RESH_TEST_KEYRING=file:<path>` or `unavailable`) instead of
//! the host's OS keyring. `secret://vault` talks to an in-process fake
//! Vault on 127.0.0.1. Nothing outside the temporary directory is touched.

#[path = "../src/handles/security/secret_fake_vault.rs"]
mod fake_vault;

use fake_vault::FakeVault;
use serde_json::{Value, json};
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
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        assert_eq!(self.err.lines().count(), 1, "{}", self.err);
        self
    }
}

struct Env {
    tmp: TempDir,
    vars: Vec<(String, String)>,
}

impl Env {
    fn new() -> Self {
        Self {
            tmp: TempDir::new().unwrap(),
            vars: Vec::new(),
        }
    }

    fn var(mut self, k: &str, v: &str) -> Self {
        self.vars.push((k.into(), v.into()));
        self
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn index(&self) -> PathBuf {
        self.dir().join("state/resh/secrets/local.json")
    }

    fn keyring(&self) -> Value {
        std::fs::read_to_string(self.dir().join("keyring.json"))
            .map(|t| serde_json::from_str(&t).unwrap())
            .unwrap_or(json!({}))
    }

    fn run(&self, args: &[&str]) -> Run {
        let d = self.dir();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(d)
            .env("HOME", d)
            .env("XDG_STATE_HOME", d.join("state"))
            // Never the host's OS keyring.
            .env(
                "RESH_TEST_KEYRING",
                format!("file:{}", d.join("keyring.json").display()),
            );
        for k in [
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "VAULT_NAMESPACE",
            "VAULT_CACERT",
        ] {
            cmd.env_remove(k);
        }
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let out = cmd.args(args).output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8(out.stdout).unwrap(),
            err: String::from_utf8(out.stderr).unwrap(),
        }
    }
}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn help_examples_work_and_values_stay_out_of_files() {
    let env = Env::new().var("DB_PASSWORD", "s3cr3t-value");
    let r = env
        .run(&[
            "--json-pretty",
            "secret://local/app/db_password.set",
            "from_env=DB_PASSWORD",
        ])
        .ok();
    assert_eq!(
        r.json(),
        json!({"backend": "local", "key": "app/db_password", "scope": "local",
               "set": true, "source": "env"})
    );
    assert!(r.out.contains("\n  \"backend\""), "pretty: {}", r.out);
    assert_eq!(env.keyring()["resh-secret/app/db_password"], "s3cr3t-value");
    let index = std::fs::read_to_string(env.index()).unwrap();
    assert!(!index.contains("s3cr3t"), "{index}");
    assert_eq!(mode_of(&env.index()), 0o600);
    assert_eq!(mode_of(env.index().parent().unwrap()), 0o700);

    let r = env
        .run(&["--json-pretty", "secret://local/app/db_password.get"])
        .ok();
    assert_eq!(r.json()["value"], "s3cr3t-value");
    env.run(&["secret://local/app/api_key.set", "value=sk-test123"])
        .ok();
    let r = env.run(&["--json-pretty", "secret://local/app.ls"]).ok();
    assert_eq!(r.json()["keys"], json!(["app/api_key", "app/db_password"]));
    let r = env
        .run(&[
            "--json-pretty",
            "secret://local/app/api_key.rotate",
            "strategy=random",
            "length=256",
        ])
        .ok();
    assert_eq!(r.json()["existed"], true);
    let rotated = env.keyring()["resh-secret/app/api_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(rotated, "sk-test123");
    assert!(!r.out.contains(&rotated));
    let r = env
        .run(&["--json-pretty", "secret://local/app/api_key.rm"])
        .ok();
    assert_eq!(r.json()["removed"], true);
    assert!(env.keyring().get("resh-secret/app/api_key").is_none());
}

#[test]
fn no_keyring_refuses_writes_with_exit_1() {
    let env = Env::new().var("RESH_TEST_KEYRING", "unavailable");
    env.run(&["secret://local/k.set", "value=v"])
        .fails(1, "secret.keyring_unavailable");
    assert!(!env.index().exists());
    assert!(!env.dir().join("keyring.json").exists());
    env.run(&["secret://local/k.get"])
        .fails(1, "secret.keyring_unavailable");
    env.run(&["secret://local/.ls"]).ok();
}

#[test]
fn legacy_plaintext_store_is_migrated_on_the_next_write() {
    let env = Env::new();
    std::fs::create_dir_all(env.index().parent().unwrap()).unwrap();
    std::fs::write(env.index(), r#"{"old/token":"legacy-value"}"#).unwrap();

    let r = env.run(&["secret://local/old/token.get"]).ok();
    assert_eq!(r.json()["value"], "legacy-value");
    assert!(r.err.starts_with("Warning: "), "{}", r.err);

    env.run(&["secret://local/new.set", "value=n"]).ok();
    let index = std::fs::read_to_string(env.index()).unwrap();
    assert!(!index.contains("legacy-value"), "{index}");
    assert_eq!(env.keyring()["resh-secret/old/token"], "legacy-value");
    let r = env.run(&["secret://local/old/token.get"]).ok();
    assert_eq!(r.json()["value"], "legacy-value");
    assert!(r.err.is_empty(), "{}", r.err);
}

#[test]
fn env_scope_and_usage_errors() {
    let env = Env::new().var("RESH_TEST_SECRET_VAR", "from-env");
    let r = env.run(&["secret://env/RESH_TEST_SECRET_VAR.get"]).ok();
    assert_eq!(r.json()["value"], "from-env");
    env.run(&["secret://env/RESH_TEST_SECRET_VAR.set", "value=x"])
        .fails(2, "secret.read_only");
    env.run(&["secret://local/k.get", "redcat=true"])
        .fails(2, "secret.invalid_argument");
    env.run(&["secret://local/k.gt"])
        .fails(2, "secret.unknown_verb");
    env.run(&["secret://local/.set", "value=v"])
        .fails(2, "secret.missing_key");
    env.run(&["secret://local/k.set"])
        .fails(2, "secret.missing_value");
    env.run(&["secret://local/k.set", "from_env=RESH_TEST_SURELY_UNSET"])
        .fails(1, "secret.env_not_set");
    env.run(&["secret://local/k.rotate", "strategy=dsa"])
        .fails(2, "secret.invalid_argument");

    // Errors raised before the handle runs: stderr only.
    let r = env.run(&["secret://disk/k.get"]);
    assert_eq!(r.code, 2);
    assert!(
        r.err.starts_with("Error: [secret.invalid_target] "),
        "{}",
        r.err
    );
    let r = env.run(&["secret://local/k.set", "value=v", "dry_run=true"]);
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(env.keyring().as_object().unwrap().is_empty());
}

#[test]
fn vault_through_the_binary() {
    let fake = FakeVault::start("t0ken", "secret");
    let env = Env::new()
        .var("VAULT_ADDR", fake.addr())
        .var("VAULT_TOKEN", "t0ken")
        .var("PW", "vault-pw");
    env.run(&["secret://vault/app/db.set", "from_env=PW", "field=password"])
        .ok();
    assert_eq!(fake.secret("app/db").unwrap()["password"], "vault-pw");
    let r = env
        .run(&["secret://vault/app/db.get", "field=password"])
        .ok();
    assert_eq!(r.json()["value"], "vault-pw");
    let r = env.run(&["secret://vault/.ls"]).ok();
    assert_eq!(r.json()["keys"], json!(["app/db"]));
    let r = env
        .run(&["secret://vault/svc/id.rotate", "strategy=uuid"])
        .ok();
    assert_eq!(r.json()["existed"], false);
    assert_eq!(
        fake.secret("svc/id").unwrap()["value"]
            .as_str()
            .unwrap()
            .len(),
        36
    );
    env.run(&["secret://vault/app/db.rm"]).ok();
    assert!(fake.secret("app/db").is_none());
    // Nothing went to the keyring or the local index.
    assert!(!env.index().exists());

    let bad = Env::new()
        .var("VAULT_ADDR", fake.addr())
        .var("VAULT_TOKEN", "nope");
    let r = bad
        .run(&["secret://vault/app/db.get"])
        .fails(1, "secret.vault_denied");
    assert!(!r.out.contains("nope") && !r.err.contains("nope"));
    Env::new()
        .run(&["secret://vault/app/db.get"])
        .fails(2, "secret.vault_not_configured");
}

#[test]
fn help_forms() {
    let env = Env::new();
    for args in [
        &["secret", "--help"][..],
        &["help", "secret"],
        &["secret", "rotate", "--help"],
    ] {
        let r = env.run(args).ok();
        assert!(r.out.starts_with("Handle: secret"), "{}", r.out);
        assert!(
            !r.out.to_lowercase().contains("not implemented"),
            "{}",
            r.out
        );
    }
    let r = env.run(&["secret", "rotate", "--help"]).ok();
    assert!(r.out.contains("strategy=random|uuid|aes|rsa"), "{}", r.out);
}
