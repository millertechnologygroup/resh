//! Unit and dispatch tests for `secret://`. The OS keyring is replaced by
//! an in-memory store and the state directory by a temporary one (both
//! per test thread); `secret://vault` talks to the in-process fake Vault.

use super::*;
use crate::core::secret_store::{MemStore, Unavailable, set_test_store};
use fake_vault::FakeVault;
use std::sync::Arc;

struct Out {
    status: Status,
    out: String,
    err: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(self) -> Self {
        assert!(self.status.ok, "out: {}\nerr: {}", self.out, self.err);
        self
    }

    /// Exit `exit`, JSON error `code`, and the standard stderr line.
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.status.exit_code(),
            exit,
            "out: {}\nerr: {}",
            self.out,
            self.err
        );
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert_eq!(self.json()["ok"], false);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        self
    }

    fn message(&self) -> String {
        self.json()["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

/// A private state directory and keyring for the current thread.
struct Ctx {
    dir: tempfile::TempDir,
    store: Arc<MemStore>,
}

impl Ctx {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        TEST_STATE_DIR.with(|d| *d.borrow_mut() = Some(dir.path().join("state")));
        let store = Arc::new(MemStore::default());
        set_test_store(Some(store.clone()));
        Self { dir, store }
    }

    fn no_keyring(&self) {
        set_test_store(Some(Arc::new(Unavailable)));
    }

    fn keyring(&self, key: &str) -> Option<String> {
        self.store.0.lock().unwrap().get(key).cloned()
    }

    fn index_path(&self) -> PathBuf {
        keystore_path_in(&self.dir.path().join("state"))
    }

    fn index(&self) -> String {
        fs::read_to_string(self.index_path()).unwrap()
    }

    fn write_legacy(&self, v: Value) {
        let p = self.index_path();
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, v.to_string()).unwrap();
    }

    fn vault_env(&self, vars: &[(&str, &str)]) {
        let mut m: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        m.entry("HOME".into())
            .or_insert_with(|| self.dir.path().display().to_string());
        TEST_VAULT_ENV.with(|e| *e.borrow_mut() = Some(m));
    }

    fn run(&self, stage: &str, args: &[&str]) -> Out {
        run(stage, args)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        TEST_STATE_DIR.with(|d| *d.borrow_mut() = None);
        TEST_VAULT_ENV.with(|e| *e.borrow_mut() = None);
        set_test_store(None);
    }
}

/// Runs one stage through the real dispatcher, with empty stdin.
fn run(stage: &str, args: &[&str]) -> Out {
    run_with_stdin(stage, args, b"")
}

/// Runs one stage through the real dispatcher with `input` on stdin.
fn run_with_stdin(stage: &str, args: &[&str], input: &[u8]) -> Out {
    let mut reg = crate::core::Registry::default();
    register(&mut reg);
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut i, mut o, mut e) = (std::io::Cursor::new(input.to_vec()), Vec::new(), Vec::new());
    let status = crate::core::dispatch_stage(&mut reg, stage, &args, &mut i, &mut o, &mut e)
        .expect("dispatch");
    Out {
        status,
        out: String::from_utf8(o).unwrap(),
        err: String::from_utf8(e).unwrap(),
    }
}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// --- local: keyring + index -------------------------------------------------

#[test]
fn local_set_get_ls_rm_keep_values_in_the_keyring_only() {
    let c = Ctx::new();
    let o = c
        .run(
            "secret://local/app/db_password.set",
            &["value=s3cr3t-value"],
        )
        .ok();
    assert_eq!(
        o.json(),
        json!({"backend": "local", "key": "app/db_password", "scope": "local",
               "set": true, "source": "literal"})
    );
    assert_eq!(
        c.keyring("app/db_password").as_deref(),
        Some("s3cr3t-value")
    );
    let index = c.index();
    assert!(!index.contains("s3cr3t-value"), "{index}");
    assert!(
        index.contains("keyring:resh-secret/app/db_password"),
        "{index}"
    );
    assert_eq!(mode_of(&c.index_path()), 0o600);
    assert_eq!(mode_of(c.index_path().parent().unwrap()), 0o700);

    c.run("secret://local/app/api_key.set", &["value=k"]).ok();
    c.run("secret://local/other.set", &["value=o"]).ok();

    let o = c.run("secret://local/app/db_password.get", &[]).ok();
    assert_eq!(
        o.json(),
        json!({"backend": "local", "exists": true, "key": "app/db_password",
               "scope": "local", "value": "s3cr3t-value"})
    );
    let o = c
        .run("secret://local/app/db_password.get", &["redact=true"])
        .ok();
    assert_eq!(o.json()["value"], Value::Null);
    assert_eq!(o.json()["redacted"], true);
    assert!(!o.out.contains("s3cr3t"));

    let o = c.run("secret://local/app.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!(["app/api_key", "app/db_password"]));
    assert_eq!(o.json()["prefix"], "app");
    assert!(!o.out.contains("s3cr3t"));
    let o = c.run("secret://local/.ls", &[]).ok();
    assert_eq!(
        o.json()["keys"],
        json!(["app/api_key", "app/db_password", "other"])
    );
    // A prefix matches whole segments only.
    let o = c.run("secret://local/ap.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!([]));

    let o = c.run("secret://local/app/db_password.rm", &[]).ok();
    assert_eq!(o.json()["removed"], true);
    assert_eq!(c.keyring("app/db_password"), None);
    assert!(!c.index().contains("app/db_password"));
    let o = c.run("secret://local/app/db_password.rm", &[]).ok();
    assert_eq!(o.json()["removed"], false);
    let o = c.run("secret://local/app/db_password.get", &[]).ok();
    assert_eq!(
        o.json(),
        json!({"backend": "local", "exists": false, "key": "app/db_password",
               "scope": "local", "value": null})
    );
}

#[test]
fn set_from_stdin_reads_all_input_and_drops_one_newline() {
    let c = Ctx::new();
    let set = |input: &[u8]| run_with_stdin("secret://local/k.set", &["from_stdin=true"], input);
    let o = set(b"pa ss\n").ok();
    assert_eq!(o.json()["source"], "stdin");
    assert_eq!(c.keyring("k").as_deref(), Some("pa ss"));
    set(b"two\n\n").ok();
    assert_eq!(c.keyring("k").as_deref(), Some("two\n"));
    set(b"crlf\r\n").ok();
    assert_eq!(c.keyring("k").as_deref(), Some("crlf"));
    set(b"multi\nline").ok();
    assert_eq!(c.keyring("k").as_deref(), Some("multi\nline"));
    set(b" spaced ").ok();
    assert_eq!(c.keyring("k").as_deref(), Some(" spaced "));
    for empty in [&b""[..], b"\n", b"\r\n"] {
        set(empty).fails(2, "secret.missing_value");
    }
    set(b"\xff\xfe").fails(2, "secret.invalid_argument");
    assert_eq!(c.keyring("k").as_deref(), Some(" spaced "));
    // from_stdin=false is no source at all.
    run_with_stdin("secret://local/k.set", &["from_stdin=false"], b"x")
        .fails(2, "secret.missing_value");
    run_with_stdin("secret://local/k.set", &["from_stdin=maybe"], b"x")
        .fails(2, "secret.invalid_argument");
    for other in ["value=v", "from_env=PATH"] {
        run_with_stdin("secret://local/k.set", &["from_stdin=true", other], b"x")
            .fails(2, "secret.invalid_argument");
    }
    assert_eq!(c.keyring("k").as_deref(), Some(" spaced "));
}

#[test]
fn set_overwrites_and_from_env_reads_the_process_environment() {
    let c = Ctx::new();
    c.run("secret://local/k.set", &["value=one"]).ok();
    c.run("secret://local/k.set", &["value=two"]).ok();
    assert_eq!(c.keyring("k").as_deref(), Some("two"));
    // PATH is set in every test environment.
    let path = std::env::var("PATH").unwrap();
    let o = c.run("secret://local/k.set", &["from_env=PATH"]).ok();
    assert_eq!(o.json()["source"], "env");
    assert_eq!(c.keyring("k"), Some(path));
}

#[test]
fn without_a_keyring_writes_are_refused_and_nothing_is_written() {
    let c = Ctx::new();
    c.no_keyring();
    let o = c
        .run("secret://local/k.set", &["value=v"])
        .fails(1, "secret.keyring_unavailable");
    assert!(
        o.message().contains("nothing was changed"),
        "{}",
        o.message()
    );
    assert!(!c.index_path().exists());
    c.run("secret://local/k.get", &[])
        .fails(1, "secret.keyring_unavailable");
    c.run("secret://local/k.rm", &[])
        .fails(1, "secret.keyring_unavailable");
    c.run("secret://local/k.rotate", &[])
        .fails(1, "secret.keyring_unavailable");
    // ls needs only the index.
    c.run("secret://local/.ls", &[]).ok();
}

#[test]
fn legacy_plaintext_store_is_read_with_a_warning_and_migrated_on_write() {
    let c = Ctx::new();
    c.write_legacy(json!({"app/a": "va", "app/b": "vb"}));

    let o = c.run("secret://local/app/a.get", &[]).ok();
    assert_eq!(o.json()["value"], "va");
    assert!(
        o.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("plaintext")
    );
    assert!(o.err.starts_with("Warning: "), "{}", o.err);
    let o = c.run("secret://local/app.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!(["app/a", "app/b"]));
    assert!(o.json()["warnings"].is_array());

    // Any write moves every value into the keyring; the file keeps only
    // references.
    let o = c.run("secret://local/app/c.set", &["value=vc"]).ok();
    assert!(
        o.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("moved 2")
    );
    for (k, v) in [("app/a", "va"), ("app/b", "vb"), ("app/c", "vc")] {
        assert_eq!(c.keyring(k).as_deref(), Some(v));
    }
    let index = c.index();
    for v in ["va", "vb", "vc"] {
        assert!(!index.contains(&format!("\"{v}\"")), "{index}");
    }
    assert_eq!(mode_of(&c.index_path()), 0o600);
    let o = c.run("secret://local/app/a.get", &[]).ok();
    assert_eq!(o.json()["value"], "va");
    assert!(o.json().get("warnings").is_none(), "{}", o.out);
}

#[test]
fn legacy_rm_migrates_the_rest_and_drops_the_key() {
    let c = Ctx::new();
    c.write_legacy(json!({"a": "1", "b": "2"}));
    let o = c.run("secret://local/a.rm", &[]).ok();
    assert_eq!(o.json()["removed"], true);
    assert_eq!(c.keyring("a"), None);
    assert_eq!(c.keyring("b").as_deref(), Some("2"));
    let o = c.run("secret://local/.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!(["b"]));
}

#[test]
fn legacy_store_without_a_keyring_stays_readable_and_unchanged() {
    let c = Ctx::new();
    c.write_legacy(json!({"a": "1"}));
    c.no_keyring();
    let before = c.index();
    let o = c.run("secret://local/a.get", &[]).ok();
    assert_eq!(o.json()["value"], "1");
    c.run("secret://local/b.set", &["value=2"])
        .fails(1, "secret.keyring_unavailable");
    c.run("secret://local/a.rm", &[])
        .fails(1, "secret.keyring_unavailable");
    assert_eq!(c.index(), before);
}

#[test]
fn index_entry_missing_from_the_keyring_is_reported() {
    let c = Ctx::new();
    c.run("secret://local/k.set", &["value=v"]).ok();
    c.store.0.lock().unwrap().clear();
    let o = c.run("secret://local/k.get", &[]).ok();
    assert_eq!(o.json()["exists"], false);
    assert!(
        o.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("missing")
    );
    let o = c.run("secret://local/k.rm", &[]).ok();
    assert_eq!(o.json()["removed"], true);
    assert!(!c.index().contains("\"k\""));
}

#[test]
fn unreadable_or_unknown_index_is_a_store_error() {
    let c = Ctx::new();
    c.write_legacy(json!(["not", "an", "object"]));
    c.run("secret://local/k.get", &[])
        .fails(1, "secret.store_error");
    c.write_legacy(json!({"a": 1}));
    c.run("secret://local/.ls", &[])
        .fails(1, "secret.store_error");
    c.write_legacy(json!({"version": 3, "keys": {}}));
    let o = c
        .run("secret://local/k.set", &["value=v"])
        .fails(1, "secret.store_error");
    assert!(o.message().contains("version 3"), "{}", o.message());
    fs::write(c.index_path(), "{not json").unwrap();
    c.run("secret://local/.ls", &[])
        .fails(1, "secret.store_error");
}

#[test]
fn index_writes_refuse_a_planted_symlink() {
    let c = Ctx::new();
    let target = c.dir.path().join("elsewhere");
    fs::write(&target, "x").unwrap();
    let p = c.index_path();
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    c.run("secret://local/k.set", &["value=v"])
        .fails(1, "secret.store_error");
    assert_eq!(fs::read_to_string(&target).unwrap(), "x");
}

#[test]
fn a_world_readable_directory_is_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let c = Ctx::new();
    let dir = c.index_path().parent().unwrap().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    c.run("secret://local/k.set", &["value=v"]).ok();
    assert_eq!(mode_of(&dir), 0o700);
}

#[test]
fn a_held_lock_times_out_with_exit_124() {
    use std::os::unix::io::AsRawFd;
    let c = Ctx::new();
    c.run("secret://local/k.set", &["value=v"]).ok();
    let lock = fs::File::open(c.index_path().parent().unwrap().join("local.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let start = Instant::now();
    c.run("secret://local/k.set", &["value=w", "timeout_ms=150"])
        .fails(124, "secret.timeout");
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(c.keyring("k").as_deref(), Some("v"));
    // Reads do not take the lock.
    c.run("secret://local/k.get", &["timeout_ms=150"]).ok();
    drop(lock);
    c.run("secret://local/k.set", &["value=w", "timeout_ms=1000"])
        .ok();
}

#[test]
fn no_state_directory_means_no_fallback_location() {
    let p = keystore_path_in(Path::new("/state"));
    assert_eq!(p, PathBuf::from("/state/resh/secrets/local.json"));
    let src = include_str!("secreth.rs");
    assert!(!src.contains("\"/tmp"), "no /tmp fallback");
}

// --- arguments and errors ---------------------------------------------------

#[test]
fn strict_arguments_and_usage_errors() {
    let c = Ctx::new();
    let o = c
        .run("secret://local/k.get", &["redcat=true"])
        .fails(2, "secret.invalid_argument");
    assert!(
        o.message().contains("did you mean \"redact\"?"),
        "{}",
        o.message()
    );
    let o = c
        .run("secret://local/k.set", &["valeu=x"])
        .fails(2, "secret.invalid_argument");
    assert!(
        o.message().contains("did you mean \"value\"?"),
        "{}",
        o.message()
    );
    c.run("secret://local/k.rm", &["force=true"])
        .fails(2, "secret.invalid_argument");
    // Vault-only options are refused for local; timeout_ms for env.
    c.run("secret://local/k.get", &["mount=kv"])
        .fails(2, "secret.invalid_argument");
    c.run("secret://env/PATH.get", &["timeout_ms=10"])
        .fails(2, "secret.invalid_argument");
    c.run("secret://local/k.get", &["redact=maybe"])
        .fails(2, "secret.invalid_argument");
    for t in ["0", "-1", "abc", "86400001"] {
        c.run("secret://local/k.get", &[&format!("timeout_ms={t}")])
            .fails(2, "secret.invalid_argument");
    }

    c.run("secret://local/.get", &[])
        .fails(2, "secret.missing_key");
    c.run("secret://local/.set", &["value=v"])
        .fails(2, "secret.missing_key");
    c.run("secret://local/.rotate", &[])
        .fails(2, "secret.missing_key");
    for bad in ["a//b.get", "a/.get", "%2Fa.get", "a%2F%2Fb.get"] {
        c.run(&format!("secret://local/{bad}"), &[])
            .fails(2, "secret.invalid_key");
    }
    // The URL parser resolves literal dot segments before the handle sees
    // the key; the handle refuses any that remain.
    for bad in ["a/../b", "a/./b", "..", "x/..", "a\u{1}b"] {
        assert_eq!(
            check_key("vault", "get", bad).unwrap_err().code,
            "secret.invalid_key",
            "{bad}"
        );
    }
    assert!(check_key("local", "get", "app/v1.2/token").is_ok());
    c.run("secret://env/A=B.get", &[])
        .fails(2, "secret.invalid_key");

    c.run("secret://local/k.set", &[])
        .fails(2, "secret.missing_value");
    c.run("secret://local/k.set", &["value="])
        .fails(2, "secret.missing_value");
    c.run("secret://local/k.set", &["value=a", "from_env=PATH"])
        .fails(2, "secret.invalid_argument");
    c.run(
        "secret://local/k.set",
        &["from_env=RESH_SECRET_TEST_SURELY_UNSET_VAR"],
    )
    .fails(1, "secret.env_not_set");
    c.run("secret://local/k.set", &["from_env="])
        .fails(2, "secret.invalid_argument");
    assert!(c.keyring("k").is_none());
    assert!(!c.index_path().exists());

    let o = c
        .run("secret://local/k.gte", &[])
        .fails(2, "secret.unknown_verb");
    assert!(
        o.message().contains("did you mean \"get\"?"),
        "{}",
        o.message()
    );

    // dry_run is refused by the dispatcher (no verb has a dry-run mode).
    let o = run("secret://local/k.set", &["value=v", "dry_run=true"]);
    assert_eq!(o.status.exit_code(), 2);
    assert!(c.keyring("k").is_none());
}

#[test]
fn unknown_scope_is_an_invalid_target() {
    let o = run("secret://disk/k.get", &[]);
    assert_eq!(o.status.exit_code(), 2);
    assert!(
        o.status
            .reason
            .unwrap()
            .starts_with("[secret.invalid_target] unsupported scope 'disk'")
    );
}

// --- env --------------------------------------------------------------------

#[test]
fn env_scope_is_read_only() {
    let c = Ctx::new();
    let path = std::env::var("PATH").unwrap();
    let o = c.run("secret://env/PATH.get", &[]).ok();
    assert_eq!(o.json()["value"], path);
    assert_eq!(o.json()["backend"], "env");
    let o = c.run("secret://env/PATH.get", &["redact=yes"]).ok();
    assert_eq!(o.json()["value"], Value::Null);
    let o = c
        .run("secret://env/RESH_SECRET_TEST_SURELY_UNSET_VAR.get", &[])
        .ok();
    assert_eq!(o.json()["exists"], false);
    let o = c.run("secret://env/PATH.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!(["PATH"]));
    let o = c.run("secret://env/.ls", &[]).ok();
    assert!(o.json()["keys"].as_array().unwrap().len() > 1);
    assert!(!o.out.contains(&path), "ls prints names only");

    c.run("secret://env/X.set", &["value=v"])
        .fails(2, "secret.read_only");
    // Read-only is reported before the missing value.
    c.run("secret://env/X.set", &[])
        .fails(2, "secret.read_only");
    c.run("secret://env/X.rm", &[]).fails(2, "secret.read_only");
    c.run("secret://env/X.rotate", &[])
        .fails(2, "secret.read_only");
}

// --- rotate -------------------------------------------------------------------

#[test]
fn rotate_generates_stores_and_never_prints_the_value() {
    let c = Ctx::new();
    let o = c.run("secret://local/app/api_key.rotate", &[]).ok();
    assert_eq!(
        o.json(),
        json!({"backend": "local", "encoding": "hex", "existed": false,
               "key": "app/api_key", "length": 256, "rotated": true,
               "scope": "local", "strategy": "random"})
    );
    let first = c.keyring("app/api_key").unwrap();
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!o.out.contains(&first));

    let o = c
        .run(
            "secret://local/app/api_key.rotate",
            &["length=512", "encoding=base64url"],
        )
        .ok();
    assert_eq!(o.json()["existed"], true);
    let second = c.keyring("app/api_key").unwrap();
    assert_ne!(first, second);
    assert_eq!(second.len(), 86); // 64 bytes, unpadded base64url
    assert!(!second.contains('=') && !second.contains('+') && !second.contains('/'));

    c.run("secret://local/k.rotate", &["encoding=base64", "length=64"])
        .ok();
    assert_eq!(c.keyring("k").unwrap().len(), 12);

    c.run("secret://local/aes.rotate", &["strategy=aes", "length=128"])
        .ok();
    assert_eq!(c.keyring("aes").unwrap().len(), 32);

    // expose_value=true prints the new value once, in the result.
    let o = c
        .run("secret://local/k.rotate", &["expose_value=true"])
        .ok();
    let exposed = o.json()["value"].as_str().unwrap().to_string();
    assert_eq!(c.keyring("k").as_deref(), Some(exposed.as_str()));
    assert_eq!(exposed.len(), 64);
    let o = c
        .run("secret://local/k.rotate", &["expose_value=false"])
        .ok();
    assert!(o.json().get("value").is_none());
    c.run("secret://local/k.rotate", &["expose_value=sure"])
        .fails(2, "secret.invalid_argument");

    let o = c.run("secret://local/id.rotate", &["strategy=uuid"]).ok();
    assert_eq!(o.json()["length"], 128);
    assert!(o.json().get("encoding").is_none());
    let id = c.keyring("id").unwrap();
    assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 4);

    let o = c.run("secret://local/.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!(["aes", "app/api_key", "id", "k"]));
}

#[test]
fn rotate_rsa_stores_a_private_key_and_prints_the_public_key() {
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    let c = Ctx::new();
    let o = c
        .run(
            "secret://local/tls/key.rotate",
            &["strategy=rsa", "length=2048"],
        )
        .ok();
    let pem = c.keyring("tls/key").unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let public = o.json()["public_key"].as_str().unwrap().to_string();
    assert_eq!(
        rsa::RsaPublicKey::from_public_key_pem(&public).unwrap(),
        key.to_public_key()
    );
    assert!(!o.out.contains("PRIVATE"));
    assert_eq!(o.json()["length"], 2048);
    let o = c
        .run(
            "secret://local/tls/key.rotate",
            &["strategy=rsa", "length=2048", "expose_value=true"],
        )
        .ok();
    assert_eq!(o.json()["value"].as_str(), c.keyring("tls/key").as_deref());
}

#[test]
fn rotate_rejects_bad_options_before_doing_anything() {
    let c = Ctx::new();
    for args in [
        &["strategy=dsa"][..],
        &["length=100"],
        &["length=56"],
        &["length=abc"],
        &["strategy=aes", "length=512"],
        &["strategy=uuid", "length=128"],
        &["strategy=uuid", "encoding=hex"],
        &["strategy=rsa", "length=1024"],
        &["strategy=rsa", "encoding=hex"],
        &["encoding=base32"],
    ] {
        c.run("secret://local/k.rotate", args)
            .fails(2, "secret.invalid_argument");
    }
    assert!(c.keyring("k").is_none());
}

#[test]
fn rotate_rsa_honours_timeout_ms() {
    let c = Ctx::new();
    c.run(
        "secret://local/k.rotate",
        &["strategy=rsa", "length=4096", "timeout_ms=1"],
    )
    .fails(124, "secret.timeout");
    assert!(c.keyring("k").is_none());
}

#[test]
fn rotate_spec_defaults() {
    let spec = |a: &[(&str, &str)]| {
        let args: Args = a
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        RotateSpec::from_args(&args).unwrap()
    };
    assert_eq!(
        spec(&[]),
        RotateSpec {
            strategy: Strategy::Random,
            length: 256,
            encoding: Some(Encoding::Hex)
        }
    );
    assert_eq!(spec(&[("strategy", "aes")]).length, 256);
    assert_eq!(spec(&[("strategy", "rsa")]).length, 3072);
}

// --- vault ------------------------------------------------------------------

fn vault_ctx(fake: &FakeVault) -> Ctx {
    let c = Ctx::new();
    c.vault_env(&[("VAULT_ADDR", fake.addr()), ("VAULT_TOKEN", "root-token")]);
    c
}

#[test]
fn vault_set_get_ls_rm_rotate() {
    let fake = FakeVault::start("root-token", "secret");
    let c = vault_ctx(&fake);
    let o = c
        .run("secret://vault/app/db_password.set", &["value=pw"])
        .ok();
    assert_eq!(o.json()["backend"], "vault");
    assert_eq!(fake.secret("app/db_password").unwrap()["value"], "pw");

    let o = c.run("secret://vault/app/db_password.get", &[]).ok();
    assert_eq!(o.json()["value"], "pw");
    assert_eq!(o.json()["exists"], true);
    let o = c
        .run("secret://vault/app/db_password.get", &["redact=true"])
        .ok();
    assert_eq!(o.json()["value"], Value::Null);
    let o = c.run("secret://vault/app/none.get", &[]).ok();
    assert_eq!(o.json()["exists"], false);

    c.run("secret://vault/app/nested/deep.set", &["value=x"])
        .ok();
    c.run("secret://vault/app.set", &["value=y"]).ok();
    c.run("secret://vault/zzz.set", &["value=z"]).ok();
    let o = c.run("secret://vault/app.ls", &[]).ok();
    assert_eq!(
        o.json()["keys"],
        json!(["app", "app/db_password", "app/nested/deep"])
    );
    let o = c.run("secret://vault/.ls", &[]).ok();
    assert_eq!(o.json()["keys"].as_array().unwrap().len(), 4);
    let o = c.run("secret://vault/nothing.ls", &[]).ok();
    assert_eq!(o.json()["keys"], json!([]));

    let o = c.run("secret://vault/app/db_password.rotate", &[]).ok();
    assert_eq!(o.json()["existed"], true);
    let new = fake.secret("app/db_password").unwrap()["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(new.len(), 64);
    assert!(!o.out.contains(&new));

    // rm soft-deletes the latest version: the data and metadata stay.
    let version = fake.version("app/db_password").unwrap();
    let o = c.run("secret://vault/app/db_password.rm", &[]).ok();
    assert_eq!(o.json()["removed"], true);
    assert_eq!(o.json()["deleted"], "latest_version");
    assert_eq!(o.json()["version"], version);
    assert!(fake.is_soft_deleted("app/db_password"));
    assert!(fake.secret("app/db_password").is_some());
    let o = c.run("secret://vault/app/db_password.get", &[]).ok();
    assert_eq!(o.json()["exists"], false);
    // Again: nothing current to delete; a warning points at destroy=true.
    let o = c.run("secret://vault/app/db_password.rm", &[]).ok();
    assert_eq!(o.json()["removed"], false);
    assert_eq!(o.json()["deleted"], Value::Null);
    assert!(
        o.json()["warnings"][0]
            .as_str()
            .unwrap()
            .contains("destroy=true")
    );
    // set after a soft delete writes a new version.
    c.run("secret://vault/app/db_password.set", &["value=again"])
        .ok();
    assert!(!fake.is_soft_deleted("app/db_password"));
    assert_eq!(fake.version("app/db_password"), Some(version + 1));

    // destroy=true removes every version and the metadata.
    let o = c
        .run("secret://vault/app/db_password.rm", &["destroy=true"])
        .ok();
    assert_eq!(o.json()["removed"], true);
    assert_eq!(o.json()["deleted"], "all_versions");
    assert!(o.json().get("version").is_none());
    assert!(fake.secret("app/db_password").is_none());
    let o = c
        .run("secret://vault/app/db_password.rm", &["destroy=true"])
        .ok();
    assert_eq!(o.json()["removed"], false);
    c.run("secret://vault/x.rm", &["destroy=maybe"])
        .fails(2, "secret.invalid_argument");
    // destroy is a vault option only.
    c.run("secret://local/x.rm", &["destroy=true"])
        .fails(2, "secret.invalid_argument");
}

#[test]
fn vault_fields_and_mounts() {
    let fake = FakeVault::start("root-token", "kv/team");
    let c = vault_ctx(&fake);
    fake.put("db", json!({"username": "app", "password": "old"}));
    // set changes one field and keeps the others.
    c.run(
        "secret://vault/db.set",
        &["value=new", "field=password", "mount=kv/team"],
    )
    .ok();
    assert_eq!(
        Value::Object(fake.secret("db").unwrap()),
        json!({"username": "app", "password": "new"})
    );
    let o = c
        .run(
            "secret://vault/db.get",
            &["field=username", "mount=/kv/team/"],
        )
        .ok();
    assert_eq!(o.json()["value"], "app");
    let o = c
        .run("secret://vault/db.get", &["mount=kv/team"])
        .fails(1, "secret.vault_field_missing");
    assert!(
        o.message().contains("password, username"),
        "{}",
        o.message()
    );
    // The default mount does not exist on this server: an unknown route is
    // an error, not a missing secret.
    c.run("secret://vault/db.get", &[])
        .fails(1, "secret.vault_error");
    c.run("secret://vault/db.get", &["mount=../sys"])
        .fails(2, "secret.invalid_argument");
    c.run("secret://vault/db.get", &["field="])
        .fails(2, "secret.invalid_argument");
    // Key segments are percent-encoded, never interpreted as a path.
    c.run("secret://vault/a%3Fb.set", &["value=q", "mount=kv/team"])
        .ok();
    assert_eq!(fake.secret("a?b").unwrap()["value"], "q");
}

#[test]
fn vault_configuration_and_access_errors() {
    let fake = FakeVault::start("root-token", "secret");
    let c = Ctx::new();
    c.vault_env(&[]);
    c.run("secret://vault/k.get", &[])
        .fails(2, "secret.vault_not_configured");
    c.vault_env(&[("VAULT_ADDR", "ftp://x")]);
    c.run("secret://vault/k.get", &[])
        .fails(2, "secret.vault_not_configured");
    c.vault_env(&[("VAULT_ADDR", fake.addr())]);
    let o = c
        .run("secret://vault/k.get", &[])
        .fails(2, "secret.vault_not_configured");
    assert!(o.message().contains("VAULT_TOKEN"));
    // ~/.vault-token is used when VAULT_TOKEN is unset.
    fs::write(c.dir.path().join(".vault-token"), "root-token\n").unwrap();
    c.run("secret://vault/k.set", &["value=v"]).ok();

    c.vault_env(&[("VAULT_ADDR", fake.addr()), ("VAULT_TOKEN", "wrong")]);
    c.run("secret://vault/k.get", &[])
        .fails(1, "secret.vault_denied");

    c.vault_env(&[("VAULT_ADDR", "http://127.0.0.1:1"), ("VAULT_TOKEN", "t")]);
    c.run("secret://vault/k.get", &[])
        .fails(1, "secret.vault_error");

    c.vault_env(&[("VAULT_ADDR", fake.addr()), ("VAULT_TOKEN", "root-token")]);
    c.run("secret://vault/k.get", &["ca_file=/nonexistent/ca.pem"])
        .fails(2, "secret.invalid_argument");
    let not_pem = c.dir.path().join("not.pem");
    fs::write(&not_pem, "hello").unwrap();
    c.run(
        "secret://vault/k.get",
        &[&format!("ca_file={}", not_pem.display())],
    )
    .fails(2, "secret.invalid_argument");
}

#[test]
fn vault_timeout_is_exit_124() {
    let fake = FakeVault::start("root-token", "secret");
    let c = vault_ctx(&fake);
    fake.set_delay(Some(Duration::from_millis(1500)));
    let start = Instant::now();
    c.run("secret://vault/k.get", &["timeout_ms=200"])
        .fails(124, "secret.timeout");
    assert!(start.elapsed() < Duration::from_millis(1400));
}

#[test]
fn vault_namespace_header_is_sent() {
    let fake = FakeVault::start("root-token", "secret");
    let c = Ctx::new();
    c.vault_env(&[
        ("VAULT_ADDR", fake.addr()),
        ("VAULT_TOKEN", "root-token"),
        ("VAULT_NAMESPACE", "team-a"),
    ]);
    c.run("secret://vault/k.get", &[]).ok();
    let log = fake.log();
    assert!(!log.is_empty());
    assert!(log.iter().all(|l| l.ends_with(" ns=team-a")), "{log:?}");
}

// --- help -------------------------------------------------------------------

#[test]
fn help_text_does_not_claim_encryption_or_unimplemented_verbs() {
    let text = help::render_legacy(
        "secret",
        &SECRET_HELP,
        &["get", "set", "rm", "ls", "rotate"],
        None,
    );
    assert!(text.starts_with("Handle: secret"));
    assert!(!text.to_lowercase().contains("encrypted"));
    assert!(!text.to_lowercase().contains("not implemented"));
    assert!(!text.contains("plain JSON"));
}

#[test]
fn every_error_code_is_documented() {
    let doc = include_str!("../../../docs/Security_Secrets/secret.md");
    for code in ERROR_CODES {
        assert!(doc.contains(code), "{code} missing from secret.md");
        assert!(crate::core::status::is_valid_error_code(code));
    }
}

#[test]
fn in_url_help_forms_are_exact() {
    let handle = |u: &str| SecretHandle::from_url(&Url::parse(u).unwrap()).unwrap();
    assert!(handle("secret://--help").is_help_request);
    assert!(handle("secret://-h").is_help_request);
    assert!(handle("secret:///--help").is_help_request);
    assert!(handle("secret://local/app/key.--help").is_help_request);
    let h = handle("secret://local/x?help=get");
    assert!(h.is_help_request);
    assert_eq!(h.help_verb.as_deref(), Some("get"));

    let h = handle("secret://local/my-hosts");
    assert!(!h.is_help_request);
    assert_eq!(h.key_path, "my-hosts");
    assert!(!handle("secret://local/pre-hotfix/token").is_help_request);
    let h = handle("secret:///local/a/b");
    assert_eq!((h.scope.as_str(), h.key_path.as_str()), ("local", "a/b"));
}

#[test]
fn in_url_help_renders_approved_help() {
    let o = run("secret://--help", &[]);
    assert!(o.status.ok);
    assert!(o.out.starts_with("Handle: secret"), "{}", o.out);
    let o = run("secret://local/x.--help", &[]);
    assert!(o.out.starts_with("Handle: secret"), "{}", o.out);
}
