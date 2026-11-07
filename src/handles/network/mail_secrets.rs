//! Where the mail handle keeps SMTP passwords of stored profiles: the OS
//! keyring (Secret Service on Linux, Keychain on macOS) through the
//! `keyring` crate. The profile file keeps only a reference
//! (`keyring:<service>/<profile>`); a password is never written to a file.
//!
//! The store sits behind [`SecretStore`] so tests can use an in-memory
//! store (unit tests) or, in debug builds only, a file store selected with
//! `RESH_TEST_KEYRING=file:<path>` (binary tests); `RESH_TEST_KEYRING=unavailable`
//! simulates a host without a keyring. Release builds ignore the variable.

use std::time::Duration;

/// The keyring service name under which profile passwords are stored; the
/// account is the profile name.
pub const SERVICE: &str = "resh-mail-smtp";

/// How long a keyring operation may take (a locked keyring can wait for an
/// unlock prompt).
const KEYRING_TIMEOUT: Duration = Duration::from_secs(10);

/// A place to keep secrets by account name.
pub trait SecretStore: Send + Sync {
    /// Stores (or replaces) the secret for `account`.
    fn set(&self, account: &str, secret: &str) -> Result<(), String>;
    /// The secret for `account`, or `None` if there is none.
    fn get(&self, account: &str) -> Result<Option<String>, String>;
    /// Removes the secret for `account`; removing a missing one is fine.
    fn delete(&self, account: &str) -> Result<(), String>;
}

/// The reference stored in the profile file for `account`.
pub fn reference(account: &str) -> String {
    format!("keyring:{SERVICE}/{account}")
}

/// The account named by a reference written by [`reference`].
pub fn account_of(reference: &str) -> Option<&str> {
    reference
        .strip_prefix("keyring:")?
        .strip_prefix(SERVICE)?
        .strip_prefix('/')
        .filter(|a| !a.is_empty())
}

/// The OS keyring.
struct OsKeyring;

/// Runs a keyring call with a tokio runtime driving zbus (secret-service
/// uses zbus with the tokio executor), within [`KEYRING_TIMEOUT`].
fn with_keyring<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, keyring::Error> + Send + 'static,
) -> Result<Result<T, keyring::Error>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the keyring client: {e}"))
            .and_then(|rt| {
                rt.block_on(async { tokio::task::spawn_blocking(f).await })
                    .map_err(|e| format!("the keyring client stopped: {e}"))
            });
        // The receiver is gone only when the caller already timed out.
        let _ = tx.send(result);
    });
    match rx.recv_timeout(KEYRING_TIMEOUT) {
        Ok(r) => r,
        Err(_) => Err(format!(
            "the OS keyring did not answer within {} s (is it locked?)",
            KEYRING_TIMEOUT.as_secs()
        )),
    }
}

fn entry(account: &str) -> Result<keyring::Entry, keyring::Error> {
    keyring::Entry::new(SERVICE, account)
}

impl SecretStore for OsKeyring {
    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        let (account, secret) = (account.to_string(), secret.to_string());
        with_keyring(move || entry(&account)?.set_password(&secret))?
            .map_err(|e| format!("the OS keyring refused to store it: {e}"))
    }

    fn get(&self, account: &str) -> Result<Option<String>, String> {
        let account = account.to_string();
        match with_keyring(move || entry(&account)?.get_password())? {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("cannot read the OS keyring: {e}")),
        }
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        let account = account.to_string();
        match with_keyring(move || entry(&account)?.delete_password())? {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("cannot remove it from the OS keyring: {e}")),
        }
    }
}

/// A store that is never available (tests: a host without a keyring).
#[cfg(any(test, debug_assertions))]
pub struct Unavailable;

#[cfg(any(test, debug_assertions))]
impl SecretStore for Unavailable {
    fn set(&self, _: &str, _: &str) -> Result<(), String> {
        Err("no OS keyring is available (test setting)".into())
    }
    fn get(&self, _: &str) -> Result<Option<String>, String> {
        Err("no OS keyring is available (test setting)".into())
    }
    fn delete(&self, _: &str) -> Result<(), String> {
        Err("no OS keyring is available (test setting)".into())
    }
}

/// A JSON file of secrets, for binary tests in debug builds only.
#[cfg(debug_assertions)]
struct FileStore(std::path::PathBuf);

#[cfg(debug_assertions)]
impl FileStore {
    fn load(&self) -> Result<std::collections::BTreeMap<String, String>, String> {
        match std::fs::read_to_string(&self.0) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn save(&self, map: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
        let text = serde_json::to_string(map).map_err(|e| e.to_string())?;
        std::fs::write(&self.0, text).map_err(|e| e.to_string())
    }
}

#[cfg(debug_assertions)]
impl SecretStore for FileStore {
    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        let mut m = self.load()?;
        m.insert(account.into(), secret.into());
        self.save(&m)
    }
    fn get(&self, account: &str) -> Result<Option<String>, String> {
        Ok(self.load()?.get(account).cloned())
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        let mut m = self.load()?;
        m.remove(account);
        self.save(&m)
    }
}

/// An in-memory store for unit tests.
#[cfg(test)]
#[derive(Default)]
pub struct MemStore(pub std::sync::Mutex<std::collections::BTreeMap<String, String>>);

#[cfg(test)]
impl SecretStore for MemStore {
    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(account.into(), secret.into());
        Ok(())
    }
    fn get(&self, account: &str) -> Result<Option<String>, String> {
        Ok(self.0.lock().unwrap().get(account).cloned())
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(account);
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static TEST_STORE: std::cell::RefCell<Option<std::sync::Arc<dyn SecretStore>>> =
        const { std::cell::RefCell::new(None) };
}

/// Replaces the store for the current thread (unit tests).
#[cfg(test)]
pub fn set_test_store(store: Option<std::sync::Arc<dyn SecretStore>>) {
    TEST_STORE.with(|s| *s.borrow_mut() = store);
}

/// The secret store to use.
pub fn store() -> std::sync::Arc<dyn SecretStore> {
    #[cfg(test)]
    if let Some(s) = TEST_STORE.with(|s| s.borrow().clone()) {
        return s;
    }
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("RESH_TEST_KEYRING") {
        if v == "unavailable" {
            return std::sync::Arc::new(Unavailable);
        }
        if let Some(path) = v.strip_prefix("file:") {
            return std::sync::Arc::new(FileStore(path.into()));
        }
    }
    std::sync::Arc::new(OsKeyring)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_round_trip() {
        assert_eq!(reference("work"), "keyring:resh-mail-smtp/work");
        assert_eq!(account_of(&reference("work")), Some("work"));
        assert_eq!(account_of("keyring:other/work"), None);
        assert_eq!(account_of("keyring:resh-mail-smtp/"), None);
        assert_eq!(account_of("cGFzcw=="), None);
    }
}
