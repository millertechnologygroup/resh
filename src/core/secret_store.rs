//! The OS keyring (Secret Service on Linux, Keychain on macOS) through the
//! `keyring` crate: where resh keeps the secrets it stores (mail profile
//! passwords, `secret://local` values). Files keep only a reference; a
//! secret is never written to a file.
//!
//! The store sits behind [`SecretStore`] so tests can use an in-memory
//! store (unit tests) or, in debug builds only, a file store selected with
//! `RESH_TEST_KEYRING=file:<path>` (binary tests); `RESH_TEST_KEYRING=unavailable`
//! simulates a host without a keyring. Release builds ignore the variable.

use std::sync::Arc;
use std::time::Duration;

/// How long a keyring operation may take by default (a locked keyring can
/// wait for an unlock prompt).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A place to keep secrets by account name, within one keyring service.
pub trait SecretStore: Send + Sync {
    /// Stores (or replaces) the secret for `account`.
    fn set(&self, account: &str, secret: &str) -> Result<(), String>;
    /// The secret for `account`, or `None` if there is none.
    fn get(&self, account: &str) -> Result<Option<String>, String>;
    /// Removes the secret for `account`; removing a missing one is fine.
    fn delete(&self, account: &str) -> Result<(), String>;
}

/// The OS keyring, for one service name.
struct OsKeyring {
    service: &'static str,
    timeout: Duration,
}

/// Runs a keyring call with a tokio runtime driving zbus (secret-service
/// uses zbus with the tokio executor), within `timeout`.
fn with_keyring<T: Send + 'static>(
    timeout: Duration,
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
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err(format!(
            "the OS keyring did not answer within {} ms (is it locked?)",
            timeout.as_millis()
        )),
    }
}

impl OsKeyring {
    fn entry(service: &'static str, account: &str) -> Result<keyring::Entry, keyring::Error> {
        keyring::Entry::new(service, account)
    }
}

impl SecretStore for OsKeyring {
    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        let (service, account, secret) = (self.service, account.to_string(), secret.to_string());
        with_keyring(self.timeout, move || {
            Self::entry(service, &account)?.set_password(&secret)
        })?
        .map_err(|e| format!("the OS keyring refused to store it: {e}"))
    }

    fn get(&self, account: &str) -> Result<Option<String>, String> {
        let (service, account) = (self.service, account.to_string());
        match with_keyring(self.timeout, move || {
            Self::entry(service, &account)?.get_password()
        })? {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("cannot read the OS keyring: {e}")),
        }
    }

    fn delete(&self, account: &str) -> Result<(), String> {
        let (service, account) = (self.service, account.to_string());
        match with_keyring(self.timeout, move || {
            Self::entry(service, &account)?.delete_password()
        })? {
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

/// A JSON file of secrets, for binary tests in debug builds only. Entries
/// are keyed `<service>/<account>`.
#[cfg(debug_assertions)]
struct FileStore {
    path: std::path::PathBuf,
    service: &'static str,
}

#[cfg(debug_assertions)]
impl FileStore {
    fn load(&self) -> Result<std::collections::BTreeMap<String, String>, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn save(&self, map: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
        let text = serde_json::to_string(map).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, text).map_err(|e| e.to_string())
    }

    fn key(&self, account: &str) -> String {
        format!("{}/{account}", self.service)
    }
}

#[cfg(debug_assertions)]
impl SecretStore for FileStore {
    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        let mut m = self.load()?;
        m.insert(self.key(account), secret.into());
        self.save(&m)
    }
    fn get(&self, account: &str) -> Result<Option<String>, String> {
        Ok(self.load()?.get(&self.key(account)).cloned())
    }
    fn delete(&self, account: &str) -> Result<(), String> {
        let mut m = self.load()?;
        m.remove(&self.key(account));
        self.save(&m)
    }
}

/// An in-memory store for unit tests (keyed by account; one store is
/// installed per test thread, whatever the service).
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
    static TEST_STORE: std::cell::RefCell<Option<Arc<dyn SecretStore>>> =
        const { std::cell::RefCell::new(None) };
}

/// Replaces the store for the current thread (unit tests).
#[cfg(test)]
pub fn set_test_store(store: Option<Arc<dyn SecretStore>>) {
    TEST_STORE.with(|s| *s.borrow_mut() = store);
}

/// The secret store for `service`, with [`DEFAULT_TIMEOUT`].
pub fn store(service: &'static str) -> Arc<dyn SecretStore> {
    store_with_timeout(service, DEFAULT_TIMEOUT)
}

/// The secret store for `service`; each OS keyring call may take at most
/// `timeout`.
pub fn store_with_timeout(service: &'static str, timeout: Duration) -> Arc<dyn SecretStore> {
    #[cfg(test)]
    if let Some(s) = TEST_STORE.with(|s| s.borrow().clone()) {
        return s;
    }
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var("RESH_TEST_KEYRING") {
        if v == "unavailable" {
            return Arc::new(Unavailable);
        }
        if let Some(path) = v.strip_prefix("file:") {
            return Arc::new(FileStore {
                path: path.into(),
                service,
            });
        }
    }
    Arc::new(OsKeyring { service, timeout })
}
