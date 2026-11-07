//! Where the mail handle keeps SMTP passwords of stored profiles: the OS
//! keyring, through the shared [`crate::core::secret_store`]. The profile
//! file keeps only a reference (`keyring:<service>/<profile>`); a password
//! is never written to a file.

use std::sync::Arc;

use crate::core::secret_store::{self, SecretStore};
#[cfg(test)]
pub use crate::core::secret_store::{MemStore, Unavailable, set_test_store};

/// The keyring service name under which profile passwords are stored; the
/// account is the profile name.
pub const SERVICE: &str = "resh-mail-smtp";

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

/// The secret store for profile passwords.
pub fn store() -> Arc<dyn SecretStore> {
    secret_store::store(SERVICE)
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
