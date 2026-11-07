//! Remote operations for the git handle: the operation deadline, libgit2's
//! network timeouts, credentials, strict SSH host-key checking and push
//! results.
//!
//! # Deadline
//!
//! Each verb runs on a worker thread whose deadline is set with
//! [`set_deadline`]. Every remote callback checks it, so a transfer that is
//! still moving data stops at the deadline; libgit2's connect and read
//! timeouts are set from it, so a stalled HTTP or git:// server stops too.
//! An SSH server that stalls inside the SSH library cannot be interrupted;
//! the dispatcher then reports the outcome as unknown.
//!
//! # Host keys
//!
//! [`HostKeyPolicy`] decides on the URL libgit2 really connects to (after
//! `url.<base>.insteadOf` / `pushInsteadOf` rewriting), refuses before
//! connecting when the file does not list the host, makes the SSH library
//! prefer the key types listed in the file, and accepts the server only when
//! its key matches a listed, non-revoked key.

use super::GitError;
use super::known_hosts::{self, KnownHosts};
use git2::{CredentialType, RemoteCallbacks};
use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::os::raw::c_int;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Sets the deadline of the operation running on this thread.
pub fn set_deadline(deadline: Option<Instant>) {
    DEADLINE.with(|d| d.set(deadline));
}

/// The deadline of the operation running on this thread.
pub fn deadline() -> Option<Instant> {
    DEADLINE.with(|d| d.get())
}

/// True once this thread's deadline has passed.
pub fn expired() -> bool {
    deadline().is_some_and(|d| Instant::now() >= d)
}

/// Time left before this thread's deadline, if it has one.
pub fn remaining() -> Option<Duration> {
    deadline().map(|d| d.saturating_duration_since(Instant::now()))
}

// libgit2's home-directory option (include/git2/common.h, libgit2 1.9).
// git2 has no wrapper for it, so the C function is called directly; it is
// part of the libgit2 that git2 links in.
const GIT_OPT_SET_HOMEDIR: c_int = 38;

unsafe extern "C" {
    fn git_libgit2_opts(option: c_int, ...) -> c_int;
}

/// Makes sure libgit2 is initialized before its options are touched.
fn init_libgit2() {
    // Any git2 options call runs git2's one-time initialization; caching
    // is enabled by default, so this changes nothing else.
    git2::opts::enable_caching(true);
}

/// Added to the remaining time for libgit2's socket timeouts.
const SOCKET_TIMEOUT_MARGIN: Duration = Duration::from_millis(100);

/// Serializes changes to libgit2's process-wide timeout options.
static TIMEOUT_LOCK: Mutex<()> = Mutex::new(());

/// Sets libgit2's connect and read timeouts (process-wide) from this
/// thread's deadline, 0 (no limit) when there is none, before connecting to
/// `url`. Keep the returned guard until the remote operation has finished:
/// it stops another operation in this process from changing the setting
/// meanwhile. A local remote (file:// or a path) opens no socket and leaves
/// the setting alone.
#[must_use = "hold the guard for the whole remote operation"]
pub fn apply_server_timeouts(url: &str) -> Option<MutexGuard<'static, ()>> {
    if is_local_url(url) {
        return None;
    }
    let lock = TIMEOUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    set_server_timeouts();
    Some(lock)
}

/// True for a file:// URL or a local path (libgit2's local transport).
pub fn is_local_url(url: &str) -> bool {
    if let Some(idx) = url.find("://") {
        return url[..idx].eq_ignore_ascii_case("file");
    }
    known_hosts::ssh_endpoint(url).is_none()
}

fn set_server_timeouts() {
    init_libgit2();
    // A little past the deadline, so a stalled socket gives up only once the
    // deadline has passed and the failure is reported as the timeout.
    let ms = remaining().map_or(0, |r| {
        (r + SOCKET_TIMEOUT_MARGIN)
            .as_millis()
            .clamp(1, i32::MAX as u128) as c_int
    });
    // SAFETY: plain integer options; callers serialize through TIMEOUT_LOCK.
    unsafe {
        if let Err(e) = git2::opts::set_server_connect_timeout_in_milliseconds(ms) {
            log::warn!("cannot set the libgit2 connect timeout: {e}");
        }
        if let Err(e) = git2::opts::set_server_timeout_in_milliseconds(ms) {
            log::warn!("cannot set the libgit2 read timeout: {e}");
        }
    }
}

/// Applies this thread's deadline and reads the libgit2 connect and read
/// timeouts back, in milliseconds.
#[cfg(test)]
pub fn apply_and_read_server_timeouts() -> (i32, i32) {
    let _lock = TIMEOUT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    set_server_timeouts();
    // SAFETY: plain integer options, read under TIMEOUT_LOCK.
    unsafe {
        (
            git2::opts::get_server_connect_timeout_in_milliseconds().unwrap_or(-1),
            git2::opts::get_server_timeout_in_milliseconds().unwrap_or(-1),
        )
    }
}

/// The error libgit2 reports when a callback stops an operation at the
/// deadline.
fn deadline_error() -> git2::Error {
    git2::Error::from_str("the operation reached its timeout_ms deadline")
}

/// Credentials for a remote operation, from the verb's arguments.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub ssh_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

/// How many times libgit2 may ask for credentials before the operation
/// fails: it asks again after each rejection and would otherwise loop.
const MAX_CREDENTIAL_ATTEMPTS: u32 = 3;

impl Credentials {
    /// Installs the credentials callback and the deadline checks.
    pub fn install(&self, callbacks: &mut RemoteCallbacks<'_>) {
        let creds = self.clone();
        let attempts = Cell::new(0u32);
        callbacks.credentials(move |_url, username_from_url, allowed| {
            if expired() {
                return Err(deadline_error());
            }
            attempts.set(attempts.get() + 1);
            if attempts.get() > MAX_CREDENTIAL_ATTEMPTS {
                return Err(git2::Error::from_str(
                    "authentication failed: the remote rejected the credentials",
                ));
            }
            if allowed.contains(CredentialType::USERNAME) {
                let user = creds
                    .username
                    .as_deref()
                    .or(username_from_url)
                    .unwrap_or("git");
                return git2::Cred::username(user);
            }
            if allowed.contains(CredentialType::SSH_KEY) {
                if let Some(key) = &creds.ssh_key {
                    let user = username_from_url
                        .or(creds.username.as_deref())
                        .unwrap_or("git");
                    return git2::Cred::ssh_key(user, None, Path::new(key), None);
                }
            }
            if allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
                if let (Some(user), Some(pass)) = (&creds.username, &creds.password) {
                    return git2::Cred::userpass_plaintext(user, pass);
                }
                if let Some(token) = &creds.token {
                    let user = creds.username.as_deref().unwrap_or("");
                    return git2::Cred::userpass_plaintext(user, token);
                }
            }
            if allowed.contains(CredentialType::DEFAULT) {
                return git2::Cred::default();
            }
            Err(git2::Error::from_str(
                "authentication required: no credential argument (ssh_key, username and \
                 password, or token) applies to this remote",
            ))
        });
        callbacks.transfer_progress(|_| !expired());
        callbacks.sideband_progress(|_| !expired());
        callbacks.push_negotiation(|_| {
            if expired() {
                Err(deadline_error())
            } else {
                Ok(())
            }
        });
    }
}

/// True when a libgit2 error is an authentication failure.
pub fn is_auth_error(e: &git2::Error) -> bool {
    e.code() == git2::ErrorCode::Auth
        || e.class() == git2::ErrorClass::Http && e.message().contains("401")
        || e.message().contains("authentication")
}

/// Collects the references a push could not update. libgit2 reports a
/// rejected reference (non-fast-forward, hook refusal) through a callback
/// while the push itself succeeds.
#[derive(Clone, Default)]
pub struct PushRejections(Rc<RefCell<Vec<(String, String)>>>);

impl PushRejections {
    pub fn install(&self, callbacks: &mut RemoteCallbacks<'_>) {
        let slot = self.0.clone();
        callbacks.push_update_reference(move |refname, status| {
            if let Some(msg) = status {
                slot.borrow_mut()
                    .push((refname.to_string(), msg.to_string()));
            }
            Ok(())
        });
    }

    /// `refname: reason` for every rejected reference, or None.
    pub fn message(&self) -> Option<String> {
        let list = self.0.borrow();
        if list.is_empty() {
            return None;
        }
        Some(
            list.iter()
                .map(|(r, m)| format!("{r}: {m}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// libssh2 parses these key types in a known_hosts file; the preference
/// list libgit2 builds from the file only uses them.
const LIBSSH2_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

/// Serializes the remote operations that point libgit2's home directory at
/// a private copy of the host's keys (the setting is process-wide).
static HOME_LOCK: Mutex<()> = Mutex::new(());

/// A private home directory whose `.ssh/known_hosts` holds only the keys
/// accepted for one host, installed as libgit2's home directory while it
/// lives. libgit2 builds the SSH host-key preference from that file, so the
/// server is asked for a key type the user's file lists.
struct HomeOverride {
    _dir: tempfile::TempDir,
    _lock: MutexGuard<'static, ()>,
}

impl HomeOverride {
    fn install(lines: &str) -> Result<Self, String> {
        let lock = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::Builder::new()
            .prefix("resh-known-hosts-")
            .tempdir()
            .map_err(|e| format!("cannot create a private directory for the host keys: {e}"))?;
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir(&ssh)
            .and_then(|()| {
                crate::core::secure_fs::write_private_file(
                    &ssh.join("known_hosts"),
                    lines.as_bytes(),
                    false,
                )
            })
            .map_err(|e| format!("cannot write the private host-key file: {e}"))?;
        let home = std::ffi::CString::new(dir.path().as_os_str().as_encoded_bytes())
            .map_err(|_| "temporary directory path contains a NUL byte".to_string())?;
        init_libgit2();
        // SAFETY: the option takes one NUL-terminated path, copied by libgit2.
        let rc = unsafe { git_libgit2_opts(GIT_OPT_SET_HOMEDIR, home.as_ptr()) };
        if rc != 0 {
            return Err("libgit2 refused the private home directory".to_string());
        }
        Ok(HomeOverride {
            _dir: dir,
            _lock: lock,
        })
    }
}

impl Drop for HomeOverride {
    fn drop(&mut self) {
        // SAFETY: NULL resets the home directory to libgit2's default.
        unsafe {
            git_libgit2_opts(
                GIT_OPT_SET_HOMEDIR,
                std::ptr::null::<std::os::raw::c_char>(),
            );
        }
    }
}

/// The SSH endpoint being checked and the file it is checked against.
struct Target {
    host: String,
    port: u16,
    url: String,
    file: Rc<KnownHosts>,
}

#[derive(Default)]
struct PolicyState {
    target: Option<Target>,
    /// Set once libgit2 asked for a remote URL to be prepared: from then on
    /// an SSH connection that was not prepared is refused.
    prepared: bool,
    /// The SSH server's key reached the certificate check.
    presented: bool,
    failure: Option<(String, String)>,
    home: Option<HomeOverride>,
}

/// Strict SSH host-key checking for one remote operation, active when
/// `known_hosts_path` is given. Without it, libgit2's own defaults apply.
#[derive(Clone)]
pub struct HostKeyPolicy {
    path: Option<String>,
    state: Rc<RefCell<PolicyState>>,
}

impl HostKeyPolicy {
    pub fn new(known_hosts_path: Option<&str>) -> Self {
        HostKeyPolicy {
            path: known_hosts_path.map(str::to_string),
            state: Rc::default(),
        }
    }

    fn refusal(&self, host: &str, port: u16, reason: String) -> GitError {
        GitError::HostKeyVerificationFailed {
            host: known_hosts::lookup_name(host, port),
            known_hosts_path: self.path.clone().unwrap_or_default(),
            reason,
        }
    }

    /// Prepares the check for `url`, the URL libgit2 will connect to (after
    /// insteadOf rewriting). Nothing to do without `known_hosts_path` or for
    /// a URL that does not use SSH. For SSH the file must list the host
    /// before anything connects.
    pub fn prepare(&self, url: &str) -> Result<(), GitError> {
        let result = self.prepare_inner(url);
        if let Err(GitError::HostKeyVerificationFailed { host, reason, .. }) = &result {
            // Kept so that a refusal raised inside a libgit2 callback (the
            // clone's remote creation) is reported as itself.
            self.state.borrow_mut().failure = Some((host.clone(), reason.clone()));
        }
        result
    }

    fn prepare_inner(&self, url: &str) -> Result<(), GitError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let mut state = self.state.borrow_mut();
        state.prepared = true;
        // A new remote replaces the previous one (submodules).
        state.target = None;
        state.home = None;
        state.presented = false;
        let Some((host, port)) = known_hosts::ssh_endpoint(url) else {
            log::debug!("known_hosts_path ignored: '{url}' is not an SSH remote");
            return Ok(());
        };
        let file = KnownHosts::load(Path::new(path))
            .map_err(|reason| self.refusal(&host, port, reason))?;
        if file.skipped() > 0 {
            log::warn!(
                "known_hosts file '{}': skipped {} malformed or unsupported line(s)",
                path,
                file.skipped()
            );
        }
        file.preflight(&host, port)
            .map_err(|reason| self.refusal(&host, port, reason))?;
        let mut lines = String::new();
        for (key_type, b64) in file.accepted_keys(&host, port) {
            if !LIBSSH2_KEY_TYPES.contains(&key_type.as_str()) {
                continue;
            }
            for name in [
                known_hosts::lookup_name(&host, port),
                lookup_name_exact(&host, port),
            ] {
                let line = format!("{name} {key_type} {b64}\n");
                if !lines.contains(&line) {
                    lines.push_str(&line);
                }
            }
        }
        // Drop a previous override first: it holds the lock.
        state.home = None;
        state.home = Some(
            HomeOverride::install(&lines).map_err(|reason| self.refusal(&host, port, reason))?,
        );
        state.target = Some(Target {
            host,
            port,
            url: url.to_string(),
            file: Rc::new(file),
        });
        Ok(())
    }

    /// Installs the certificate check. Without `known_hosts_path` nothing is
    /// installed.
    pub fn install(&self, callbacks: &mut RemoteCallbacks<'_>) {
        if self.path.is_none() {
            return;
        }
        let policy = self.clone();
        callbacks.certificate_check(move |cert, hostname| {
            if expired() {
                return Err(deadline_error());
            }
            // A TLS certificate keeps libgit2's own validation.
            let Some(hostkey) = cert.as_hostkey() else {
                return Ok(git2::CertificateCheckStatus::CertificatePassthrough);
            };
            let key_type = match hostkey.hostkey_type() {
                Some(git2::cert::SshHostKeyType::Unknown) | None => None,
                Some(t) => Some(t.name().to_string()),
            };
            let presented = known_hosts::PresentedKey {
                key_type,
                blob: hostkey.hostkey().map(<[u8]>::to_vec),
                sha256: hostkey.hash_sha256().copied(),
            };
            policy.check(hostname, &presented)
        });
    }

    fn check(
        &self,
        hostname: &str,
        presented: &known_hosts::PresentedKey,
    ) -> Result<git2::CertificateCheckStatus, git2::Error> {
        let mut state = self.state.borrow_mut();
        state.presented = true;
        let verdict = match &state.target {
            Some(t) => {
                let host = if hostname.is_empty() {
                    t.host.as_str()
                } else {
                    hostname
                };
                t.file
                    .verify(host, t.port, presented)
                    .map_err(|reason| (known_hosts::lookup_name(host, t.port), reason))
            }
            // libgit2 opened an SSH connection for a URL that was never
            // prepared as SSH: fail closed.
            None => Err((
                if hostname.is_empty() {
                    "unknown host".to_string()
                } else {
                    hostname.to_string()
                },
                if state.prepared {
                    "the remote was not recognized as an SSH remote before connecting, so its \
                     host key cannot be checked"
                        .to_string()
                } else {
                    "the SSH connection was opened before its URL could be checked".to_string()
                },
            )),
        };
        match verdict {
            Ok(()) => Ok(git2::CertificateCheckStatus::CertificateOk),
            Err((host, reason)) => {
                let message = format!("SSH host key verification failed: {reason}");
                state.failure = Some((host, reason));
                Err(git2::Error::new(
                    git2::ErrorCode::Certificate,
                    git2::ErrorClass::Ssh,
                    message,
                ))
            }
        }
    }

    /// The host-key refusal that explains `err`, if host-key checking caused
    /// it: a key the callback refused, or an SSH handshake that failed
    /// because the server offers none of the key types the file lists.
    pub fn explain(&self, err: &git2::Error) -> Option<GitError> {
        let state = self.state.borrow();
        if let Some((host, reason)) = &state.failure {
            return Some(GitError::HostKeyVerificationFailed {
                host: host.clone(),
                known_hosts_path: self.path.clone().unwrap_or_default(),
                reason: reason.clone(),
            });
        }
        let target = state.target.as_ref()?;
        if state.presented
            || err.class() != git2::ErrorClass::Ssh
            || !err.message().contains("failed to start SSH session")
        {
            return None;
        }
        let listed = target.file.accepted_types(&target.host, target.port);
        let offered = probe_host_key_algorithms(&target.host, target.port);
        Some(self.refusal(
            &target.host,
            target.port,
            negotiation_failure(&target.url, &listed, offered, err.message()),
        ))
    }
}

/// `host` or `[host]:port` with the host's case kept, as libgit2 passes it
/// to the SSH library.
fn lookup_name_exact(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Explains an SSH handshake that failed after the SSH library was limited
/// to the key types listed in the file.
fn negotiation_failure(
    url: &str,
    listed: &[String],
    offered: Result<Vec<String>, String>,
    library_message: &str,
) -> String {
    let listed_text = if listed.is_empty() {
        "no key types".to_string()
    } else {
        listed.join(", ")
    };
    let mut reason = match &offered {
        Ok(algs) => format!(
            "the SSH server for '{url}' offers host key types {}, but the known_hosts file lists \
             only {listed_text} for it, so no host key could be negotiated",
            algs.join(", ")
        ),
        Err(probe) => format!(
            "the SSH handshake with '{url}' failed ({library_message}); the known_hosts file \
             lists {listed_text} for this host, and the host key types the server offers could \
             not be read ({probe})"
        ),
    };
    if let Ok(algs) = &offered {
        if let Some(first) = algs.iter().find(|a| !a.contains("-cert-")) {
            let key_type = key_type_of_algorithm(first);
            reason.push_str(&format!(
                ". Add the host's {key_type} key to the file (for example with \
                 ssh-keyscan -t {key_type})"
            ));
        }
    }
    reason
}

/// The key type a host-key signature algorithm uses.
fn key_type_of_algorithm(alg: &str) -> &str {
    match alg {
        "rsa-sha2-256" | "rsa-sha2-512" => "ssh-rsa",
        other => other,
    }
}

/// Reads the host-key algorithms an SSH server offers, from its unencrypted
/// key-exchange init message. Used only to explain a failed handshake.
pub fn probe_host_key_algorithms(host: &str, port: u16) -> Result<Vec<String>, String> {
    use std::net::{TcpStream, ToSocketAddrs};
    let budget = remaining()
        .unwrap_or(Duration::from_secs(5))
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(200));
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {host}"))?;
    let mut s = TcpStream::connect_timeout(&addr, budget).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(budget))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(budget))
        .map_err(|e| e.to_string())?;
    s.write_all(b"SSH-2.0-resh_probe\r\n")
        .map_err(|e| e.to_string())?;
    // The server's identification line(s), up to the "SSH-" line.
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).map_err(|e| e.to_string())?;
        line.push(b[0]);
        if b[0] == b'\n' {
            if line.starts_with(b"SSH-") {
                break;
            }
            line.clear();
        }
        if line.len() > 1024 {
            return Err("no SSH identification line".to_string());
        }
    }
    let mut header = [0u8; 5];
    s.read_exact(&mut header).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(17..=256 * 1024).contains(&len) {
        return Err("malformed key-exchange packet".to_string());
    }
    let mut body = vec![0u8; len - 1];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    let payload_len = body.len().saturating_sub(header[4] as usize);
    parse_kexinit_host_key_algorithms(&body[..payload_len])
}

/// The `server_host_key_algorithms` name-list of an SSH_MSG_KEXINIT payload.
fn parse_kexinit_host_key_algorithms(payload: &[u8]) -> Result<Vec<String>, String> {
    const SSH_MSG_KEXINIT: u8 = 20;
    if payload.first() != Some(&SSH_MSG_KEXINIT) {
        return Err("the server did not start the key exchange".to_string());
    }
    // message byte + 16-byte cookie, then name-lists.
    let mut pos = 17;
    let mut name_list = || -> Result<String, String> {
        let len_bytes = payload
            .get(pos..pos + 4)
            .ok_or("truncated key-exchange packet")?;
        let len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        let text = payload
            .get(pos + 4..pos + 4 + len)
            .ok_or("truncated key-exchange packet")?;
        pos += 4 + len;
        String::from_utf8(text.to_vec()).map_err(|_| "malformed name-list".to_string())
    };
    let _kex = name_list()?;
    let host_keys = name_list()?;
    Ok(host_keys
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kexinit(host_keys: &str) -> Vec<u8> {
        let mut p = vec![20u8];
        p.extend_from_slice(&[7u8; 16]);
        for list in ["curve25519-sha256", host_keys, "aes128-ctr"] {
            p.extend_from_slice(&(list.len() as u32).to_be_bytes());
            p.extend_from_slice(list.as_bytes());
        }
        p
    }

    #[test]
    fn kexinit_host_key_algorithms_are_read() {
        let algs = parse_kexinit_host_key_algorithms(&kexinit("rsa-sha2-512,ssh-ed25519")).unwrap();
        assert_eq!(algs, ["rsa-sha2-512", "ssh-ed25519"]);
        assert!(parse_kexinit_host_key_algorithms(&[21u8; 30]).is_err());
        assert!(parse_kexinit_host_key_algorithms(&kexinit("x")[..20]).is_err());
    }

    #[test]
    fn negotiation_failure_names_offered_and_listed_types() {
        let msg = negotiation_failure(
            "ssh://h/r",
            &["ecdsa-sha2-nistp256".to_string()],
            Ok(vec!["ssh-ed25519".to_string()]),
            "x",
        );
        assert!(msg.contains("offers host key types ssh-ed25519"), "{msg}");
        assert!(msg.contains("lists only ecdsa-sha2-nistp256"), "{msg}");
        assert!(msg.contains("ssh-keyscan -t ssh-ed25519"), "{msg}");

        let msg = negotiation_failure("ssh://h/r", &[], Err("refused".into()), "kex failed");
        assert!(
            msg.contains("kex failed") && msg.contains("refused"),
            "{msg}"
        );
    }

    #[test]
    fn server_timeouts_follow_the_deadline() {
        set_deadline(Some(Instant::now() + Duration::from_secs(30)));
        let (connect, read) = apply_and_read_server_timeouts();
        assert!((29_000..=30_100).contains(&connect), "{connect}");
        assert!((29_000..=30_100).contains(&read), "{read}");
        set_deadline(None);
        assert_eq!(apply_and_read_server_timeouts(), (0, 0));
    }

    #[test]
    fn local_urls() {
        for url in ["file:///srv/r.git", "/srv/r.git", "../r", "FILE:///x"] {
            assert!(is_local_url(url), "{url}");
        }
        for url in ["https://h/r", "git://h/r", "ssh://h/r", "git@h:r.git"] {
            assert!(!is_local_url(url), "{url}");
        }
    }

    #[test]
    fn deadline_is_per_thread() {
        set_deadline(Some(Instant::now() - Duration::from_millis(1)));
        assert!(expired());
        std::thread::spawn(|| assert!(!expired())).join().unwrap();
        set_deadline(None);
        assert!(!expired());
    }

    #[test]
    fn push_rejections_are_collected() {
        let r = PushRejections::default();
        assert_eq!(r.message(), None);
        r.0.borrow_mut()
            .push(("refs/heads/main".into(), "non-fast-forward".into()));
        assert_eq!(r.message().unwrap(), "refs/heads/main: non-fast-forward");
    }
}
