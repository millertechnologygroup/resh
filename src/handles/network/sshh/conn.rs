//! Connection options shared by every connecting verb: the target, the
//! authentication method and its credentials, host key checking, and the
//! ssh command line built from them.

use super::args::ArgReader;
use super::runner::{ProcessOutput, RunError, SshCommandLine};
use super::types::{KnownHostsMode, SshAuthMethod, SshError};
use base64::prelude::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use url::Url;

/// What the URL says about the target.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshTarget {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl SshTarget {
    pub fn from_url(url: &Url) -> Self {
        // The URL keeps user info percent-encoded (p%40ss for p@ss).
        let decode = |s: &str| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned()
        };
        SshTarget {
            host: url
                .host_str()
                .filter(|h| !h.is_empty())
                .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string()),
            port: url.port(),
            username: Some(url.username()).filter(|u| !u.is_empty()).map(decode),
            password: url.password().map(decode),
        }
    }
}

/// Whether a verb may fall back to the local user name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRule {
    /// `$USER`, then `$USERNAME`, then `root`.
    DefaultToLocal,
    Required,
}

/// Resolved connection options of one call.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,
    pub connect_timeout_ms: u64,
}

pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

fn conflict(what: &str, url: &str, arg: &str) -> SshError {
    SshError::TargetConflict(format!("the URL {what} is {url:?} but {what}= is {arg:?}"))
}

/// Refuses a host name that ssh could read as an option or that is not a
/// plain host name or address.
pub fn check_host(host: &str) -> Result<(), SshError> {
    let bad = host.is_empty()
        || host.starts_with('-')
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "@/\\'\"`$;|&<>()".contains(c));
    if bad {
        return Err(SshError::InvalidArgument(format!(
            "invalid host {host:?}: expected a host name or IP address"
        )));
    }
    Ok(())
}

/// Refuses a user name that is not a plain login name.
pub fn check_user(key: &str, user: &str) -> Result<(), SshError> {
    let bad = user.is_empty()
        || user.starts_with('-')
        || user.chars().any(|c| {
            c.is_control() || c.is_whitespace() || "@:/\\'\"`$;|&<>()*?[]~!{}".contains(c)
        });
    if bad {
        return Err(SshError::InvalidArgument(format!(
            "invalid {key} {user:?}: expected a login name"
        )));
    }
    Ok(())
}

/// Merges a URL value and an argument value, refusing a conflict.
fn merge(what: &str, url: Option<String>, arg: Option<String>) -> Result<Option<String>, SshError> {
    match (url, arg) {
        (Some(u), Some(a)) if u != a => Err(conflict(what, &u, &a)),
        (u, a) => Ok(u.or(a)),
    }
}

/// Parses and validates the connection options. Nothing is read from disk
/// and no tool is looked up here; see [`ConnOptions::prepare`].
pub fn parse_conn(
    r: &ArgReader,
    target: &SshTarget,
    rule: UserRule,
) -> Result<ConnOptions, SshError> {
    let host =
        merge("host", target.host.clone(), r.text("host")?)?.ok_or(SshError::HostRequired)?;
    check_host(&host)?;

    let port = match (target.port, r.port("port", false)?) {
        (Some(u), Some(a)) if u != a => {
            return Err(conflict("port", &u.to_string(), &a.to_string()));
        }
        (Some(0), None) => {
            return Err(SshError::InvalidArgument(
                "invalid port 0 in the URL".into(),
            ));
        }
        (u, a) => u.or(a).unwrap_or(22),
    };

    let username = match merge("username", target.username.clone(), r.text("username")?)? {
        Some(u) => u,
        None if rule == UserRule::Required => return Err(SshError::UsernameRequired),
        None => std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "root".to_string()),
    };
    check_user("username", &username)?;

    let auth_method = r
        .choice("auth_method", SshAuthMethod::VALUES)?
        .unwrap_or_default();
    let password = merge(
        "password",
        target.password.clone(),
        r.data("password", false)?,
    )?;
    let identity_path = r.text("identity_path")?;
    let identity_data = r.data("identity_data", false)?;
    let identity_passphrase = r.data("identity_passphrase", false)?;
    let agent_socket = r.text("agent_socket")?;

    if identity_path.is_some() && identity_data.is_some() {
        return Err(SshError::InvalidArgument(
            "give identity_path or identity_data, not both".into(),
        ));
    }
    let has_identity = identity_path.is_some() || identity_data.is_some();
    if identity_passphrase.is_some() && !has_identity {
        return Err(SshError::InvalidArgument(
            "identity_passphrase needs identity_path or identity_data".into(),
        ));
    }
    let only = |what: &str, methods: &str| {
        SshError::InvalidArgument(format!("{what} is only used with auth_method={methods}"))
    };
    match auth_method {
        SshAuthMethod::Password => {
            if password.is_none() {
                return Err(SshError::AuthMissingPassword);
            }
            if has_identity {
                return Err(only("identity_path/identity_data", "key or auto"));
            }
            if agent_socket.is_some() {
                return Err(only("agent_socket", "agent or auto"));
            }
        }
        SshAuthMethod::Key => {
            if password.is_some() {
                return Err(only("password", "password or auto"));
            }
            if agent_socket.is_some() {
                return Err(only("agent_socket", "agent or auto"));
            }
        }
        SshAuthMethod::Agent => {
            if password.is_some() {
                return Err(only("password", "password or auto"));
            }
            if has_identity {
                return Err(only("identity_path/identity_data", "key or auto"));
            }
        }
        SshAuthMethod::Auto => {}
    }

    let known_hosts_mode = r
        .choice("known_hosts_mode", KnownHostsMode::VALUES)?
        .unwrap_or_default();
    let known_hosts_path = r.text("known_hosts_path")?;
    if let Some(p) = &known_hosts_path {
        if p.contains('"') {
            return Err(SshError::InvalidArgument(
                "known_hosts_path must not contain a double quote".into(),
            ));
        }
    }
    let connect_timeout_ms = r.u64_or("connect_timeout_ms", DEFAULT_CONNECT_TIMEOUT_MS)?;

    Ok(ConnOptions {
        host,
        port,
        username,
        auth_method,
        password,
        identity_path,
        identity_data,
        identity_passphrase,
        agent_socket,
        known_hosts_mode,
        known_hosts_path,
        connect_timeout_ms,
    })
}

/// Credentials made ready for ssh. Holds the private temporary directory
/// (mode 0700) with an `identity_data` key or the passphrase helper; it is
/// removed when this is dropped.
#[derive(Debug)]
pub struct Prepared {
    pub auth: SshAuthMethod,
    pub identity_file: Option<String>,
    pub env: Vec<(String, String)>,
    /// ssh may prompt (askpass for a passphrase); BatchMode stays off.
    pub interactive: bool,
    _dir: Option<tempfile::TempDir>,
}

/// Name of the environment variable the askpass helper prints.
const PASSPHRASE_VAR: &str = "RESH_SSH_KEY_PASSPHRASE";

/// A fresh temporary directory, mode 0700.
pub fn private_dir(prefix: &str) -> Result<tempfile::TempDir, SshError> {
    let err = |e: std::io::Error| {
        SshError::IoError(format!("cannot create a private temp directory: {e}"))
    };
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(err)?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).map_err(err)?;
    Ok(dir)
}

fn write_private(path: &std::path::Path, data: &[u8], mode: u32) -> Result<(), SshError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| SshError::IoError(format!("cannot write {}: {e}", path.display())))?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .and_then(|_| f.write_all(data))
        .and_then(|_| f.sync_all())
        .map_err(|e| SshError::IoError(format!("cannot write {}: {e}", path.display())))
}

/// The private key text of `identity_data`: PEM/OpenSSH text as given, or
/// the same text base64-encoded.
pub fn identity_text(data: &str) -> Result<String, SshError> {
    let looks_like_key = |s: &str| s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----");
    let text = if looks_like_key(data) {
        data.to_string()
    } else {
        let compact: String = data.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded = BASE64_STANDARD.decode(compact.as_bytes()).map_err(|_| {
            SshError::IdentityInvalid(
                "expected a PEM or OpenSSH private key, as text or base64".into(),
            )
        })?;
        let text = String::from_utf8(decoded).map_err(|_| {
            SshError::IdentityInvalid("the base64 value does not decode to key text".into())
        })?;
        if !looks_like_key(&text) {
            return Err(SshError::IdentityInvalid(
                "the base64 value does not decode to a private key".into(),
            ));
        }
        text
    };
    // ssh refuses a key file without a final newline.
    let mut text = text.replace("\r\n", "\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

impl ConnOptions {
    /// The method `auto` resolves to: password, then key, then agent (from
    /// `agent_socket` or `env_agent`, the caller's SSH_AUTH_SOCK), then
    /// ssh's default key lookup.
    pub fn effective_auth(&self, env_agent: Option<&str>) -> Result<SshAuthMethod, SshError> {
        let agent = self.agent_socket.is_some() || env_agent.is_some_and(|s| !s.is_empty());
        Ok(match self.auth_method {
            SshAuthMethod::Auto if self.password.is_some() => SshAuthMethod::Password,
            SshAuthMethod::Auto if self.identity_path.is_some() || self.identity_data.is_some() => {
                SshAuthMethod::Key
            }
            SshAuthMethod::Auto if agent => SshAuthMethod::Agent,
            SshAuthMethod::Auto => SshAuthMethod::Key,
            SshAuthMethod::Agent if !agent => return Err(SshError::AgentUnavailable),
            other => other,
        })
    }

    /// Checks the local side and materializes credentials: the identity file
    /// must be readable, `identity_data` is written to a private temp file,
    /// a passphrase gets an askpass helper, password logins need sshpass and
    /// an agent socket must exist. Nothing connects.
    pub fn prepare(&self) -> Result<Prepared, SshError> {
        let env_agent = std::env::var("SSH_AUTH_SOCK").ok();
        let auth = self.effective_auth(env_agent.as_deref())?;
        let mut env = Vec::new();
        let mut dir = None;
        let mut identity_file = None;

        if auth == SshAuthMethod::Agent {
            let sock = self.agent_socket.clone().or(env_agent).unwrap_or_default();
            if std::fs::metadata(&sock).is_err() {
                return Err(SshError::AgentUnavailable);
            }
            if let Some(s) = &self.agent_socket {
                env.push(("SSH_AUTH_SOCK".to_string(), s.clone()));
            }
        }
        if auth == SshAuthMethod::Password && !sshpass_available() {
            return Err(SshError::ToolNotFound(
                "password authentication needs sshpass, which is not installed".into(),
            ));
        }
        if let Some(path) = &self.identity_path {
            let readable = std::fs::File::open(path)
                .and_then(|f| f.metadata())
                .is_ok_and(|m| m.is_file());
            if !readable {
                return Err(SshError::IdentityNotFound(path.clone()));
            }
            identity_file = Some(path.clone());
        }
        if let Some(data) = &self.identity_data {
            let text = identity_text(data)?;
            let d = private_dir("resh-ssh-")?;
            let key = d.path().join("identity");
            write_private(&key, text.as_bytes(), 0o600)?;
            identity_file = Some(key.display().to_string());
            dir = Some(d);
        }
        if let Some(pass) = &self.identity_passphrase {
            if dir.is_none() {
                dir = Some(private_dir("resh-ssh-")?);
            }
            let d = dir
                .as_ref()
                .map(|d| d.path().to_path_buf())
                .unwrap_or_default();
            let helper = d.join("askpass");
            let script = format!("#!/bin/sh\nprintf '%s\\n' \"${PASSPHRASE_VAR}\"\n");
            write_private(&helper, script.as_bytes(), 0o700)?;
            env.push(("SSH_ASKPASS".to_string(), helper.display().to_string()));
            env.push(("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()));
            if std::env::var_os("DISPLAY").is_none() {
                env.push(("DISPLAY".to_string(), ":0".to_string()));
            }
            env.push((PASSPHRASE_VAR.to_string(), pass.clone()));
        }
        if let (SshAuthMethod::Password, Some(p)) = (auth, &self.password) {
            env.push(("SSHPASS".to_string(), p.clone()));
        }
        Ok(Prepared {
            auth,
            identity_file,
            env,
            interactive: self.identity_passphrase.is_some(),
            _dir: dir,
        })
    }

    /// The `user@host` destination.
    pub fn destination(&self) -> String {
        format!("{}@{}", self.username, self.host)
    }

    /// The ssh command line: connection options, then `extra` ssh options,
    /// then `--`, the destination and the remote command (when given).
    pub fn command_line(
        &self,
        prep: &Prepared,
        extra: &[String],
        remote: Option<&str>,
        pty: bool,
    ) -> SshCommandLine {
        let mut args: Vec<String> = vec!["-p".into(), self.port.to_string()];
        let mut opt = |o: String| {
            args.push("-o".into());
            args.push(o);
        };
        match prep.auth {
            SshAuthMethod::Password => {
                opt("PreferredAuthentications=password,keyboard-interactive".into());
                opt("PubkeyAuthentication=no".into());
            }
            SshAuthMethod::Key | SshAuthMethod::Agent | SshAuthMethod::Auto => {
                opt("PasswordAuthentication=no".into());
                opt("KbdInteractiveAuthentication=no".into());
            }
        }
        if let Some(file) = &prep.identity_file {
            opt("IdentitiesOnly=yes".into());
            args.push("-i".into());
            args.push(file.clone());
        }
        let mut opt = |o: String| {
            args.push("-o".into());
            args.push(o);
        };
        opt(format!(
            "StrictHostKeyChecking={}",
            self.known_hosts_mode.ssh_value()
        ));
        if let Some(path) = &self.known_hosts_path {
            opt(format!("UserKnownHostsFile=\"{path}\""));
        }
        if self.connect_timeout_ms > 0 {
            opt(format!(
                "ConnectTimeout={}",
                self.connect_timeout_ms.div_ceil(1000)
            ));
        }
        let batch = prep.auth != SshAuthMethod::Password && !prep.interactive;
        opt(format!("BatchMode={}", if batch { "yes" } else { "no" }));
        args.push(if pty { "-tt" } else { "-T" }.into());
        args.extend(extra.iter().cloned());
        args.push("--".into());
        args.push(self.destination());
        if let Some(r) = remote {
            args.push(r.to_string());
        }

        if prep.auth == SshAuthMethod::Password {
            let mut sshpass = vec!["-e".to_string(), "ssh".to_string()];
            sshpass.extend(args);
            SshCommandLine {
                program: "sshpass".into(),
                args: sshpass,
                env: prep.env.clone(),
            }
        } else {
            SshCommandLine {
                program: "ssh".into(),
                args,
                env: prep.env.clone(),
            }
        }
    }
}

#[cfg(not(test))]
fn sshpass_available() -> bool {
    which::which("sshpass").is_ok()
}

#[cfg(test)]
thread_local! {
    pub static SSHPASS_INSTALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

#[cfg(test)]
fn sshpass_available() -> bool {
    SSHPASS_INSTALLED.with(|s| s.get())
}

/// Maps a failed ssh run (connection, host key or login trouble) to an
/// error, or `None` when ssh itself worked and the remote side failed.
pub fn connection_error(cmd: &SshCommandLine, out: &ProcessOutput) -> Option<SshError> {
    let stderr = out.stderr_text();
    let detail = || {
        stderr
            .lines()
            .filter(|l| !l.starts_with("debug") && !l.starts_with("Warning: Permanently added"))
            .collect::<Vec<_>>()
            .join("; ")
    };
    if stderr.contains("Host key verification failed")
        || stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || (cmd.program == "sshpass" && out.exit_code == Some(6))
    {
        return Some(SshError::HostKeyVerificationFailed(detail()));
    }
    let auth_failed = stderr.contains("Permission denied")
        || stderr.contains("Too many authentication failures")
        || (cmd.program == "sshpass" && out.exit_code == Some(5));
    if out.exit_code == Some(255) || (cmd.program == "sshpass" && auth_failed) {
        if auth_failed {
            return Some(SshError::AuthFailed(detail()));
        }
        return Some(SshError::ConnectFailed(detail()));
    }
    None
}

/// Maps a runner error; `timeout` is used when the deadline passed.
pub fn run_error(e: RunError, timeout: SshError) -> SshError {
    match e {
        RunError::Timeout => timeout,
        RunError::Interrupted => SshError::Interrupted,
        RunError::TooLarge => SshError::IoError("output larger than the limit".into()),
        RunError::Spawn(program, e) if e.kind() == std::io::ErrorKind::NotFound => {
            if program == "sshpass" {
                SshError::ToolNotFound(
                    "password authentication needs sshpass, which is not installed".into(),
                )
            } else {
                SshError::ToolNotFound(format!("{program} was not found on PATH"))
            }
        }
        RunError::Spawn(program, e) => SshError::IoError(format!("cannot start {program}: {e}")),
        RunError::Io(msg) => SshError::IoError(msg),
    }
}

/// POSIX single-quoting for the remote shell.
pub fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// One argument for a POSIX shell: left bare when it only has characters
/// no POSIX shell (zsh included) treats specially, otherwise single-quoted.
pub fn posix_quote(arg: &str) -> String {
    let bare = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+:,./-".contains(c));
    if bare {
        arg.to_string()
    } else {
        shell_escape(arg)
    }
}

/// A remote path for the remote shell. A leading `~/` (or `~user/`, with a
/// plain login name) stays unquoted so the remote shell expands it.
pub fn quote_remote_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("~/{}", shell_escape(rest));
    }
    if path == "~" {
        return "~".to_string();
    }
    if let Some(after) = path.strip_prefix('~') {
        let (user, rest) = after.split_once('/').unwrap_or((after, ""));
        if check_user("user", user).is_ok() {
            return if rest.is_empty() {
                format!("~{user}")
            } else {
                format!("~{user}/{}", shell_escape(rest))
            };
        }
    }
    shell_escape(path)
}

/// Refuses a remote path with control characters, an empty path, or one
/// that starts with `-`.
pub fn check_remote_path(key: &str, path: &str) -> Result<(), SshError> {
    if path.is_empty() || path.chars().any(char::is_control) {
        return Err(SshError::InvalidArgument(format!(
            "{key} must be a non-empty path without control characters"
        )));
    }
    if path.starts_with('-') {
        return Err(SshError::InvalidArgument(format!(
            "{key} must not start with '-'"
        )));
    }
    Ok(())
}

/// The first hex token printed by sha256sum/sha1sum/md5sum.
pub fn parse_checksum_output(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let token = text.split_whitespace().next()?;
    (!token.is_empty() && token.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| token.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::Args;

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn target(url: &str) -> SshTarget {
        SshTarget::from_url(&Url::parse(url).unwrap())
    }

    fn conn(url: &str, pairs: &[(&str, &str)]) -> Result<ConnOptions, SshError> {
        let a = args(pairs);
        parse_conn(&ArgReader::new(&a), &target(url), UserRule::Required)
    }

    #[test]
    fn target_from_url() {
        let t = target("ssh://alice:p%40ss@example.com:2222");
        assert_eq!(t.host.as_deref(), Some("example.com"));
        assert_eq!(t.port, Some(2222));
        assert_eq!(t.username.as_deref(), Some("alice"));
        assert_eq!(t.password.as_deref(), Some("p@ss"));
        let t = target("ssh://example.com");
        assert_eq!(t.port, None);
        assert_eq!(t.username, None);
        assert_eq!(target("ssh://[::1]:22").host.as_deref(), Some("::1"));
    }

    #[test]
    fn url_and_arguments_merge_and_conflicts_are_refused() {
        let c = conn("ssh://u@h", &[("port", "2200")]).unwrap();
        assert_eq!(
            (c.host.as_str(), c.port, c.username.as_str()),
            ("h", 2200, "u")
        );
        assert!(matches!(
            conn("ssh://u@h", &[("host", "other")]),
            Err(SshError::TargetConflict(_))
        ));
        assert!(matches!(
            conn("ssh://u@h:22", &[("port", "23")]),
            Err(SshError::TargetConflict(_))
        ));
        assert!(matches!(
            conn("ssh://u@h", &[("username", "v")]),
            Err(SshError::TargetConflict(_))
        ));
        assert!(matches!(
            conn("ssh://u:a@h", &[("password", "b")]),
            Err(SshError::TargetConflict(_))
        ));
        assert!(conn("ssh://u@h", &[("host", "h"), ("username", "u")]).is_ok());
        assert!(matches!(
            conn("ssh://h", &[]),
            Err(SshError::UsernameRequired)
        ));
        let a = args(&[]);
        let c = parse_conn(
            &ArgReader::new(&a),
            &target("ssh://h"),
            UserRule::DefaultToLocal,
        )
        .unwrap();
        assert!(!c.username.is_empty());
    }

    #[test]
    fn hosts_and_users_that_look_like_options_are_refused() {
        for bad in ["-oProxyCommand=x", "a b", "a;b", "a\nb"] {
            assert!(check_host(bad).is_err(), "{bad:?}");
            assert!(check_user("username", bad).is_err(), "{bad:?}");
        }
        assert!(check_host("db-1.example.com").is_ok());
        assert!(check_host("192.0.2.10").is_ok());
        assert!(check_host("::1").is_ok());
        assert!(check_user("username", "svc_deploy.1").is_ok());
    }

    #[test]
    fn credentials_must_match_the_auth_method() {
        let e = |pairs: &[(&str, &str)]| conn("ssh://u@h", pairs).unwrap_err();
        assert_eq!(
            e(&[("auth_method", "password")]),
            SshError::AuthMissingPassword
        );
        for pairs in [
            &[("auth_method", "key"), ("password", "x")][..],
            &[("auth_method", "agent"), ("identity_path", "/k")],
            &[
                ("auth_method", "password"),
                ("password", "x"),
                ("identity_path", "/k"),
            ],
            &[("auth_method", "key"), ("agent_socket", "/s")],
            &[("identity_path", "/k"), ("identity_data", "x")],
            &[("identity_passphrase", "x")],
            &[("auth_method", "magic")],
            &[("known_hosts_mode", "accept_new")],
            &[("known_hosts_path", "/a\"b")],
            &[("connect_timeout_ms", "soon")],
            &[("port", "0")],
        ] {
            assert_eq!(e(pairs).exit_code(), 2, "{pairs:?}");
        }
    }

    #[test]
    fn auto_resolution_does_not_depend_on_the_environment() {
        let c = conn("ssh://u@h", &[]).unwrap();
        assert_eq!(c.effective_auth(None).unwrap(), SshAuthMethod::Key);
        assert_eq!(
            c.effective_auth(Some("/tmp/agent")).unwrap(),
            SshAuthMethod::Agent
        );
        assert_eq!(c.effective_auth(Some("")).unwrap(), SshAuthMethod::Key);
        let c = conn("ssh://u:pw@h", &[]).unwrap();
        assert_eq!(
            c.effective_auth(Some("/a")).unwrap(),
            SshAuthMethod::Password
        );
        let c = conn("ssh://u@h", &[("identity_path", "/k")]).unwrap();
        assert_eq!(c.effective_auth(Some("/a")).unwrap(), SshAuthMethod::Key);
        let c = conn("ssh://u@h", &[("auth_method", "agent")]).unwrap();
        assert_eq!(c.effective_auth(None), Err(SshError::AgentUnavailable));
        let c = conn("ssh://u@h", &[("agent_socket", "/s")]).unwrap();
        assert_eq!(c.effective_auth(None).unwrap(), SshAuthMethod::Agent);
    }

    #[test]
    fn command_line_for_each_method() {
        let c = conn(
            "ssh://u@h:2222",
            &[
                ("known_hosts_path", "/k h"),
                ("known_hosts_mode", "accept-new"),
            ],
        )
        .unwrap();
        let prep = Prepared {
            auth: SshAuthMethod::Key,
            identity_file: Some("/id".into()),
            env: vec![],
            interactive: false,
            _dir: None,
        };
        let cmd = c.command_line(&prep, &["-N".into()], Some("true"), false);
        assert_eq!(cmd.program, "ssh");
        let line = cmd.args.join(" ");
        assert!(line.starts_with("-p 2222 "), "{line}");
        assert!(line.contains("-o IdentitiesOnly=yes -i /id"), "{line}");
        assert!(line.contains("StrictHostKeyChecking=accept-new"), "{line}");
        assert!(line.contains("UserKnownHostsFile=\"/k h\""), "{line}");
        assert!(line.contains("ConnectTimeout=10"), "{line}");
        assert!(line.contains("BatchMode=yes"), "{line}");
        assert!(line.ends_with("-T -N -- u@h true"), "{line}");

        let c = conn("ssh://u:secret@h", &[]).unwrap();
        let prep = Prepared {
            auth: SshAuthMethod::Password,
            identity_file: None,
            env: vec![("SSHPASS".into(), "secret".into())],
            interactive: false,
            _dir: None,
        };
        let cmd = c.command_line(&prep, &[], Some("ls"), true);
        assert_eq!(cmd.program, "sshpass");
        assert_eq!(&cmd.args[..2], &["-e".to_string(), "ssh".to_string()]);
        assert!(!cmd.args.iter().any(|a| a.contains("secret")));
        assert!(cmd.args.contains(&"BatchMode=no".to_string()));
        assert!(cmd.args.contains(&"-tt".to_string()));
    }

    #[test]
    fn prepare_writes_identity_data_privately_and_removes_it() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let c = conn(
            "ssh://u@h",
            &[("identity_data", key), ("identity_passphrase", "pp")],
        )
        .unwrap();
        let prep = c.prepare().unwrap();
        let file = std::path::PathBuf::from(prep.identity_file.clone().unwrap());
        let meta = std::fs::metadata(&file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{key}\n"));
        assert!(prep.interactive);
        assert!(
            prep.env
                .iter()
                .any(|(k, v)| k == PASSPHRASE_VAR && v == "pp")
        );
        let helper = prep
            .env
            .iter()
            .find(|(k, _)| k == "SSH_ASKPASS")
            .map(|(_, v)| v.clone())
            .unwrap();
        let out = std::process::Command::new(&helper)
            .env(PASSPHRASE_VAR, "pp")
            .output()
            .unwrap();
        assert_eq!(out.stdout, b"pp\n");
        drop(prep);
        assert!(!file.exists());
    }

    #[test]
    fn identity_data_accepts_base64_and_refuses_other_text() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n";
        let b64 = BASE64_STANDARD.encode(key);
        assert_eq!(identity_text(&b64).unwrap(), key);
        assert!(matches!(
            identity_text("hello"),
            Err(SshError::IdentityInvalid(_))
        ));
        let not_key = BASE64_STANDARD.encode("ssh-ed25519 AAAA");
        assert!(matches!(
            identity_text(&not_key),
            Err(SshError::IdentityInvalid(_))
        ));
    }

    #[test]
    fn prepare_checks_the_local_side() {
        let c = conn("ssh://u@h", &[("identity_path", "/nonexistent/key")]).unwrap();
        assert_eq!(
            c.prepare().unwrap_err(),
            SshError::IdentityNotFound("/nonexistent/key".into())
        );
        let c = conn("ssh://u@h", &[("agent_socket", "/nonexistent/agent")]).unwrap();
        assert_eq!(c.prepare().unwrap_err(), SshError::AgentUnavailable);
        let c = conn("ssh://u:pw@h", &[]).unwrap();
        SSHPASS_INSTALLED.with(|s| s.set(false));
        let e = c.prepare().unwrap_err();
        SSHPASS_INSTALLED.with(|s| s.set(true));
        assert_eq!(e.code(), "ssh.tool_not_found");
        let prep = c.prepare().unwrap();
        assert!(prep.env.contains(&("SSHPASS".into(), "pw".into())));
    }

    #[test]
    fn failures_are_classified() {
        let ssh = SshCommandLine {
            program: "ssh".into(),
            args: vec![],
            env: vec![],
        };
        let out = |code: i32, err: &str| ProcessOutput {
            exit_code: Some(code),
            stderr: err.as_bytes().to_vec(),
            ..Default::default()
        };
        assert!(matches!(
            connection_error(&ssh, &out(255, "Host key verification failed.")),
            Some(SshError::HostKeyVerificationFailed(_))
        ));
        assert!(matches!(
            connection_error(&ssh, &out(255, "u@h: Permission denied (publickey).")),
            Some(SshError::AuthFailed(_))
        ));
        assert!(matches!(
            connection_error(
                &ssh,
                &out(255, "connect to host h port 22: Connection refused")
            ),
            Some(SshError::ConnectFailed(_))
        ));
        assert_eq!(connection_error(&ssh, &out(1, "")), None);
        let sshpass = SshCommandLine {
            program: "sshpass".into(),
            ..ssh.clone()
        };
        assert!(matches!(
            connection_error(&sshpass, &out(5, "")),
            Some(SshError::AuthFailed(_))
        ));
        assert!(matches!(
            run_error(
                RunError::Spawn("sshpass".into(), std::io::ErrorKind::NotFound.into()),
                SshError::Interrupted
            ),
            SshError::ToolNotFound(_)
        ));
    }

    #[test]
    fn remote_paths_keep_home_expansion() {
        assert_eq!(quote_remote_path("~/a b"), "~/'a b'");
        assert_eq!(quote_remote_path("~bob/.ssh/x"), "~bob/'.ssh/x'");
        assert_eq!(quote_remote_path("~bob"), "~bob");
        assert_eq!(quote_remote_path("~$(x)/y"), "'~$(x)/y'");
        assert_eq!(quote_remote_path("/etc/it's"), "'/etc/it'\"'\"'s'");
        assert!(check_remote_path("dest", "-x").is_err());
        assert!(check_remote_path("dest", "a\nb").is_err());
        assert_eq!(
            parse_checksum_output(b"ABC123  -\n").as_deref(),
            Some("abc123")
        );
        assert_eq!(parse_checksum_output(b"sha256sum: x: No such file"), None);
    }
}
