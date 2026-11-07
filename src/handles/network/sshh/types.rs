//! Shared enums, the ssh error type and the JSON response shapes of every
//! ssh verb. Field order in the response structs is the printed order.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Authentication method requested with `auth_method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SshAuthMethod {
    /// Password, then key, then agent, then ssh's default key lookup.
    #[default]
    Auto,
    Agent,
    Key,
    Password,
}

impl SshAuthMethod {
    pub const VALUES: &'static [(&'static str, SshAuthMethod)] = &[
        ("auto", SshAuthMethod::Auto),
        ("agent", SshAuthMethod::Agent),
        ("key", SshAuthMethod::Key),
        ("password", SshAuthMethod::Password),
    ];
}

/// Host key checking (`known_hosts_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnownHostsMode {
    #[default]
    Strict,
    AcceptNew,
    Insecure,
}

impl KnownHostsMode {
    pub const VALUES: &'static [(&'static str, KnownHostsMode)] = &[
        ("strict", KnownHostsMode::Strict),
        ("accept-new", KnownHostsMode::AcceptNew),
        ("insecure", KnownHostsMode::Insecure),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            KnownHostsMode::Strict => "strict",
            KnownHostsMode::AcceptNew => "accept-new",
            KnownHostsMode::Insecure => "insecure",
        }
    }

    /// The `StrictHostKeyChecking` value for this mode.
    pub fn ssh_value(self) -> &'static str {
        match self {
            KnownHostsMode::Strict => "yes",
            KnownHostsMode::AcceptNew => "accept-new",
            KnownHostsMode::Insecure => "no",
        }
    }
}

/// How exec wraps the remote command (`shell_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShellMode {
    #[default]
    None,
    Sh,
    Bash,
    Cmd,
    Powershell,
}

impl ShellMode {
    pub const VALUES: &'static [(&'static str, ShellMode)] = &[
        ("none", ShellMode::None),
        ("sh", ShellMode::Sh),
        ("bash", ShellMode::Bash),
        ("cmd", ShellMode::Cmd),
        ("powershell", ShellMode::Powershell),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ShellMode::None => "none",
            ShellMode::Sh => "sh",
            ShellMode::Bash => "bash",
            ShellMode::Cmd => "cmd",
            ShellMode::Powershell => "powershell",
        }
    }

    pub fn is_windows(self) -> bool {
        matches!(self, ShellMode::Cmd | ShellMode::Powershell)
    }
}

/// Encoding of exec output and of downloaded content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    #[default]
    Utf8,
    Base64,
}

impl Encoding {
    pub const VALUES: &'static [(&'static str, Encoding)] =
        &[("utf8", Encoding::Utf8), ("base64", Encoding::Base64)];

    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf8",
            Encoding::Base64 => "base64",
        }
    }
}

/// Report format (`format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Json,
    Text,
}

impl OutputFormat {
    pub const VALUES: &'static [(&'static str, OutputFormat)] =
        &[("json", OutputFormat::Json), ("text", OutputFormat::Text)];
}

/// Checksum tools available on the remote host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChecksumAlgorithm {
    #[default]
    Sha256,
    Sha1,
    Md5,
}

impl ChecksumAlgorithm {
    pub const VALUES: &'static [(&'static str, ChecksumAlgorithm)] = &[
        ("sha256", ChecksumAlgorithm::Sha256),
        ("sha1", ChecksumAlgorithm::Sha1),
        ("md5", ChecksumAlgorithm::Md5),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumAlgorithm::Sha256 => "sha256",
            ChecksumAlgorithm::Sha1 => "sha1",
            ChecksumAlgorithm::Md5 => "md5",
        }
    }

    /// The remote command that prints `<hex>  <path>`.
    pub fn remote_tool(self) -> &'static str {
        match self {
            ChecksumAlgorithm::Sha256 => "sha256sum",
            ChecksumAlgorithm::Sha1 => "sha1sum",
            ChecksumAlgorithm::Md5 => "md5sum",
        }
    }

    /// Lower-case hex digest of `data`.
    pub fn digest(self, data: &[u8]) -> String {
        match self {
            ChecksumAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(data))
            }
            ChecksumAlgorithm::Sha1 => {
                use sha1::{Digest, Sha1};
                format!("{:x}", Sha1::digest(data))
            }
            ChecksumAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
        }
    }
}

/// Tunnel forwarding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    Local,
    Remote,
    Dynamic,
}

impl TunnelMode {
    pub const VALUES: &'static [(&'static str, TunnelMode)] = &[
        ("local", TunnelMode::Local),
        ("remote", TunnelMode::Remote),
        ("dynamic", TunnelMode::Dynamic),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TunnelMode::Local => "local",
            TunnelMode::Remote => "remote",
            TunnelMode::Dynamic => "dynamic",
        }
    }
}

/// SOCKS version accepted by a dynamic tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocksVersion {
    #[default]
    Socks5,
    Socks4,
}

impl SocksVersion {
    pub const VALUES: &'static [(&'static str, SocksVersion)] = &[
        ("socks5", SocksVersion::Socks5),
        ("socks4", SocksVersion::Socks4),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SocksVersion::Socks5 => "socks5",
            SocksVersion::Socks4 => "socks4",
        }
    }

    /// The first byte a client of this version sends.
    pub fn first_byte(self) -> u8 {
        match self {
            SocksVersion::Socks5 => 5,
            SocksVersion::Socks4 => 4,
        }
    }
}

/// Which key files keys.list reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeysScope {
    #[default]
    Authorized,
    Host,
    Custom,
}

impl KeysScope {
    pub const VALUES: &'static [(&'static str, KeysScope)] = &[
        ("authorized", KeysScope::Authorized),
        ("host", KeysScope::Host),
        ("custom", KeysScope::Custom),
    ];
}

/// Which file key.add changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyAddScope {
    #[default]
    Authorized,
    Custom,
}

impl KeyAddScope {
    pub const VALUES: &'static [(&'static str, KeyAddScope)] = &[
        ("authorized", KeyAddScope::Authorized),
        ("custom", KeyAddScope::Custom),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            KeyAddScope::Authorized => "authorized",
            KeyAddScope::Custom => "custom",
        }
    }
}

/// What key.add does when the key is already in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnDuplicate {
    #[default]
    Skip,
    Error,
    Replace,
}

impl OnDuplicate {
    pub const VALUES: &'static [(&'static str, OnDuplicate)] = &[
        ("skip", OnDuplicate::Skip),
        ("error", OnDuplicate::Error),
        ("replace", OnDuplicate::Replace),
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            OnDuplicate::Skip => "skip",
            OnDuplicate::Error => "error",
            OnDuplicate::Replace => "replace",
        }
    }
}

/// Status of one `test` check.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Planned,
    Passed,
    Failed,
    Skipped,
}

// ---------------------------------------------------------------- errors --

/// Every failure an ssh verb reports. `code()` is the `error.code` field and
/// `exit_code()` the process exit status (2 usage, 1 failure, 124 timeout).
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SshError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("target and argument conflict: {0}")]
    TargetConflict(String),
    #[error("host is required")]
    HostRequired,
    #[error("username is required")]
    UsernameRequired,
    #[error("password is required for auth_method=password")]
    AuthMissingPassword,
    #[error("ssh agent is not available (set agent_socket or SSH_AUTH_SOCK)")]
    AgentUnavailable,
    #[error("identity file not found or not readable: {0}")]
    IdentityNotFound(String),
    #[error("identity_data is not a private key: {0}")]
    IdentityInvalid(String),
    #[error("{0}")]
    ToolNotFound(String),
    #[error("failed to connect: {0}")]
    ConnectFailed(String),
    #[error("host key verification failed: {0}")]
    HostKeyVerificationFailed(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("I/O error: {0}")]
    IoError(String),
    #[error("interrupted; the remote side may have been left part-way")]
    Interrupted,

    #[error("command is required")]
    CommandRequired,

    #[error("source is required")]
    UploadSourceMissing,
    #[error("source file not found: {0}")]
    UploadSourceNotFound(String),
    #[error("cannot read source: {0}")]
    UploadSourceReadError(String),
    #[error("invalid base64 source: {0}")]
    UploadInvalidSourceEncoding(String),
    #[error("source is {0} bytes, more than max_size_bytes={1}")]
    UploadTooLarge(u64, u64),
    #[error("dest is required")]
    UploadDestMissing,
    #[error("remote file exists and overwrite=false: {0}")]
    UploadDestExists(String),
    #[error("remote dest is a directory: {0}")]
    UploadDestIsDirectory(String),
    #[error("remote directory missing and mkdir_parents=false: {0}")]
    UploadRemoteDirMissing(String),
    #[error("remote write failed: {0}")]
    UploadRemoteWriteFailed(String),
    #[error("upload timed out: {0}")]
    UploadTimeout(String),
    #[error("checksum mismatch: local {0}, remote {1}")]
    UploadChecksumMismatch(String, String),

    #[error("source is required")]
    DownloadSourceMissing,
    #[error("remote file not found: {0}")]
    DownloadSourceNotFound(String),
    #[error("remote source is a directory: {0}")]
    DownloadSourceIsDirectory(String),
    #[error("remote read failed: {0}")]
    DownloadRemoteReadFailed(String),
    #[error("remote file is larger than max_size_bytes={0}")]
    DownloadTooLarge(u64),
    #[error("dest is required when dest_mode=file")]
    DownloadDestMissing,
    #[error("local file exists and overwrite=false: {0}")]
    DownloadDestExists(String),
    #[error("local directory missing and mkdir_parents=false: {0}")]
    DownloadLocalDirMissing(String),
    #[error("local write failed: {0}")]
    DownloadLocalWriteFailed(String),
    #[error("content is not valid UTF-8 (use return_encoding=base64)")]
    DownloadInvalidUtf8,
    #[error("download timed out: {0}; dest was not changed")]
    DownloadTimeout(String),
    #[error("checksum mismatch: remote {0}, local {1}")]
    DownloadChecksumMismatch(String, String),

    #[error("mode is required (local, remote or dynamic)")]
    TunnelModeRequired,
    #[error("mode=local needs remote_dest_host and remote_dest_port")]
    TunnelMissingRemoteDest,
    #[error("mode=remote needs local_dest_host and local_dest_port")]
    TunnelMissingLocalDest,
    #[error("wildcard bind address {0} needs allow_wildcard_binds=true")]
    TunnelWildcardBindForbidden(String),
    #[error("cannot listen on {1} port {0}: {2}")]
    TunnelBindFailed(u16, String, String),
    #[error("ssh could not set up the forward: {0}")]
    TunnelForwardFailed(String),
    #[error("the ssh connection closed: {0}")]
    TunnelClosed(String),
    #[error("tunnel stopped at timeout_ms={0}")]
    TunnelTimeout(u64),

    #[error("custom_paths is required when scope=custom")]
    KeysListCustomPathsRequired,
    #[error("remote read failed: {0}")]
    KeysListRemoteReadFailed(String),
    #[error("{0} is larger than max_bytes={1}")]
    KeysListTooLarge(String, u64),
    #[error("reading the key files timed out: {0}")]
    KeysListTimeout(String),

    #[error("a public key is required (public_key or public_key_path)")]
    KeyAddMissingPublicKey,
    #[error("invalid public key: {0}")]
    KeyAddInvalidPublicKey(String),
    #[error("custom_paths is required when scope=custom")]
    KeyAddCustomPathsRequired,
    #[error("target file does not exist and create_if_missing=false: {0}")]
    KeyAddTargetMissing(String),
    #[error("target file is a symbolic link; it is not changed: {0}")]
    KeyAddTargetIsSymlink(String),
    #[error("{0} is {1} bytes, more than max_file_bytes={2}")]
    KeyAddFileTooLarge(String, u64, u64),
    #[error("remote read failed: {0}")]
    KeyAddRemoteReadFailed(String),
    #[error("remote write failed: {0}")]
    KeyAddRemoteWriteFailed(String),
    #[error("backup failed: {0}")]
    KeyAddBackupFailed(String),
    #[error("setting permissions failed: {0}")]
    KeyAddPermissionsFailed(String),
    #[error("the key is already present and on_duplicate=error")]
    KeyAddDuplicate,
    #[error("the target file changed while the key was being added; nothing was written")]
    KeyAddConcurrentChange,
    #[error("public key file not found: {0}")]
    KeyAddPublicKeyFileNotFound(String),
    #[error("cannot read public key file: {0}")]
    KeyAddPublicKeyFileReadFailed(String),
    #[error("key.add timed out: {0}")]
    KeyAddTimeout(String),

    #[error("host is required (in the URL or as host=)")]
    ConfigGetHostRequired,
    #[error("cannot read config file: {0}")]
    ConfigGetReadFailed(String),
    #[error("config files are larger than max_config_bytes={0}")]
    ConfigGetTooLarge(u64),
    #[error("more than max_includes={0} Include files")]
    ConfigGetTooManyIncludes(u64),
    #[error("more than max_hosts={0} Host blocks")]
    ConfigGetTooManyHosts(u64),

    #[error("unknown test {0:?} (expected connect, auth, sftp, exec, hostkey)")]
    TestInvalidTestName(String),
    #[error("known_hosts_mode=insecure needs allow_insecure_hostkey=true")]
    TestInsecureHostkeyForbidden,
    #[error("connect check failed: {0}")]
    TestConnectFailed(String),
    #[error("auth check failed: {0}")]
    TestAuthFailed(String),
    #[error("sftp check failed: {0}")]
    TestSftpFailed(String),
    #[error("exec check failed: {0}")]
    TestExecFailed(String),
    #[error("hostkey check failed: {0}")]
    TestHostkeyFailed(String),
    #[error("skipped: {0}")]
    TestDependencyFailed(String),
    #[error("{0} check timed out")]
    TestCheckTimeout(String),
    #[error("overall test timeout exceeded")]
    TestOverallTimeout,
    #[error("{0}")]
    TestFailed(String),
}

impl SshError {
    /// The `error.code` value.
    pub fn code(&self) -> &'static str {
        use SshError::*;
        match self {
            InvalidArgument(_) => "ssh.invalid_argument",
            TargetConflict(_) => "ssh.target_conflict",
            HostRequired => "ssh.host_required",
            UsernameRequired => "ssh.username_required",
            AuthMissingPassword => "ssh.auth_missing_password",
            AgentUnavailable => "ssh.agent_unavailable",
            IdentityNotFound(_) => "ssh.identity_not_found",
            IdentityInvalid(_) => "ssh.identity_invalid",
            ToolNotFound(_) => "ssh.tool_not_found",
            ConnectFailed(_) => "ssh.connect_failed",
            HostKeyVerificationFailed(_) => "ssh.hostkey_verification_failed",
            AuthFailed(_) => "ssh.auth_failed",
            IoError(_) => "ssh.io_error",
            Interrupted => "ssh.interrupted",
            CommandRequired => "ssh.command_required",
            UploadSourceMissing => "ssh.upload_source_missing",
            UploadSourceNotFound(_) => "ssh.upload_source_not_found",
            UploadSourceReadError(_) => "ssh.upload_source_read_error",
            UploadInvalidSourceEncoding(_) => "ssh.upload_invalid_source_encoding",
            UploadTooLarge(..) => "ssh.upload_too_large",
            UploadDestMissing => "ssh.upload_dest_missing",
            UploadDestExists(_) => "ssh.upload_dest_exists",
            UploadDestIsDirectory(_) => "ssh.upload_dest_is_directory",
            UploadRemoteDirMissing(_) => "ssh.upload_remote_dir_missing",
            UploadRemoteWriteFailed(_) => "ssh.upload_remote_write_failed",
            UploadTimeout(_) => "ssh.upload_timeout",
            UploadChecksumMismatch(..) => "ssh.upload_checksum_mismatch",
            DownloadSourceMissing => "ssh.download_source_missing",
            DownloadSourceNotFound(_) => "ssh.download_source_not_found",
            DownloadSourceIsDirectory(_) => "ssh.download_source_is_directory",
            DownloadRemoteReadFailed(_) => "ssh.download_remote_read_failed",
            DownloadTooLarge(_) => "ssh.download_too_large",
            DownloadDestMissing => "ssh.download_dest_missing",
            DownloadDestExists(_) => "ssh.download_dest_exists",
            DownloadLocalDirMissing(_) => "ssh.download_local_dir_missing",
            DownloadLocalWriteFailed(_) => "ssh.download_local_write_failed",
            DownloadInvalidUtf8 => "ssh.download_invalid_utf8",
            DownloadTimeout(_) => "ssh.download_timeout",
            DownloadChecksumMismatch(..) => "ssh.download_checksum_mismatch",
            TunnelModeRequired => "ssh.tunnel_mode_required",
            TunnelMissingRemoteDest => "ssh.tunnel_missing_remote_dest",
            TunnelMissingLocalDest => "ssh.tunnel_missing_local_dest",
            TunnelWildcardBindForbidden(_) => "ssh.tunnel_wildcard_bind_forbidden",
            TunnelBindFailed(..) => "ssh.tunnel_bind_failed",
            TunnelForwardFailed(_) => "ssh.tunnel_forward_failed",
            TunnelClosed(_) => "ssh.tunnel_closed",
            TunnelTimeout(_) => "ssh.tunnel_timeout",
            KeysListCustomPathsRequired => "ssh.keys_list_custom_paths_required",
            KeysListRemoteReadFailed(_) => "ssh.keys_list_remote_read_failed",
            KeysListTooLarge(..) => "ssh.keys_list_too_large",
            KeysListTimeout(_) => "ssh.keys_list_timeout",
            KeyAddMissingPublicKey => "ssh.key_add_missing_public_key",
            KeyAddInvalidPublicKey(_) => "ssh.key_add_invalid_public_key",
            KeyAddCustomPathsRequired => "ssh.key_add_custom_paths_required",
            KeyAddTargetMissing(_) => "ssh.key_add_target_missing",
            KeyAddTargetIsSymlink(_) => "ssh.key_add_target_is_symlink",
            KeyAddFileTooLarge(..) => "ssh.key_add_file_too_large",
            KeyAddRemoteReadFailed(_) => "ssh.key_add_remote_read_failed",
            KeyAddRemoteWriteFailed(_) => "ssh.key_add_remote_write_failed",
            KeyAddBackupFailed(_) => "ssh.key_add_backup_failed",
            KeyAddPermissionsFailed(_) => "ssh.key_add_permissions_failed",
            KeyAddDuplicate => "ssh.key_add_duplicate",
            KeyAddConcurrentChange => "ssh.key_add_concurrent_change",
            KeyAddPublicKeyFileNotFound(_) => "ssh.key_add_public_key_file_not_found",
            KeyAddPublicKeyFileReadFailed(_) => "ssh.key_add_public_key_file_read_failed",
            KeyAddTimeout(_) => "ssh.key_add_timeout",
            ConfigGetHostRequired => "ssh.config_get_host_required",
            ConfigGetReadFailed(_) => "ssh.config_get_read_failed",
            ConfigGetTooLarge(_) => "ssh.config_get_too_large",
            ConfigGetTooManyIncludes(_) => "ssh.config_get_too_many_includes",
            ConfigGetTooManyHosts(_) => "ssh.config_get_too_many_hosts",
            TestInvalidTestName(_) => "ssh.test_invalid_test_name",
            TestInsecureHostkeyForbidden => "ssh.test_insecure_hostkey_forbidden",
            TestConnectFailed(_) => "ssh.test_connect_failed",
            TestAuthFailed(_) => "ssh.test_auth_failed",
            TestSftpFailed(_) => "ssh.test_sftp_failed",
            TestExecFailed(_) => "ssh.test_exec_failed",
            TestHostkeyFailed(_) => "ssh.test_hostkey_failed",
            TestDependencyFailed(_) => "ssh.test_dependency_failed",
            TestCheckTimeout(_) => "ssh.test_check_timeout",
            TestOverallTimeout => "ssh.test_overall_timeout",
            TestFailed(_) => "ssh.test_failed",
        }
    }

    /// Process exit status: 2 invalid usage (nothing done), 124 timeout or
    /// unknown outcome, 1 every other failure.
    pub fn exit_code(&self) -> i32 {
        use SshError::*;
        match self {
            InvalidArgument(_)
            | TargetConflict(_)
            | HostRequired
            | UsernameRequired
            | AuthMissingPassword
            | IdentityInvalid(_)
            | CommandRequired
            | UploadSourceMissing
            | UploadInvalidSourceEncoding(_)
            | UploadDestMissing
            | DownloadSourceMissing
            | DownloadDestMissing
            | TunnelModeRequired
            | TunnelMissingRemoteDest
            | TunnelMissingLocalDest
            | TunnelWildcardBindForbidden(_)
            | KeysListCustomPathsRequired
            | KeyAddMissingPublicKey
            | KeyAddInvalidPublicKey(_)
            | KeyAddCustomPathsRequired
            | ConfigGetHostRequired
            | TestInvalidTestName(_)
            | TestInsecureHostkeyForbidden => 2,
            Interrupted | UploadTimeout(_) | DownloadTimeout(_) | TunnelTimeout(_)
            | KeysListTimeout(_) | KeyAddTimeout(_) | TestOverallTimeout => 124,
            _ => 1,
        }
    }

    /// Extra fields for `error.details`.
    pub fn details(&self) -> HashMap<String, String> {
        use SshError::*;
        let kv = |pairs: &[(&str, String)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        match self {
            UploadSourceNotFound(p)
            | UploadDestExists(p)
            | UploadDestIsDirectory(p)
            | UploadRemoteDirMissing(p)
            | DownloadSourceNotFound(p)
            | DownloadSourceIsDirectory(p)
            | DownloadDestExists(p)
            | DownloadLocalDirMissing(p)
            | KeyAddTargetMissing(p)
            | KeyAddTargetIsSymlink(p)
            | KeyAddPublicKeyFileNotFound(p)
            | IdentityNotFound(p) => kv(&[("path", p.clone())]),
            UploadTooLarge(size, max) => kv(&[
                ("size_bytes", size.to_string()),
                ("max_size_bytes", max.to_string()),
            ]),
            DownloadTooLarge(max) => kv(&[("max_size_bytes", max.to_string())]),
            UploadChecksumMismatch(a, b) | DownloadChecksumMismatch(a, b) => {
                kv(&[("expected", a.clone()), ("actual", b.clone())])
            }
            TunnelBindFailed(port, host, reason) => kv(&[
                ("port", port.to_string()),
                ("host", host.clone()),
                ("reason", reason.clone()),
            ]),
            KeysListTooLarge(p, max) => kv(&[("path", p.clone()), ("max_bytes", max.to_string())]),
            KeyAddFileTooLarge(p, size, max) => kv(&[
                ("path", p.clone()),
                ("size_bytes", size.to_string()),
                ("max_file_bytes", max.to_string()),
            ]),
            TestInvalidTestName(n) => kv(&[("test_name", n.clone())]),
            _ => HashMap::new(),
        }
    }

    pub fn to_json(&self) -> SshErrorDetails {
        SshErrorDetails {
            code: self.code().to_string(),
            message: self.to_string(),
            details: self.details(),
        }
    }
}

/// `error` object of a response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshErrorDetails {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,
}

// ------------------------------------------------------------- responses --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnectionInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub backend: String,
}

impl SshConnectionInfo {
    pub fn new(host: &str, port: u16, username: &str) -> Self {
        SshConnectionInfo {
            host: host.to_string(),
            port,
            username: username.to_string(),
            backend: "system".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCommandInfo {
    pub raw: String,
    pub shell_mode: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub allocate_pty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecResult {
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub output_truncated: bool,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

impl SshExecResult {
    /// For a request refused before ssh was started.
    pub fn not_executed() -> Self {
        SshExecResult {
            executed: false,
            exit_code: None,
            signal: None,
            timed_out: false,
            output_truncated: false,
            stdout: None,
            stderr: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTimingInfo {
    pub connect_ms: Option<u64>,
    pub command_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub connection: SshConnectionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<SshCommandInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SshExecResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<SshTimingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadSourceInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadDestInfo {
    pub path: String,
    pub overwrite: bool,
    pub atomic: bool,
    pub mkdir_parents: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadResult {
    pub uploaded: bool,
    pub planned: bool,
    pub verify_checksum: bool,
    pub checksum_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub connection: SshConnectionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SshUploadSourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<SshUploadDestInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SshUploadResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<SshTimingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadSourceInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadDestInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub overwrite: bool,
    pub mkdir_parents: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadResult {
    pub downloaded: bool,
    pub planned: bool,
    pub return_content: bool,
    pub return_encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub verify_checksum: bool,
    pub checksum_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadTimingInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub connection: SshConnectionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SshDownloadSourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<SshDownloadDestInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SshDownloadResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<SshDownloadTimingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelInfo {
    pub mode: String,
    pub local_bind_host: Option<String>,
    pub local_bind_port: Option<u16>,
    pub remote_bind_host: Option<String>,
    pub remote_bind_port: Option<u16>,
    pub remote_dest_host: Option<String>,
    pub remote_dest_port: Option<u16>,
    pub local_dest_host: Option<String>,
    pub local_dest_port: Option<u16>,
    pub socks_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelLifetimeConfig {
    pub connect_timeout_ms: u64,
    pub tunnel_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub max_connections: Option<u64>,
    pub max_bytes_in: Option<u64>,
    pub max_bytes_out: Option<u64>,
    pub closed_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshTunnelStats {
    pub connections_accepted: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelResponse {
    pub ok: bool,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<SshConnectionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<SshTunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<SshTunnelLifetimeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<SshTunnelStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshKeyInfo {
    pub index: usize,
    pub source_line: usize,
    #[serde(rename = "type")]
    pub type_normalized: String,
    pub type_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    pub fingerprint: String,
    pub fingerprint_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshKeysFileReport {
    pub path: String,
    pub exists: bool,
    pub readable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parse_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<SshKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeysListSummary {
    pub total_keys: usize,
    pub matched_keys: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeysListResponse {
    pub ok: bool,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<SshConnectionInfo>,
    pub scope: KeysScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<SshKeysFileReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<SshKeysListSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyAddOperation {
    /// `added`, `already_present`, `replaced` or `dry_run`.
    pub status: String,
    pub on_duplicate: OnDuplicate,
    pub duplicates_found: usize,
    pub created_file: bool,
    pub backup_created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeySummary {
    #[serde(rename = "type")]
    pub type_normalized: String,
    pub type_raw: String,
    pub fingerprint: String,
    pub fingerprint_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyAddResponse {
    pub ok: bool,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<SshConnectionInfo>,
    pub scope: KeyAddScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<SshKeyAddOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<SshKeySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshConfigSettingOrigin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshConfigSetting {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<SshConfigSettingOrigin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshConfigRawEntry {
    pub file: String,
    pub line: usize,
    pub block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_pattern: Option<String>,
    pub option: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigSummary {
    pub total_files: usize,
    pub total_entries: usize,
    pub matched_blocks: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigGetResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub host: String,
    pub sources: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<std::collections::BTreeMap<String, SshConfigSetting>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_entries: Option<Vec<SshConfigRawEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<SshConfigSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSingleTestResult {
    pub name: String,
    pub status: TestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestSummary {
    pub tests_requested: Vec<String>,
    pub tests_run: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub tests_skipped: usize,
    pub overall_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestTargetInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestSecurityInfo {
    pub known_hosts_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_hosts_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostkey_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostkey_fingerprint: Option<String>,
    pub insecure_hostkey_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub target: SshTestTargetInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SshTestSecurityInfo>,
    pub tests: Vec<SshSingleTestResult>,
    pub summary: SshTestSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SshErrorDetails>,
    #[serde(default)]
    pub warnings: Vec<String>,
}
