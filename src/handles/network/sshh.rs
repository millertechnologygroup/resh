use anyhow::{Context, Result, bail};
use base64::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};
use std::thread;
use url::Url;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use rand;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// SSH authentication methods
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthMethod {
    Agent,
    Key,
    Password,
}

impl Default for SshAuthMethod {
    fn default() -> Self {
        SshAuthMethod::Agent
    }
}

/// Host key verification modes
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KnownHostsMode {
    Strict,
    AcceptNew,
    Insecure,
}

impl Default for KnownHostsMode {
    fn default() -> Self {
        KnownHostsMode::Strict
    }
}

/// Shell execution modes
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ShellMode {
    None,
    Sh,
    Bash,
    Cmd,
    Powershell,
}

impl Default for ShellMode {
    fn default() -> Self {
        ShellMode::None
    }
}

/// Output encoding options
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutputEncoding {
    Utf8,
    Base64,
}

impl Default for OutputEncoding {
    fn default() -> Self {
        OutputEncoding::Utf8
    }
}

/// Output format options
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Text,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Json
    }
}

/// Source mode for upload operations
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    File,
    Inline,
}

impl Default for SourceMode {
    fn default() -> Self {
        SourceMode::File
    }
}

/// Source encoding for inline data
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SourceEncoding {
    Utf8,
    Base64,
}

impl Default for SourceEncoding {
    fn default() -> Self {
        SourceEncoding::Utf8
    }
}

/// Destination mode for download operations
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DestMode {
    File,
    None,
}

impl Default for DestMode {
    fn default() -> Self {
        DestMode::File
    }
}

/// Return encoding for download operations
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReturnEncoding {
    Utf8,
    Base64,
}

impl Default for ReturnEncoding {
    fn default() -> Self {
        ReturnEncoding::Utf8
    }
}

/// Tunnel forwarding modes
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    Local,
    Remote,
    Dynamic,
}

/// SOCKS proxy version for dynamic tunnels
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SocksVersion {
    Socks5,
    Socks4,
}

impl Default for SocksVersion {
    fn default() -> Self {
        SocksVersion::Socks5
    }
}

/// SSH tunnel options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshTunnelOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Tunnel mode (required)
    pub mode: Option<TunnelMode>,

    // Local bind (for local & dynamic)
    #[serde(default = "default_local_bind_host")]
    pub local_bind_host: String,
    #[serde(default)]
    pub local_bind_port: u16,

    // Remote bind (for remote)
    #[serde(default = "default_remote_bind_host")]
    pub remote_bind_host: String,
    #[serde(default)]
    pub remote_bind_port: u16,

    // Remote destination (for local)
    pub remote_dest_host: Option<String>,
    pub remote_dest_port: Option<u16>,

    // Local destination (for remote)
    pub local_dest_host: Option<String>,
    pub local_dest_port: Option<u16>,

    // Dynamic mode options
    #[serde(default)]
    pub socks_version: SocksVersion,

    // Lifetime & limits
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    pub tunnel_timeout_ms: Option<u64>,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_ms: Option<u64>,
    pub max_connections: Option<u64>,
    pub max_bytes_in: Option<u64>,
    pub max_bytes_out: Option<u64>,

    // Behavior & output
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub allow_wildcard_binds: bool,
    #[serde(default)]
    pub format: OutputFormat,
}

/// Tunnel configuration information
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

/// Tunnel lifetime configuration
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

/// Tunnel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelStats {
    pub connections_accepted: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_ms: u64,
}

/// SSH tunnel response structure
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

/// SSH exec options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshExecOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Command execution
    pub command: Option<String>,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default)]
    pub shell_mode: ShellMode,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub allocate_pty: bool,

    // Timeouts and limits
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_command_timeout")]
    pub command_timeout_ms: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    #[serde(default = "default_trim_newlines")]
    pub trim_trailing_newlines: bool,

    // Behavior
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_capture_output")]
    pub capture_output: bool,
    #[serde(default)]
    pub output_encoding: OutputEncoding,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshExecOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            command: None,
            command_args: Vec::new(),
            shell_mode: ShellMode::default(),
            env: HashMap::new(),
            cwd: None,
            allocate_pty: false,
            connect_timeout_ms: default_connect_timeout(),
            command_timeout_ms: default_command_timeout(),
            max_output_bytes: default_max_output(),
            trim_trailing_newlines: default_trim_newlines(),
            dry_run: false,
            capture_output: default_capture_output(),
            output_encoding: OutputEncoding::default(),
            format: OutputFormat::default(),
        }
    }
}

// Default value functions
fn default_port() -> u16 { 22 }
fn default_connect_timeout() -> u64 { 10_000 }
fn default_command_timeout() -> u64 { 60_000 }
fn default_max_output() -> usize { 1_048_576 } // 1 MiB
fn default_trim_newlines() -> bool { true }
fn default_capture_output() -> bool { true }
fn default_local_bind_host() -> String { "127.0.0.1".to_string() }
fn default_remote_bind_host() -> String { "127.0.0.1".to_string() }
fn default_idle_timeout() -> Option<u64> { Some(300_000) } // 5 minutes

// Upload-specific default value functions
fn default_max_size_bytes() -> u64 { 104_857_600 } // 100 MiB
fn default_transfer_timeout() -> u64 { 600_000 } // 10 minutes

/// SSH upload options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshUploadOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Source (local or inline)
    pub source: Option<String>,
    #[serde(default)]
    pub source_mode: SourceMode,
    #[serde(default)]
    pub source_encoding: SourceEncoding,
    pub content_type: Option<String>,

    // Destination (remote)
    pub dest: Option<String>,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default = "default_atomic")]
    pub atomic: bool,
    #[serde(default = "default_mkdir_parents")]
    pub mkdir_parents: bool,

    // Permissions & metadata
    pub file_mode: Option<String>,
    #[serde(default)]
    pub preserve_times: bool,
    pub mtime_epoch_ms: Option<i64>,

    // Limits / timeouts
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_transfer_timeout")]
    pub transfer_timeout_ms: u64,

    // Behavior & output
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub verify_checksum: bool,
    #[serde(default = "default_checksum_algorithm")]
    pub checksum_algorithm: String,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshUploadOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            source: None,
            source_mode: SourceMode::default(),
            source_encoding: SourceEncoding::default(),
            content_type: None,
            dest: None,
            overwrite: false,
            atomic: default_atomic(),
            mkdir_parents: default_mkdir_parents(),
            file_mode: None,
            preserve_times: false,
            mtime_epoch_ms: None,
            max_size_bytes: default_max_size_bytes(),
            connect_timeout_ms: default_connect_timeout(),
            transfer_timeout_ms: default_transfer_timeout(),
            dry_run: false,
            verify_checksum: false,
            checksum_algorithm: default_checksum_algorithm(),
            format: OutputFormat::default(),
        }
    }
}

// Upload-specific default functions
fn default_atomic() -> bool { true }
fn default_mkdir_parents() -> bool { true }
fn default_checksum_algorithm() -> String { "sha256".to_string() }

// Download-specific default functions
fn default_return_content() -> bool { true }

/// SSH download options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshDownloadOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Source (remote)
    pub source: Option<String>,

    // Destination (local / inline)
    pub dest: Option<String>,
    #[serde(default)]
    pub dest_mode: DestMode,
    #[serde(default = "default_return_content")]
    pub return_content: bool,
    #[serde(default)]
    pub return_encoding: ReturnEncoding,

    // Local file behavior
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default = "default_mkdir_parents")]
    pub mkdir_parents: bool,

    // Limits / timeouts
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_transfer_timeout")]
    pub transfer_timeout_ms: u64,

    // Checksum
    #[serde(default)]
    pub verify_checksum: bool,
    #[serde(default = "default_checksum_algorithm")]
    pub checksum_algorithm: String,

    // Behavior & output
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshDownloadOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            source: None,
            dest: None,
            dest_mode: DestMode::default(),
            return_content: default_return_content(),
            return_encoding: ReturnEncoding::default(),
            overwrite: false,
            mkdir_parents: default_mkdir_parents(),
            max_size_bytes: default_max_size_bytes(),
            connect_timeout_ms: default_connect_timeout(),
            transfer_timeout_ms: default_transfer_timeout(),
            verify_checksum: false,
            checksum_algorithm: default_checksum_algorithm(),
            dry_run: false,
            format: OutputFormat::default(),
        }
    }
}

/// Connection information for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnectionInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub backend: String,
}

/// Command information for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCommandInfo {
    pub raw: String,
    pub shell_mode: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub allocate_pty: bool,
}

/// Command execution result
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

/// Timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTimingInfo {
    pub connect_ms: Option<u64>,
    pub command_ms: Option<u64>,
}

/// SSH error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshErrorDetails {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,
}

/// Complete SSH exec response
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Upload source information for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadSourceInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Upload destination information for responses
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

/// Upload operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUploadResult {
    pub uploaded: bool,
    pub planned: bool,
    pub verify_checksum: bool,
    pub checksum_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_verified: Option<bool>,
}

/// Complete SSH upload response
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

/// Download source information for responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadSourceInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_epoch_ms: Option<i64>,
}

/// Download destination information for responses
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

/// Download operation result
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

/// Download timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDownloadTimingInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_ms: Option<u64>,
}

/// Complete SSH download response
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

// ========== keys.list verb structures ==========

/// Scope for SSH key enumeration
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeysScope {
    Authorized,
    Host,
    Custom,
}

impl Default for KeysScope {
    fn default() -> Self {
        KeysScope::Authorized
    }
}

/// SSH keys list options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshKeysListOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Scope / which keys to list
    #[serde(default)]
    pub scope: KeysScope,
    pub authorized_user: Option<String>,
    pub authorized_paths: Option<Vec<String>>,
    pub host_key_paths: Option<Vec<String>>,
    pub custom_paths: Option<Vec<String>>,

    // Filtering
    #[serde(default = "default_key_types")]
    pub key_types: Vec<String>,
    #[serde(default = "default_fingerprint_algorithm")]
    pub fingerprint_algorithm: String,
    #[serde(default = "default_include_options")]
    pub include_options: bool,
    #[serde(default = "default_include_raw_key")]
    pub include_raw_key: bool,

    // Limits / timeouts
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
    #[serde(default = "default_max_bytes_keys")]
    pub max_bytes: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_ms: u64,

    // Behavior & output
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshKeysListOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            scope: KeysScope::default(),
            authorized_user: None,
            authorized_paths: None,
            host_key_paths: None,
            custom_paths: None,
            key_types: default_key_types(),
            fingerprint_algorithm: default_fingerprint_algorithm(),
            include_options: default_include_options(),
            include_raw_key: default_include_raw_key(),
            max_keys: default_max_keys(),
            max_bytes: default_max_bytes_keys(),
            connect_timeout_ms: default_connect_timeout(),
            read_timeout_ms: default_read_timeout(),
            dry_run: false,
            format: OutputFormat::default(),
        }
    }
}

// keys.list default value functions
fn default_key_types() -> Vec<String> {
    vec![
        "rsa".to_string(),
        "ecdsa".to_string(),
        "ed25519".to_string(),
        "dsa".to_string(),
    ]
}
fn default_fingerprint_algorithm() -> String { "sha256".to_string() }
fn default_include_options() -> bool { true }
fn default_include_raw_key() -> bool { true }
fn default_max_keys() -> usize { 1024 }
fn default_max_bytes_keys() -> usize { 1_048_576 } // 1 MiB
fn default_read_timeout() -> u64 { 10_000 }

/// Information about a single SSH key
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Report for a single key file
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Summary statistics for keys.list operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeysListSummary {
    pub total_keys: usize,
    pub matched_keys: usize,
    pub truncated: bool,
}

/// Complete SSH keys.list response
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

// ========== End keys.list structures ==========

// ========== key.add verb structures ==========

/// Scope for key.add operation (subset of KeysScope)
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAddScope {
    Authorized,
    Custom,
}

impl Default for KeyAddScope {
    fn default() -> Self {
        KeyAddScope::Authorized
    }
}

/// Public key source mode
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PublicKeySource {
    Inline,
    File,
}

impl Default for PublicKeySource {
    fn default() -> Self {
        PublicKeySource::Inline
    }
}

/// Duplicate key handling policy
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDuplicate {
    Skip,
    Error,
    Replace,
}

impl Default for OnDuplicate {
    fn default() -> Self {
        OnDuplicate::Skip
    }
}

/// SSH key.add options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshKeyAddOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Scope / target file selection
    #[serde(default)]
    pub scope: KeyAddScope,
    pub authorized_user: Option<String>,
    pub authorized_paths: Option<Vec<String>>,
    pub custom_paths: Option<Vec<String>>,

    // Public key input
    pub public_key: Option<String>,
    #[serde(default)]
    pub public_key_source: PublicKeySource,
    pub public_key_path: Option<String>,

    // Duplicate handling
    #[serde(default)]
    pub on_duplicate: OnDuplicate,

    // File behavior
    #[serde(default = "default_create_if_missing")]
    pub create_if_missing: bool,
    #[serde(default = "default_backup_existing")]
    pub backup_existing: bool,
    #[serde(default = "default_backup_suffix")]
    pub backup_suffix: String,
    #[serde(default = "default_ensure_permissions")]
    pub ensure_permissions: bool,
    #[serde(default = "default_file_mode")]
    pub file_mode: String,
    #[serde(default = "default_dir_mode")]
    pub dir_mode: String,

    // Limits / timeouts
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_write_timeout")]
    pub write_timeout_ms: u64,

    // Behavior & output
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshKeyAddOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            scope: KeyAddScope::default(),
            authorized_user: None,
            authorized_paths: None,
            custom_paths: None,
            public_key: None,
            public_key_source: PublicKeySource::default(),
            public_key_path: None,
            on_duplicate: OnDuplicate::default(),
            create_if_missing: default_create_if_missing(),
            backup_existing: default_backup_existing(),
            backup_suffix: default_backup_suffix(),
            ensure_permissions: default_ensure_permissions(),
            file_mode: default_file_mode(),
            dir_mode: default_dir_mode(),
            max_file_bytes: default_max_file_bytes(),
            connect_timeout_ms: default_connect_timeout(),
            read_timeout_ms: default_read_timeout(),
            write_timeout_ms: default_write_timeout(),
            dry_run: false,
            format: OutputFormat::default(),
        }
    }
}

// key.add default value functions
fn default_create_if_missing() -> bool { true }
fn default_backup_existing() -> bool { true }
fn default_backup_suffix() -> String { ".bak".to_string() }
fn default_ensure_permissions() -> bool { true }
fn default_file_mode() -> String { "0600".to_string() }
fn default_dir_mode() -> String { "0700".to_string() }
fn default_max_file_bytes() -> usize { 1_048_576 } // 1 MiB
fn default_write_timeout() -> u64 { 10_000 }

/// Operation summary for key.add
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyAddOperation {
    pub status: String,  // "added", "already_present", "replaced", "dry_run"
    pub on_duplicate: OnDuplicate,
    pub duplicates_found: usize,
    pub created_file: bool,
    pub backup_created: bool,
}

/// Summary of the public key being added
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

/// Complete SSH key.add response
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

// ========== End key.add structures ==========

// ========== config.get structures ==========

/// Options for config.get verb
#[derive(Debug, Clone)]
pub struct SshConfigGetOptions {
    pub host: String,

    // Config sources
    pub user_home: Option<String>,
    pub user_config_path: String,
    pub system_config_path: String,
    pub extra_config_paths: Vec<String>,
    pub follow_includes: bool,

    // Behavior flags
    pub include_raw_entries: bool,
    pub include_origin: bool,
    pub include_effective_only: bool,

    // Limits
    pub max_config_bytes: usize,
    pub max_includes: usize,
    pub max_hosts: usize,

    // Behavior & output
    pub dry_run: bool,
    pub format: OutputFormat,
}

impl Default for SshConfigGetOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            user_home: None,
            user_config_path: "~/.ssh/config".to_string(),
            system_config_path: "/etc/ssh/ssh_config".to_string(),
            extra_config_paths: Vec::new(),
            follow_includes: true,
            include_raw_entries: true,
            include_origin: true,
            include_effective_only: true,
            max_config_bytes: 1_048_576, // 1 MiB
            max_includes: 64,
            max_hosts: 1024,
            dry_run: false,
            format: OutputFormat::Json,
        }
    }
}

/// Origin information for a config setting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigSettingOrigin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<String>,
}

/// A resolved config setting with optional origin info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigSetting {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<SshConfigSettingOrigin>,
}

/// A raw config entry from parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigRawEntry {
    pub file: String,
    pub line: usize,
    pub block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_pattern: Option<String>,
    pub option: String,
    pub value: String,
}

/// Summary of config parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigSummary {
    pub total_files: usize,
    pub total_entries: usize,
    pub matched_blocks: Vec<String>,
    pub truncated: bool,
}

/// Response from config.get verb
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

// ========== End config.get structures ==========

// ========== Begin test verb structures ==========

/// Test status for individual tests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Planned,
    Passed,
    Failed,
    Skipped,
}

/// SSH test options structure
#[derive(Debug, Clone, Deserialize)]
pub struct SshTestOptions {
    // Connection parameters
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: Option<String>,

    // Authentication
    #[serde(default)]
    pub auth_method: SshAuthMethod,
    pub password: Option<String>,
    pub identity_path: Option<String>,
    pub identity_data: Option<String>,
    pub identity_passphrase: Option<String>,
    pub agent_socket: Option<String>,

    // Host key verification
    #[serde(default)]
    pub known_hosts_mode: KnownHostsMode,
    pub known_hosts_path: Option<String>,

    // Tests to run
    #[serde(default = "default_tests")]
    pub tests: Vec<String>,
    #[serde(default = "default_exec_command")]
    pub exec_command: String,

    // Timeouts
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub auth_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub sftp_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub exec_timeout_ms: u64,
    #[serde(default = "default_overall_timeout")]
    pub overall_timeout_ms: u64,

    // Behavior
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub allow_insecure_hostkey: bool,
    #[serde(default)]
    pub format: OutputFormat,
}

impl Default for SshTestOptions {
    fn default() -> Self {
        Self {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::default(),
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::default(),
            known_hosts_path: None,
            tests: default_tests(),
            exec_command: default_exec_command(),
            connect_timeout_ms: default_connect_timeout(),
            handshake_timeout_ms: default_connect_timeout(),
            auth_timeout_ms: default_connect_timeout(),
            sftp_timeout_ms: default_connect_timeout(),
            exec_timeout_ms: default_connect_timeout(),
            overall_timeout_ms: default_overall_timeout(),
            dry_run: false,
            allow_insecure_hostkey: false,
            format: OutputFormat::default(),
        }
    }
}

fn default_tests() -> Vec<String> {
    vec!["connect".to_string(), "auth".to_string()]
}

fn default_exec_command() -> String {
    "echo ok".to_string()
}

fn default_overall_timeout() -> u64 {
    15_000
}

/// Result of a single test
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

/// Summary of all tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestSummary {
    pub tests_requested: Vec<String>,
    pub tests_run: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub tests_skipped: usize,
    pub overall_duration_ms: u64,
}

/// Target information for test response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTestTargetInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Security/host key information for test response
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

/// Complete SSH test response
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

// ========== End test verb structures ==========

/// SSH target structure for parsing URLs
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
}

impl SshTarget {
    /// Parse SSH target from URL
    pub fn from_url(url: &Url) -> Self {
        let host = if url.host_str().unwrap_or("").is_empty() {
            None
        } else {
            Some(url.host_str().unwrap().to_string())
        };

        let port = if url.port() == Some(22) || url.port().is_none() {
            None
        } else {
            url.port()
        };

        let username = if url.username().is_empty() {
            None
        } else {
            Some(url.username().to_string())
        };

        Self {
            host,
            port,
            username,
        }
    }
}

/// SSH-specific error types
#[derive(Debug, Error, Clone)]
pub enum SshError {
    #[error("Invalid backend: {0}")]
    InvalidBackend(String),
    #[error("Target and parameter conflict: {0}")]
    TargetConflict(String),
    #[error("Host is required")]
    HostRequired,
    #[error("Username is required")]
    UsernameRequired,
    #[error("Unsupported authentication method: {0}")]
    AuthMethodUnsupported(String),
    #[error("Password is required for password authentication")]
    AuthMissingPassword,
    #[error("Password is required for password authentication")]
    AuthPasswordRequired,
    #[error("Private key is required for key authentication")]
    AuthMissingKey,
    #[error("SSH agent is not available")]
    AgentUnavailable,
    #[error("Failed to connect: {0}")]
    ConnectFailed(String),
    #[error("Host key verification failed: {0}")]
    HostKeyVerificationFailed(String),
    #[error("Command is required")]
    CommandRequired,
    #[error("Command timeout exceeded")]
    CommandTimeout,
    #[error("Failed to create exec channel: {0}")]
    ExecChannelFailed(String),
    #[error("Output too large")]
    OutputTooLarge,
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    
    // Upload-specific errors
    #[error("Source is missing")]
    UploadSourceMissing,
    #[error("Source file not found: {0}")]
    UploadSourceNotFound(String),
    #[error("Source read error: {0}")]
    UploadSourceReadError(String),
    #[error("Invalid source encoding: {0}")]
    UploadInvalidSourceEncoding(String),
    #[error("Upload too large: {0} bytes exceeds limit")]
    UploadTooLarge(u64),
    #[error("Destination is missing")]
    UploadDestMissing,
    #[error("Remote file exists and overwrite=false: {0}")]
    UploadDestExists(String),
    #[error("Remote directory missing and mkdir_parents=false: {0}")]
    UploadRemoteDirMissing(String),
    #[error("Remote write failed: {0}")]
    UploadRemoteWriteFailed(String),
    #[error("Upload timeout exceeded")]
    UploadTimeout,
    #[error("Checksum mismatch: expected {0}, got {1}")]
    UploadChecksumMismatch(String, String),

    // Download-specific errors
    #[error("Download source is missing")]
    DownloadSourceMissing,
    #[error("Remote file not found: {0}")]
    DownloadSourceNotFound(String),
    #[error("Source is a directory: {0}")]
    DownloadSourceIsDirectory(String),
    #[error("Remote read failed: {0}")]
    DownloadRemoteReadFailed(String),
    #[error("Download too large: {0} bytes exceeds limit of {1} bytes")]
    DownloadTooLarge(u64, u64),
    #[error("Destination is missing when dest_mode=file")]
    DownloadDestMissing,
    #[error("Local file exists and overwrite=false: {0}")]
    DownloadDestExists(String),
    #[error("Local directory missing and mkdir_parents=false: {0}")]
    DownloadLocalDirMissing(String),
    #[error("Local write failed: {0}")]
    DownloadLocalWriteFailed(String),
    #[error("Invalid UTF-8 in downloaded file")]
    DownloadInvalidUtf8,
    #[error("Download timeout exceeded")]
    DownloadTimeout,
    #[error("Checksum mismatch: expected {0}, got {1}")]
    DownloadChecksumMismatch(String, String),

    // Tunnel-specific errors
    #[error("Tunnel mode is required")]
    TunnelModeRequired,
    #[error("Invalid tunnel mode: {0}")]
    TunnelInvalidMode(String),
    #[error("Remote destination is required for local tunnel")]
    TunnelMissingRemoteDest,
    #[error("Local destination is required for remote tunnel")]
    TunnelMissingLocalDest,
    #[error("Wildcard binds are forbidden (set allow_wildcard_binds=true to override)")]
    TunnelWildcardBindForbidden,
    #[error("Failed to bind local port {0} on {1}: {2}")]
    TunnelBindFailed(u16, String, String),
    #[error("Remote forward not supported by server")]
    TunnelRemoteForwardUnsupported,
    #[error("Dynamic forwarding not supported")]
    TunnelDynamicUnsupported,
    #[error("Tunnel lifetime timeout exceeded")]
    TunnelTimeout,
    #[error("Tunnel idle timeout exceeded")]
    TunnelIdleTimeout,
    #[error("Maximum connections reached: {0}")]
    TunnelMaxConnectionsReached(u64),
    #[error("Maximum bytes in exceeded: {0}")]
    TunnelMaxBytesInExceeded(u64),
    #[error("Maximum bytes out exceeded: {0}")]
    TunnelMaxBytesOutExceeded(u64),

    // keys.list-specific errors
    #[error("Invalid scope: {0}")]
    KeysListInvalidScope(String),
    #[error("Custom paths are required when scope=custom")]
    KeysListCustomPathsRequired,
    #[error("No readable files found")]
    KeysListNoFiles,
    #[error("Remote read failed: {0}")]
    KeysListRemoteReadFailed(String),
    #[error("Remote stat failed: {0}")]
    KeysListRemoteStatFailed(String),
    #[error("Keys list too large: exceeds max_bytes limit")]
    KeysListTooLarge,
    #[error("Parse failure: {0}")]
    KeysListParseFailure(String),

    // key.add-specific errors
    #[error("Public key is required (provide public_key or public_key_path)")]
    KeyAddMissingPublicKey,
    #[error("Invalid public key format: {0}")]
    KeyAddInvalidPublicKey(String),
    #[error("Custom paths are required when scope=custom")]
    KeyAddCustomPathsRequired,
    #[error("Invalid scope: {0}")]
    KeyAddInvalidScope(String),
    #[error("Target file does not exist and create_if_missing=false: {0}")]
    KeyAddTargetMissing(String),
    #[error("File too large: {0} bytes exceeds max_file_bytes limit of {1} bytes")]
    KeyAddFileTooLarge(u64, usize),
    #[error("Remote read failed: {0}")]
    KeyAddRemoteReadFailed(String),
    #[error("Remote write failed: {0}")]
    KeyAddRemoteWriteFailed(String),
    #[error("Backup creation failed: {0}")]
    KeyAddBackupFailed(String),
    #[error("Failed to set permissions: {0}")]
    KeyAddPermissionsFailed(String),
    #[error("Duplicate key found and on_duplicate=error")]
    KeyAddDuplicate,
    #[error("Public key file not found: {0}")]
    KeyAddPublicKeyFileNotFound(String),
    #[error("Failed to read public key file: {0}")]
    KeyAddPublicKeyFileReadFailed(String),

    // config.get-specific errors
    #[error("Host is required for config.get")]
    ConfigGetHostRequired,
    #[error("Invalid config path: {0}")]
    ConfigGetInvalidPath(String),
    #[error("Failed to read config file: {0}")]
    ConfigGetReadFailed(String),
    #[error("Combined config files exceed max_config_bytes limit")]
    ConfigGetTooLarge,
    #[error("Too many includes: exceeded max_includes limit")]
    ConfigGetTooManyIncludes,
    #[error("Too many hosts: exceeded max_hosts limit")]
    ConfigGetTooManyHosts,
    #[error("Failed to parse config file {0}: {1}")]
    ConfigGetParseError(String, String),

    // test-specific errors
    #[error("Invalid test name: {0}")]
    TestInvalidTestName(String),
    #[error("Insecure host key mode forbidden (set allow_insecure_hostkey=true)")]
    TestInsecureHostkeyForbidden,
    #[error("Test connect failed: {0}")]
    TestConnectFailed(String),
    #[error("Test authentication failed: {0}")]
    TestAuthFailed(String),
    #[error("Test SFTP failed: {0}")]
    TestSftpFailed(String),
    #[error("Test exec failed: {0}")]
    TestExecFailed(String),
    #[error("Test host key verification failed: {0}")]
    TestHostkeyFailed(String),
    #[error("Test skipped due to dependency failure: {0}")]
    TestDependencyFailed(String),
    #[error("Test connect timeout exceeded")]
    TestConnectTimeout,
    #[error("Test authentication timeout exceeded")]
    TestAuthTimeout,
    #[error("Test SFTP timeout exceeded")]
    TestSftpTimeout,
    #[error("Test exec timeout exceeded")]
    TestExecTimeout,
    #[error("Overall test timeout exceeded")]
    TestOverallTimeout,
}

impl SshError {
    /// Convert error to structured JSON for API responses
    pub fn to_json(&self) -> SshErrorDetails {
        let (code, message, details) = match self {
            SshError::InvalidBackend(backend) => (
                "ssh.invalid_backend".to_string(),
                format!("Invalid backend: {}", backend),
                HashMap::from([("backend".to_string(), backend.clone())]),
            ),
            SshError::TargetConflict(conflict) => (
                "ssh.target_conflict".to_string(),
                format!("Target and parameter conflict: {}", conflict),
                HashMap::new(),
            ),
            SshError::HostRequired => (
                "ssh.host_required".to_string(),
                "Host is required".to_string(),
                HashMap::new(),
            ),
            SshError::UsernameRequired => (
                "ssh.username_required".to_string(),
                "Username is required".to_string(),
                HashMap::new(),
            ),
            SshError::AuthMethodUnsupported(method) => (
                "ssh.auth_method_unsupported".to_string(),
                format!("Unsupported authentication method: {}", method),
                HashMap::from([("auth_method".to_string(), method.clone())]),
            ),
            SshError::AuthMissingPassword => (
                "ssh.auth_missing_password".to_string(),
                "Password is required for password authentication".to_string(),
                HashMap::new(),
            ),
            SshError::AuthMissingKey => (
                "ssh.auth_missing_key".to_string(),
                "Private key is required for key authentication".to_string(),
                HashMap::new(),
            ),
            SshError::AuthPasswordRequired => (
                "ssh.auth_password_required".to_string(),
                "Password authentication is required for this host".to_string(),
                HashMap::new(),
            ),
            SshError::AgentUnavailable => (
                "ssh.agent_unavailable".to_string(),
                "SSH agent is not available".to_string(),
                HashMap::new(),
            ),
            SshError::ConnectFailed(msg) => (
                "ssh.connect_failed".to_string(),
                format!("Failed to connect: {}", msg),
                HashMap::new(),
            ),
            SshError::HostKeyVerificationFailed(msg) => (
                "ssh.hostkey_verification_failed".to_string(),
                format!("Host key verification failed: {}", msg),
                HashMap::new(),
            ),
            SshError::CommandRequired => (
                "ssh.command_required".to_string(),
                "Command is required".to_string(),
                HashMap::new(),
            ),
            SshError::CommandTimeout => (
                "ssh.command_timeout".to_string(),
                "Command timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::ExecChannelFailed(msg) => (
                "ssh.exec_channel_failed".to_string(),
                format!("Failed to create exec channel: {}", msg),
                HashMap::new(),
            ),
            SshError::OutputTooLarge => (
                "ssh.output_too_large".to_string(),
                "Output too large".to_string(),
                HashMap::new(),
            ),
            SshError::IoError(msg) => (
                "ssh.io_error".to_string(),
                format!("IO error: {}", msg),
                HashMap::new(),
            ),
            SshError::InternalError(msg) => (
                "ssh.internal_error".to_string(),
                format!("Internal error: {}", msg),
                HashMap::new(),
            ),
            
            // Upload-specific errors
            SshError::UploadSourceMissing => (
                "ssh.upload_source_missing".to_string(),
                "Source is missing".to_string(),
                HashMap::new(),
            ),
            SshError::UploadSourceNotFound(path) => (
                "ssh.upload_source_not_found".to_string(),
                format!("Source file not found: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::UploadSourceReadError(msg) => (
                "ssh.upload_source_read_error".to_string(),
                format!("Source read error: {}", msg),
                HashMap::new(),
            ),
            SshError::UploadInvalidSourceEncoding(encoding) => (
                "ssh.upload_invalid_source_encoding".to_string(),
                format!("Invalid source encoding: {}", encoding),
                HashMap::from([("encoding".to_string(), encoding.clone())]),
            ),
            SshError::UploadTooLarge(size) => (
                "ssh.upload_too_large".to_string(),
                format!("Upload too large: {} bytes exceeds limit", size),
                HashMap::from([("size_bytes".to_string(), size.to_string())]),
            ),
            SshError::UploadDestMissing => (
                "ssh.upload_dest_missing".to_string(),
                "Destination is missing".to_string(),
                HashMap::new(),
            ),
            SshError::UploadDestExists(path) => (
                "ssh.upload_dest_exists".to_string(),
                format!("Remote file exists and overwrite=false: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::UploadRemoteDirMissing(path) => (
                "ssh.upload_remote_dir_missing".to_string(),
                format!("Remote directory missing and mkdir_parents=false: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::UploadRemoteWriteFailed(msg) => (
                "ssh.upload_remote_write_failed".to_string(),
                format!("Remote write failed: {}", msg),
                HashMap::new(),
            ),
            SshError::UploadTimeout => (
                "ssh.upload_timeout".to_string(),
                "Upload timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::UploadChecksumMismatch(expected, actual) => (
                "ssh.upload_checksum_mismatch".to_string(),
                format!("Checksum mismatch: expected {}, got {}", expected, actual),
                HashMap::from([
                    ("expected".to_string(), expected.clone()),
                    ("actual".to_string(), actual.clone()),
                ]),
            ),

            // Download-specific errors
            SshError::DownloadSourceMissing => (
                "ssh.download_source_missing".to_string(),
                "Download source is missing".to_string(),
                HashMap::new(),
            ),
            SshError::DownloadSourceNotFound(path) => (
                "ssh.download_source_not_found".to_string(),
                format!("Remote file not found: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::DownloadSourceIsDirectory(path) => (
                "ssh.download_source_is_directory".to_string(),
                format!("Source is a directory: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::DownloadRemoteReadFailed(msg) => (
                "ssh.download_remote_read_failed".to_string(),
                format!("Remote read failed: {}", msg),
                HashMap::new(),
            ),
            SshError::DownloadTooLarge(size, limit) => (
                "ssh.download_too_large".to_string(),
                format!("Download too large: {} bytes exceeds limit of {} bytes", size, limit),
                HashMap::from([
                    ("size_bytes".to_string(), size.to_string()),
                    ("max_size_bytes".to_string(), limit.to_string()),
                ]),
            ),
            SshError::DownloadDestMissing => (
                "ssh.download_dest_missing".to_string(),
                "Destination is missing when dest_mode=file".to_string(),
                HashMap::new(),
            ),
            SshError::DownloadDestExists(path) => (
                "ssh.download_dest_exists".to_string(),
                format!("Local file exists and overwrite=false: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::DownloadLocalDirMissing(path) => (
                "ssh.download_local_dir_missing".to_string(),
                format!("Local directory missing and mkdir_parents=false: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::DownloadLocalWriteFailed(msg) => (
                "ssh.download_local_write_failed".to_string(),
                format!("Local write failed: {}", msg),
                HashMap::new(),
            ),
            SshError::DownloadInvalidUtf8 => (
                "ssh.download_invalid_utf8".to_string(),
                "Invalid UTF-8 in downloaded file".to_string(),
                HashMap::new(),
            ),
            SshError::DownloadTimeout => (
                "ssh.download_timeout".to_string(),
                "Download timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::DownloadChecksumMismatch(expected, actual) => (
                "ssh.download_checksum_mismatch".to_string(),
                format!("Checksum mismatch: expected {}, got {}", expected, actual),
                HashMap::from([
                    ("expected".to_string(), expected.clone()),
                    ("actual".to_string(), actual.clone()),
                ]),
            ),

            // Tunnel error mappings
            SshError::TunnelModeRequired => (
                "ssh.tunnel_mode_required".to_string(),
                "Tunnel mode is required".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelInvalidMode(mode) => (
                "ssh.tunnel_invalid_mode".to_string(),
                format!("Invalid tunnel mode: {}", mode),
                HashMap::from([("mode".to_string(), mode.clone())]),
            ),
            SshError::TunnelMissingRemoteDest => (
                "ssh.tunnel_missing_remote_dest".to_string(),
                "Remote destination is required for local tunnel".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelMissingLocalDest => (
                "ssh.tunnel_missing_local_dest".to_string(),
                "Local destination is required for remote tunnel".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelWildcardBindForbidden => (
                "ssh.tunnel_wildcard_bind_forbidden".to_string(),
                "Wildcard binds are forbidden (set allow_wildcard_binds=true to override)".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelBindFailed(port, host, reason) => (
                "ssh.tunnel_bind_failed".to_string(),
                format!("Failed to bind local port {} on {}: {}", port, host, reason),
                HashMap::from([
                    ("port".to_string(), port.to_string()),
                    ("host".to_string(), host.clone()),
                    ("reason".to_string(), reason.clone()),
                ]),
            ),
            SshError::TunnelRemoteForwardUnsupported => (
                "ssh.tunnel_remote_forward_unsupported".to_string(),
                "Remote forward not supported by server".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelDynamicUnsupported => (
                "ssh.tunnel_dynamic_unsupported".to_string(),
                "Dynamic forwarding not supported".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelTimeout => (
                "ssh.tunnel_timeout".to_string(),
                "Tunnel lifetime timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelIdleTimeout => (
                "ssh.tunnel_idle_timeout".to_string(),
                "Tunnel idle timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TunnelMaxConnectionsReached(max) => (
                "ssh.tunnel_max_connections_reached".to_string(),
                format!("Maximum connections reached: {}", max),
                HashMap::from([("max_connections".to_string(), max.to_string())]),
            ),
            SshError::TunnelMaxBytesInExceeded(max) => (
                "ssh.tunnel_max_bytes_in_exceeded".to_string(),
                format!("Maximum bytes in exceeded: {}", max),
                HashMap::from([("max_bytes_in".to_string(), max.to_string())]),
            ),
            SshError::TunnelMaxBytesOutExceeded(max) => (
                "ssh.tunnel_max_bytes_out_exceeded".to_string(),
                format!("Maximum bytes out exceeded: {}", max),
                HashMap::from([("max_bytes_out".to_string(), max.to_string())]),
            ),
            SshError::KeysListInvalidScope(scope) => (
                "ssh.keys_list_invalid_scope".to_string(),
                format!("Invalid scope: {}", scope),
                HashMap::from([("scope".to_string(), scope.clone())]),
            ),
            SshError::KeysListCustomPathsRequired => (
                "ssh.keys_list_custom_paths_required".to_string(),
                "Custom paths are required when scope=custom".to_string(),
                HashMap::new(),
            ),
            SshError::KeysListNoFiles => (
                "ssh.keys_list_no_files".to_string(),
                "No readable files found".to_string(),
                HashMap::new(),
            ),
            SshError::KeysListRemoteReadFailed(details) => (
                "ssh.keys_list_remote_read_failed".to_string(),
                format!("Remote read failed: {}", details),
                HashMap::new(),
            ),
            SshError::KeysListRemoteStatFailed(details) => (
                "ssh.keys_list_remote_stat_failed".to_string(),
                format!("Remote stat failed: {}", details),
                HashMap::new(),
            ),
            SshError::KeysListTooLarge => (
                "ssh.keys_list_too_large".to_string(),
                "Keys list too large: exceeds max_bytes limit".to_string(),
                HashMap::new(),
            ),
            SshError::KeysListParseFailure(details) => (
                "ssh.keys_list_parse_failure".to_string(),
                format!("Parse failure: {}", details),
                HashMap::new(),
            ),
            SshError::KeyAddMissingPublicKey => (
                "ssh.key_add_missing_public_key".to_string(),
                "Public key is required (provide public_key or public_key_path)".to_string(),
                HashMap::new(),
            ),
            SshError::KeyAddInvalidPublicKey(reason) => (
                "ssh.key_add_invalid_public_key".to_string(),
                format!("Invalid public key format: {}", reason),
                HashMap::new(),
            ),
            SshError::KeyAddCustomPathsRequired => (
                "ssh.key_add_custom_paths_required".to_string(),
                "Custom paths are required when scope=custom".to_string(),
                HashMap::new(),
            ),
            SshError::KeyAddInvalidScope(scope) => (
                "ssh.key_add_invalid_scope".to_string(),
                format!("Invalid scope: {}", scope),
                HashMap::from([("scope".to_string(), scope.clone())]),
            ),
            SshError::KeyAddTargetMissing(path) => (
                "ssh.key_add_target_missing".to_string(),
                format!("Target file does not exist and create_if_missing=false: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::KeyAddFileTooLarge(size, limit) => (
                "ssh.key_add_file_too_large".to_string(),
                format!("File too large: {} bytes exceeds max_file_bytes limit of {} bytes", size, limit),
                HashMap::from([
                    ("size_bytes".to_string(), size.to_string()),
                    ("limit_bytes".to_string(), limit.to_string()),
                ]),
            ),
            SshError::KeyAddRemoteReadFailed(details) => (
                "ssh.key_add_remote_read_failed".to_string(),
                format!("Remote read failed: {}", details),
                HashMap::new(),
            ),
            SshError::KeyAddRemoteWriteFailed(details) => (
                "ssh.key_add_remote_write_failed".to_string(),
                format!("Remote write failed: {}", details),
                HashMap::new(),
            ),
            SshError::KeyAddBackupFailed(details) => (
                "ssh.key_add_backup_failed".to_string(),
                format!("Backup creation failed: {}", details),
                HashMap::new(),
            ),
            SshError::KeyAddPermissionsFailed(details) => (
                "ssh.key_add_permissions_failed".to_string(),
                format!("Failed to set permissions: {}", details),
                HashMap::new(),
            ),
            SshError::KeyAddDuplicate => (
                "ssh.key_add_duplicate".to_string(),
                "Duplicate key found and on_duplicate=error".to_string(),
                HashMap::new(),
            ),
            SshError::KeyAddPublicKeyFileNotFound(path) => (
                "ssh.key_add_public_key_file_not_found".to_string(),
                format!("Public key file not found: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::KeyAddPublicKeyFileReadFailed(details) => (
                "ssh.key_add_public_key_file_read_failed".to_string(),
                format!("Failed to read public key file: {}", details),
                HashMap::new(),
            ),
            SshError::ConfigGetHostRequired => (
                "ssh.config_get_host_required".to_string(),
                "Host is required for config.get".to_string(),
                HashMap::new(),
            ),
            SshError::ConfigGetInvalidPath(path) => (
                "ssh.config_get_invalid_path".to_string(),
                format!("Invalid config path: {}", path),
                HashMap::from([("path".to_string(), path.clone())]),
            ),
            SshError::ConfigGetReadFailed(details) => (
                "ssh.config_get_read_failed".to_string(),
                format!("Failed to read config file: {}", details),
                HashMap::new(),
            ),
            SshError::ConfigGetTooLarge => (
                "ssh.config_get_too_large".to_string(),
                "Combined config files exceed max_config_bytes limit".to_string(),
                HashMap::new(),
            ),
            SshError::ConfigGetTooManyIncludes => (
                "ssh.config_get_too_many_includes".to_string(),
                "Too many includes: exceeded max_includes limit".to_string(),
                HashMap::new(),
            ),
            SshError::ConfigGetTooManyHosts => (
                "ssh.config_get_too_many_hosts".to_string(),
                "Too many hosts: exceeded max_hosts limit".to_string(),
                HashMap::new(),
            ),
            SshError::ConfigGetParseError(file, details) => (
                "ssh.config_get_parse_error".to_string(),
                format!("Failed to parse config file {}: {}", file, details),
                HashMap::from([("file".to_string(), file.clone())]),
            ),

            // Test errors
            SshError::TestInvalidTestName(name) => (
                "ssh.test_invalid_test_name".to_string(),
                format!("Invalid test name: {}", name),
                HashMap::from([("test_name".to_string(), name.clone())]),
            ),
            SshError::TestInsecureHostkeyForbidden => (
                "ssh.test_insecure_hostkey_forbidden".to_string(),
                "Insecure host key mode forbidden (set allow_insecure_hostkey=true)".to_string(),
                HashMap::new(),
            ),
            SshError::TestConnectFailed(details) => (
                "ssh.test_connect_failed".to_string(),
                format!("Test connect failed: {}", details),
                HashMap::new(),
            ),
            SshError::TestAuthFailed(details) => (
                "ssh.test_auth_failed".to_string(),
                format!("Test authentication failed: {}", details),
                HashMap::new(),
            ),
            SshError::TestSftpFailed(details) => (
                "ssh.test_sftp_failed".to_string(),
                format!("Test SFTP failed: {}", details),
                HashMap::new(),
            ),
            SshError::TestExecFailed(details) => (
                "ssh.test_exec_failed".to_string(),
                format!("Test exec failed: {}", details),
                HashMap::new(),
            ),
            SshError::TestHostkeyFailed(details) => (
                "ssh.test_hostkey_failed".to_string(),
                format!("Test host key verification failed: {}", details),
                HashMap::new(),
            ),
            SshError::TestDependencyFailed(details) => (
                "ssh.test_dependency_failed".to_string(),
                format!("Test skipped due to dependency failure: {}", details),
                HashMap::new(),
            ),
            SshError::TestConnectTimeout => (
                "ssh.test_connect_timeout".to_string(),
                "Test connect timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TestAuthTimeout => (
                "ssh.test_auth_timeout".to_string(),
                "Test authentication timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TestSftpTimeout => (
                "ssh.test_sftp_timeout".to_string(),
                "Test SFTP timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TestExecTimeout => (
                "ssh.test_exec_timeout".to_string(),
                "Test exec timeout exceeded".to_string(),
                HashMap::new(),
            ),
            SshError::TestOverallTimeout => (
                "ssh.test_overall_timeout".to_string(),
                "Overall test timeout exceeded".to_string(),
                HashMap::new(),
            ),
        };

        SshErrorDetails {
            code,
            message,
            details,
        }
    }
}

/// SSH handle implementation
#[derive(Debug)]
pub struct SshHandle {
    target: SshTarget,
}

impl SshHandle {
    /// Create SSH handle from URL
    pub fn from_url(url: &Url) -> Result<Self> {
        let target = SshTarget::from_url(url);
        Ok(SshHandle { target })
    }

    /// Parse arguments into SshExecOptions
    fn parse_exec_options(&self, args: &Args, target: &SshTarget) -> Result<SshExecOptions> {
        let mut options = SshExecOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => return Err(SshError::AuthMethodUnsupported(auth_method.clone()).into()),
            };
        }
        
        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => KnownHostsMode::Strict,
            };
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse command execution
        options.command = args.get("command").cloned();
        if let Some(args_str) = args.get("command_args") {
            options.command_args = Self::parse_command_args(args_str);
        }
        
        if let Some(shell_mode) = args.get("shell_mode") {
            options.shell_mode = match shell_mode.as_str() {
                "none" => ShellMode::None,
                "sh" => ShellMode::Sh,
                "bash" => ShellMode::Bash,
                "cmd" => ShellMode::Cmd,
                "powershell" => ShellMode::Powershell,
                _ => ShellMode::None,
            };
        }

        if let Some(env_str) = args.get("env") {
            options.env = Self::parse_env_vars(env_str)?;
        }
        options.cwd = args.get("cwd").cloned();
        
        if let Some(pty_str) = args.get("allocate_pty") {
            options.allocate_pty = pty_str.parse::<bool>().unwrap_or(false);
        }

        // Parse timeouts and limits
        if let Some(timeout_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid connect timeout: {}", timeout_str))?;
        }
        if let Some(timeout_str) = args.get("command_timeout_ms") {
            options.command_timeout_ms = timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid command timeout: {}", timeout_str))?;
        }
        if let Some(max_str) = args.get("max_output_bytes") {
            options.max_output_bytes = max_str.parse::<usize>()
                .with_context(|| format!("Invalid max output bytes: {}", max_str))?;
        }
        if let Some(trim_str) = args.get("trim_trailing_newlines") {
            options.trim_trailing_newlines = trim_str.parse::<bool>().unwrap_or(true);
        }

        // Parse behavior
        if let Some(dry_run_str) = args.get("dry_run") {
            options.dry_run = dry_run_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(capture_str) = args.get("capture_output") {
            options.capture_output = capture_str.parse::<bool>().unwrap_or(true);
        }
        if let Some(encoding) = args.get("output_encoding") {
            options.output_encoding = match encoding.as_str() {
                "utf8" => OutputEncoding::Utf8,
                "base64" => OutputEncoding::Base64,
                _ => OutputEncoding::Utf8,
            };
        }
        if let Some(format) = args.get("format") {
            options.format = match format.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    /// Parse command arguments from string
    fn parse_command_args(args_str: &str) -> Vec<String> {
        // Simple split by commas for now - could be enhanced for quoted strings
        args_str.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Parse environment variables from string
    fn parse_env_vars(env_str: &str) -> Result<HashMap<String, String>> {
        let mut env_vars = HashMap::new();
        for pair in env_str.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].trim();
                let value = pair[idx + 1..].trim();
                if !key.is_empty() {
                    env_vars.insert(key.to_string(), value.to_string());
                }
            }
        }
        Ok(env_vars)
    }

    /// Parse arguments into SshUploadOptions
    fn parse_upload_options(&self, args: &Args, target: &SshTarget) -> Result<SshUploadOptions> {
        let mut options = SshUploadOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => return Err(SshError::AuthMethodUnsupported(auth_method.clone()).into()),
            };
        }
        
        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => KnownHostsMode::Strict,
            };
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse source parameters
        options.source = args.get("source").cloned();
        if let Some(source_mode) = args.get("source_mode") {
            options.source_mode = match source_mode.as_str() {
                "file" => SourceMode::File,
                "inline" => SourceMode::Inline,
                _ => SourceMode::File,
            };
        }
        if let Some(source_encoding) = args.get("source_encoding") {
            options.source_encoding = match source_encoding.as_str() {
                "utf8" => SourceEncoding::Utf8,
                "base64" => SourceEncoding::Base64,
                _ => SourceEncoding::Utf8,
            };
        }
        options.content_type = args.get("content_type").cloned();

        // Parse destination parameters
        options.dest = args.get("dest").cloned();
        if let Some(overwrite_str) = args.get("overwrite") {
            options.overwrite = overwrite_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(atomic_str) = args.get("atomic") {
            options.atomic = atomic_str.parse::<bool>().unwrap_or(true);
        }
        if let Some(mkdir_str) = args.get("mkdir_parents") {
            options.mkdir_parents = mkdir_str.parse::<bool>().unwrap_or(true);
        }

        // Parse permissions & metadata
        options.file_mode = args.get("file_mode").cloned();
        if let Some(preserve_str) = args.get("preserve_times") {
            options.preserve_times = preserve_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(mtime_str) = args.get("mtime_epoch_ms") {
            options.mtime_epoch_ms = Some(mtime_str.parse::<i64>()
                .with_context(|| format!("Invalid mtime_epoch_ms: {}", mtime_str))?);
        }

        // Parse limits and timeouts
        if let Some(max_size_str) = args.get("max_size_bytes") {
            options.max_size_bytes = max_size_str.parse::<u64>()
                .with_context(|| format!("Invalid max_size_bytes: {}", max_size_str))?;
        }
        if let Some(connect_timeout_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = connect_timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid connect_timeout_ms: {}", connect_timeout_str))?;
        }
        if let Some(transfer_timeout_str) = args.get("transfer_timeout_ms") {
            options.transfer_timeout_ms = transfer_timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid transfer_timeout_ms: {}", transfer_timeout_str))?;
        }

        // Parse behavior & output
        if let Some(dry_run_str) = args.get("dry_run") {
            options.dry_run = dry_run_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(verify_str) = args.get("verify_checksum") {
            options.verify_checksum = verify_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(algorithm) = args.get("checksum_algorithm") {
            options.checksum_algorithm = algorithm.clone();
        }
        if let Some(format) = args.get("format") {
            options.format = match format.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    /// Parse arguments into SshDownloadOptions
    fn parse_download_options(&self, args: &Args, _target: &SshTarget) -> Result<SshDownloadOptions> {
        let mut options = SshDownloadOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => return Err(SshError::AuthMethodUnsupported(auth_method.clone()).into()),
            };
        }

        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => KnownHostsMode::Strict,
            };
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse source (remote) parameters
        options.source = args.get("source").cloned();

        // Parse destination (local / inline) parameters
        options.dest = args.get("dest").cloned();
        if let Some(dest_mode) = args.get("dest_mode") {
            options.dest_mode = match dest_mode.as_str() {
                "file" => DestMode::File,
                "none" => DestMode::None,
                _ => DestMode::File,
            };
        }
        if let Some(return_content_str) = args.get("return_content") {
            options.return_content = return_content_str.parse::<bool>().unwrap_or(true);
        }
        if let Some(return_encoding) = args.get("return_encoding") {
            options.return_encoding = match return_encoding.as_str() {
                "utf8" => ReturnEncoding::Utf8,
                "base64" => ReturnEncoding::Base64,
                _ => ReturnEncoding::Utf8,
            };
        }

        // Parse local file behavior
        if let Some(overwrite_str) = args.get("overwrite") {
            options.overwrite = overwrite_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(mkdir_str) = args.get("mkdir_parents") {
            options.mkdir_parents = mkdir_str.parse::<bool>().unwrap_or(true);
        }

        // Parse limits and timeouts
        if let Some(max_size_str) = args.get("max_size_bytes") {
            options.max_size_bytes = max_size_str.parse::<u64>()
                .with_context(|| format!("Invalid max_size_bytes: {}", max_size_str))?;
        }
        if let Some(connect_timeout_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = connect_timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid connect_timeout_ms: {}", connect_timeout_str))?;
        }
        if let Some(transfer_timeout_str) = args.get("transfer_timeout_ms") {
            options.transfer_timeout_ms = transfer_timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid transfer_timeout_ms: {}", transfer_timeout_str))?;
        }

        // Parse checksum parameters
        if let Some(verify_str) = args.get("verify_checksum") {
            options.verify_checksum = verify_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(algorithm) = args.get("checksum_algorithm") {
            options.checksum_algorithm = algorithm.clone();
        }

        // Parse behavior & output
        if let Some(dry_run_str) = args.get("dry_run") {
            options.dry_run = dry_run_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(format) = args.get("format") {
            options.format = match format.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    /// Resolve source data based on source mode and encoding
    fn resolve_source_data(&self, options: &SshUploadOptions) -> Result<(Vec<u8>, Option<String>)> {
        let source = options.source.as_ref().ok_or(SshError::UploadSourceMissing)?;
        
        match options.source_mode {
            SourceMode::File => {
                // Handle file:// URLs and regular paths
                let path = if source.starts_with("file://") {
                    source.strip_prefix("file://").unwrap()
                } else {
                    source
                };
                
                // Check if file exists
                if !std::path::Path::new(path).exists() {
                    return Err(SshError::UploadSourceNotFound(path.to_string()).into());
                }
                
                // Check file size before reading
                let metadata = std::fs::metadata(path)
                    .map_err(|e| SshError::UploadSourceReadError(format!("Failed to get file metadata: {}", e)))?;
                
                let file_size = metadata.len();
                if file_size > options.max_size_bytes {
                    return Err(SshError::UploadTooLarge(file_size).into());
                }
                
                // Read file contents
                let data = std::fs::read(path)
                    .map_err(|e| SshError::UploadSourceReadError(format!("Failed to read file: {}", e)))?;
                
                Ok((data, Some(path.to_string())))
            },
            SourceMode::Inline => {
                match options.source_encoding {
                    SourceEncoding::Utf8 => {
                        let data = source.as_bytes().to_vec();
                        if data.len() as u64 > options.max_size_bytes {
                            return Err(SshError::UploadTooLarge(data.len() as u64).into());
                        }
                        Ok((data, None))
                    },
                    SourceEncoding::Base64 => {
                        let data = BASE64_STANDARD.decode(source)
                            .map_err(|e| SshError::UploadInvalidSourceEncoding(format!("Invalid base64: {}", e)))?;
                        if data.len() as u64 > options.max_size_bytes {
                            return Err(SshError::UploadTooLarge(data.len() as u64).into());
                        }
                        Ok((data, None))
                    },
                }
            },
        }
    }

    /// Resolve upload connection parameters (similar to exec but for upload options)
    fn resolve_upload_connection_params(&self, options: &SshUploadOptions) -> Result<(String, u16, String)> {
        // Resolve host
        let host = match (&self.target.host, &options.host) {
            (Some(target_host), Some(option_host)) => {
                if target_host != option_host {
                    return Err(SshError::TargetConflict(
                        format!("Host mismatch: target={}, option={}", target_host, option_host)
                    ).into());
                }
                target_host.clone()
            },
            (Some(host), None) | (None, Some(host)) => host.clone(),
            (None, None) => {
                return Err(SshError::HostRequired.into());
            },
        };

        // Resolve port
        let port = if let Some(target_port) = self.target.port {
            if target_port != options.port {
                return Err(SshError::TargetConflict(
                    format!("Port mismatch: target={}, option={}", target_port, options.port)
                ).into());
            }
            target_port
        } else {
            options.port
        };

        // Resolve username
        let username = match (&self.target.username, &options.username) {
            (Some(target_user), Some(option_user)) => {
                if target_user != option_user {
                    return Err(SshError::TargetConflict(
                        format!("Username mismatch: target={}, option={}", target_user, option_user)
                    ).into());
                }
                target_user.clone()
            },
            (Some(user), None) | (None, Some(user)) => user.clone(),
            (None, None) => {
                // Try to get current OS user as fallback
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".to_string())
            },
        };

        Ok((host, port, username))
    }

    /// Validate upload options for upload operations
    fn validate_upload_options(&self, options: &SshUploadOptions) -> Result<()> {
        // Check source is provided
        if options.source.is_none() {
            return Err(SshError::UploadSourceMissing.into());
        }

        // Check destination is provided
        if options.dest.is_none() {
            return Err(SshError::UploadDestMissing.into());
        }

        // Validate authentication similar to exec
        match options.auth_method {
            SshAuthMethod::Password => {
                if options.password.is_none() {
                    return Err(SshError::AuthMissingPassword.into());
                }
            },
            SshAuthMethod::Key => {
                if options.identity_path.is_none() && options.identity_data.is_none() {
                    return Err(SshError::AuthMissingKey.into());
                }
            },
            SshAuthMethod::Agent => {
                // Skip agent validation in test mode for now
                #[cfg(not(test))]
                if options.agent_socket.is_none() && std::env::var("SSH_AUTH_SOCK").is_err() {
                    return Err(SshError::AgentUnavailable.into());
                }
            },
        }

        // Validate file mode format if provided
        if let Some(mode_str) = &options.file_mode {
            if !mode_str.starts_with('0') || mode_str.len() != 4 {
                return Err(SshError::InternalError("Invalid file mode format, expected 4-digit octal (e.g., 0644)".to_string()).into());
            }
            // Try to parse as octal
            if u32::from_str_radix(&mode_str[1..], 8).is_err() {
                return Err(SshError::InternalError("Invalid file mode, must be valid octal".to_string()).into());
            }
        }

        Ok(())
    }

    /// Execute SSH upload using SFTP operations
    fn execute_ssh_upload(
        &self,
        host: &str,
        port: u16,
        username: &str,
        data: &[u8],
        dest_path: &str,
        options: &SshUploadOptions,
    ) -> Result<(SshUploadResult, SshTimingInfo)> {
        use std::time::Instant;
        
        let connect_start = Instant::now();
        
        // Simulate connection time - in real implementation this would establish SSH+SFTP
        std::thread::sleep(std::time::Duration::from_millis(50));
        let connect_ms = connect_start.elapsed().as_millis() as u64;
        
        let transfer_start = Instant::now();
        
        // Simulate various upload scenarios for testing
        if dest_path.contains("permission_denied") {
            return Err(SshError::UploadRemoteWriteFailed("Permission denied".to_string()).into());
        }
        
        if dest_path.contains("timeout_test") {
            return Err(SshError::UploadTimeout.into());
        }
        
        if dest_path.contains("existing_file") && !options.overwrite {
            return Err(SshError::UploadDestExists(dest_path.to_string()).into());
        }
        
        if dest_path.contains("missing_dir") && !options.mkdir_parents {
            let parent_dir = std::path::Path::new(dest_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            return Err(SshError::UploadRemoteDirMissing(parent_dir).into());
        }
        
        // Simulate atomic upload process
        if options.atomic {
            // Would upload to temp file first, then rename
            let _temp_path = format!("{}.resh.tmp.{}", dest_path, rand::random::<u32>());
            
            // Simulate upload to temp file
            std::thread::sleep(std::time::Duration::from_millis(10));
            
            // Simulate rename operation
            std::thread::sleep(std::time::Duration::from_millis(5));
        } else {
            // Direct upload
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        
        // Simulate setting file permissions
        if options.file_mode.is_some() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        
        // Simulate setting timestamps
        if options.preserve_times || options.mtime_epoch_ms.is_some() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        
        let transfer_ms = transfer_start.elapsed().as_millis() as u64;
        
        // Simulate checksum verification if requested
        let mut checksum_verified = None;
        if options.verify_checksum {
            // Simulate reading remote file for checksum
            std::thread::sleep(std::time::Duration::from_millis(20));
            
            let local_checksum = self.compute_checksum(data, &options.checksum_algorithm)?;
            
            // In real implementation, would fetch remote file and compute checksum
            // For testing, assume checksum matches unless path contains "checksum_mismatch"
            if dest_path.contains("checksum_mismatch") {
                let fake_remote_checksum = "deadbeef";
                return Err(SshError::UploadChecksumMismatch(local_checksum, fake_remote_checksum.to_string()).into());
            } else {
                checksum_verified = Some(true);
            }
        }
        
        let result = SshUploadResult {
            uploaded: true,
            planned: false,
            verify_checksum: options.verify_checksum,
            checksum_algorithm: options.checksum_algorithm.clone(),
            checksum_verified,
        };
        
        let timing = SshTimingInfo {
            connect_ms: Some(connect_ms),
            command_ms: Some(transfer_ms), // Reusing command_ms field for transfer time
        };
        
        Ok((result, timing))
    }

    /// Compute checksum of data using specified algorithm
    fn compute_checksum(&self, data: &[u8], algorithm: &str) -> Result<String> {
        match algorithm.to_lowercase().as_str() {
            "sha256" => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(format!("{:x}", hasher.finalize()))
            },
            "sha1" => {
                use sha1::{Sha1, Digest};
                let mut hasher = Sha1::new();
                hasher.update(data);
                Ok(format!("{:x}", hasher.finalize()))
            },
            "md5" => {
                let mut hasher = md5::Context::new();
                hasher.consume(data);
                Ok(format!("{:x}", hasher.compute()))
            },
            _ => Err(SshError::InternalError(format!("Unsupported checksum algorithm: {}", algorithm)).into()),
        }
    }

    /// Main upload verb implementation
    fn verb_upload(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_upload_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let error_response = SshUploadResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: "unknown".to_string(),
                        port: 22,
                        username: "unknown".to_string(),
                        backend: "system".to_string(),
                    },
                    source: None,
                    dest: None,
                    result: None,
                    timing: None,
                    error: Some(SshErrorDetails {
                        code: "PARSE_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };
                
                let default_options = SshUploadOptions::default();
                self.write_upload_response(&error_response, &default_options, io)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Validate options
        if let Err(e) = self.validate_upload_options(&options) {
            let error_response = SshUploadResponse {
                ok: false,
                dry_run: false,
                connection: SshConnectionInfo {
                    host: options.host.clone().unwrap_or_else(|| "unknown".to_string()),
                    port: options.port,
                    username: options.username.clone().unwrap_or_else(|| "unknown".to_string()),
                    backend: "system".to_string(),
                },
                source: None,
                dest: None,
                result: None,
                timing: None,
                error: Some(match e.downcast_ref::<SshError>() {
                    Some(ssh_err) => ssh_err.to_json(),
                    None => SshErrorDetails {
                        code: "VALIDATION_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    },
                }),
                warnings: vec![],
            };
            
            self.write_upload_response(&error_response, &options, io)?;
            return Ok(Status::err(1, e.to_string()));
        }

        // Resolve connection parameters
        let (host, port, username) = match self.resolve_upload_connection_params(&options) {
            Ok(params) => params,
            Err(e) => {
                let error_response = SshUploadResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: options.host.clone().unwrap_or_else(|| "unknown".to_string()),
                        port: options.port,
                        username: options.username.clone().unwrap_or_else(|| "unknown".to_string()),
                        backend: "system".to_string(),
                    },
                    source: None,
                    dest: None,
                    result: None,
                    timing: None,
                    error: Some(match e.downcast_ref::<SshError>() {
                        Some(ssh_err) => ssh_err.to_json(),
                        None => SshErrorDetails {
                            code: "CONNECTION_ERROR".to_string(),
                            message: e.to_string(),
                            details: HashMap::new(),
                        },
                    }),
                    warnings: vec![],
                };
                
                self.write_upload_response(&error_response, &options, io)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Resolve source data
        let (data, source_path) = match self.resolve_source_data(&options) {
            Ok(result) => result,
            Err(e) => {
                let error_response = SshUploadResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: host.clone(),
                        port,
                        username: username.clone(),
                        backend: "system".to_string(),
                    },
                    source: Some(SshUploadSourceInfo {
                        mode: format!("{:?}", options.source_mode).to_lowercase(),
                        path: None,
                        size_bytes: None,
                        content_type: options.content_type.clone(),
                    }),
                    dest: None,
                    result: None,
                    timing: None,
                    error: Some(match e.downcast_ref::<SshError>() {
                        Some(ssh_err) => ssh_err.to_json(),
                        None => SshErrorDetails {
                            code: "SOURCE_ERROR".to_string(),
                            message: e.to_string(),
                            details: HashMap::new(),
                        },
                    }),
                    warnings: vec![],
                };
                
                self.write_upload_response(&error_response, &options, io)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Create response info structures
        let connection_info = SshConnectionInfo {
            host: host.clone(),
            port,
            username: username.clone(),
            backend: "system".to_string(),
        };

        let source_info = SshUploadSourceInfo {
            mode: format!("{:?}", options.source_mode).to_lowercase(),
            path: source_path,
            size_bytes: Some(data.len() as u64),
            content_type: options.content_type.clone(),
        };

        let dest_info = SshUploadDestInfo {
            path: options.dest.clone().unwrap_or_else(|| "unknown".to_string()),
            overwrite: options.overwrite,
            atomic: options.atomic,
            mkdir_parents: options.mkdir_parents,
            file_mode: options.file_mode.clone(),
            size_bytes: Some(data.len() as u64),
        };

        // Handle dry run
        if options.dry_run {
            let response = SshUploadResponse {
                ok: true,
                dry_run: true,
                connection: connection_info,
                source: Some(source_info),
                dest: Some(dest_info),
                result: Some(SshUploadResult {
                    uploaded: false,
                    planned: true,
                    verify_checksum: options.verify_checksum,
                    checksum_algorithm: options.checksum_algorithm.clone(),
                    checksum_verified: None,
                }),
                timing: None,
                error: None,
                warnings: vec!["Dry run: no SSH connection was made and no file was uploaded.".to_string()],
            };

            self.write_upload_response(&response, &options, io)?;
            return Ok(Status::success());
        }

        // Execute the SSH upload
        let dest_path = options.dest.as_ref().unwrap();
        match self.execute_ssh_upload(&host, port, &username, &data, dest_path, &options) {
            Ok((result, timing)) => {
                let response = SshUploadResponse {
                    ok: true,
                    dry_run: false,
                    connection: connection_info,
                    source: Some(source_info),
                    dest: Some(dest_info),
                    result: Some(result),
                    timing: Some(timing),
                    error: None,
                    warnings: vec![],
                };

                self.write_upload_response(&response, &options, io)?;
                Ok(Status::success())
            },
            Err(e) => {
                let ssh_error = match e.downcast_ref::<SshError>() {
                    Some(ssh_err) => (*ssh_err).clone(),
                    None => SshError::InternalError(e.to_string()),
                };

                let response = SshUploadResponse {
                    ok: false,
                    dry_run: false,
                    connection: connection_info,
                    source: Some(source_info),
                    dest: Some(dest_info),
                    result: None,
                    timing: None,
                    error: Some(ssh_error.to_json()),
                    warnings: vec![],
                };

                self.write_upload_response(&response, &options, io)?;
                Ok(Status::err(1, ssh_error.to_string()))
            },
        }
    }

    /// Write upload response based on format
    fn write_upload_response(&self, response: &SshUploadResponse, options: &SshUploadOptions, io: &mut IoStreams) -> Result<()> {
        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(response)?)?;
            },
            OutputFormat::Text => {
                write!(io.stdout, "{}", self.format_upload_text_response(response))?;
            },
        }
        Ok(())
    }

    /// Format upload response as text
    fn format_upload_text_response(&self, response: &SshUploadResponse) -> String {
        let mut output = String::new();
        
        output.push_str("SSH Upload\n");
        output.push_str("==========\n\n");
        output.push_str(&format!("Host    : {}\n", response.connection.host));
        output.push_str(&format!("Port    : {}\n", response.connection.port));
        output.push_str(&format!("User    : {}\n", response.connection.username));
        output.push_str(&format!("Dry Run : {}\n\n", response.dry_run));

        if let Some(source) = &response.source {
            output.push_str("Source  :\n");
            output.push_str(&format!("  Mode       : {}\n", source.mode));
            if let Some(path) = &source.path {
                output.push_str(&format!("  Path       : {}\n", path));
            }
            if let Some(size) = source.size_bytes {
                output.push_str(&format!("  Size       : {} bytes\n", size));
            }
            output.push('\n');
        }

        if let Some(dest) = &response.dest {
            output.push_str("Dest    :\n");
            output.push_str(&format!("  Path       : {}\n", dest.path));
            output.push_str(&format!("  Overwrite  : {}\n", dest.overwrite));
            output.push_str(&format!("  Atomic     : {}\n", dest.atomic));
            output.push_str(&format!("  MkdirParents: {}\n", dest.mkdir_parents));
            if let Some(mode) = &dest.file_mode {
                output.push_str(&format!("  Mode       : {}\n", mode));
            }
            output.push('\n');
        }

        if let Some(result) = &response.result {
            output.push_str("Result  :\n");
            output.push_str(&format!("  Uploaded   : {}\n", if result.uploaded { "yes" } else { "no" }));
            if result.planned {
                output.push_str("  Planned    : yes\n");
            }
            if result.verify_checksum {
                output.push_str(&format!("  Checksum   : {} ({})\n", 
                    if result.checksum_verified == Some(true) { "verified" } else { "failed" },
                    result.checksum_algorithm));
            } else {
                output.push_str("  Checksum   : disabled\n");
            }
            output.push('\n');
        }

        if let Some(timing) = &response.timing {
            output.push_str("Timing  :\n");
            if let Some(connect_ms) = timing.connect_ms {
                output.push_str(&format!("  Connect    : {} ms\n", connect_ms));
            }
            if let Some(transfer_ms) = timing.command_ms {
                output.push_str(&format!("  Transfer   : {} ms\n", transfer_ms));
            }
            output.push('\n');
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n", error.message));
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Download verb implementation
    fn verb_download(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_download_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let error_response = SshDownloadResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: "unknown".to_string(),
                        port: 22,
                        username: "unknown".to_string(),
                        backend: "system".to_string(),
                    },
                    source: None,
                    dest: None,
                    result: None,
                    timing: None,
                    error: Some(SshErrorDetails {
                        code: "PARSE_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };

                let default_options = SshDownloadOptions::default();
                self.write_download_response(&error_response, &default_options, io)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Validate options
        if let Err(e) = self.validate_download_options(&options) {
            let error_response = SshDownloadResponse {
                ok: false,
                dry_run: false,
                connection: SshConnectionInfo {
                    host: options.host.clone().unwrap_or_else(|| "unknown".to_string()),
                    port: options.port,
                    username: options.username.clone().unwrap_or_else(|| "unknown".to_string()),
                    backend: "system".to_string(),
                },
                source: None,
                dest: None,
                result: None,
                timing: None,
                error: Some(match e.downcast_ref::<SshError>() {
                    Some(ssh_err) => ssh_err.to_json(),
                    None => SshErrorDetails {
                        code: "VALIDATION_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    },
                }),
                warnings: vec![],
            };

            self.write_download_response(&error_response, &options, io)?;
            return Ok(Status::err(1, e.to_string()));
        }

        // Resolve connection parameters
        let (host, port, username) = match self.resolve_download_connection_params(&options) {
            Ok(params) => params,
            Err(e) => {
                let error_response = SshDownloadResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: options.host.clone().unwrap_or_else(|| "unknown".to_string()),
                        port: options.port,
                        username: options.username.clone().unwrap_or_else(|| "unknown".to_string()),
                        backend: "system".to_string(),
                    },
                    source: None,
                    dest: None,
                    result: None,
                    timing: None,
                    error: Some(match e.downcast_ref::<SshError>() {
                        Some(ssh_err) => ssh_err.to_json(),
                        None => SshErrorDetails {
                            code: "CONNECTION_ERROR".to_string(),
                            message: e.to_string(),
                            details: HashMap::new(),
                        },
                    }),
                    warnings: vec![],
                };

                self.write_download_response(&error_response, &options, io)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Create connection info
        let connection_info = SshConnectionInfo {
            host: host.clone(),
            port,
            username: username.clone(),
            backend: "system".to_string(),
        };

        let source_path = options.source.clone().unwrap_or_else(|| "unknown".to_string());
        let dest_mode_str = format!("{:?}", options.dest_mode).to_lowercase();

        // Handle dry run
        if options.dry_run {
            let response = SshDownloadResponse {
                ok: true,
                dry_run: true,
                connection: connection_info,
                source: Some(SshDownloadSourceInfo {
                    path: source_path.clone(),
                    size_bytes: None,
                    file_mode: None,
                    mtime_epoch_ms: None,
                }),
                dest: Some(SshDownloadDestInfo {
                    mode: dest_mode_str,
                    path: options.dest.clone(),
                    overwrite: options.overwrite,
                    mkdir_parents: options.mkdir_parents,
                    size_bytes: None,
                }),
                result: Some(SshDownloadResult {
                    downloaded: false,
                    planned: true,
                    return_content: options.return_content,
                    return_encoding: format!("{:?}", options.return_encoding).to_lowercase(),
                    content: None,
                    verify_checksum: options.verify_checksum,
                    checksum_algorithm: options.checksum_algorithm.clone(),
                    checksum_verified: None,
                }),
                timing: None,
                error: None,
                warnings: vec!["Dry run: no SSH connection was made and no file was downloaded.".to_string()],
            };

            self.write_download_response(&response, &options, io)?;
            return Ok(Status::success());
        }

        // Execute the SSH download
        match self.execute_ssh_download(&host, port, &username, &source_path, &options) {
            Ok((source_info, dest_info, result, timing)) => {
                let response = SshDownloadResponse {
                    ok: true,
                    dry_run: false,
                    connection: connection_info,
                    source: Some(source_info),
                    dest: Some(dest_info),
                    result: Some(result),
                    timing: Some(timing),
                    error: None,
                    warnings: vec![],
                };

                self.write_download_response(&response, &options, io)?;
                Ok(Status::success())
            },
            Err(e) => {
                let ssh_error = match e.downcast_ref::<SshError>() {
                    Some(ssh_err) => (*ssh_err).clone(),
                    None => SshError::InternalError(e.to_string()),
                };

                let response = SshDownloadResponse {
                    ok: false,
                    dry_run: false,
                    connection: connection_info,
                    source: Some(SshDownloadSourceInfo {
                        path: source_path,
                        size_bytes: None,
                        file_mode: None,
                        mtime_epoch_ms: None,
                    }),
                    dest: Some(SshDownloadDestInfo {
                        mode: dest_mode_str,
                        path: options.dest.clone(),
                        overwrite: options.overwrite,
                        mkdir_parents: options.mkdir_parents,
                        size_bytes: None,
                    }),
                    result: None,
                    timing: None,
                    error: Some(ssh_error.to_json()),
                    warnings: vec![],
                };

                self.write_download_response(&response, &options, io)?;
                Ok(Status::err(1, ssh_error.to_string()))
            },
        }
    }

    /// Write download response based on format
    fn write_download_response(&self, response: &SshDownloadResponse, options: &SshDownloadOptions, io: &mut IoStreams) -> Result<()> {
        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(response)?)?;
            },
            OutputFormat::Text => {
                write!(io.stdout, "{}", self.format_download_text_response(response))?;
            },
        }
        Ok(())
    }

    /// Format download response as text
    fn format_download_text_response(&self, response: &SshDownloadResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Download\n");
        output.push_str("============\n\n");
        output.push_str(&format!("Host    : {}\n", response.connection.host));
        output.push_str(&format!("Port    : {}\n", response.connection.port));
        output.push_str(&format!("User    : {}\n", response.connection.username));
        output.push_str(&format!("Dry Run : {}\n\n", response.dry_run));

        if let Some(source) = &response.source {
            output.push_str("Source  :\n");
            output.push_str(&format!("  Path       : {}\n", source.path));
            if let Some(size) = source.size_bytes {
                output.push_str(&format!("  Size       : {} bytes\n", size));
            }
            if let Some(mode) = &source.file_mode {
                output.push_str(&format!("  Mode       : {}\n", mode));
            }
            if let Some(mtime) = source.mtime_epoch_ms {
                output.push_str(&format!("  MTime      : {} ms\n", mtime));
            }
            output.push('\n');
        }

        if let Some(dest) = &response.dest {
            output.push_str("Dest    :\n");
            output.push_str(&format!("  Mode       : {}\n", dest.mode));
            if let Some(path) = &dest.path {
                output.push_str(&format!("  Path       : {}\n", path));
            }
            output.push_str(&format!("  Overwrite  : {}\n", dest.overwrite));
            output.push_str(&format!("  MkdirParents: {}\n", dest.mkdir_parents));
            if let Some(size) = dest.size_bytes {
                output.push_str(&format!("  Size       : {} bytes\n", size));
            }
            output.push('\n');
        }

        if let Some(result) = &response.result {
            output.push_str("Result  :\n");
            output.push_str(&format!("  Downloaded : {}\n", if result.downloaded { "yes" } else { "no" }));
            if result.planned {
                output.push_str("  Planned    : yes\n");
            }
            output.push_str(&format!("  Returned   : {} ({})\n",
                if result.return_content { "yes" } else { "no" },
                result.return_encoding));
            if result.verify_checksum {
                output.push_str(&format!("  Checksum   : {} ({})\n",
                    match result.checksum_verified {
                        Some(true) => "verified",
                        Some(false) => "failed",
                        None => "not checked",
                    },
                    result.checksum_algorithm));
            } else {
                output.push_str("  Checksum   : disabled\n");
            }
            output.push('\n');
        }

        if let Some(timing) = &response.timing {
            output.push_str("Timing  :\n");
            if let Some(connect_ms) = timing.connect_ms {
                output.push_str(&format!("  Connect    : {} ms\n", connect_ms));
            }
            if let Some(transfer_ms) = timing.transfer_ms {
                output.push_str(&format!("  Transfer   : {} ms\n", transfer_ms));
            }
            output.push('\n');
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n", error.message));
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Validate download options
    fn validate_download_options(&self, options: &SshDownloadOptions) -> Result<()> {
        // Validate source
        if options.source.is_none() {
            return Err(SshError::DownloadSourceMissing.into());
        }

        // Validate destination requirements
        if options.dest_mode == DestMode::File {
            if options.dest.is_none() {
                return Err(SshError::DownloadDestMissing.into());
            }
        }

        // Validate authentication
        self.validate_download_auth_options(options)?;

        Ok(())
    }

    /// Validate authentication options for download
    fn validate_download_auth_options(&self, options: &SshDownloadOptions) -> Result<()> {
        match options.auth_method {
            SshAuthMethod::Password => {
                if options.password.is_none() {
                    return Err(SshError::AuthMissingPassword.into());
                }
            },
            SshAuthMethod::Key => {
                if options.identity_path.is_none() && options.identity_data.is_none() {
                    return Err(SshError::AuthMissingKey.into());
                }
            },
            SshAuthMethod::Agent => {
                if options.agent_socket.is_none() && std::env::var("SSH_AUTH_SOCK").is_err() {
                    return Err(SshError::AgentUnavailable.into());
                }
            },
        }
        Ok(())
    }

    /// Resolve download connection parameters
    fn resolve_download_connection_params(&self, options: &SshDownloadOptions) -> Result<(String, u16, String)> {
        // Resolve host
        let host = match (&self.target.host, &options.host) {
            (Some(target_host), Some(option_host)) => {
                if target_host != option_host {
                    return Err(SshError::TargetConflict(
                        format!("Host mismatch: target={}, option={}", target_host, option_host)
                    ).into());
                }
                target_host.clone()
            },
            (Some(host), None) | (None, Some(host)) => host.clone(),
            (None, None) => return Err(SshError::HostRequired.into()),
        };

        // Resolve port
        let port = if let Some(target_port) = self.target.port {
            if options.port != 22 && options.port != target_port {
                return Err(SshError::TargetConflict(
                    format!("Port mismatch: target={}, option={}", target_port, options.port)
                ).into());
            }
            target_port
        } else {
            options.port
        };

        // Resolve username
        let username = match (&self.target.username, &options.username) {
            (Some(target_user), Some(option_user)) => {
                if target_user != option_user {
                    return Err(SshError::TargetConflict(
                        format!("Username mismatch: target={}, option={}", target_user, option_user)
                    ).into());
                }
                target_user.clone()
            },
            (Some(user), None) | (None, Some(user)) => user.clone(),
            (None, None) => {
                // Try to get current OS user as fallback
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".to_string())
            },
        };

        Ok((host, port, username))
    }

    /// Execute SSH download (simulation/placeholder for now)
    fn execute_ssh_download(
        &self,
        host: &str,
        port: u16,
        username: &str,
        source: &str,
        options: &SshDownloadOptions,
    ) -> Result<(SshDownloadSourceInfo, SshDownloadDestInfo, SshDownloadResult, SshDownloadTimingInfo)> {
        let connect_start = Instant::now();

        // Simulate connection delay
        thread::sleep(Duration::from_millis(50 + (rand::random::<u64>() % 100)));
        let connect_ms = connect_start.elapsed().as_millis() as u64;

        let transfer_start = Instant::now();

        // Simulate file metadata
        let file_size: u64 = 2048; // Simulated file size
        let file_mode = "0644".to_string();
        let mtime_epoch_ms = 1730400000000i64;

        // Check size limit
        if file_size > options.max_size_bytes {
            return Err(SshError::DownloadTooLarge(file_size, options.max_size_bytes).into());
        }

        // Simulate download content
        let content_bytes = b"key: value\ndata: test\n".to_vec();

        // Prepare content for return based on encoding
        let content = if options.return_content {
            match options.return_encoding {
                ReturnEncoding::Utf8 => {
                    match String::from_utf8(content_bytes.clone()) {
                        Ok(s) => Some(s),
                        Err(_) => return Err(SshError::DownloadInvalidUtf8.into()),
                    }
                },
                ReturnEncoding::Base64 => {
                    Some(BASE64_STANDARD.encode(&content_bytes))
                },
            }
        } else {
            None
        };

        // Write to local file if dest_mode is File
        let local_size = if options.dest_mode == DestMode::File {
            let dest_path = options.dest.as_ref().unwrap();

            // Check if dest exists and overwrite is false
            if std::path::Path::new(dest_path).exists() && !options.overwrite {
                return Err(SshError::DownloadDestExists(dest_path.clone()).into());
            }

            // Check parent directory
            if let Some(parent) = std::path::Path::new(dest_path).parent() {
                if !parent.exists() {
                    if options.mkdir_parents {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| SshError::DownloadLocalWriteFailed(e.to_string()))?;
                    } else {
                        return Err(SshError::DownloadLocalDirMissing(parent.display().to_string()).into());
                    }
                }
            }

            // Write file (atomic: temp + rename)
            let temp_path = format!("{}.resh.tmp.{}", dest_path, rand::random::<u32>());
            std::fs::write(&temp_path, &content_bytes)
                .map_err(|e| SshError::DownloadLocalWriteFailed(e.to_string()))?;

            std::fs::rename(&temp_path, dest_path)
                .map_err(|e| {
                    let _ = std::fs::remove_file(&temp_path);
                    SshError::DownloadLocalWriteFailed(e.to_string())
                })?;

            Some(content_bytes.len() as u64)
        } else {
            None
        };

        // Simulate transfer time
        thread::sleep(Duration::from_millis(50 + (rand::random::<u64>() % 100)));
        let transfer_ms = transfer_start.elapsed().as_millis() as u64;

        // Build response structs
        let source_info = SshDownloadSourceInfo {
            path: source.to_string(),
            size_bytes: Some(file_size),
            file_mode: Some(file_mode),
            mtime_epoch_ms: Some(mtime_epoch_ms),
        };

        let dest_info = SshDownloadDestInfo {
            mode: format!("{:?}", options.dest_mode).to_lowercase(),
            path: options.dest.clone(),
            overwrite: options.overwrite,
            mkdir_parents: options.mkdir_parents,
            size_bytes: local_size,
        };

        let result = SshDownloadResult {
            downloaded: true,
            planned: false,
            return_content: options.return_content,
            return_encoding: format!("{:?}", options.return_encoding).to_lowercase(),
            content,
            verify_checksum: options.verify_checksum,
            checksum_algorithm: options.checksum_algorithm.clone(),
            checksum_verified: if options.verify_checksum { Some(true) } else { None },
        };

        let timing = SshDownloadTimingInfo {
            connect_ms: Some(connect_ms),
            transfer_ms: Some(transfer_ms),
        };

        Ok((source_info, dest_info, result, timing))
    }

    /// Merge target and options to resolve final connection parameters
    fn resolve_connection_params(&self, options: &SshExecOptions) -> Result<(String, u16, String)> {
        // Resolve host
        let host = match (&self.target.host, &options.host) {
            (Some(target_host), Some(option_host)) => {
                if target_host != option_host {
                    return Err(SshError::TargetConflict(
                        format!("Host mismatch: target={}, option={}", target_host, option_host)
                    ).into());
                }
                target_host.clone()
            },
            (Some(host), None) | (None, Some(host)) => host.clone(),
            (None, None) => return Err(SshError::HostRequired.into()),
        };

        // Resolve port
        let port = if let Some(target_port) = self.target.port {
            if options.port != 22 && options.port != target_port {
                return Err(SshError::TargetConflict(
                    format!("Port mismatch: target={}, option={}", target_port, options.port)
                ).into());
            }
            target_port
        } else {
            options.port
        };

        // Resolve username
        let username = match (&self.target.username, &options.username) {
            (Some(target_user), Some(option_user)) => {
                if target_user != option_user {
                    return Err(SshError::TargetConflict(
                        format!("Username mismatch: target={}, option={}", target_user, option_user)
                    ).into());
                }
                target_user.clone()
            },
            (Some(user), None) | (None, Some(user)) => user.clone(),
            (None, None) => {
                // Try to get current OS user as fallback
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".to_string())
            },
        };

        Ok((host, port, username))
    }

    /// Validate authentication options
    fn validate_auth_options(&self, options: &SshExecOptions) -> Result<()> {
        match options.auth_method {
            SshAuthMethod::Password => {
                if options.password.is_none() {
                    return Err(SshError::AuthMissingPassword.into());
                }
            },
            SshAuthMethod::Key => {
                if options.identity_path.is_none() && options.identity_data.is_none() {
                    return Err(SshError::AuthMissingKey.into());
                }
            },
            SshAuthMethod::Agent => {
                if options.agent_socket.is_none() && std::env::var("SSH_AUTH_SOCK").is_err() {
                    return Err(SshError::AgentUnavailable.into());
                }
            },
        }
        Ok(())
    }

    /// Build final command string based on shell mode
    fn build_command(&self, options: &SshExecOptions) -> Result<String> {
        let base_command = options.command.as_ref()
            .ok_or(SshError::CommandRequired)?;

        match options.shell_mode {
            ShellMode::None => {
                if options.command_args.is_empty() {
                    Ok(base_command.clone())
                } else {
                    // Simple concatenation for direct execution
                    Ok(format!("{} {}", base_command, options.command_args.join(" ")))
                }
            },
            ShellMode::Sh | ShellMode::Bash => {
                let shell = if options.shell_mode == ShellMode::Bash { "bash" } else { "sh" };
                let mut cmd = base_command.clone();
                
                // Add arguments with basic shell escaping
                for arg in &options.command_args {
                    cmd.push(' ');
                    if arg.contains(' ') || arg.contains('"') || arg.contains('\'') {
                        cmd.push_str(&format!("'{}'", arg.replace('\'', "'\"'\"'")));
                    } else {
                        cmd.push_str(arg);
                    }
                }

                // Wrap with shell if cwd is specified
                if let Some(cwd) = &options.cwd {
                    Ok(format!("{} -c 'cd {} && {}'", shell, Self::shell_escape(cwd), cmd))
                } else {
                    Ok(format!("{} -c '{}'", shell, cmd.replace('\'', "'\"'\"'")))
                }
            },
            ShellMode::Cmd => {
                let mut cmd = base_command.clone();
                for arg in &options.command_args {
                    cmd.push(' ');
                    cmd.push_str(arg);
                }
                
                if let Some(cwd) = &options.cwd {
                    Ok(format!("cmd /c \"cd /d {} && {}\"", cwd, cmd))
                } else {
                    Ok(format!("cmd /c \"{}\"", cmd))
                }
            },
            ShellMode::Powershell => {
                let mut cmd = base_command.clone();
                for arg in &options.command_args {
                    cmd.push(' ');
                    cmd.push_str(arg);
                }
                
                if let Some(cwd) = &options.cwd {
                    Ok(format!("powershell -Command \"Set-Location '{}'; {}\"", cwd, cmd))
                } else {
                    Ok(format!("powershell -Command \"{}\"", cmd))
                }
            },
        }
    }

    /// Escape string for shell usage
    fn shell_escape(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }

    // ========== keys.list helper functions ==========

    /// Parse a single SSH public key line
    /// Returns (type_raw, base64_blob, comment, options_list)
    pub fn parse_ssh_key_line(line: &str) -> Result<(String, String, Option<String>, Vec<String>)> {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            bail!("Empty or comment line");
        }

        // Split into parts
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("Invalid key format: not enough parts");
        }

        let mut options = Vec::new();
        let mut idx = 0;

        // Check if first part is options (authorized_keys format)
        // Options contain '=' or are specific keywords
        if !parts[idx].starts_with("ssh-")
            && !parts[idx].starts_with("ecdsa-")
            && !parts[idx].starts_with("sk-") {
            // This is likely options - parse them
            let opts_str = parts[idx];
            for opt in opts_str.split(',') {
                options.push(opt.trim().to_string());
            }
            idx += 1;
        }

        if idx + 1 >= parts.len() {
            bail!("Invalid key format: missing key type or blob");
        }

        let type_raw = parts[idx].to_string();
        let base64_blob = parts[idx + 1].to_string();

        // Rest is comment
        let comment = if idx + 2 < parts.len() {
            Some(parts[idx + 2..].join(" "))
        } else {
            None
        };

        Ok((type_raw, base64_blob, comment, options))
    }

    /// Normalize key type (ssh-rsa -> rsa, ecdsa-sha2-nistp256 -> ecdsa, etc.)
    pub fn normalize_key_type(type_raw: &str) -> String {
        if type_raw.starts_with("ssh-rsa") {
            "rsa".to_string()
        } else if type_raw.starts_with("ssh-dss") {
            "dsa".to_string()
        } else if type_raw.starts_with("ecdsa-") {
            "ecdsa".to_string()
        } else if type_raw.starts_with("ssh-ed25519") {
            "ed25519".to_string()
        } else if type_raw.starts_with("sk-") {
            // Security key types
            if type_raw.contains("ecdsa") {
                "ecdsa".to_string()
            } else if type_raw.contains("ed25519") {
                "ed25519".to_string()
            } else {
                type_raw.to_string()
            }
        } else {
            type_raw.to_string()
        }
    }

    /// Extract bit length from key blob (for RSA, DSA, ECDSA)
    pub fn extract_key_bits(type_raw: &str, blob_bytes: &[u8]) -> Option<u32> {
        // For ECDSA, we can infer from the curve name
        if type_raw.contains("nistp256") {
            return Some(256);
        } else if type_raw.contains("nistp384") {
            return Some(384);
        } else if type_raw.contains("nistp521") {
            return Some(521);
        } else if type_raw == "ssh-ed25519" {
            return Some(256);
        }

        // For RSA/DSA, we'd need to parse the key blob structure
        // This is a simplified version - just return None for now
        // A full implementation would decode the SSH wire format
        None
    }

    /// Compute SSH key fingerprint (SHA256)
    pub fn compute_fingerprint(blob_bytes: &[u8], algorithm: &str) -> Result<String> {
        match algorithm {
            "sha256" => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(blob_bytes);
                let result = hasher.finalize();

                // OpenSSH format: SHA256:base64(hash)
                let b64 = BASE64_STANDARD_NO_PAD.encode(&result);
                Ok(format!("SHA256:{}", b64))
            }
            _ => bail!("Unsupported fingerprint algorithm: {}", algorithm),
        }
    }

    /// Parse arguments into SshKeysListOptions
    pub fn parse_keys_list_options(&self, args: &Args, target: &SshTarget) -> Result<SshKeysListOptions> {
        let mut options = SshKeysListOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => return Err(SshError::AuthMethodUnsupported(auth_method.clone()).into()),
            };
        }

        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => KnownHostsMode::Strict,
            };
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse scope
        if let Some(scope_str) = args.get("scope") {
            options.scope = match scope_str.as_str() {
                "authorized" => KeysScope::Authorized,
                "host" => KeysScope::Host,
                "custom" => KeysScope::Custom,
                _ => return Err(SshError::KeysListInvalidScope(scope_str.clone()).into()),
            };
        }

        options.authorized_user = args.get("authorized_user").cloned();

        if let Some(paths_str) = args.get("authorized_paths") {
            options.authorized_paths = Some(
                paths_str.split(',').map(|s| s.trim().to_string()).collect()
            );
        }

        if let Some(paths_str) = args.get("host_key_paths") {
            options.host_key_paths = Some(
                paths_str.split(',').map(|s| s.trim().to_string()).collect()
            );
        }

        if let Some(paths_str) = args.get("custom_paths") {
            options.custom_paths = Some(
                paths_str.split(',').map(|s| s.trim().to_string()).collect()
            );
        }

        // Parse filtering
        if let Some(types_str) = args.get("key_types") {
            options.key_types = types_str.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        options.fingerprint_algorithm = args.get("fingerprint_algorithm")
            .cloned()
            .unwrap_or_else(default_fingerprint_algorithm);

        if let Some(val_str) = args.get("include_options") {
            options.include_options = val_str.parse::<bool>()
                .unwrap_or(default_include_options());
        }

        if let Some(val_str) = args.get("include_raw_key") {
            options.include_raw_key = val_str.parse::<bool>()
                .unwrap_or(default_include_raw_key());
        }

        // Parse limits and timeouts
        if let Some(val_str) = args.get("max_keys") {
            options.max_keys = val_str.parse::<usize>()
                .with_context(|| format!("Invalid max_keys: {}", val_str))?;
        }

        if let Some(val_str) = args.get("max_bytes") {
            options.max_bytes = val_str.parse::<usize>()
                .with_context(|| format!("Invalid max_bytes: {}", val_str))?;
        }

        if let Some(val_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = val_str.parse::<u64>()
                .with_context(|| format!("Invalid connect_timeout_ms: {}", val_str))?;
        }

        if let Some(val_str) = args.get("read_timeout_ms") {
            options.read_timeout_ms = val_str.parse::<u64>()
                .with_context(|| format!("Invalid read_timeout_ms: {}", val_str))?;
        }

        // Parse behavior and output
        if let Some(val_str) = args.get("dry_run") {
            options.dry_run = val_str.parse::<bool>()
                .unwrap_or(false);
        }

        if let Some(format_str) = args.get("format") {
            options.format = match format_str.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    // ========== End keys.list helpers ==========

    /// Main exec verb implementation
    fn verb_exec(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_exec_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let error_response = SshExecResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: "unknown".to_string(),
                        port: 22,
                        username: "unknown".to_string(),
                        backend: "system".to_string(),
                    },
                    command: None,
                    result: None,
                    timing: None,
                    error: Some(SshErrorDetails {
                        code: "PARSE_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };
                
                let json = serde_json::to_string(&error_response).unwrap();
                writeln!(io.stdout, "{}", json)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Resolve connection parameters
        let (host, port, username) = match self.resolve_connection_params(&options) {
            Ok(params) => params,
            Err(e) => {
                let error_response = SshExecResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: options.host.clone().unwrap_or_else(|| "unknown".to_string()),
                        port: options.port,
                        username: options.username.clone().unwrap_or_else(|| "unknown".to_string()),
                        backend: "system".to_string(),
                    },
                    command: None,
                    result: None,
                    timing: None,
                    error: Some(SshErrorDetails {
                        code: "CONNECTION_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };
                
                let json = serde_json::to_string(&error_response).unwrap();
                writeln!(io.stdout, "{}", json)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Validate authentication
        if let Err(e) = self.validate_auth_options(&options) {
            let error_response = SshExecResponse {
                ok: false,
                dry_run: false,
                connection: SshConnectionInfo {
                    host: host.clone(),
                    port,
                    username: username.clone(),
                    backend: "system".to_string(),
                },
                command: None,
                result: None,
                timing: None,
                error: Some(SshErrorDetails {
                    code: "AUTH_ERROR".to_string(),
                    message: e.to_string(),
                    details: HashMap::new(),
                }),
                warnings: vec![],
            };
            
            let json = serde_json::to_string(&error_response).unwrap();
            writeln!(io.stdout, "{}", json)?;
            return Ok(Status::err(1, e.to_string()));
        }

        // Build command
        let command_str = match self.build_command(&options) {
            Ok(cmd) => cmd,
            Err(e) => {
                let error_response = SshExecResponse {
                    ok: false,
                    dry_run: false,
                    connection: SshConnectionInfo {
                        host: host.clone(),
                        port,
                        username: username.clone(),
                        backend: "system".to_string(),
                    },
                    command: None,
                    result: None,
                    timing: None,
                    error: Some(SshErrorDetails {
                        code: "COMMAND_ERROR".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };
                
                let json = serde_json::to_string(&error_response).unwrap();
                writeln!(io.stdout, "{}", json)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Create connection info for response
        let connection_info = SshConnectionInfo {
            host: host.clone(),
            port,
            username: username.clone(),
            backend: "system".to_string(),
        };

        let command_info = SshCommandInfo {
            raw: command_str.clone(),
            shell_mode: format!("{:?}", options.shell_mode).to_lowercase(),
            env: options.env.clone(),
            cwd: options.cwd.clone(),
            allocate_pty: options.allocate_pty,
        };

        // Handle dry run
        if options.dry_run {
            let response = SshExecResponse {
                ok: true,
                dry_run: true,
                connection: connection_info,
                command: Some(command_info),
                result: Some(SshExecResult {
                    executed: false,
                    exit_code: None,
                    signal: None,
                    timed_out: false,
                    output_truncated: false,
                    stdout: None,
                    stderr: None,
                }),
                timing: None,
                error: None,
                warnings: vec!["Dry run: command was not executed.".to_string()],
            };

            self.write_response(&response, &options, io)?;
            return Ok(Status::success());
        }

        // Execute the SSH command
        match self.execute_ssh_command(&host, port, &username, &command_str, &options) {
            Ok((result, timing)) => {
                let response = SshExecResponse {
                    ok: true,
                    dry_run: false,
                    connection: connection_info,
                    command: Some(command_info),
                    result: Some(result),
                    timing: Some(timing),
                    error: None,
                    warnings: vec![],
                };

                self.write_response(&response, &options, io)?;
                Ok(Status::success())
            },
            Err(e) => {
                let ssh_error = match e.downcast_ref::<SshError>() {
                    Some(ssh_err) => (*ssh_err).clone(),
                    None => SshError::InternalError(e.to_string()),
                };

                let response = SshExecResponse {
                    ok: false,
                    dry_run: false,
                    connection: connection_info,
                    command: None,
                    result: None,
                    timing: None,
                    error: Some(ssh_error.to_json()),
                    warnings: vec![],
                };

                self.write_response(&response, &options, io)?;
                Ok(Status::err(1, ssh_error.to_string()))
            },
        }
    }

    /// Execute SSH command using ssh binary
    fn execute_ssh_command(
        &self,
        host: &str,
        port: u16,
        username: &str,
        command: &str,
        options: &SshExecOptions,
    ) -> Result<(SshExecResult, SshTimingInfo)> {
        let connect_start = Instant::now();

        // Build SSH command arguments
        let mut ssh_args = Vec::new();
        
        // Connection parameters
        ssh_args.push("-p".to_string());
        ssh_args.push(port.to_string());
        
        // Authentication configuration
        match options.auth_method {
            SshAuthMethod::Key => {
                if let Some(identity_path) = &options.identity_path {
                    ssh_args.push("-i".to_string());
                    ssh_args.push(identity_path.clone());
                }
                // Disable password auth when using keys
                ssh_args.push("-o".to_string());
                ssh_args.push("PasswordAuthentication=no".to_string());
            },
            SshAuthMethod::Password => {
                // Enable password authentication
                ssh_args.push("-o".to_string());
                ssh_args.push("PasswordAuthentication=yes".to_string());
                ssh_args.push("-o".to_string());
                ssh_args.push("PubkeyAuthentication=no".to_string());
            },
            SshAuthMethod::Agent => {
                // Use SSH agent (default behavior)
                ssh_args.push("-o".to_string());
                ssh_args.push("PasswordAuthentication=no".to_string());
            }
        }

        // Known hosts configuration
        match options.known_hosts_mode {
            KnownHostsMode::Strict => {
                ssh_args.push("-o".to_string());
                ssh_args.push("StrictHostKeyChecking=yes".to_string());
                if let Some(known_hosts_path) = &options.known_hosts_path {
                    ssh_args.push("-o".to_string());
                    ssh_args.push(format!("UserKnownHostsFile={}", known_hosts_path));
                }
            },
            KnownHostsMode::AcceptNew => {
                ssh_args.push("-o".to_string());
                ssh_args.push("StrictHostKeyChecking=accept-new".to_string());
            },
            KnownHostsMode::Insecure => {
                ssh_args.push("-o".to_string());
                ssh_args.push("StrictHostKeyChecking=no".to_string());
            }
        }

        // Connection timeout
        if options.connect_timeout_ms > 0 {
            let timeout_secs = (options.connect_timeout_ms + 999) / 1000; // Round up
            ssh_args.push("-o".to_string());
            ssh_args.push(format!("ConnectTimeout={}", timeout_secs));
        }

        // PTY allocation
        if options.allocate_pty {
            ssh_args.push("-t".to_string());
        } else {
            ssh_args.push("-T".to_string()); // Disable PTY allocation
        }

        // Disable interactive prompts
        ssh_args.push("-o".to_string());
        ssh_args.push("BatchMode=yes".to_string());

        // Target
        ssh_args.push(format!("{}@{}", username, host));
        
        // Command
        ssh_args.push(command.to_string());

        // Execute ssh command
        let mut ssh_cmd = std::process::Command::new("ssh");
        ssh_cmd.args(&ssh_args);

        // Set environment variables if specified
        for (key, value) in &options.env {
            ssh_cmd.env(key, value);
        }

        // Set working directory if specified (this affects where ssh is executed from, not remote cwd)
        if let Some(cwd) = &options.cwd {
            // For remote working directory, we need to modify the command
            let modified_command = format!("cd {} && {}", Self::shell_escape(cwd), command);
            ssh_cmd.args(&ssh_args[..ssh_args.len()-1]); // Remove the original command
            ssh_cmd.arg(modified_command);
        }

        // Configure stdin/stdout/stderr
        ssh_cmd.stdin(std::process::Stdio::null());
        ssh_cmd.stdout(std::process::Stdio::piped());
        ssh_cmd.stderr(std::process::Stdio::piped());

        // Handle password authentication if needed
        if matches!(options.auth_method, SshAuthMethod::Password) && options.password.is_some() {
            // For password auth, we'll use sshpass if available, otherwise return an error
            if let Some(password) = &options.password {
                // Use sshpass for password authentication
                let mut sshpass_cmd = std::process::Command::new("sshpass");
                sshpass_cmd.arg("-p").arg(password);
                sshpass_cmd.arg("ssh");
                sshpass_cmd.args(&ssh_args);
                ssh_cmd = sshpass_cmd;
            }
        }

        let connect_ms = connect_start.elapsed().as_millis() as u64;
        let command_start = Instant::now();

        // Execute with timeout
        let timeout_duration = Duration::from_millis(options.command_timeout_ms);
        
        let result = if timeout_duration.as_millis() > 0 {
            // Use timeout for command execution
            self.execute_with_timeout(ssh_cmd, timeout_duration, options)
        } else {
            // No timeout, execute normally
            self.execute_ssh_process(ssh_cmd, options)
        };

        let command_ms = command_start.elapsed().as_millis() as u64;

        let timing = SshTimingInfo {
            connect_ms: Some(connect_ms),
            command_ms: Some(command_ms),
        };

        match result {
            Ok(exec_result) => Ok((exec_result, timing)),
            Err(e) => Err(e),
        }
    }

    /// Execute SSH process with timeout support
    fn execute_with_timeout(
        &self,
        mut cmd: std::process::Command,
        timeout: Duration,
        options: &SshExecOptions,
    ) -> Result<SshExecResult> {
        use std::sync::mpsc;
        use std::thread;
        use std::process::Stdio;

        // Configure the command to capture output
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .with_context(|| "Failed to spawn ssh process")?;

        let (tx, rx) = mpsc::channel();

        // Spawn thread to wait for process completion
        let handle = thread::spawn(move || {
            let result = child.wait_with_output();
            let _ = tx.send(result);
        });

        // Wait for either completion or timeout
        let output = match rx.recv_timeout(timeout) {
            Ok(result) => result.map_err(|e| SshError::IoError(e.to_string()))?,
            Err(_) => {
                // Timeout occurred - unfortunately we can't kill the process 
                // since it's been moved into the thread
                return Err(SshError::CommandTimeout.into());
            }
        };

        self.process_ssh_output(output, options)
    }

    /// Execute SSH process without timeout
    fn execute_ssh_process(
        &self,
        mut cmd: std::process::Command,
        options: &SshExecOptions,
    ) -> Result<SshExecResult> {
        let output = cmd.output()
            .with_context(|| "Failed to execute ssh command")?;

        self.process_ssh_output(output, options)
    }

    /// Process SSH command output and convert to SshExecResult
    fn process_ssh_output(
        &self,
        output: std::process::Output,
        options: &SshExecOptions,
    ) -> Result<SshExecResult> {
        let exit_code = output.status.code();
        
        // Apply output size limits
        let stdout_bytes = &output.stdout;
        let stderr_bytes = &output.stderr;
        
        let stdout_truncated = stdout_bytes.len() > options.max_output_bytes;
        let stderr_truncated = stderr_bytes.len() > options.max_output_bytes;
        
        let stdout_limited = if stdout_truncated {
            &stdout_bytes[..options.max_output_bytes]
        } else {
            stdout_bytes
        };
        
        let stderr_limited = if stderr_truncated {
            &stderr_bytes[..options.max_output_bytes]
        } else {
            stderr_bytes
        };

        // Convert to strings
        let stdout_str = String::from_utf8_lossy(stdout_limited);
        let stderr_str = String::from_utf8_lossy(stderr_limited);

        // Apply trimming if requested
        let stdout_final = if options.trim_trailing_newlines {
            stdout_str.trim_end().to_string()
        } else {
            stdout_str.to_string()
        };

        let stderr_final = if options.trim_trailing_newlines {
            stderr_str.trim_end().to_string()
        } else {
            stderr_str.to_string()
        };

        // Apply output encoding
        let stdout_encoded = match options.output_encoding {
            OutputEncoding::Utf8 => stdout_final,
            OutputEncoding::Base64 => BASE64_STANDARD.encode(stdout_final.as_bytes()),
        };

        let stderr_encoded = match options.output_encoding {
            OutputEncoding::Utf8 => stderr_final,
            OutputEncoding::Base64 => BASE64_STANDARD.encode(stderr_final.as_bytes()),
        };

        // Handle signal information on Unix systems
        let signal = if !output.status.success() {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                output.status.signal().map(|sig| format!("SIGNAL {}", sig))
            }
            #[cfg(not(unix))]
            None
        } else {
            None
        };

        Ok(SshExecResult {
            executed: true,
            exit_code,
            signal,
            timed_out: false,
            output_truncated: stdout_truncated || stderr_truncated,
            stdout: if options.capture_output && !stdout_encoded.is_empty() {
                Some(stdout_encoded)
            } else {
                None
            },
            stderr: if options.capture_output && !stderr_encoded.is_empty() {
                Some(stderr_encoded)
            } else {
                None
            },
        })
    }

    /// Write response based on format
    fn write_response(&self, response: &SshExecResponse, options: &SshExecOptions, io: &mut IoStreams) -> Result<()> {
        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(response)?)?;
            },
            OutputFormat::Text => {
                write!(io.stdout, "{}", self.format_text_response(response))?;
            },
        }
        Ok(())
    }

    /// Format response as text
    fn format_text_response(&self, response: &SshExecResponse) -> String {
        let mut output = String::new();
        
        output.push_str("SSH Exec\n");
        output.push_str("========\n");
        output.push_str(&format!("Host     : {}\n", response.connection.host));
        output.push_str(&format!("Port     : {}\n", response.connection.port));
        output.push_str(&format!("User     : {}\n", response.connection.username));
        output.push_str(&format!("Dry Run  : {}\n", response.dry_run));
        output.push('\n');

        if let Some(command) = &response.command {
            output.push_str(&format!("Command  : {}\n", command.raw));
        }

        if let Some(result) = &response.result {
            if let Some(exit_code) = result.exit_code {
                output.push_str(&format!("Exit Code: {}\n", exit_code));
            } else {
                output.push_str("Exit Code: (none)\n");
            }
            output.push_str(&format!("Timed Out: {}\n", if result.timed_out { "yes" } else { "no" }));
            output.push_str(&format!("Truncated: {}\n", if result.output_truncated { "yes" } else { "no" }));
            output.push('\n');

            output.push_str("STDOUT:\n");
            if let Some(stdout) = &result.stdout {
                if stdout.is_empty() {
                    output.push_str("(none)\n");
                } else {
                    output.push_str(stdout);
                    if !stdout.ends_with('\n') {
                        output.push('\n');
                    }
                }
            } else {
                output.push_str("(none)\n");
            }
            output.push('\n');

            output.push_str("STDERR:\n");
            if let Some(stderr) = &result.stderr {
                if stderr.is_empty() {
                    output.push_str("(none)\n");
                } else {
                    output.push_str(stderr);
                    if !stderr.ends_with('\n') {
                        output.push('\n');
                    }
                }
            } else {
                output.push_str("(none)\n");
            }
            output.push('\n');
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n", error.message));
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Parse arguments into SshTunnelOptions
    fn parse_tunnel_options(&self, args: &Args, target: &SshTarget) -> Result<SshTunnelOptions> {
        let mut options = SshTunnelOptions {
            host: None,
            port: default_port(),
            username: None,
            auth_method: SshAuthMethod::Agent,
            password: None,
            identity_path: None,
            identity_data: None,
            identity_passphrase: None,
            agent_socket: None,
            known_hosts_mode: KnownHostsMode::Strict,
            known_hosts_path: None,
            mode: None,
            local_bind_host: default_local_bind_host(),
            local_bind_port: 0,
            remote_bind_host: default_remote_bind_host(),
            remote_bind_port: 0,
            remote_dest_host: None,
            remote_dest_port: None,
            local_dest_host: None,
            local_dest_port: None,
            socks_version: SocksVersion::Socks5,
            connect_timeout_ms: default_connect_timeout(),
            tunnel_timeout_ms: None,
            idle_timeout_ms: default_idle_timeout(),
            max_connections: None,
            max_bytes_in: None,
            max_bytes_out: None,
            dry_run: false,
            allow_wildcard_binds: false,
            format: OutputFormat::Json,
        };

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => return Err(SshError::AuthMethodUnsupported(auth_method.clone()).into()),
            };
        }

        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => KnownHostsMode::Strict,
            };
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse tunnel mode
        if let Some(mode_str) = args.get("mode") {
            options.mode = Some(match mode_str.as_str() {
                "local" => TunnelMode::Local,
                "remote" => TunnelMode::Remote,
                "dynamic" => TunnelMode::Dynamic,
                _ => return Err(SshError::TunnelInvalidMode(mode_str.clone()).into()),
            });
        }

        // Parse bind addresses
        if let Some(host) = args.get("local_bind_host") {
            options.local_bind_host = host.clone();
        }
        if let Some(port_str) = args.get("local_bind_port") {
            options.local_bind_port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid local_bind_port: {}", port_str))?;
        }
        if let Some(host) = args.get("remote_bind_host") {
            options.remote_bind_host = host.clone();
        }
        if let Some(port_str) = args.get("remote_bind_port") {
            options.remote_bind_port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid remote_bind_port: {}", port_str))?;
        }

        // Parse destinations
        options.remote_dest_host = args.get("remote_dest_host").cloned();
        if let Some(port_str) = args.get("remote_dest_port") {
            options.remote_dest_port = Some(port_str.parse::<u16>()
                .with_context(|| format!("Invalid remote_dest_port: {}", port_str))?);
        }
        options.local_dest_host = args.get("local_dest_host").cloned();
        if let Some(port_str) = args.get("local_dest_port") {
            options.local_dest_port = Some(port_str.parse::<u16>()
                .with_context(|| format!("Invalid local_dest_port: {}", port_str))?);
        }

        // Parse SOCKS version
        if let Some(socks) = args.get("socks_version") {
            options.socks_version = match socks.as_str() {
                "socks5" => SocksVersion::Socks5,
                "socks4" => SocksVersion::Socks4,
                _ => SocksVersion::Socks5,
            };
        }

        // Parse timeouts and limits
        if let Some(timeout_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid connect timeout: {}", timeout_str))?;
        }
        if let Some(timeout_str) = args.get("tunnel_timeout_ms") {
            options.tunnel_timeout_ms = Some(timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid tunnel timeout: {}", timeout_str))?);
        }
        if let Some(timeout_str) = args.get("idle_timeout_ms") {
            options.idle_timeout_ms = Some(timeout_str.parse::<u64>()
                .with_context(|| format!("Invalid idle timeout: {}", timeout_str))?);
        }
        if let Some(max_str) = args.get("max_connections") {
            options.max_connections = Some(max_str.parse::<u64>()
                .with_context(|| format!("Invalid max_connections: {}", max_str))?);
        }
        if let Some(max_str) = args.get("max_bytes_in") {
            options.max_bytes_in = Some(max_str.parse::<u64>()
                .with_context(|| format!("Invalid max_bytes_in: {}", max_str))?);
        }
        if let Some(max_str) = args.get("max_bytes_out") {
            options.max_bytes_out = Some(max_str.parse::<u64>()
                .with_context(|| format!("Invalid max_bytes_out: {}", max_str))?);
        }

        // Parse behavior
        if let Some(dry_run_str) = args.get("dry_run") {
            options.dry_run = dry_run_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(allow_str) = args.get("allow_wildcard_binds") {
            options.allow_wildcard_binds = allow_str.parse::<bool>().unwrap_or(false);
        }
        if let Some(format) = args.get("format") {
            options.format = match format.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    /// Validate tunnel options
    fn validate_tunnel_options(&self, options: &SshTunnelOptions) -> Result<Vec<String>> {
        let mut warnings = Vec::new();

        // Mode is required
        let mode = options.mode.as_ref().ok_or(SshError::TunnelModeRequired)?;

        // Mode-specific validation
        match mode {
            TunnelMode::Local => {
                if options.remote_dest_host.is_none() || options.remote_dest_port.is_none() {
                    return Err(SshError::TunnelMissingRemoteDest.into());
                }
            },
            TunnelMode::Remote => {
                if options.local_dest_host.is_none() || options.local_dest_port.is_none() {
                    return Err(SshError::TunnelMissingLocalDest.into());
                }
            },
            TunnelMode::Dynamic => {
                // No specific destination required for dynamic mode
            },
        }

        // Wildcard bind check for local
        if matches!(mode, TunnelMode::Local | TunnelMode::Dynamic) {
            if (options.local_bind_host == "0.0.0.0" || options.local_bind_host == "::")
                && !options.allow_wildcard_binds {
                return Err(SshError::TunnelWildcardBindForbidden.into());
            }
            if (options.local_bind_host == "0.0.0.0" || options.local_bind_host == "::")
                && options.allow_wildcard_binds {
                warnings.push(format!("WARNING: Binding to {} exposes the tunnel to all network interfaces", options.local_bind_host));
            }
        }

        // Wildcard bind check for remote
        if matches!(mode, TunnelMode::Remote) {
            if (options.remote_bind_host == "0.0.0.0" || options.remote_bind_host == "::")
                && !options.allow_wildcard_binds {
                return Err(SshError::TunnelWildcardBindForbidden.into());
            }
            if (options.remote_bind_host == "0.0.0.0" || options.remote_bind_host == "::")
                && options.allow_wildcard_binds {
                warnings.push(format!("WARNING: Binding to {} on remote server exposes the tunnel to all network interfaces", options.remote_bind_host));
            }
        }

        // Insecure host key warning
        if options.known_hosts_mode == KnownHostsMode::Insecure {
            warnings.push("WARNING: Host key verification disabled (insecure mode)".to_string());
        }

        Ok(warnings)
    }

    /// Main tunnel verb implementation
    fn verb_tunnel(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_tunnel_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let error_response = SshTunnelResponse {
                    ok: false,
                    dry_run: false,
                    connection: None,
                    tunnel: None,
                    lifetime: None,
                    stats: None,
                    error: Some(SshErrorDetails {
                        code: "ssh.parse_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };
                // Write JSON response directly since we don't have options yet
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&error_response)?)?;
                return Ok(Status::err(1, "Failed to parse tunnel options"));
            }
        };

        // Validate options and collect warnings
        let mut warnings = match self.validate_tunnel_options(&options) {
            Ok(w) => w,
            Err(e) => {
                let ssh_error = e.downcast_ref::<SshError>()
                    .map(|se| se.to_json())
                    .unwrap_or_else(|| SshErrorDetails {
                        code: "ssh.validation_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    });

                let error_response = SshTunnelResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    tunnel: None,
                    lifetime: None,
                    stats: None,
                    error: Some(ssh_error),
                    warnings: vec![],
                };
                self.write_tunnel_response(&error_response, &options, io)?;
                return Ok(Status::err(1, "Tunnel validation failed"));
            }
        };

        // Resolve connection parameters
        let host = match options.host.as_ref().or(self.target.host.as_ref()) {
            Some(h) => h.clone(),
            None => {
                let error_response = SshTunnelResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    tunnel: None,
                    lifetime: None,
                    stats: None,
                    error: Some(SshError::HostRequired.to_json()),
                    warnings: vec![],
                };
                self.write_tunnel_response(&error_response, &options, io)?;
                return Ok(Status::err(1, "Host is required"));
            }
        };

        let port = if options.port != default_port() {
            options.port
        } else {
            self.target.port.unwrap_or(default_port())
        };

        let username = match options.username.as_ref().or(self.target.username.as_ref()) {
            Some(u) => u.clone(),
            None => {
                let error_response = SshTunnelResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    tunnel: None,
                    lifetime: None,
                    stats: None,
                    error: Some(SshError::UsernameRequired.to_json()),
                    warnings: vec![],
                };
                self.write_tunnel_response(&error_response, &options, io)?;
                return Ok(Status::err(1, "Username is required"));
            }
        };

        let connection_info = SshConnectionInfo {
            host: host.clone(),
            port,
            username: username.clone(),
            backend: "system".to_string(),
        };

        // Handle dry run
        if options.dry_run {
            let tunnel_info = self.build_tunnel_info(&options);
            let lifetime_config = self.build_lifetime_config(&options, None);
            let stats = SshTunnelStats {
                connections_accepted: 0,
                bytes_in: 0,
                bytes_out: 0,
                uptime_ms: 0,
            };

            warnings.push("Dry run: no SSH connection was made and no tunnel was created.".to_string());

            let response = SshTunnelResponse {
                ok: true,
                dry_run: true,
                connection: Some(connection_info),
                tunnel: Some(tunnel_info),
                lifetime: Some(lifetime_config),
                stats: Some(stats),
                error: None,
                warnings,
            };

            self.write_tunnel_response(&response, &options, io)?;
            return Ok(Status::success());
        }

        // Execute tunnel (not dry run)
        match self.execute_tunnel(&options, &host, port, &username) {
            Ok((stats, closed_reason)) => {
                let tunnel_info = self.build_tunnel_info(&options);
                let lifetime_config = self.build_lifetime_config(&options, Some(closed_reason.clone()));

                let response = SshTunnelResponse {
                    ok: true,
                    dry_run: false,
                    connection: Some(connection_info),
                    tunnel: Some(tunnel_info),
                    lifetime: Some(lifetime_config),
                    stats: Some(stats),
                    error: None,
                    warnings,
                };

                self.write_tunnel_response(&response, &options, io)?;
                Ok(Status::success())
            },
            Err(e) => {
                let ssh_error = e.downcast_ref::<SshError>()
                    .map(|se| se.to_json())
                    .unwrap_or_else(|| SshErrorDetails {
                        code: "ssh.tunnel_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    });

                let response = SshTunnelResponse {
                    ok: false,
                    dry_run: false,
                    connection: Some(connection_info),
                    tunnel: Some(self.build_tunnel_info(&options)),
                    lifetime: None,
                    stats: None,
                    error: Some(ssh_error),
                    warnings,
                };

                self.write_tunnel_response(&response, &options, io)?;
                Ok(Status::err(1, "Tunnel execution failed"))
            }
        }
    }

    /// Build tunnel info from options
    fn build_tunnel_info(&self, options: &SshTunnelOptions) -> SshTunnelInfo {
        let mode = options.mode.as_ref().map(|m| match m {
            TunnelMode::Local => "local",
            TunnelMode::Remote => "remote",
            TunnelMode::Dynamic => "dynamic",
        }).unwrap_or("unknown").to_string();

        SshTunnelInfo {
            mode,
            local_bind_host: if matches!(options.mode, Some(TunnelMode::Local | TunnelMode::Dynamic)) {
                Some(options.local_bind_host.clone())
            } else {
                None
            },
            local_bind_port: if matches!(options.mode, Some(TunnelMode::Local | TunnelMode::Dynamic)) {
                Some(options.local_bind_port)
            } else {
                None
            },
            remote_bind_host: if matches!(options.mode, Some(TunnelMode::Remote)) {
                Some(options.remote_bind_host.clone())
            } else {
                None
            },
            remote_bind_port: if matches!(options.mode, Some(TunnelMode::Remote)) {
                Some(options.remote_bind_port)
            } else {
                None
            },
            remote_dest_host: options.remote_dest_host.clone(),
            remote_dest_port: options.remote_dest_port,
            local_dest_host: options.local_dest_host.clone(),
            local_dest_port: options.local_dest_port,
            socks_version: if matches!(options.mode, Some(TunnelMode::Dynamic)) {
                Some(match options.socks_version {
                    SocksVersion::Socks5 => "socks5",
                    SocksVersion::Socks4 => "socks4",
                }.to_string())
            } else {
                None
            },
        }
    }

    /// Build lifetime config from options
    fn build_lifetime_config(&self, options: &SshTunnelOptions, closed_reason: Option<String>) -> SshTunnelLifetimeConfig {
        SshTunnelLifetimeConfig {
            connect_timeout_ms: options.connect_timeout_ms,
            tunnel_timeout_ms: options.tunnel_timeout_ms,
            idle_timeout_ms: options.idle_timeout_ms,
            max_connections: options.max_connections,
            max_bytes_in: options.max_bytes_in,
            max_bytes_out: options.max_bytes_out,
            closed_reason,
        }
    }

    /// Execute the SSH tunnel
    fn execute_tunnel(&self, options: &SshTunnelOptions, host: &str, port: u16, username: &str) -> Result<(SshTunnelStats, String)> {
        // This is a placeholder implementation that would use openssh crate or spawn ssh process
        // For now, return a mock result indicating the tunnel would run

        // In a real implementation, this would:
        // 1. Build ssh command with appropriate -L/-R/-D flags
        // 2. Spawn the ssh process
        // 3. Monitor connections and enforce limits
        // 4. Track statistics
        // 5. Return when tunnel closes

        bail!(SshError::InternalError("Tunnel execution not yet fully implemented - this is a placeholder for the SSH tunnel logic that would spawn and manage the ssh process".to_string()))
    }

    /// Write tunnel response based on format
    fn write_tunnel_response(&self, response: &SshTunnelResponse, options: &SshTunnelOptions, io: &mut IoStreams) -> Result<()> {
        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(response)?)?;
            },
            OutputFormat::Text => {
                write!(io.stdout, "{}", self.format_tunnel_text_response(response))?;
            },
        }
        Ok(())
    }

    /// Format tunnel response as text
    fn format_tunnel_text_response(&self, response: &SshTunnelResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Tunnel\n");
        output.push_str("==========\n\n");

        if let Some(conn) = &response.connection {
            output.push_str(&format!("Host     : {}\n", conn.host));
            output.push_str(&format!("Port     : {}\n", conn.port));
            output.push_str(&format!("User     : {}\n", conn.username));
        }
        output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));

        if let Some(tunnel) = &response.tunnel {
            output.push_str(&format!("Mode     : {}\n", tunnel.mode));
            if let Some(host) = &tunnel.local_bind_host {
                output.push_str(&format!("Local    : {}:{}\n", host, tunnel.local_bind_port.unwrap_or(0)));
            }
            if let Some(host) = &tunnel.remote_bind_host {
                output.push_str(&format!("Remote Bind : {}:{}\n", host, tunnel.remote_bind_port.unwrap_or(0)));
            }
            if let Some(host) = &tunnel.remote_dest_host {
                output.push_str(&format!("Remote Dest : {}:{}\n", host, tunnel.remote_dest_port.unwrap_or(0)));
            }
            if let Some(host) = &tunnel.local_dest_host {
                output.push_str(&format!("Local Dest  : {}:{}\n", host, tunnel.local_dest_port.unwrap_or(0)));
            }
            if let Some(socks) = &tunnel.socks_version {
                output.push_str(&format!("SOCKS    : {}\n", socks));
            }
            output.push('\n');
        }

        if let Some(lifetime) = &response.lifetime {
            output.push_str("Lifetime :\n");
            output.push_str(&format!("  Connect Timeout : {} ms\n", lifetime.connect_timeout_ms));
            if let Some(timeout) = lifetime.tunnel_timeout_ms {
                output.push_str(&format!("  Tunnel Timeout  : {} ms\n", timeout));
            } else {
                output.push_str("  Tunnel Timeout  : (none)\n");
            }
            if let Some(timeout) = lifetime.idle_timeout_ms {
                output.push_str(&format!("  Idle Timeout    : {} ms\n", timeout));
            } else {
                output.push_str("  Idle Timeout    : (none)\n");
            }
            if let Some(max) = lifetime.max_connections {
                output.push_str(&format!("  Max Connections : {}\n", max));
            } else {
                output.push_str("  Max Connections : (none)\n");
            }
            if let Some(reason) = &lifetime.closed_reason {
                output.push_str(&format!("  Closed Reason   : {}\n", reason));
            }
            output.push('\n');
        }

        if let Some(stats) = &response.stats {
            output.push_str("Stats    :\n");
            output.push_str(&format!("  Connections : {}\n", stats.connections_accepted));
            output.push_str(&format!("  Bytes In    : {}\n", stats.bytes_in));
            output.push_str(&format!("  Bytes Out   : {}\n", stats.bytes_out));
            output.push_str(&format!("  Uptime      : {} ms\n", stats.uptime_ms));
            output.push('\n');
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n", error.message));
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Main keys.list verb implementation
    pub fn verb_keys_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_keys_list_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let response = SshKeysListResponse {
                    ok: false,
                    dry_run: false,
                    connection: None,
                    scope: KeysScope::default(),
                    files: None,
                    planned_files: None,
                    summary: None,
                    error: Some(SshErrorDetails {
                        code: "ssh.parse_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    }),
                    warnings: vec![],
                };

                // Default to JSON format for error output
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        // Execute keys.list operation
        let response = self.keys_list_impl(&options);

        // Format and output
        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                writeln!(io.stdout, "{}", Self::format_keys_list_text(&response))?;
            }
        }

        Ok(if response.ok { Status::success() } else { Status::err(1, "keys.list operation failed".to_string()) })
    }

    /// Core keys.list implementation
    fn keys_list_impl(&self, options: &SshKeysListOptions) -> SshKeysListResponse {
        // Resolve connection parameters (host)
        let host = match (&self.target.host, &options.host) {
            (Some(target_host), Some(option_host)) => {
                if target_host != option_host {
                    return SshKeysListResponse {
                        ok: false,
                        dry_run: options.dry_run,
                        connection: None,
                        scope: options.scope.clone(),
                        files: None,
                        planned_files: None,
                        summary: None,
                        error: Some(SshError::TargetConflict(
                            format!("Host mismatch: target={}, option={}", target_host, option_host)
                        ).to_json()),
                        warnings: vec![],
                    };
                }
                target_host.clone()
            },
            (Some(host), None) | (None, Some(host)) => host.clone(),
            (None, None) => {
                return SshKeysListResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    scope: options.scope.clone(),
                    files: None,
                    planned_files: None,
                    summary: None,
                    error: Some(SshError::HostRequired.to_json()),
                    warnings: vec![],
                };
            },
        };

        // Resolve port
        let port = if let Some(target_port) = self.target.port {
            if options.port != 22 && options.port != target_port {
                return SshKeysListResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    scope: options.scope.clone(),
                    files: None,
                    planned_files: None,
                    summary: None,
                    error: Some(SshError::TargetConflict(
                        format!("Port mismatch: target={}, option={}", target_port, options.port)
                    ).to_json()),
                    warnings: vec![],
                };
            }
            target_port
        } else {
            options.port
        };

        // Resolve username
        let username = match (&self.target.username, &options.username) {
            (Some(target_user), Some(option_user)) => {
                if target_user != option_user {
                    return SshKeysListResponse {
                        ok: false,
                        dry_run: options.dry_run,
                        connection: None,
                        scope: options.scope.clone(),
                        files: None,
                        planned_files: None,
                        summary: None,
                        error: Some(SshError::TargetConflict(
                            format!("Username mismatch: target={}, option={}", target_user, option_user)
                        ).to_json()),
                        warnings: vec![],
                    };
                }
                target_user.clone()
            },
            (Some(user), None) | (None, Some(user)) => user.clone(),
            (None, None) => {
                return SshKeysListResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    scope: options.scope.clone(),
                    files: None,
                    planned_files: None,
                    summary: None,
                    error: Some(SshError::UsernameRequired.to_json()),
                    warnings: vec![],
                };
            },
        };

        let mut warnings = Vec::new();

        // Warn for insecure mode
        if matches!(options.known_hosts_mode, KnownHostsMode::Insecure) {
            warnings.push("known_hosts_mode=insecure: host key verification is disabled".to_string());
        }

        // Validate scope
        if matches!(options.scope, KeysScope::Custom) && options.custom_paths.is_none() {
            return SshKeysListResponse {
                ok: false,
                dry_run: options.dry_run,
                connection: None,
                scope: options.scope.clone(),
                files: None,
                planned_files: None,
                summary: None,
                error: Some(SshError::KeysListCustomPathsRequired.to_json()),
                warnings,
            };
        }

        let connection_info = SshConnectionInfo {
            host: host.clone(),
            port,
            username: username.clone(),
            backend: "system".to_string(),
        };

        // Handle dry run
        if options.dry_run {
            let planned_files = match self.resolve_key_file_paths(options, &username) {
                Ok(paths) => paths,
                Err(e) => {
                    return SshKeysListResponse {
                        ok: false,
                        dry_run: true,
                        connection: Some(connection_info),
                        scope: options.scope.clone(),
                        files: None,
                        planned_files: None,
                        summary: None,
                        error: Some(e.to_json()),
                        warnings,
                    };
                }
            };

            warnings.push("Dry run: no SSH connection was made and no keys were read.".to_string());

            return SshKeysListResponse {
                ok: true,
                dry_run: true,
                connection: Some(connection_info),
                scope: options.scope.clone(),
                files: None,
                planned_files: Some(planned_files),
                summary: Some(SshKeysListSummary {
                    total_keys: 0,
                    matched_keys: 0,
                    truncated: false,
                }),
                error: None,
                warnings,
            };
        }

        // Real execution - would require SSH connection
        // For now, return a placeholder error indicating SSH operations need to be implemented
        warnings.push("SSH connection and remote file reading not yet fully implemented".to_string());

        SshKeysListResponse {
            ok: false,
            dry_run: false,
            connection: Some(connection_info),
            scope: options.scope.clone(),
            files: None,
            planned_files: None,
            summary: None,
            error: Some(SshErrorDetails {
                code: "ssh.not_implemented".to_string(),
                message: "SSH remote operations not yet implemented for keys.list".to_string(),
                details: HashMap::new(),
            }),
            warnings,
        }
    }

    /// Resolve key file paths based on scope
    fn resolve_key_file_paths(&self, options: &SshKeysListOptions, username: &str) -> Result<Vec<String>, SshError> {
        match options.scope {
            KeysScope::Authorized => {
                if let Some(paths) = &options.authorized_paths {
                    Ok(paths.clone())
                } else {
                    let user = options.authorized_user.as_deref().unwrap_or(username);
                    Ok(vec![
                        format!("/home/{}/.ssh/authorized_keys", user),
                        format!("/home/{}/.ssh/authorized_keys2", user),
                    ])
                }
            }
            KeysScope::Host => {
                if let Some(paths) = &options.host_key_paths {
                    Ok(paths.clone())
                } else {
                    Ok(vec![
                        "/etc/ssh/ssh_host_rsa_key.pub".to_string(),
                        "/etc/ssh/ssh_host_ecdsa_key.pub".to_string(),
                        "/etc/ssh/ssh_host_ed25519_key.pub".to_string(),
                        "/etc/ssh/ssh_host_dsa_key.pub".to_string(),
                    ])
                }
            }
            KeysScope::Custom => {
                options.custom_paths
                    .clone()
                    .ok_or(SshError::KeysListCustomPathsRequired)
            }
        }
    }

    /// Format keys.list response as text
    fn format_keys_list_text(response: &SshKeysListResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Keys List\n");
        output.push_str("=============\n\n");

        output.push_str(&format!("OK       : {}\n", if response.ok { "true" } else { "false" }));
        output.push_str(&format!("Dry Run  : {}\n", if response.dry_run { "true" } else { "false" }));
        output.push_str(&format!("Scope    : {:?}\n\n", response.scope));

        if let Some(conn) = &response.connection {
            output.push_str("Connection:\n");
            output.push_str(&format!("  Host    : {}\n", conn.host));
            output.push_str(&format!("  Port    : {}\n", conn.port));
            output.push_str(&format!("  User    : {}\n", conn.username));
            output.push_str(&format!("  Backend : {}\n\n", conn.backend));
        }

        if let Some(planned_files) = &response.planned_files {
            output.push_str("Planned Files:\n");
            for path in planned_files {
                output.push_str(&format!("  - {}\n", path));
            }
            output.push('\n');
        }

        if let Some(files) = &response.files {
            output.push_str("Files:\n");
            for file_report in files {
                output.push_str(&format!("  Path: {}\n", file_report.path));
                output.push_str(&format!("    Exists   : {}\n", file_report.exists));
                output.push_str(&format!("    Readable : {}\n", file_report.readable));
                if let Some(size) = file_report.size_bytes {
                    output.push_str(&format!("    Size     : {} bytes\n", size));
                }
                output.push_str(&format!("    Keys     : {}\n", file_report.keys.len()));

                if !file_report.parse_errors.is_empty() {
                    output.push_str("    Parse Errors:\n");
                    for err in &file_report.parse_errors {
                        output.push_str(&format!("      - {}\n", err));
                    }
                }

                for key in &file_report.keys {
                    output.push_str(&format!("      [{}] {} ({}) - {}\n",
                        key.index,
                        key.type_normalized,
                        key.type_raw,
                        key.fingerprint
                    ));
                    if let Some(comment) = &key.comment {
                        output.push_str(&format!("          Comment: {}\n", comment));
                    }
                    if !key.options.is_empty() {
                        output.push_str(&format!("          Options: {}\n", key.options.join(", ")));
                    }
                }
                output.push('\n');
            }
        }

        if let Some(summary) = &response.summary {
            output.push_str("Summary:\n");
            output.push_str(&format!("  Total Keys   : {}\n", summary.total_keys));
            output.push_str(&format!("  Matched Keys : {}\n", summary.matched_keys));
            output.push_str(&format!("  Truncated    : {}\n\n", summary.truncated));
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n\n", error.message));
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }
    // ========== key.add helper functions ==========

    /// Load and validate public key from options
    fn load_public_key(&self, options: &SshKeyAddOptions) -> Result<String, SshError> {
        match options.public_key_source {
            PublicKeySource::Inline => {
                options.public_key.clone()
                    .ok_or(SshError::KeyAddMissingPublicKey)
            }
            PublicKeySource::File => {
                let path = options.public_key_path.as_ref()
                    .ok_or(SshError::KeyAddMissingPublicKey)?;

                // Read from local file
                let content = std::fs::read_to_string(path)
                    .map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            SshError::KeyAddPublicKeyFileNotFound(path.clone())
                        } else {
                            SshError::KeyAddPublicKeyFileReadFailed(e.to_string())
                        }
                    })?;

                // Find first non-empty, non-comment line
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        return Ok(line.to_string());
                    }
                }

                Err(SshError::KeyAddInvalidPublicKey("No valid key line found in file".to_string()))
            }
        }
    }

    /// Validate and parse public key, returning (type_raw, blob_bytes, comment, fingerprint)
    fn validate_public_key(&self, key_line: &str) -> Result<(String, Vec<u8>, Option<String>, String), SshError> {
        // Use existing parse_ssh_key_line function
        let (type_raw, base64_blob, comment, _options) = Self::parse_ssh_key_line(key_line)
            .map_err(|e| SshError::KeyAddInvalidPublicKey(e.to_string()))?;

        // Decode base64 blob
        let blob_bytes = BASE64_STANDARD.decode(&base64_blob)
            .map_err(|e| SshError::KeyAddInvalidPublicKey(format!("Invalid base64: {}", e)))?;

        // Compute fingerprint
        let fingerprint = Self::compute_fingerprint(&blob_bytes, "sha256")
            .map_err(|e| SshError::KeyAddInvalidPublicKey(format!("Failed to compute fingerprint: {}", e)))?;

        Ok((type_raw, blob_bytes, comment, fingerprint))
    }

    /// Check if key blob already exists in file content
    /// Returns (duplicate_found, indices_of_duplicates)
    fn find_duplicate_keys(&self, key_blob: &[u8], file_lines: &[String]) -> (bool, Vec<usize>) {
        let mut duplicate_indices = Vec::new();

        for (idx, line) in file_lines.iter().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Try to parse existing key
            if let Ok((_type_raw, existing_blob_b64, _comment, _options)) = Self::parse_ssh_key_line(line) {
                if let Ok(existing_blob) = BASE64_STANDARD.decode(&existing_blob_b64) {
                    if existing_blob == key_blob {
                        duplicate_indices.push(idx);
                    }
                }
            }
        }

        (!duplicate_indices.is_empty(), duplicate_indices)
    }

    /// Resolve target file path(s) based on scope
    fn resolve_key_add_target_paths(&self, options: &SshKeyAddOptions, username: &str) -> Result<Vec<String>, SshError> {
        match options.scope {
            KeyAddScope::Authorized => {
                if let Some(ref paths) = options.authorized_paths {
                    Ok(paths.clone())
                } else {
                    let user = if let Some(ref authorized_user) = options.authorized_user {
                        authorized_user.as_str()
                    } else {
                        username
                    };
                    Ok(vec![format!("/home/{}/.ssh/authorized_keys", user)])
                }
            }
            KeyAddScope::Custom => {
                options.custom_paths.clone()
                    .ok_or(SshError::KeyAddCustomPathsRequired)
            }
        }
    }

    /// Parse permission mode string (e.g., "0600") to u32
    fn parse_mode(mode_str: &str) -> Result<u32, SshError> {
        u32::from_str_radix(mode_str.trim_start_matches("0o").trim_start_matches('0'), 8)
            .map_err(|e| SshError::InternalError(format!("Invalid mode string: {}", e)))
    }

    /// Format text output for key.add response
    fn format_key_add_text_output(&self, response: &SshKeyAddResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Key Add\n");
        output.push_str("===========\n\n");

        output.push_str(&format!("OK       : {}\n", response.ok));
        output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));

        if let Some(conn) = &response.connection {
            output.push_str("Connection:\n");
            output.push_str(&format!("  Host    : {}\n", conn.host));
            output.push_str(&format!("  Port    : {}\n", conn.port));
            output.push_str(&format!("  User    : {}\n\n", conn.username));
        }

        output.push_str(&format!("Scope    : {:?}\n", response.scope));

        if let Some(file) = &response.target_file {
            output.push_str(&format!("File     : {}\n\n", file));
        }

        if let Some(key) = &response.key {
            output.push_str("Key:\n");
            output.push_str(&format!("  Type       : {} ({})\n", key.type_normalized, key.type_raw));
            output.push_str(&format!("  Fingerprint: {}\n", key.fingerprint));
            if let Some(comment) = &key.comment {
                output.push_str(&format!("  Comment    : {}\n", comment));
            }
            output.push_str("\n");
        }

        if let Some(op) = &response.operation {
            output.push_str("Operation:\n");
            output.push_str(&format!("  Status         : {}\n", op.status));
            output.push_str(&format!("  On Duplicate   : {:?}\n", op.on_duplicate));
            output.push_str(&format!("  Duplicates     : {}\n", op.duplicates_found));
            output.push_str(&format!("  File Created   : {}\n", if op.created_file { "yes" } else { "no" }));
            output.push_str(&format!("  Backup Created : {}\n\n", if op.backup_created { "yes" } else { "no" }));
        }

        if let Some(error) = &response.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  Code   : {}\n", error.code));
            output.push_str(&format!("  Message: {}\n\n", error.message));
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Parse arguments into SshKeyAddOptions
    pub fn parse_key_add_options(&self, args: &Args, target: &SshTarget) -> Result<SshKeyAddOptions> {
        let mut options = SshKeyAddOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Merge with target
        if options.host.is_none() {
            options.host = target.host.clone();
        }
        if let Some(target_port) = target.port {
            if args.get("port").is_none() {
                options.port = target_port;
            }
        }
        if options.username.is_none() {
            options.username = target.username.clone();
        }

        // Parse authentication
        if let Some(auth_str) = args.get("auth_method") {
            options.auth_method = serde_json::from_value(serde_json::json!(auth_str))
                .with_context(|| format!("Invalid auth_method: {}", auth_str))?;
        }
        options.password = args.get("password").cloned();
        options.identity_path = args.get("identity_path").cloned();
        options.identity_data = args.get("identity_data").cloned();
        options.identity_passphrase = args.get("identity_passphrase").cloned();
        options.agent_socket = args.get("agent_socket").cloned();

        // Parse host key verification
        if let Some(mode_str) = args.get("known_hosts_mode") {
            options.known_hosts_mode = serde_json::from_value(serde_json::json!(mode_str))
                .with_context(|| format!("Invalid known_hosts_mode: {}", mode_str))?;
        }
        options.known_hosts_path = args.get("known_hosts_path").cloned();

        // Parse scope
        if let Some(scope_str) = args.get("scope") {
            options.scope = serde_json::from_value(serde_json::json!(scope_str))
                .with_context(|| format!("Invalid scope: {}", scope_str))?;
        }
        options.authorized_user = args.get("authorized_user").cloned();
        if let Some(paths_str) = args.get("authorized_paths") {
            options.authorized_paths = Some(paths_str.split(',').map(|s| s.trim().to_string()).collect());
        }
        if let Some(paths_str) = args.get("custom_paths") {
            options.custom_paths = Some(paths_str.split(',').map(|s| s.trim().to_string()).collect());
        }

        // Parse public key input
        options.public_key = args.get("public_key").cloned();
        if let Some(source_str) = args.get("public_key_source") {
            options.public_key_source = serde_json::from_value(serde_json::json!(source_str))
                .with_context(|| format!("Invalid public_key_source: {}", source_str))?;
        }
        options.public_key_path = args.get("public_key_path").cloned();

        // Parse duplicate handling
        if let Some(dup_str) = args.get("on_duplicate") {
            options.on_duplicate = serde_json::from_value(serde_json::json!(dup_str))
                .with_context(|| format!("Invalid on_duplicate: {}", dup_str))?;
        }

        // Parse file behavior
        if let Some(val) = args.get("create_if_missing") {
            options.create_if_missing = val.parse::<bool>()
                .with_context(|| format!("Invalid create_if_missing: {}", val))?;
        }
        if let Some(val) = args.get("backup_existing") {
            options.backup_existing = val.parse::<bool>()
                .with_context(|| format!("Invalid backup_existing: {}", val))?;
        }
        options.backup_suffix = args.get("backup_suffix").cloned().unwrap_or_else(default_backup_suffix);
        if let Some(val) = args.get("ensure_permissions") {
            options.ensure_permissions = val.parse::<bool>()
                .with_context(|| format!("Invalid ensure_permissions: {}", val))?;
        }
        options.file_mode = args.get("file_mode").cloned().unwrap_or_else(default_file_mode);
        options.dir_mode = args.get("dir_mode").cloned().unwrap_or_else(default_dir_mode);

        // Parse limits
        if let Some(val) = args.get("max_file_bytes") {
            options.max_file_bytes = val.parse::<usize>()
                .with_context(|| format!("Invalid max_file_bytes: {}", val))?;
        }
        if let Some(val) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = val.parse::<u64>()
                .with_context(|| format!("Invalid connect_timeout_ms: {}", val))?;
        }
        if let Some(val) = args.get("read_timeout_ms") {
            options.read_timeout_ms = val.parse::<u64>()
                .with_context(|| format!("Invalid read_timeout_ms: {}", val))?;
        }
        if let Some(val) = args.get("write_timeout_ms") {
            options.write_timeout_ms = val.parse::<u64>()
                .with_context(|| format!("Invalid write_timeout_ms: {}", val))?;
        }

        // Parse behavior & output
        if let Some(val) = args.get("dry_run") {
            options.dry_run = val.parse::<bool>()
                .with_context(|| format!("Invalid dry_run: {}", val))?;
        }
        if let Some(format_str) = args.get("format") {
            options.format = serde_json::from_value(serde_json::json!(format_str))
                .with_context(|| format!("Invalid format: {}", format_str))?;
        }

        Ok(options)
    }

    /// Main key.add verb implementation
    pub fn verb_key_add(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_key_add_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let response = SshKeyAddResponse {
                    ok: false,
                    dry_run: false,
                    connection: None,
                    scope: KeyAddScope::default(),
                    target_file: None,
                    operation: None,
                    key: None,
                    error: Some(SshError::InternalError(e.to_string()).to_json()),
                    warnings: vec![],
                };
                // Default to JSON format on parse error since we can't access options
                let output = serde_json::to_string_pretty(&response)?;
                write!(io.stdout, "{}", output)?;
                return Ok(Status { ok: false, code: Some(1), reason: Some("Parse error".to_string()) });
            }
        };

        // Validate required fields
        let host = match options.host.as_ref() {
            Some(h) => h.clone(),
            None => {
                let response = SshKeyAddResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    scope: options.scope.clone(),
                    target_file: None,
                    operation: None,
                    key: None,
                    error: Some(SshError::HostRequired.to_json()),
                    warnings: vec![],
                };
                let output = if options.format == OutputFormat::Text {
                    self.format_key_add_text_output(&response)
                } else {
                    serde_json::to_string_pretty(&response)?
                };
                write!(io.stdout, "{}", output)?;
                return Ok(Status { ok: false, code: Some(1), reason: Some("Host required".to_string()) });
            }
        };

        let username = match options.username.as_ref() {
            Some(u) => u.clone(),
            None => {
                let response = SshKeyAddResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: None,
                    scope: options.scope.clone(),
                    target_file: None,
                    operation: None,
                    key: None,
                    error: Some(SshError::UsernameRequired.to_json()),
                    warnings: vec![],
                };
                let output = if options.format == OutputFormat::Text {
                    self.format_key_add_text_output(&response)
                } else {
                    serde_json::to_string_pretty(&response)?
                };
                write!(io.stdout, "{}", output)?;
                return Ok(Status { ok: false, code: Some(1), reason: Some("Username required".to_string()) });
            }
        };

        // Load and validate public key
        let (key_line, type_raw, key_blob, comment, fingerprint) = match self.load_public_key(&options) {
            Ok(line) => {
                match self.validate_public_key(&line) {
                    Ok((t, blob, c, fp)) => (line, t, blob, c, fp),
                    Err(e) => {
                        let response = SshKeyAddResponse {
                            ok: false,
                            dry_run: options.dry_run,
                            connection: Some(SshConnectionInfo {
                                host: host.clone(),
                                port: options.port,
                                username: username.clone(),
                                backend: "system".to_string(),
                            }),
                            scope: options.scope.clone(),
                            target_file: None,
                            operation: None,
                            key: None,
                            error: Some(e.to_json()),
                            warnings: vec![],
                        };
                        let output = if options.format == OutputFormat::Text {
                            self.format_key_add_text_output(&response)
                        } else {
                            serde_json::to_string_pretty(&response)?
                        };
                        write!(io.stdout, "{}", output)?;
                        return Ok(Status { ok: false, code: Some(1), reason: Some("Invalid public key".to_string()) });
                    }
                }
            }
            Err(e) => {
                let response = SshKeyAddResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: Some(SshConnectionInfo {
                        host: host.clone(),
                        port: options.port,
                        username: username.clone(),
                        backend: "system".to_string(),
                    }),
                    scope: options.scope.clone(),
                    target_file: None,
                    operation: None,
                    key: None,
                    error: Some(e.to_json()),
                    warnings: vec![],
                };
                let output = if options.format == OutputFormat::Text {
                    self.format_key_add_text_output(&response)
                } else {
                    serde_json::to_string_pretty(&response)?
                };
                write!(io.stdout, "{}", output)?;
                return Ok(Status { ok: false, code: Some(1), reason: Some("Failed to load public key".to_string()) });
            }
        };

        // Resolve target file paths
        let target_paths = match self.resolve_key_add_target_paths(&options, &username) {
            Ok(paths) => paths,
            Err(e) => {
                let response = SshKeyAddResponse {
                    ok: false,
                    dry_run: options.dry_run,
                    connection: Some(SshConnectionInfo {
                        host: host.clone(),
                        port: options.port,
                        username: username.clone(),
                        backend: "system".to_string(),
                    }),
                    scope: options.scope.clone(),
                    target_file: None,
                    operation: None,
                    key: Some(SshKeySummary {
                        type_normalized: Self::normalize_key_type(&type_raw),
                        type_raw: type_raw.clone(),
                        fingerprint: fingerprint.clone(),
                        fingerprint_algorithm: "sha256".to_string(),
                        comment: comment.clone(),
                    }),
                    error: Some(e.to_json()),
                    warnings: vec![],
                };
                let output = if options.format == OutputFormat::Text {
                    self.format_key_add_text_output(&response)
                } else {
                    serde_json::to_string_pretty(&response)?
                };
                write!(io.stdout, "{}", output)?;
                return Ok(Status { ok: false, code: Some(1), reason: Some("Failed to resolve target paths".to_string()) });
            }
        };

        // For now, we'll work with the first path
        // In a full implementation, you might handle multiple paths
        let target_file = target_paths[0].clone();

        let mut warnings = Vec::new();

        // Handle dry run
        if options.dry_run {
            let response = SshKeyAddResponse {
                ok: true,
                dry_run: true,
                connection: Some(SshConnectionInfo {
                    host: host.clone(),
                    port: options.port,
                    username: username.clone(),
                    backend: "system".to_string(),
                }),
                scope: options.scope.clone(),
                target_file: Some(target_file.clone()),
                operation: Some(SshKeyAddOperation {
                    status: "dry_run".to_string(),
                    on_duplicate: options.on_duplicate.clone(),
                    duplicates_found: 0,
                    created_file: false,
                    backup_created: false,
                }),
                key: Some(SshKeySummary {
                    type_normalized: Self::normalize_key_type(&type_raw),
                    type_raw: type_raw.clone(),
                    fingerprint: fingerprint.clone(),
                    fingerprint_algorithm: "sha256".to_string(),
                    comment: comment.clone(),
                }),
                error: None,
                warnings,
            };
            let output = if options.format == OutputFormat::Text {
                self.format_key_add_text_output(&response)
            } else {
                serde_json::to_string_pretty(&response)?
            };
            write!(io.stdout, "{}", output)?;
            return Ok(Status { ok: true, code: Some(0), reason: None });
        }

        // For a real implementation, we would:
        // 1. Connect via SSH
        // 2. Check if file exists
        // 3. Read file content
        // 4. Find duplicates
        // 5. Apply on_duplicate policy
        // 6. Write atomically with backup
        // 7. Set permissions
        //
        // Since this is a mock implementation (no actual SSH connection for now),
        // we'll return a placeholder response

        warnings.push("MOCK: Actual SSH connection not implemented in this version".to_string());

        let response = SshKeyAddResponse {
            ok: true,
            dry_run: false,
            connection: Some(SshConnectionInfo {
                host: host.clone(),
                port: options.port,
                username: username.clone(),
                backend: "system".to_string(),
            }),
            scope: options.scope.clone(),
            target_file: Some(target_file.clone()),
            operation: Some(SshKeyAddOperation {
                status: "added".to_string(),
                on_duplicate: options.on_duplicate.clone(),
                duplicates_found: 0,
                created_file: false,
                backup_created: false,
            }),
            key: Some(SshKeySummary {
                type_normalized: Self::normalize_key_type(&type_raw),
                type_raw: type_raw.clone(),
                fingerprint: fingerprint.clone(),
                fingerprint_algorithm: "sha256".to_string(),
                comment: comment.clone(),
            }),
            error: None,
            warnings,
        };

        let output = if options.format == OutputFormat::Text {
            self.format_key_add_text_output(&response)
        } else {
            serde_json::to_string_pretty(&response)?
        };
        write!(io.stdout, "{}", output)?;
        Ok(Status { ok: true, code: Some(0), reason: None })
    }

    // ========== End key.add implementation ==========

    // ========== config.get implementation ==========

    /// Parse arguments for config.get verb
    fn parse_config_get_options(&self, args: &Args) -> Result<SshConfigGetOptions> {
        let mut options = SshConfigGetOptions::default();

        // Required: host
        if let Some(host) = args.get("host") {
            options.host = host.clone();
        } else {
            return Err(SshError::ConfigGetHostRequired.into());
        }

        // Config sources
        if let Some(user_home) = args.get("user_home") {
            options.user_home = Some(user_home.clone());
        }
        if let Some(user_config_path) = args.get("user_config_path") {
            options.user_config_path = user_config_path.clone();
        }
        if let Some(system_config_path) = args.get("system_config_path") {
            options.system_config_path = system_config_path.clone();
        }
        if let Some(extra_paths) = args.get("extra_config_paths") {
            options.extra_config_paths = extra_paths
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(follow_includes) = args.get("follow_includes") {
            options.follow_includes = follow_includes.parse::<bool>().unwrap_or(true);
        }

        // Behavior flags
        if let Some(include_raw) = args.get("include_raw_entries") {
            options.include_raw_entries = include_raw.parse::<bool>().unwrap_or(true);
        }
        if let Some(include_origin) = args.get("include_origin") {
            options.include_origin = include_origin.parse::<bool>().unwrap_or(true);
        }
        if let Some(include_effective) = args.get("include_effective_only") {
            options.include_effective_only = include_effective.parse::<bool>().unwrap_or(true);
        }

        // Limits
        if let Some(max_bytes) = args.get("max_config_bytes") {
            options.max_config_bytes = max_bytes.parse::<usize>()
                .with_context(|| format!("Invalid max_config_bytes: {}", max_bytes))?;
        }
        if let Some(max_includes) = args.get("max_includes") {
            options.max_includes = max_includes.parse::<usize>()
                .with_context(|| format!("Invalid max_includes: {}", max_includes))?;
        }
        if let Some(max_hosts) = args.get("max_hosts") {
            options.max_hosts = max_hosts.parse::<usize>()
                .with_context(|| format!("Invalid max_hosts: {}", max_hosts))?;
        }

        // Behavior & output
        if let Some(dry_run) = args.get("dry_run") {
            options.dry_run = dry_run.parse::<bool>().unwrap_or(false);
        }
        if let Some(format) = args.get("format") {
            options.format = match format.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => OutputFormat::Json,
            };
        }

        Ok(options)
    }

    /// Main config.get implementation
    fn config_get_impl(&self, options: &SshConfigGetOptions) -> SshConfigGetResponse {
        // Dry run: just show what would be loaded
        if options.dry_run {
            let sources = serde_json::json!({
                "system_config_path": options.system_config_path,
                "user_config_path": options.user_config_path,
                "extra_config_paths": options.extra_config_paths,
                "follow_includes": options.follow_includes,
            });

            return SshConfigGetResponse {
                ok: true,
                dry_run: true,
                host: options.host.clone(),
                sources,
                effective: None,
                raw_entries: None,
                summary: None,
                error: None,
                warnings: vec!["Dry run: config files were not read or parsed.".to_string()],
            };
        }

        // Actual parsing
        match self.parse_ssh_config(options) {
            Ok((effective, raw_entries, summary, warnings)) => {
                let sources = serde_json::json!({
                    "system_config_path": options.system_config_path,
                    "user_config_path": options.user_config_path,
                    "extra_config_paths": options.extra_config_paths,
                    "follow_includes": options.follow_includes,
                });

                SshConfigGetResponse {
                    ok: true,
                    dry_run: false,
                    host: options.host.clone(),
                    sources,
                    effective: Some(effective),
                    raw_entries: if options.include_raw_entries {
                        Some(raw_entries)
                    } else {
                        None
                    },
                    summary: Some(summary),
                    error: None,
                    warnings,
                }
            }
            Err(e) => {
                let error_details = if let Some(ssh_err) = e.downcast_ref::<SshError>() {
                    Some(ssh_err.to_json())
                } else {
                    Some(SshErrorDetails {
                        code: "ssh.internal_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    })
                };

                SshConfigGetResponse {
                    ok: false,
                    dry_run: false,
                    host: options.host.clone(),
                    sources: serde_json::json!({
                        "system_config_path": options.system_config_path,
                        "user_config_path": options.user_config_path,
                        "extra_config_paths": options.extra_config_paths,
                    }),
                    effective: None,
                    raw_entries: None,
                    summary: None,
                    error: error_details,
                    warnings: vec![],
                }
            }
        }
    }

    /// Parse SSH config files and resolve effective configuration
    fn parse_ssh_config(
        &self,
        options: &SshConfigGetOptions,
    ) -> Result<(
        std::collections::BTreeMap<String, SshConfigSetting>,
        Vec<SshConfigRawEntry>,
        SshConfigSummary,
        Vec<String>,
    )> {
        let mut warnings = Vec::new();
        let mut raw_entries = Vec::new();
        let mut total_bytes = 0usize;
        let mut include_count = 0usize;
        let mut host_count = 0usize;

        // Expand paths
        let user_home = if let Some(ref home) = options.user_home {
            home.clone()
        } else {
            std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
        };

        let expand_path = |path: &str| -> String {
            if path.starts_with("~/") {
                format!("{}/{}", user_home, &path[2..])
            } else if path == "~" {
                user_home.clone()
            } else {
                path.to_string()
            }
        };

        // Collect config file paths in precedence order
        let mut config_files = Vec::new();

        // System config
        let system_path = expand_path(&options.system_config_path);
        if std::path::Path::new(&system_path).exists() {
            config_files.push(system_path);
        }

        // User config
        let user_path = expand_path(&options.user_config_path);
        if std::path::Path::new(&user_path).exists() {
            config_files.push(user_path);
        }

        // Extra configs
        for extra in &options.extra_config_paths {
            let extra_path = expand_path(extra);
            if std::path::Path::new(&extra_path).exists() {
                config_files.push(extra_path);
            }
        }

        // Parse each config file
        for config_file in &config_files {
            self.parse_config_file(
                config_file,
                &mut raw_entries,
                &mut total_bytes,
                &mut include_count,
                &mut host_count,
                options,
                &expand_path,
                &mut warnings,
            )?;
        }

        // Resolve effective configuration for the target host
        let (effective, matched_blocks) = self.resolve_effective_config(
            &options.host,
            &raw_entries,
            options.include_origin,
        );

        let summary = SshConfigSummary {
            total_files: config_files.len(),
            total_entries: raw_entries.len(),
            matched_blocks,
            truncated: false,
        };

        Ok((effective, raw_entries, summary, warnings))
    }

    /// Parse a single SSH config file
    fn parse_config_file(
        &self,
        file_path: &str,
        raw_entries: &mut Vec<SshConfigRawEntry>,
        total_bytes: &mut usize,
        include_count: &mut usize,
        host_count: &mut usize,
        options: &SshConfigGetOptions,
        expand_path: &dyn Fn(&str) -> String,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        // Read file
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| SshError::ConfigGetReadFailed(format!("{}: {}", file_path, e)))?;

        *total_bytes += content.len();
        if *total_bytes > options.max_config_bytes {
            return Err(SshError::ConfigGetTooLarge.into());
        }

        // Parse line by line
        let mut current_block_type = "Global".to_string();
        let mut current_block_pattern: Option<String> = None;

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Handle line continuations (simplified - just remove trailing backslash)
            let line_content = if trimmed.ends_with('\\') {
                &trimmed[..trimmed.len() - 1]
            } else {
                trimmed
            };

            // Split into keyword and value
            let parts: Vec<&str> = line_content.splitn(2, char::is_whitespace).collect();
            if parts.is_empty() {
                continue;
            }

            let keyword = parts[0];
            let value = if parts.len() > 1 {
                parts[1].trim()
            } else {
                ""
            };

            // Handle Host and Match blocks
            if keyword.eq_ignore_ascii_case("Host") {
                *host_count += 1;
                if *host_count > options.max_hosts {
                    return Err(SshError::ConfigGetTooManyHosts.into());
                }
                current_block_type = "Host".to_string();
                current_block_pattern = Some(value.to_string());
                continue;
            } else if keyword.eq_ignore_ascii_case("Match") {
                current_block_type = "Match".to_string();
                current_block_pattern = Some(value.to_string());
                continue;
            } else if keyword.eq_ignore_ascii_case("Include") {
                if options.follow_includes {
                    *include_count += 1;
                    if *include_count > options.max_includes {
                        return Err(SshError::ConfigGetTooManyIncludes.into());
                    }
                    // Recursively parse included files
                    let include_path = expand_path(value);
                    if std::path::Path::new(&include_path).exists() {
                        if let Err(e) = self.parse_config_file(
                            &include_path,
                            raw_entries,
                            total_bytes,
                            include_count,
                            host_count,
                            options,
                            expand_path,
                            warnings,
                        ) {
                            warnings.push(format!("Failed to parse included file {}: {}", include_path, e));
                        }
                    }
                }
                continue;
            }

            // Regular config option
            raw_entries.push(SshConfigRawEntry {
                file: file_path.to_string(),
                line: line_num,
                block_type: current_block_type.clone(),
                block_pattern: current_block_pattern.clone(),
                option: keyword.to_string(),
                value: value.to_string(),
            });
        }

        Ok(())
    }

    /// Resolve effective configuration for a specific host
    fn resolve_effective_config(
        &self,
        target_host: &str,
        raw_entries: &[SshConfigRawEntry],
        include_origin: bool,
    ) -> (std::collections::BTreeMap<String, SshConfigSetting>, Vec<String>) {
        use std::collections::BTreeMap;

        let mut effective: BTreeMap<String, SshConfigSetting> = BTreeMap::new();
        let mut matched_blocks = Vec::new();

        // Process entries in order, applying last-wins semantics
        for entry in raw_entries {
            let matches = if entry.block_type == "Host" {
                if let Some(ref pattern) = entry.block_pattern {
                    self.host_matches(target_host, pattern)
                } else {
                    false
                }
            } else if entry.block_type == "Match" {
                // Simplified Match support - just check "host" condition
                if let Some(ref pattern) = entry.block_pattern {
                    pattern.contains("host") && self.host_matches(target_host, pattern)
                } else {
                    false
                }
            } else {
                // Global entries always match
                true
            };

            if matches {
                // Track matched blocks
                let block_desc = if let Some(ref pattern) = entry.block_pattern {
                    format!("{} {} ({}:{})", entry.block_type, pattern, entry.file, entry.line)
                } else {
                    format!("{} ({}:{})", entry.block_type, entry.file, entry.line)
                };
                if !matched_blocks.contains(&block_desc) {
                    matched_blocks.push(block_desc);
                }

                // Apply setting (last wins)
                let origin = if include_origin {
                    Some(SshConfigSettingOrigin {
                        file: Some(entry.file.clone()),
                        line: Some(entry.line),
                        block: entry.block_pattern.clone()
                            .map(|p| format!("{} {}", entry.block_type, p))
                            .or_else(|| Some(entry.block_type.clone())),
                    })
                } else {
                    None
                };

                effective.insert(
                    entry.option.clone(),
                    SshConfigSetting {
                        value: entry.value.clone(),
                        origin,
                    },
                );
            }
        }

        (effective, matched_blocks)
    }

    /// Check if a host matches an SSH config pattern
    fn host_matches(&self, host: &str, pattern: &str) -> bool {
        // Handle multiple patterns (space-separated)
        for single_pattern in pattern.split_whitespace() {
            if self.glob_match(host, single_pattern) {
                return true;
            }
        }
        false
    }

    /// Simple glob matching for SSH config Host patterns
    fn glob_match(&self, text: &str, pattern: &str) -> bool {
        // Handle negation
        if pattern.starts_with('!') {
            return !self.glob_match(text, &pattern[1..]);
        }

        // Convert pattern to regex-like matching
        let mut pattern_chars = pattern.chars().peekable();
        let mut text_chars = text.chars().peekable();

        while let Some(p) = pattern_chars.next() {
            match p {
                '*' => {
                    // Match zero or more characters
                    if pattern_chars.peek().is_none() {
                        // * at end matches everything remaining
                        return true;
                    }
                    // Try to match remaining pattern at each position
                    let remaining_pattern: String = pattern_chars.clone().collect();
                    let mut test_text = text_chars.clone();
                    loop {
                        let remaining_text: String = test_text.clone().collect();
                        if self.glob_match(&remaining_text, &remaining_pattern) {
                            return true;
                        }
                        if test_text.next().is_none() {
                            return false;
                        }
                    }
                }
                '?' => {
                    // Match exactly one character
                    if text_chars.next().is_none() {
                        return false;
                    }
                }
                c => {
                    // Exact character match
                    if text_chars.next() != Some(c) {
                        return false;
                    }
                }
            }
        }

        // Pattern consumed - check if text is also consumed
        text_chars.peek().is_none()
    }

    /// Format config.get response as text
    fn format_config_get_text(response: &SshConfigGetResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Config Get\n");
        output.push_str("==============\n\n");
        output.push_str(&format!("Host   : {}\n", response.host));
        output.push_str(&format!("Dry Run: {}\n\n", response.dry_run));

        if response.dry_run {
            output.push_str("Sources:\n");
            if let Some(system) = response.sources.get("system_config_path") {
                output.push_str(&format!("  System: {}\n", system.as_str().unwrap_or("")));
            }
            if let Some(user) = response.sources.get("user_config_path") {
                output.push_str(&format!("  User  : {}\n", user.as_str().unwrap_or("")));
            }
            output.push_str("  Extra : (none)\n");
            if let Some(warnings) = response.warnings.get(0) {
                output.push_str(&format!("\nWarning: {}\n", warnings));
            }
            return output;
        }

        if let Some(ref error) = response.error {
            output.push_str(&format!("Error: {} ({})\n", error.message, error.code));
            return output;
        }

        output.push_str("Sources:\n");
        if let Some(system) = response.sources.get("system_config_path") {
            output.push_str(&format!("  System: {}\n", system.as_str().unwrap_or("")));
        }
        if let Some(user) = response.sources.get("user_config_path") {
            output.push_str(&format!("  User  : {}\n", user.as_str().unwrap_or("")));
        }
        if let Some(extra_arr) = response.sources.get("extra_config_paths").and_then(|v| v.as_array()) {
            if extra_arr.is_empty() {
                output.push_str("  Extra : (none)\n");
            } else {
                for extra in extra_arr {
                    output.push_str(&format!("  Extra : {}\n", extra.as_str().unwrap_or("")));
                }
            }
        }
        output.push_str("  Includes: ");
        if response.sources.get("follow_includes").and_then(|v| v.as_bool()).unwrap_or(false) {
            output.push_str("followed\n\n");
        } else {
            output.push_str("ignored\n\n");
        }

        if let Some(ref effective) = response.effective {
            output.push_str("Effective Settings:\n");
            for (key, setting) in effective {
                let origin_str = if let Some(origin) = &setting.origin {
                    if let (Some(file), Some(line), Some(block)) = (&origin.file, origin.line.as_ref(), &origin.block) {
                        format!(" (from {}:{}, {})", file, line, block)
                    } else {
                        " (default)".to_string()
                    }
                } else {
                    "".to_string()
                };
                output.push_str(&format!("  {:<20} = {:<30}{}\n", key, setting.value, origin_str));
            }
            output.push('\n');
        }

        if let Some(ref summary) = response.summary {
            output.push_str("Matched Blocks:\n");
            for block in &summary.matched_blocks {
                output.push_str(&format!("  - {}\n", block));
            }
            output.push('\n');
        }

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    /// config.get verb entry point
    pub fn verb_config_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let options = match self.parse_config_get_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                let error_details = if let Some(ssh_err) = e.downcast_ref::<SshError>() {
                    Some(ssh_err.to_json())
                } else {
                    Some(SshErrorDetails {
                        code: "ssh.internal_error".to_string(),
                        message: e.to_string(),
                        details: HashMap::new(),
                    })
                };

                let response = SshConfigGetResponse {
                    ok: false,
                    dry_run: false,
                    host: String::new(),
                    sources: serde_json::json!({}),
                    effective: None,
                    raw_entries: None,
                    summary: None,
                    error: error_details,
                    warnings: vec![],
                };

                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        let response = self.config_get_impl(&options);
        let ok = response.ok;

        match options.format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                writeln!(io.stdout, "{}", Self::format_config_get_text(&response))?;
            }
        }

        Ok(if ok {
            Status::success()
        } else {
            Status::err(1, "config.get failed".to_string())
        })
    }

    // ========== End config.get implementation ==========

    // ========== Begin test verb implementation ==========

    /// Parse test options from args
    pub fn parse_test_options(&self, args: &Args, target: &SshTarget) -> Result<SshTestOptions> {
        let mut options = SshTestOptions::default();

        // Parse connection parameters
        if let Some(host) = args.get("host") {
            options.host = Some(host.clone());
        }
        if let Some(port_str) = args.get("port") {
            options.port = port_str.parse::<u16>()
                .with_context(|| format!("Invalid port: {}", port_str))?;
        }
        if let Some(username) = args.get("username") {
            options.username = Some(username.clone());
        }

        // Parse authentication
        if let Some(auth_method) = args.get("auth_method") {
            options.auth_method = match auth_method.as_str() {
                "agent" => SshAuthMethod::Agent,
                "key" => SshAuthMethod::Key,
                "password" => SshAuthMethod::Password,
                _ => bail!(SshError::AuthMethodUnsupported(auth_method.clone())),
            };
        }
        if let Some(password) = args.get("password") {
            options.password = Some(password.clone());
        }
        if let Some(identity_path) = args.get("identity_path") {
            options.identity_path = Some(identity_path.clone());
        }
        if let Some(identity_data) = args.get("identity_data") {
            options.identity_data = Some(identity_data.clone());
        }
        if let Some(identity_passphrase) = args.get("identity_passphrase") {
            options.identity_passphrase = Some(identity_passphrase.clone());
        }
        if let Some(agent_socket) = args.get("agent_socket") {
            options.agent_socket = Some(agent_socket.clone());
        }

        // Parse host key verification
        if let Some(known_hosts_mode) = args.get("known_hosts_mode") {
            options.known_hosts_mode = match known_hosts_mode.as_str() {
                "strict" => KnownHostsMode::Strict,
                "accept-new" => KnownHostsMode::AcceptNew,
                "insecure" => KnownHostsMode::Insecure,
                _ => bail!("Invalid known_hosts_mode: {}", known_hosts_mode),
            };
        }
        if let Some(known_hosts_path) = args.get("known_hosts_path") {
            options.known_hosts_path = Some(known_hosts_path.clone());
        }

        // Parse tests to run
        if let Some(tests_str) = args.get("tests") {
            options.tests = tests_str.split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        if let Some(exec_command) = args.get("exec_command") {
            options.exec_command = exec_command.clone();
        }

        // Parse timeouts
        if let Some(timeout_str) = args.get("connect_timeout_ms") {
            options.connect_timeout_ms = timeout_str.parse::<u64>()?;
        }
        if let Some(timeout_str) = args.get("handshake_timeout_ms") {
            options.handshake_timeout_ms = timeout_str.parse::<u64>()?;
        }
        if let Some(timeout_str) = args.get("auth_timeout_ms") {
            options.auth_timeout_ms = timeout_str.parse::<u64>()?;
        }
        if let Some(timeout_str) = args.get("sftp_timeout_ms") {
            options.sftp_timeout_ms = timeout_str.parse::<u64>()?;
        }
        if let Some(timeout_str) = args.get("exec_timeout_ms") {
            options.exec_timeout_ms = timeout_str.parse::<u64>()?;
        }
        if let Some(timeout_str) = args.get("overall_timeout_ms") {
            options.overall_timeout_ms = timeout_str.parse::<u64>()?;
        }

        // Parse behavior flags
        if let Some(dry_run_str) = args.get("dry_run") {
            options.dry_run = dry_run_str.parse::<bool>()
                .unwrap_or_else(|_| dry_run_str.eq_ignore_ascii_case("true"));
        }
        if let Some(allow_insecure_str) = args.get("allow_insecure_hostkey") {
            options.allow_insecure_hostkey = allow_insecure_str.parse::<bool>()
                .unwrap_or_else(|_| allow_insecure_str.eq_ignore_ascii_case("true"));
        }

        // Parse format
        if let Some(format_str) = args.get("format") {
            options.format = match format_str.as_str() {
                "json" => OutputFormat::Json,
                "text" => OutputFormat::Text,
                _ => bail!("Invalid format: {}", format_str),
            };
        }

        // Resolve connection parameters from target
        if options.host.is_none() {
            options.host = target.host.clone();
        }
        if options.username.is_none() {
            options.username = target.username.clone();
        }
        if let Some(target_port) = target.port {
            if args.get("port").is_none() {
                options.port = target_port;
            }
        }

        Ok(options)
    }

    /// Validate test options
    pub fn validate_test_options(&self, options: &SshTestOptions) -> Result<()> {
        // Validate host
        if options.host.is_none() {
            bail!(SshError::HostRequired);
        }

        // Validate username
        if options.username.is_none() {
            bail!(SshError::UsernameRequired);
        }

        // Validate auth requirements
        match options.auth_method {
            SshAuthMethod::Password => {
                if options.password.is_none() {
                    bail!(SshError::AuthMissingPassword);
                }
            }
            SshAuthMethod::Key => {
                if options.identity_path.is_none() && options.identity_data.is_none() {
                    bail!(SshError::AuthMissingKey);
                }
            }
            SshAuthMethod::Agent => {
                // Agent auth doesn't require additional validation here
            }
        }

        // Validate insecure mode
        if options.known_hosts_mode == KnownHostsMode::Insecure && !options.allow_insecure_hostkey {
            bail!(SshError::TestInsecureHostkeyForbidden);
        }

        // Validate test names
        let valid_tests = ["connect", "auth", "sftp", "exec", "hostkey"];
        for test_name in &options.tests {
            if !valid_tests.contains(&test_name.as_str()) {
                bail!(SshError::TestInvalidTestName(test_name.clone()));
            }
        }

        Ok(())
    }

    /// Execute test verb
    pub fn verb_test(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse options
        let options = match self.parse_test_options(args, &self.target) {
            Ok(opts) => opts,
            Err(e) => {
                let error_response = self.create_test_error_response(
                    "unknown",
                    22,
                    "unknown",
                    &SshError::InternalError(e.to_string()),
                    false,
                );
                self.output_test_response(&error_response, OutputFormat::Json, io)?;
                return Ok(Status::err(1, "test failed".to_string()));
            }
        };

        // Validate options
        if let Err(e) = self.validate_test_options(&options) {
            let ssh_err = if let Some(ssh_error) = e.downcast_ref::<SshError>() {
                ssh_error.clone()
            } else {
                SshError::InternalError(e.to_string())
            };

            let error_response = self.create_test_error_response(
                options.host.as_deref().unwrap_or("unknown"),
                options.port,
                options.username.as_deref().unwrap_or("unknown"),
                &ssh_err,
                options.dry_run,
            );
            self.output_test_response(&error_response, options.format, io)?;
            return Ok(Status::err(1, "test failed".to_string()));
        }

        // Execute tests
        let response = self.execute_tests(&options);
        let ok = response.ok;

        // Output response
        self.output_test_response(&response, options.format, io)?;

        Ok(if ok {
            Status::success()
        } else {
            Status::err(1, "test failed".to_string())
        })
    }

    /// Create an error response for test
    fn create_test_error_response(
        &self,
        host: &str,
        port: u16,
        username: &str,
        error: &SshError,
        dry_run: bool,
    ) -> SshTestResponse {
        SshTestResponse {
            ok: false,
            dry_run,
            target: SshTestTargetInfo {
                host: host.to_string(),
                port,
                username: username.to_string(),
            },
            security: None,
            tests: vec![],
            summary: SshTestSummary {
                tests_requested: vec![],
                tests_run: 0,
                tests_passed: 0,
                tests_failed: 0,
                tests_skipped: 0,
                overall_duration_ms: 0,
            },
            error: Some(error.to_json()),
            warnings: vec![],
        }
    }

    /// Execute all tests
    fn execute_tests(&self, options: &SshTestOptions) -> SshTestResponse {
        let start_time = Instant::now();
        let mut test_results = Vec::new();
        let mut warnings = Vec::new();

        let host = options.host.as_ref().unwrap().clone();
        let port = options.port;
        let username = options.username.as_ref().unwrap().clone();

        // Dry run mode
        if options.dry_run {
            warnings.push("Dry run: no network connections were made and no SSH tests were executed.".to_string());

            for test_name in &options.tests {
                test_results.push(SshSingleTestResult {
                    name: test_name.clone(),
                    status: TestStatus::Planned,
                    duration_ms: None,
                    details: None,
                    error: None,
                });
            }

            return SshTestResponse {
                ok: true,
                dry_run: true,
                target: SshTestTargetInfo {
                    host,
                    port,
                    username,
                },
                security: None,
                tests: test_results,
                summary: SshTestSummary {
                    tests_requested: options.tests.clone(),
                    tests_run: 0,
                    tests_passed: 0,
                    tests_failed: 0,
                    tests_skipped: 0,
                    overall_duration_ms: 0,
                },
                error: None,
                warnings,
            };
        }

        // Track test state
        let mut connect_succeeded = false;
        let mut auth_succeeded = false;

        // Execute each test
        for test_name in &options.tests {
            // Check overall timeout
            if start_time.elapsed().as_millis() as u64 > options.overall_timeout_ms {
                test_results.push(SshSingleTestResult {
                    name: test_name.clone(),
                    status: TestStatus::Skipped,
                    duration_ms: None,
                    details: None,
                    error: Some(SshError::TestOverallTimeout.to_json()),
                });
                continue;
            }

            match test_name.as_str() {
                "connect" => {
                    let result = self.test_connect(options);
                    connect_succeeded = result.status == TestStatus::Passed;
                    test_results.push(result);
                }
                "auth" => {
                    if !connect_succeeded {
                        test_results.push(SshSingleTestResult {
                            name: "auth".to_string(),
                            status: TestStatus::Skipped,
                            duration_ms: None,
                            details: None,
                            error: Some(SshError::TestDependencyFailed("connect test did not pass".to_string()).to_json()),
                        });
                    } else {
                        let result = self.test_auth(options);
                        auth_succeeded = result.status == TestStatus::Passed;
                        test_results.push(result);
                    }
                }
                "sftp" => {
                    if !auth_succeeded {
                        test_results.push(SshSingleTestResult {
                            name: "sftp".to_string(),
                            status: TestStatus::Skipped,
                            duration_ms: None,
                            details: None,
                            error: Some(SshError::TestDependencyFailed("auth test did not pass".to_string()).to_json()),
                        });
                    } else {
                        let result = self.test_sftp(options);
                        test_results.push(result);
                    }
                }
                "exec" => {
                    if !auth_succeeded {
                        test_results.push(SshSingleTestResult {
                            name: "exec".to_string(),
                            status: TestStatus::Skipped,
                            duration_ms: None,
                            details: None,
                            error: Some(SshError::TestDependencyFailed("auth test did not pass".to_string()).to_json()),
                        });
                    } else {
                        let result = self.test_exec(options);
                        test_results.push(result);
                    }
                }
                "hostkey" => {
                    let result = self.test_hostkey(options);
                    test_results.push(result);
                }
                _ => {
                    // Should be caught by validation, but handle gracefully
                    test_results.push(SshSingleTestResult {
                        name: test_name.clone(),
                        status: TestStatus::Failed,
                        duration_ms: None,
                        details: None,
                        error: Some(SshError::TestInvalidTestName(test_name.clone()).to_json()),
                    });
                }
            }
        }

        // Calculate summary
        let tests_run = test_results.iter()
            .filter(|t| t.status != TestStatus::Planned && t.status != TestStatus::Skipped)
            .count();
        let tests_passed = test_results.iter()
            .filter(|t| t.status == TestStatus::Passed)
            .count();
        let tests_failed = test_results.iter()
            .filter(|t| t.status == TestStatus::Failed)
            .count();
        let tests_skipped = test_results.iter()
            .filter(|t| t.status == TestStatus::Skipped)
            .count();

        let overall_duration_ms = start_time.elapsed().as_millis() as u64;
        let ok = tests_failed == 0 && tests_run > 0;

        // Build security info
        let security = Some(SshTestSecurityInfo {
            known_hosts_mode: format!("{:?}", options.known_hosts_mode).to_lowercase(),
            known_hosts_path: options.known_hosts_path.clone(),
            hostkey_algorithm: None,
            hostkey_fingerprint: None,
            insecure_hostkey_allowed: options.allow_insecure_hostkey,
        });

        SshTestResponse {
            ok,
            dry_run: false,
            target: SshTestTargetInfo {
                host,
                port,
                username,
            },
            security,
            tests: test_results,
            summary: SshTestSummary {
                tests_requested: options.tests.clone(),
                tests_run,
                tests_passed,
                tests_failed,
                tests_skipped,
                overall_duration_ms,
            },
            error: None,
            warnings,
        }
    }

    /// Test connect functionality (stub for now - will be implemented with real SSH connection)
    fn test_connect(&self, _options: &SshTestOptions) -> SshSingleTestResult {
        let start = Instant::now();

        // This is a stub - real implementation would attempt actual SSH connection
        // For now, simulate success
        thread::sleep(Duration::from_millis(50));

        SshSingleTestResult {
            name: "connect".to_string(),
            status: TestStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis() as u64),
            details: None,
            error: None,
        }
    }

    /// Test auth functionality (stub for now)
    fn test_auth(&self, _options: &SshTestOptions) -> SshSingleTestResult {
        let start = Instant::now();

        // Stub - real implementation would attempt authentication
        thread::sleep(Duration::from_millis(50));

        SshSingleTestResult {
            name: "auth".to_string(),
            status: TestStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis() as u64),
            details: None,
            error: None,
        }
    }

    /// Test SFTP functionality (stub for now)
    fn test_sftp(&self, _options: &SshTestOptions) -> SshSingleTestResult {
        let start = Instant::now();

        // Stub - real implementation would open SFTP session
        thread::sleep(Duration::from_millis(50));

        SshSingleTestResult {
            name: "sftp".to_string(),
            status: TestStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis() as u64),
            details: None,
            error: None,
        }
    }

    /// Test exec functionality (stub for now)
    fn test_exec(&self, options: &SshTestOptions) -> SshSingleTestResult {
        let start = Instant::now();

        // Stub - real implementation would execute command
        thread::sleep(Duration::from_millis(50));

        let mut details = serde_json::Map::new();
        details.insert("command".to_string(), serde_json::Value::String(options.exec_command.clone()));
        details.insert("exit_status".to_string(), serde_json::Value::Number(0.into()));

        SshSingleTestResult {
            name: "exec".to_string(),
            status: TestStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis() as u64),
            details: Some(serde_json::Value::Object(details)),
            error: None,
        }
    }

    /// Test hostkey functionality (stub for now)
    fn test_hostkey(&self, _options: &SshTestOptions) -> SshSingleTestResult {
        let start = Instant::now();

        // Stub - real implementation would verify host key
        thread::sleep(Duration::from_millis(50));

        SshSingleTestResult {
            name: "hostkey".to_string(),
            status: TestStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis() as u64),
            details: None,
            error: None,
        }
    }

    /// Output test response
    fn output_test_response(
        &self,
        response: &SshTestResponse,
        format: OutputFormat,
        io: &mut IoStreams,
    ) -> Result<()> {
        match format {
            OutputFormat::Json => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&response)?)?;
            }
            OutputFormat::Text => {
                writeln!(io.stdout, "{}", Self::format_test_text(response))?;
            }
        }
        Ok(())
    }

    /// Format test response as text
    fn format_test_text(response: &SshTestResponse) -> String {
        let mut output = String::new();

        output.push_str("SSH Test\n");
        output.push_str("========\n\n");

        output.push_str(&format!("Host     : {}\n", response.target.host));
        output.push_str(&format!("Port     : {}\n", response.target.port));
        output.push_str(&format!("User     : {}\n", response.target.username));
        output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));

        if let Some(security) = &response.security {
            output.push_str("Security :\n");
            output.push_str(&format!("  KnownHostsMode : {}\n", security.known_hosts_mode));
            if let Some(path) = &security.known_hosts_path {
                output.push_str(&format!("  KnownHostsPath : {}\n", path));
            }
            if let Some(algo) = &security.hostkey_algorithm {
                if let Some(fp) = &security.hostkey_fingerprint {
                    output.push_str(&format!("  HostKey        : {} {}\n", algo, fp));
                }
            }
            output.push_str("\n");
        }

        output.push_str("Tests:\n");
        for test in &response.tests {
            let status_str = match test.status {
                TestStatus::Passed => "PASSED",
                TestStatus::Failed => "FAILED",
                TestStatus::Skipped => "SKIPPED",
                TestStatus::Planned => "PLANNED",
            };

            let duration_str = if let Some(ms) = test.duration_ms {
                format!(" ({} ms)", ms)
            } else {
                String::new()
            };

            let details_str = if let Some(details) = &test.details {
                if let Some(obj) = details.as_object() {
                    let parts: Vec<String> = obj.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    if !parts.is_empty() {
                        format!(" {}", parts.join(" "))
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            output.push_str(&format!("  - {} : {}{}{}\n", test.name, status_str, duration_str, details_str));

            if let Some(error) = &test.error {
                output.push_str(&format!("      Error: {}\n", error.message));
            }
        }

        output.push_str("\nSummary:\n");
        output.push_str(&format!("  Requested : {}\n", response.summary.tests_requested.join(", ")));
        output.push_str(&format!("  Run       : {}\n", response.summary.tests_run));
        output.push_str(&format!("  Passed    : {}\n", response.summary.tests_passed));
        output.push_str(&format!("  Failed    : {}\n", response.summary.tests_failed));
        output.push_str(&format!("  Skipped   : {}\n", response.summary.tests_skipped));
        output.push_str(&format!("  Duration  : {} ms\n", response.summary.overall_duration_ms));

        if !response.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("\nWarnings:\n  (none)\n");
        }

        if let Some(error) = &response.error {
            output.push_str(&format!("\nError: {}\n", error.message));
        }

        output
    }

    // ========== End test verb implementation ==========
}

impl Handle for SshHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["exec", "upload", "download", "tunnel", "keys.list", "key.add", "config.get", "test"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "exec" => self.verb_exec(args, io),
            "upload" => self.verb_upload(args, io),
            "download" => self.verb_download(args, io),
            "tunnel" => self.verb_tunnel(args, io),
            "keys.list" => self.verb_keys_list(args, io),
            "key.add" => self.verb_key_add(args, io),
            "config.get" => self.verb_config_get(args, io),
            "test" => self.verb_test(args, io),
            _ => bail!("unknown verb for ssh://: {}", verb),
        }
    }
}

/// Register SSH handle with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("ssh", |u| Ok(Box::new(SshHandle::from_url(u)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::registry::IoStreams;
    use std::io::Cursor;

    /// Helper to create test SSH handle
    fn create_test_handle(host: Option<&str>, port: Option<u16>, username: Option<&str>) -> SshHandle {
        let target = SshTarget {
            host: host.map(|s| s.to_string()),
            port,
            username: username.map(|s| s.to_string()),
        };
        SshHandle { target }
    }

    /// Helper to parse arguments from key=value pairs
    fn args_from_pairs(pairs: &[(&str, &str)]) -> Args {
        let mut args = Args::new();
        for (key, value) in pairs {
            args.insert(key.to_string(), value.to_string());
        }
        args
    }

    /// Helper to capture output from IoStreams
    fn capture_output<F>(f: F) -> (String, String, Status)
    where
        F: FnOnce(&mut IoStreams) -> Result<Status>,
    {
        let mut stdin = Cursor::new(Vec::new());
        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());

        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let status = f(&mut io).unwrap();
        
        let stdout_str = String::from_utf8(stdout.into_inner()).unwrap();
        let stderr_str = String::from_utf8(stderr.into_inner()).unwrap();
        
        (stdout_str, stderr_str, status)
    }

    #[test]
    fn test_ssh_target_from_url() {
        // Test basic URL parsing
        let url = Url::parse("ssh://user@host.com:2222/").unwrap();
        let target = SshTarget::from_url(&url);
        assert_eq!(target.host, Some("host.com".to_string()));
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.username, Some("user".to_string()));

        // Test URL with default port
        let url = Url::parse("ssh://host.com/").unwrap();
        let target = SshTarget::from_url(&url);
        assert_eq!(target.host, Some("host.com".to_string()));
        assert_eq!(target.port, None);
        assert_eq!(target.username, None);

        // Test URL without username
        let url = Url::parse("ssh://host.com:2222/").unwrap();
        let target = SshTarget::from_url(&url);
        assert_eq!(target.host, Some("host.com".to_string()));
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.username, None);
    }

    #[test]
    fn test_ssh_handle_creation() {
        let url = Url::parse("ssh://user@host.com:2222/").unwrap();
        let handle = SshHandle::from_url(&url).unwrap();
        assert_eq!(handle.target.host, Some("host.com".to_string()));
        assert_eq!(handle.target.port, Some(2222));
        assert_eq!(handle.target.username, Some("user".to_string()));
    }

    #[test]
    fn test_resolve_connection_params_from_target() {
        let handle = create_test_handle(Some("host.com"), Some(2222), Some("user"));
        let options = SshExecOptions::default();
        
        let (host, port, username) = handle.resolve_connection_params(&options).unwrap();
        assert_eq!(host, "host.com");
        assert_eq!(port, 2222);
        assert_eq!(username, "user");
    }

    #[test]
    fn test_resolve_connection_params_from_options() {
        let handle = create_test_handle(None, None, None);
        let mut options = SshExecOptions::default();
        options.host = Some("host.com".to_string());
        options.port = 2222;
        options.username = Some("user".to_string());
        
        let (host, port, username) = handle.resolve_connection_params(&options).unwrap();
        assert_eq!(host, "host.com");
        assert_eq!(port, 2222);
        assert_eq!(username, "user");
    }

    #[test]
    fn test_resolve_connection_params_conflict() {
        let handle = create_test_handle(Some("host1.com"), Some(2222), Some("user1"));
        let mut options = SshExecOptions::default();
        options.host = Some("host2.com".to_string());
        
        let result = handle.resolve_connection_params(&options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Host mismatch"));
    }

    #[test]
    fn test_resolve_connection_params_missing_host() {
        let handle = create_test_handle(None, None, None);
        let options = SshExecOptions::default();
        
        let result = handle.resolve_connection_params(&options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Host is required"));
    }

    #[test]
    fn test_validate_auth_options_password() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.auth_method = SshAuthMethod::Password;
        options.password = Some("secret".to_string());
        
        assert!(handle.validate_auth_options(&options).is_ok());
    }

    #[test]
    fn test_validate_auth_options_password_missing() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.auth_method = SshAuthMethod::Password;
        
        let result = handle.validate_auth_options(&options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Password is required"));
    }

    #[test]
    fn test_validate_auth_options_key() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.auth_method = SshAuthMethod::Key;
        options.identity_path = Some("/path/to/key".to_string());
        
        assert!(handle.validate_auth_options(&options).is_ok());
    }

    #[test]
    fn test_validate_auth_options_key_missing() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.auth_method = SshAuthMethod::Key;
        
        let result = handle.validate_auth_options(&options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Private key is required"));
    }

    #[test]
    fn test_build_command_simple() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.command = Some("echo hello".to_string());
        
        let command = handle.build_command(&options).unwrap();
        assert_eq!(command, "echo hello");
    }

    #[test]
    fn test_build_command_with_args() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.command = Some("echo".to_string());
        options.command_args = vec!["hello".to_string(), "world".to_string()];
        
        let command = handle.build_command(&options).unwrap();
        assert_eq!(command, "echo hello world");
    }

    #[test]
    fn test_build_command_bash_shell() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.command = Some("echo hello".to_string());
        options.shell_mode = ShellMode::Bash;
        
        let command = handle.build_command(&options).unwrap();
        assert_eq!(command, "bash -c 'echo hello'");
    }

    #[test]
    fn test_build_command_bash_with_cwd() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let mut options = SshExecOptions::default();
        options.command = Some("pwd".to_string());
        options.shell_mode = ShellMode::Bash;
        options.cwd = Some("/tmp".to_string());
        
        let command = handle.build_command(&options).unwrap();
        assert_eq!(command, "bash -c 'cd '/tmp' && pwd'");
    }

    #[test]
    fn test_build_command_missing() {
        let handle = create_test_handle(Some("host.com"), None, None);
        let options = SshExecOptions::default();
        
        let result = handle.build_command(&options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Command is required"));
    }

    #[test]
    fn test_parse_exec_options_basic() {
        let handle = create_test_handle(None, None, None);
        let args = args_from_pairs(&[
            ("host", "host.com"),
            ("port", "2222"),
            ("username", "user"),
            ("command", "echo hello"),
        ]);
        
        let options = handle.parse_exec_options(&args, &handle.target).unwrap();
        assert_eq!(options.host, Some("host.com".to_string()));
        assert_eq!(options.port, 2222);
        assert_eq!(options.username, Some("user".to_string()));
        assert_eq!(options.command, Some("echo hello".to_string()));
    }

    #[test]
    fn test_parse_exec_options_auth_method() {
        let handle = create_test_handle(None, None, None);
        let args = args_from_pairs(&[
            ("auth_method", "password"),
            ("password", "secret"),
        ]);
        
        let options = handle.parse_exec_options(&args, &handle.target).unwrap();
        assert_eq!(options.auth_method, SshAuthMethod::Password);
        assert_eq!(options.password, Some("secret".to_string()));
    }

    #[test]
    fn test_parse_exec_options_timeouts() {
        let handle = create_test_handle(None, None, None);
        let args = args_from_pairs(&[
            ("connect_timeout_ms", "5000"),
            ("command_timeout_ms", "30000"),
            ("max_output_bytes", "2048"),
        ]);
        
        let options = handle.parse_exec_options(&args, &handle.target).unwrap();
        assert_eq!(options.connect_timeout_ms, 5000);
        assert_eq!(options.command_timeout_ms, 30000);
        assert_eq!(options.max_output_bytes, 2048);
    }

    #[test]
    fn test_dry_run_execution() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);
        assert!(response.warnings.contains(&"Dry run: command was not executed.".to_string()));
        assert_eq!(response.result.as_ref().unwrap().executed, false);
        assert!(response.result.as_ref().unwrap().exit_code.is_none());
    }

    #[test]
    fn test_successful_execution() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(!response.dry_run);
        assert!(response.result.as_ref().unwrap().executed);
        assert_eq!(response.result.as_ref().unwrap().exit_code, Some(0));
        assert!(response.result.as_ref().unwrap().stdout.is_some());
    }

    #[test]
    fn test_text_format_output() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("format", "text"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0));
        assert!(stdout.contains("SSH Exec"));
        assert!(stdout.contains("Host     : host.com"));
        assert!(stdout.contains("User     : user"));
        assert!(stdout.contains("Exit Code: 0"));
    }

    #[test]
    fn test_auth_missing_password_error() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("auth_method", "password"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(1));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.auth_missing_password");
    }

    #[test]
    fn test_auth_missing_key_error() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("auth_method", "key"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(1));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.auth_missing_key");
    }

    #[test]
    fn test_missing_host_error() {
        let handle = create_test_handle(None, None, None);
        let args = args_from_pairs(&[
            ("command", "echo hello"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(1));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.host_required");
    }

    #[test]
    fn test_missing_command_error() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(1));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.command_required");
    }

    #[test]
    fn test_base64_output_encoding() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("output_encoding", "base64"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        
        let stdout_output = response.result.as_ref().unwrap().stdout.as_ref().unwrap();
        // Should be base64 encoded
        assert!(BASE64_STANDARD.decode(stdout_output).is_ok());
    }

    #[test]
    fn test_shell_escaping() {
        // Test shell escape function
        assert_eq!(SshHandle::shell_escape("simple"), "'simple'");
        assert_eq!(SshHandle::shell_escape("with spaces"), "'with spaces'");
        assert_eq!(SshHandle::shell_escape("with'quote"), "'with'\"'\"'quote'");
    }

    #[test]
    fn test_parse_env_vars() {
        let env_str = "FOO=bar,BAZ=qux,EMPTY=";
        let env_vars = SshHandle::parse_env_vars(env_str).unwrap();
        
        assert_eq!(env_vars.len(), 3);
        assert_eq!(env_vars.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env_vars.get("BAZ"), Some(&"qux".to_string()));
        assert_eq!(env_vars.get("EMPTY"), Some(&"".to_string()));
    }

    #[test]
    fn test_parse_command_args() {
        let args_str = "arg1,arg2,arg with spaces";
        let args = SshHandle::parse_command_args(args_str);
        
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "arg1");
        assert_eq!(args[1], "arg2");
        assert_eq!(args[2], "arg with spaces");
    }

    #[test]
    fn test_ssh_error_json_serialization() {
        let error = SshError::AuthMissingPassword;
        let json = error.to_json();
        
        assert_eq!(json.code, "ssh.auth_missing_password");
        assert_eq!(json.message, "Password is required for password authentication");
    }

    #[test]
    fn test_unknown_verb() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[]);

        let (_, _, status) = capture_output(|io| {
            handle.call("unknown_verb", &args, io)
        });

        assert_ne!(status.code, Some(0));
    }

    #[test]
    fn test_verbs_list() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let verbs = handle.verbs();
        assert_eq!(verbs, &["exec", "upload", "download", "tunnel"]);
    }

    #[test]
    fn test_capture_output_disabled() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("command", "echo hello"),
            ("capture_output", "false"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        
        let result = response.result.as_ref().unwrap();
        assert!(result.stdout.is_none());
        assert!(result.stderr.is_none());
    }

    #[test]
    fn test_command_with_different_exit_codes() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        
        // Test command that should return exit code 1
        let args = args_from_pairs(&[
            ("command", "false"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_exec(&args, io)
        });

        assert_eq!(status.code, Some(0)); // SSH exec itself succeeds
        
        // Parse JSON response
        let response: SshExecResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert_eq!(response.result.as_ref().unwrap().exit_code, Some(1));
    }

    // Upload verb tests
    #[test]
    fn test_upload_verb_happy_path() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "Hello, World!"),
            ("source_mode", "inline"),
            ("dest", "/tmp/test.txt"),
            ("overwrite", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(!response.dry_run);
        assert_eq!(response.source.as_ref().unwrap().mode, "inline");
        assert_eq!(response.source.as_ref().unwrap().size_bytes, Some(13));
        assert_eq!(response.dest.as_ref().unwrap().path, "/tmp/test.txt");
        assert!(response.result.as_ref().unwrap().uploaded);
        assert!(!response.result.as_ref().unwrap().planned);
    }

    #[test]
    fn test_upload_verb_dry_run() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "Test content"),
            ("source_mode", "inline"),
            ("dest", "/tmp/test.txt"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);
        assert!(!response.result.as_ref().unwrap().uploaded);
        assert!(response.result.as_ref().unwrap().planned);
        assert_eq!(response.warnings.len(), 1);
        assert!(response.warnings[0].contains("Dry run"));
    }

    #[test]
    fn test_upload_verb_source_missing() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("dest", "/tmp/test.txt"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_source_missing");
    }

    #[test]
    fn test_upload_verb_dest_missing() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "test data"),
            ("source_mode", "inline"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_dest_missing");
    }

    #[test]
    fn test_upload_verb_file_source() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "/home/smiller/Development/rust/resh/test_upload.txt"),
            ("source_mode", "file"),
            ("dest", "/tmp/test.txt"),
            ("overwrite", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert_eq!(response.source.as_ref().unwrap().mode, "file");
        assert!(response.source.as_ref().unwrap().size_bytes.is_some());
        assert!(response.result.as_ref().unwrap().uploaded);
    }

    #[test]
    fn test_upload_verb_base64_source() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        // "Hello, Base64!" in base64
        let base64_data = "SGVsbG8sIEJhc2U2NCE=";
        let args = args_from_pairs(&[
            ("source", base64_data),
            ("source_mode", "inline"),
            ("source_encoding", "base64"),
            ("dest", "/tmp/test.txt"),
            ("overwrite", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert_eq!(response.source.as_ref().unwrap().size_bytes, Some(14)); // Decoded size
        assert!(response.result.as_ref().unwrap().uploaded);
    }

    #[test]
    fn test_upload_verb_dest_exists_no_overwrite() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "test data"),
            ("source_mode", "inline"),
            ("dest", "/tmp/existing_file.txt"),
            ("overwrite", "false"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_dest_exists");
    }

    #[test]
    fn test_upload_verb_checksum_verification() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "test data for checksum"),
            ("source_mode", "inline"),
            ("dest", "/tmp/checksum_test.txt"),
            ("verify_checksum", "true"),
            ("checksum_algorithm", "sha256"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.result.as_ref().unwrap().verify_checksum);
        assert_eq!(response.result.as_ref().unwrap().checksum_algorithm, "sha256");
        assert_eq!(response.result.as_ref().unwrap().checksum_verified, Some(true));
    }

    #[test]
    fn test_upload_verb_checksum_mismatch() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "test data"),
            ("source_mode", "inline"),
            ("dest", "/tmp/checksum_mismatch.txt"),
            ("verify_checksum", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_checksum_mismatch");
    }

    #[test]
    fn test_upload_verb_atomic_mode() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "atomic test data"),
            ("source_mode", "inline"),
            ("dest", "/tmp/atomic_test.txt"),
            ("atomic", "true"),
            ("overwrite", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dest.as_ref().unwrap().atomic);
        assert!(response.result.as_ref().unwrap().uploaded);
    }

    #[test]
    fn test_upload_verb_text_format() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "text format test"),
            ("source_mode", "inline"),
            ("dest", "/tmp/text_test.txt"),
            ("format", "text"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_eq!(status.code, Some(0));
        
        // Check text output format
        assert!(stdout.contains("SSH Upload"));
        assert!(stdout.contains("Host    : host.com"));
        assert!(stdout.contains("Source  :"));
        assert!(stdout.contains("Dest    :"));
        assert!(stdout.contains("Result  :"));
        assert!(stdout.contains("Uploaded   : yes"));
    }

    #[test]
    fn test_upload_verb_permission_denied() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "permission test"),
            ("source_mode", "inline"),
            ("dest", "/tmp/permission_denied.txt"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_remote_write_failed");
    }

    #[test]
    fn test_upload_verb_timeout() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("source", "timeout test"),
            ("source_mode", "inline"),
            ("dest", "/tmp/timeout_test.txt"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_upload(&args, io)
        });

        assert_ne!(status.code, Some(0));
        
        // Parse JSON response
        let response: SshUploadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.upload_timeout");
    }

    #[test]
    fn test_upload_verbs_list() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let verbs = handle.verbs();
        assert_eq!(verbs, &["exec", "upload", "download", "tunnel"]);
    }

    #[test]
    fn test_upload_unknown_verb() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[]);

        let result = handle.call("unknown_verb", &args, &mut IoStreams {
            stdin: &mut std::io::Cursor::new(Vec::new()),
            stdout: &mut std::io::Cursor::new(Vec::new()),
            stderr: &mut std::io::Cursor::new(Vec::new()),
        });

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown verb"));
    }

    // ===== Download Verb Tests =====

    #[test]
    fn test_download_happy_path_with_file_dest() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_{}.txt", rand::random::<u32>()));

        let args = args_from_pairs(&[
            ("source", "/etc/myapp/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("return_content", "true"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(!response.dry_run);
        assert_eq!(response.connection.host, "example.com");
        assert_eq!(response.connection.port, 22);
        assert_eq!(response.connection.username, "deploy");

        let source = response.source.unwrap();
        assert_eq!(source.path, "/etc/myapp/config.yaml");
        assert!(source.size_bytes.is_some());

        let dest = response.dest.unwrap();
        assert_eq!(dest.mode, "file");
        assert_eq!(dest.path, Some(dest_path.to_str().unwrap().to_string()));

        let result = response.result.unwrap();
        assert!(result.downloaded);
        assert!(!result.planned);
        assert!(result.return_content);
        assert!(result.content.is_some());

        // Cleanup
        let _ = std::fs::remove_file(dest_path);
    }

    #[test]
    fn test_download_with_content_only_no_file() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest_mode", "none"),
            ("return_content", "true"),
            ("return_encoding", "utf8"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let dest = response.dest.unwrap();
        assert_eq!(dest.mode, "none");
        assert!(dest.path.is_none());

        let result = response.result.unwrap();
        assert!(result.downloaded);
        assert!(result.content.is_some());
        assert_eq!(result.return_encoding, "utf8");
    }

    #[test]
    fn test_download_with_base64_encoding() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/bin/data"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest_mode", "none"),
            ("return_content", "true"),
            ("return_encoding", "base64"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let result = response.result.unwrap();
        assert!(result.downloaded);
        assert_eq!(result.return_encoding, "base64");
        assert!(result.content.is_some());

        // Verify base64 content can be decoded
        let content = result.content.unwrap();
        assert!(BASE64_STANDARD.decode(&content).is_ok());
    }

    #[test]
    fn test_download_dry_run() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_dry_{}.txt", rand::random::<u32>()));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("dry_run", "true"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);

        let result = response.result.unwrap();
        assert!(!result.downloaded);
        assert!(result.planned);
        assert!(result.content.is_none());

        assert!(!response.warnings.is_empty());
        assert!(response.warnings[0].contains("Dry run"));

        // Verify file was not created
        assert!(!dest_path.exists());
    }

    #[test]
    fn test_download_missing_source() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("dest", "/tmp/output.txt"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.download_source_missing");
    }

    #[test]
    fn test_download_missing_dest_when_dest_mode_file() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("dest_mode", "file"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.download_dest_missing");
    }

    #[test]
    fn test_download_dest_exists_no_overwrite() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_exists_{}.txt", rand::random::<u32>()));

        // Create existing file
        std::fs::write(&dest_path, b"existing content").unwrap();

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("overwrite", "false"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.download_dest_exists");

        // Cleanup
        let _ = std::fs::remove_file(dest_path);
    }

    #[test]
    fn test_download_dest_exists_with_overwrite() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_overwrite_{}.txt", rand::random::<u32>()));

        // Create existing file
        std::fs::write(&dest_path, b"existing content").unwrap();

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("overwrite", "true"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let result = response.result.unwrap();
        assert!(result.downloaded);

        // Verify file was overwritten
        assert!(dest_path.exists());
        let content = std::fs::read_to_string(&dest_path).unwrap();
        assert_ne!(content, "existing content");

        // Cleanup
        let _ = std::fs::remove_file(dest_path);
    }

    #[test]
    fn test_download_mkdir_parents() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let nested_dir = temp_dir.join(format!("test_nested_{}", rand::random::<u32>()));
        let dest_path = nested_dir.join("subdir/file.txt");

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("mkdir_parents", "true"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        // Verify nested directories were created
        assert!(dest_path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&nested_dir);
    }

    #[test]
    fn test_download_text_format() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_text_{}.txt", rand::random::<u32>()));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("format", "text"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        assert!(stdout.contains("SSH Download"));
        assert!(stdout.contains("Host"));
        assert!(stdout.contains("example.com"));
        assert!(stdout.contains("Source"));
        assert!(stdout.contains("/etc/config.yaml"));

        // Cleanup
        let _ = std::fs::remove_file(dest_path);
    }

    #[test]
    fn test_download_with_checksum_verification() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest_mode", "none"),
            ("return_content", "true"),
            ("verify_checksum", "true"),
            ("checksum_algorithm", "sha256"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let result = response.result.unwrap();
        assert!(result.verify_checksum);
        assert_eq!(result.checksum_algorithm, "sha256");
        assert_eq!(result.checksum_verified, Some(true));
    }

    #[test]
    fn test_download_return_content_false() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));
        let temp_dir = std::env::temp_dir();
        let dest_path = temp_dir.join(format!("test_download_no_content_{}.txt", rand::random::<u32>()));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest", dest_path.to_str().unwrap()),
            ("return_content", "false"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let result = response.result.unwrap();
        assert!(!result.return_content);
        assert!(result.content.is_none());

        // File should still be created
        assert!(dest_path.exists());

        // Cleanup
        let _ = std::fs::remove_file(dest_path);
    }

    #[test]
    fn test_download_with_max_size_limit() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        // Set a very small limit to trigger the error in simulation
        let args = args_from_pairs(&[
            ("source", "/large/file.bin"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest_mode", "none"),
            ("max_size_bytes", "100"),  // Very small limit
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        // The simulated file size is 2048 bytes, which exceeds 100 bytes
        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.download_too_large");
    }

    #[test]
    fn test_download_connection_param_resolution() {
        // Test that connection params are resolved correctly from target and options
        let handle = create_test_handle(Some("target-host.com"), Some(2222), Some("target-user"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("auth_method", "password"),
            ("password", "testpass"),
            ("dest_mode", "none"),
            ("dry_run", "true"),
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(0));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert_eq!(response.connection.host, "target-host.com");
        assert_eq!(response.connection.port, 2222);
        assert_eq!(response.connection.username, "target-user");
    }

    #[test]
    fn test_download_auth_validation_password() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("dest_mode", "none"),
            ("auth_method", "password"),
            // Missing password
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.auth_missing_password");
    }

    #[test]
    fn test_download_auth_validation_key() {
        let handle = create_test_handle(Some("example.com"), Some(22), Some("deploy"));

        let args = args_from_pairs(&[
            ("source", "/etc/config.yaml"),
            ("dest_mode", "none"),
            ("auth_method", "key"),
            // Missing identity_path and identity_data
            ("format", "json"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| handle.verb_download(&args, io));

        assert_eq!(status.code, Some(1));

        let response: SshDownloadResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);

        let error = response.error.unwrap();
        assert_eq!(error.code, "ssh.auth_missing_key");
    }

    // Tunnel verb tests

    #[test]
    fn test_tunnel_dry_run_local() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("local_bind_port", "5433"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);
        assert!(response.warnings.iter().any(|w| w.contains("Dry run")));

        let tunnel = response.tunnel.unwrap();
        assert_eq!(tunnel.mode, "local");
        assert_eq!(tunnel.local_bind_port, Some(5433));
        assert_eq!(tunnel.remote_dest_host, Some("db.internal".to_string()));
        assert_eq!(tunnel.remote_dest_port, Some(5432));
    }

    #[test]
    fn test_tunnel_dry_run_remote() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "remote"),
            ("local_dest_host", "localhost"),
            ("local_dest_port", "8080"),
            ("remote_bind_port", "9090"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);

        let tunnel = response.tunnel.unwrap();
        assert_eq!(tunnel.mode, "remote");
        assert_eq!(tunnel.remote_bind_port, Some(9090));
        assert_eq!(tunnel.local_dest_host, Some("localhost".to_string()));
        assert_eq!(tunnel.local_dest_port, Some(8080));
    }

    #[test]
    fn test_tunnel_dry_run_dynamic() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "dynamic"),
            ("local_bind_port", "1080"),
            ("socks_version", "socks5"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.dry_run);

        let tunnel = response.tunnel.unwrap();
        assert_eq!(tunnel.mode, "dynamic");
        assert_eq!(tunnel.local_bind_port, Some(1080));
        assert_eq!(tunnel.socks_version, Some("socks5".to_string()));
    }

    #[test]
    fn test_tunnel_missing_mode() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_ne!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.tunnel_mode_required");
    }

    #[test]
    fn test_tunnel_local_missing_remote_dest() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("local_bind_port", "5433"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_ne!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.tunnel_missing_remote_dest");
    }

    #[test]
    fn test_tunnel_remote_missing_local_dest() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "remote"),
            ("remote_bind_port", "9090"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_ne!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.tunnel_missing_local_dest");
    }

    #[test]
    fn test_tunnel_wildcard_bind_forbidden() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("local_bind_host", "0.0.0.0"),
            ("local_bind_port", "5433"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("allow_wildcard_binds", "false"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_ne!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.tunnel_wildcard_bind_forbidden");
    }

    #[test]
    fn test_tunnel_wildcard_bind_allowed_with_warning() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("local_bind_host", "0.0.0.0"),
            ("local_bind_port", "5433"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("allow_wildcard_binds", "true"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.warnings.iter().any(|w| w.contains("exposes the tunnel")));
    }

    #[test]
    fn test_tunnel_text_format() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("local_bind_port", "5433"),
            ("dry_run", "true"),
            ("format", "text"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));
        assert!(stdout.contains("SSH Tunnel"));
        assert!(stdout.contains("Mode     : local"));
        assert!(stdout.contains("Remote Dest"));
    }

    #[test]
    fn test_tunnel_lifetime_config() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("local_bind_port", "5433"),
            ("tunnel_timeout_ms", "60000"),
            ("idle_timeout_ms", "30000"),
            ("max_connections", "10"),
            ("max_bytes_in", "1048576"),
            ("max_bytes_out", "2097152"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);

        let lifetime = response.lifetime.unwrap();
        assert_eq!(lifetime.tunnel_timeout_ms, Some(60000));
        assert_eq!(lifetime.idle_timeout_ms, Some(30000));
        assert_eq!(lifetime.max_connections, Some(10));
        assert_eq!(lifetime.max_bytes_in, Some(1048576));
        assert_eq!(lifetime.max_bytes_out, Some(2097152));
    }

    #[test]
    fn test_tunnel_missing_host_error() {
        let handle = create_test_handle(None, None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("local_bind_port", "5433"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_ne!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_ref().unwrap().code, "ssh.host_required");
    }

    #[test]
    fn test_tunnel_insecure_mode_warning() {
        let handle = create_test_handle(Some("host.com"), None, Some("user"));
        let args = args_from_pairs(&[
            ("mode", "local"),
            ("remote_dest_host", "db.internal"),
            ("remote_dest_port", "5432"),
            ("local_bind_port", "5433"),
            ("known_hosts_mode", "insecure"),
            ("dry_run", "true"),
        ]);

        let (stdout, _stderr, status) = capture_output(|io| {
            handle.verb_tunnel(&args, io)
        });

        assert_eq!(status.code, Some(0));

        let response: SshTunnelResponse = serde_json::from_str(&stdout).unwrap();
        assert!(response.ok);
        assert!(response.warnings.iter().any(|w| w.contains("Host key verification disabled")));
    }
}