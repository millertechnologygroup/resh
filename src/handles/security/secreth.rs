//! `secret://`: small secret values (API keys, passwords, tokens) in one of
//! three scopes:
//!
//! - `local`: the values live in the OS keyring (Secret Service on Linux,
//!   Keychain on macOS) under the service `resh-secret`, one entry per key
//!   path. `<state-dir>/resh/secrets/local.json` (0600, in a 0700
//!   directory) holds only the key names and their keyring references, for
//!   `ls`. Without a keyring, writes are refused. A plaintext store written
//!   by older releases is still read (with a warning) and is moved into the
//!   keyring by the next write.
//! - `env`: the read-only process environment.
//! - `vault`: a HashiCorp Vault KV version 2 engine (`VAULT_ADDR`,
//!   `VAULT_TOKEN` or `~/.vault-token`).
//!
//! `rotate` replaces a secret with a newly generated one (random bytes, a
//! UUID, an AES key or an RSA private key) and never prints it.

use anyhow::Result;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    lenient,
    registry::{Args, Handle, IoStreams},
    secret_store::{self, SecretStore},
    status::{Status, error_json, error_line, exit},
};

#[cfg(test)]
#[path = "secret_fake_vault.rs"]
mod fake_vault;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("secret", |u| Ok(Box::new(SecretHandle::from_url(u)?)));
    reg.set_probe_url("secret", "secret://local/resh-help-probe");
}

/// The OS keyring service under which `secret://local` values are kept;
/// the account is the key path.
pub const KEYRING_SERVICE: &str = "resh-secret";

/// Every error code this handle reports (documented in
/// docs/Security_Secrets/secret.md).
pub const ERROR_CODES: &[&str] = &[
    "secret.invalid_argument",
    "secret.unknown_verb",
    "secret.missing_key",
    "secret.invalid_key",
    "secret.missing_value",
    "secret.read_only",
    "secret.env_not_set",
    "secret.keyring_unavailable",
    "secret.store_error",
    "secret.vault_not_configured",
    "secret.vault_denied",
    "secret.vault_error",
    "secret.vault_field_missing",
    "secret.vault_conflict",
    "secret.timeout",
];

/// How long a Vault request may take when no `timeout_ms` is given.
const VAULT_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a write waits for another resh process's keystore lock when no
/// `timeout_ms` is given.
const LOCK_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Metadata for `resh secret --help` and `resh secret <verb> --help`.
static SECRET_HELP: HandleHelp = HandleHelp {
    description: "The secret handle reads and stores secrets in one of three scopes: local, \
        where values live in the OS keyring and a 0600 index file under the user's state \
        directory lists only their names; env, the read-only process environment; and \
        vault, a HashiCorp Vault KV version 2 engine reached through VAULT_ADDR and \
        VAULT_TOKEN. The scope is the URL host and the key path follows it, as in \
        secret://local/app/db_password. Every verb prints a single JSON object, and only \
        get ever prints a secret value.",
    usage: "resh secret://<scope>/<key-path>.<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "get",
            definition: "Reads one secret from the keyring, the environment or Vault and \
                prints it as JSON, optionally withholding the value.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|env|vault>/<key-path>.get [redact=true|false]\n  \
                    [timeout_ms=<ms>] (local, vault)\n  \
                    [mount=<path>] [field=<name>] [ca_file=<pem>] (vault)",
                example: "resh --json-pretty secret://local/app/db_password.get",
                example_output: Some(
                    r#"{
  "backend": "local",
  "exists": true,
  "key": "app/db_password",
  "scope": "local",
  "value": "s3cr3t-value"
}

Shown with --json-pretty. With redact=true the value is null and a
"redacted": true field is added; a missing key gives exists false.
A value still in the plaintext store of an older release is returned
with a warning; the next write moves it into the keyring."#,
                ),
            }),
        },
        VerbHelp {
            name: "ls",
            definition: "Lists the keys equal to the key path or nested under it, or every key \
                when the path is empty, in sorted order, without their values.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|env|vault>/[<prefix>].ls\n  \
                    [timeout_ms=<ms>] (local, vault)\n  \
                    [mount=<path>] [ca_file=<pem>] (vault)",
                example: "resh --json-pretty secret://local/app.ls",
                example_output: Some(
                    r#"{
  "backend": "local",
  "keys": [
    "app/api_key",
    "app/db_password"
  ],
  "prefix": "app",
  "scope": "local"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "set",
            definition: "Stores a secret in the OS keyring or in Vault from a literal value or \
                from an environment variable.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|vault>/<key-path>.set\n  \
                    value=<secret>|from_env=<VAR_NAME> [timeout_ms=<ms>]\n  \
                    [mount=<path>] [field=<name>] [ca_file=<pem>] (vault)",
                example: "resh --json-pretty secret://local/app/db_password.set from_env=DB_PASSWORD",
                example_output: Some(
                    r#"{
  "backend": "local",
  "key": "app/db_password",
  "scope": "local",
  "set": true,
  "source": "env"
}

Shown with --json-pretty. The source is "literal" when value= is used.
local values go to the OS keyring only; without one, set fails with
secret.keyring_unavailable and nothing is stored."#,
                ),
            }),
        },
        VerbHelp {
            name: "rm",
            definition: "Removes a secret from the OS keyring or from Vault and reports \
                whether it existed.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|vault>/<key-path>.rm [timeout_ms=<ms>]\n  \
                    [mount=<path>] [ca_file=<pem>] (vault)",
                example: "resh --json-pretty secret://local/app/old_token.rm",
                example_output: Some(
                    r#"{
  "backend": "local",
  "key": "app/old_token",
  "removed": true,
  "scope": "local"
}

Shown with --json-pretty. In vault, rm deletes every version and field
of the secret."#,
                ),
            }),
        },
        VerbHelp {
            name: "rotate",
            definition: "Replaces a secret with a newly generated value (random bytes, a UUID, \
                an AES key or an RSA private key) without printing it.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|vault>/<key-path>.rotate\n  \
                    [strategy=random|uuid|aes|rsa] [length=<bits>]\n  \
                    [encoding=hex|base64|base64url] [timeout_ms=<ms>]\n  \
                    [mount=<path>] [field=<name>] [ca_file=<pem>] (vault)",
                example: "resh --json-pretty secret://local/app/api_key.rotate strategy=random",
                example_output: Some(
                    r#"{
  "backend": "local",
  "encoding": "hex",
  "existed": true,
  "key": "app/api_key",
  "length": 256,
  "rotated": true,
  "scope": "local",
  "strategy": "random"
}

Shown with --json-pretty. Defaults: random, 256 bits, hex. aes takes
128, 192 or 256 bits; rsa 2048, 3072 (default) or 4096 bits, stores a
PKCS#8 PEM private key and prints the public key as public_key; uuid
takes no length. Read the new value with get."#,
                ),
            }),
        },
    ],
};

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// A failure with its exit status and `secret.<code>`.
#[derive(Debug)]
struct Failure {
    exit: i32,
    code: &'static str,
    message: String,
}

type VResult<T> = std::result::Result<T, Failure>;

impl Failure {
    fn usage(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit: exit::USAGE,
            code,
            message: message.into(),
        }
    }
    fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit: exit::FAILED,
            code,
            message: message.into(),
        }
    }
    fn timeout(message: impl Into<String>) -> Self {
        Self {
            exit: exit::TIMEOUT,
            code: "secret.timeout",
            message: message.into(),
        }
    }
}

/// The deadline set by `timeout_ms`, if any.
#[derive(Clone, Copy)]
struct Deadline {
    end: Option<Instant>,
    ms: Option<u64>,
}

impl Deadline {
    fn none() -> Self {
        Self {
            end: None,
            ms: None,
        }
    }

    /// The time an operation may take: what is left of the deadline, or
    /// `default` without one. An expired deadline is a timeout failure.
    fn budget(&self, default: Duration) -> VResult<Duration> {
        match self.end {
            None => Ok(default),
            Some(end) => {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(self.expired())
                } else {
                    Ok(left)
                }
            }
        }
    }

    fn expired(&self) -> Failure {
        match self.ms {
            Some(ms) => Failure::timeout(format!(
                "timeout_ms={ms} passed before the operation finished"
            )),
            None => Failure::timeout("the operation did not finish in time"),
        }
    }
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

pub struct SecretHandle {
    scope: String,
    key_path: String,
    is_help_request: bool,
    help_verb: Option<String>,
}

/// One verb's work: its JSON result fields and warnings.
struct Outcome {
    fields: Map<String, Value>,
    warnings: Vec<String>,
}

impl Outcome {
    fn new() -> Self {
        Self {
            fields: Map::new(),
            warnings: Vec::new(),
        }
    }
    fn with(mut self, k: &str, v: Value) -> Self {
        self.fields.insert(k.into(), v);
        self
    }
}

impl SecretHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        // In-URL help forms: secret://--help, secret://-h, secret:///--help,
        // secret://<scope>/<key>.--help, and ?help=<verb> / ?--help=<verb>.
        // Matched exactly, so keys such as "my-hosts" are not help requests.
        let path_str = u.path();
        let is_help_request = help::is_help_flag(path_str)
            || u.host_str().is_some_and(help::is_help_flag)
            || path_str
                .rsplit_once('.')
                .is_some_and(|(_, last)| help::is_help_flag(last));

        let help_verb = u.query_pairs().find_map(|(k, v)| {
            if k == "help" || (k == "--help" && !v.is_empty()) {
                Some(v.to_string())
            } else {
                None
            }
        });

        if is_help_request || help_verb.is_some() {
            return Ok(SecretHandle {
                scope: "local".to_string(),
                key_path: String::new(),
                is_help_request: true,
                help_verb,
            });
        }

        // secret://scope/key_path, or secret:///scope/key_path.
        let path = u.path().strip_prefix('/').unwrap_or(u.path());
        let (scope, key_path) = match u.host_str() {
            Some(host) => (host.to_string(), path.to_string()),
            None => {
                let (scope, rest) = path.split_once('/').unwrap_or((path, ""));
                if scope.is_empty() {
                    anyhow::bail!("secret URL must contain a scope (local, env or vault)");
                }
                (scope.to_string(), rest.to_string())
            }
        };
        // The URL parser percent-encodes some characters; key paths are
        // used as written.
        let key_path = percent_encoding::percent_decode_str(&key_path)
            .decode_utf8()
            .map_err(|_| anyhow::anyhow!("secret key path is not valid UTF-8"))?
            .into_owned();

        match scope.as_str() {
            "local" | "env" | "vault" => {}
            _ => anyhow::bail!(
                "unsupported scope '{}'; supported scopes: local, env, vault",
                scope
            ),
        }

        Ok(SecretHandle {
            scope,
            key_path,
            is_help_request: false,
            help_verb: None,
        })
    }

    /// Writes the approved help for the in-URL help forms.
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> Result<Status> {
        let text = help::render_legacy("secret", &SECRET_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text)?;
        if !text.ends_with('\n') {
            writeln!(io.stdout)?;
        }
        Ok(Status::ok())
    }

    fn base(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("scope".into(), json!(self.scope));
        m.insert("backend".into(), json!(self.scope));
        m
    }

    /// Writes the standard failure: `Error: [secret.<code>] <message>` on
    /// stderr and a JSON object with `"error": {"code", "message"}` on
    /// stdout.
    fn emit_failure(&self, io: &mut IoStreams, f: Failure, verb: &str) -> Result<Status> {
        debug_assert!(ERROR_CODES.contains(&f.code), "{} not listed", f.code);
        writeln!(io.stderr, "{}", error_line(f.code, &f.message))?;
        let mut obj = self.base();
        obj.insert("ok".into(), json!(false));
        if verb == "ls" {
            obj.insert("prefix".into(), json!(self.key_path));
        } else {
            obj.insert("key".into(), json!(self.key_path));
        }
        obj.insert("error".into(), error_json(f.code, &f.message));
        writeln!(io.stdout, "{}", Value::Object(obj))?;
        Ok(Status::coded(f.exit, f.code, &f.message))
    }

    fn emit(&self, io: &mut IoStreams, out: Outcome) -> Result<Status> {
        for w in &out.warnings {
            writeln!(io.stderr, "Warning: {w}")?;
        }
        let mut obj = self.base();
        for (k, v) in out.fields {
            obj.insert(k, v);
        }
        if !out.warnings.is_empty() {
            obj.insert("warnings".into(), json!(out.warnings));
        }
        writeln!(io.stdout, "{}", Value::Object(obj))?;
        Ok(Status::ok())
    }

    fn run(&self, verb: &str, args: &Args) -> VResult<Outcome> {
        check_args(&self.scope, verb, args)?;
        check_key(&self.scope, verb, &self.key_path)?;
        let deadline = parse_deadline(args)?;
        let backend: Box<dyn Backend> = match self.scope.as_str() {
            "local" => Box::new(Local::new(deadline)?),
            "env" => Box::new(EnvScope),
            "vault" => Box::new(Vault::from_args(args, deadline)?),
            other => unreachable!("scope {other} validated in from_url"),
        };
        let key = self.key_path.as_str();
        match verb {
            "get" => {
                let redact = match args.get("redact") {
                    None => false,
                    Some(v) => lenient::parse_bool(v).ok_or_else(|| {
                        Failure::usage(
                            "secret.invalid_argument",
                            format!("redact={v:?} is not true or false; nothing was read"),
                        )
                    })?,
                };
                let mut out = Outcome::new().with("key", json!(key));
                let value = backend.get(key, &mut out.warnings)?;
                out = out.with("exists", json!(value.is_some()));
                match value {
                    Some(_) if redact => {
                        out = out.with("value", Value::Null).with("redacted", json!(true))
                    }
                    Some(v) => out = out.with("value", json!(v)),
                    None => out = out.with("value", Value::Null),
                }
                Ok(out)
            }
            "set" => {
                backend.check_writable()?;
                let (value, source) = secret_input(args)?;
                let mut out = Outcome::new();
                backend.set(key, &value, &mut out.warnings)?;
                Ok(out
                    .with("key", json!(key))
                    .with("set", json!(true))
                    .with("source", json!(source)))
            }
            "rm" => {
                backend.check_writable()?;
                let mut out = Outcome::new();
                let removed = backend.rm(key, &mut out.warnings)?;
                Ok(out.with("key", json!(key)).with("removed", json!(removed)))
            }
            "ls" => {
                let mut out = Outcome::new();
                let keys = backend.ls(key, &mut out.warnings)?;
                Ok(out.with("prefix", json!(key)).with("keys", json!(keys)))
            }
            "rotate" => {
                let spec = RotateSpec::from_args(args)?;
                // Fails before generating anything when the scope is
                // read-only or unreachable.
                backend.check_writable()?;
                let generated = spec.generate(deadline)?;
                let mut out = Outcome::new();
                let existed = backend.exists(key, &mut out.warnings)?;
                backend.set(key, &generated.value, &mut out.warnings)?;
                out = out
                    .with("key", json!(key))
                    .with("rotated", json!(true))
                    .with("existed", json!(existed))
                    .with("strategy", json!(spec.strategy.name()))
                    .with("length", json!(spec.length));
                if let Some(e) = spec.encoding {
                    out = out.with("encoding", json!(e.name()));
                }
                if let Some(pk) = generated.public_key {
                    out = out.with("public_key", json!(pk));
                }
                Ok(out)
            }
            _ => unreachable!("verb checked by check_args"),
        }
    }
}

impl Handle for SecretHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "set", "rm", "ls", "rotate"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&SECRET_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help: secret://--help, secret://--help=get (the parser
        // passes the verb as verb=get), ?help=get, or a help verb.
        if self.is_help_request || help::HELP_ALIASES.contains(&verb) {
            let wanted = self
                .help_verb
                .as_deref()
                .or(args.get("verb").map(String::as_str));
            return self.display_help(wanted, io);
        }
        if !self.verbs().contains(&verb) {
            let hint = suggest(verb, self.verbs())
                .map(|s| format!("; did you mean {s:?}?"))
                .unwrap_or_default();
            let f = Failure::usage(
                "secret.unknown_verb",
                format!(
                    "unknown verb {verb:?} for secret://{hint} (verbs: {})",
                    self.verbs().join(", ")
                ),
            );
            return self.emit_failure(io, f, verb);
        }
        match self.run(verb, args) {
            Ok(out) => self.emit(io, out),
            Err(f) => self.emit_failure(io, f, verb),
        }
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// The arguments `verb` accepts in `scope`.
fn allowed_args(scope: &str, verb: &str) -> Vec<&'static str> {
    let mut a: Vec<&'static str> = match verb {
        "get" => vec!["redact"],
        "set" => vec!["value", "from_env"],
        "rotate" => vec!["strategy", "length", "encoding"],
        _ => vec![],
    };
    match scope {
        "local" => a.push("timeout_ms"),
        "vault" => {
            a.extend(["timeout_ms", "mount", "ca_file"]);
            if matches!(verb, "get" | "set" | "rotate") {
                a.push("field");
            }
        }
        _ => {}
    }
    a
}

fn check_args(scope: &str, verb: &str, args: &Args) -> VResult<()> {
    let allowed = allowed_args(scope, verb);
    let mut unknown: Vec<&str> = args
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    unknown.sort_unstable();
    if let Some(k) = unknown.first() {
        let hint = suggest(k, &allowed)
            .map(|s| format!("; did you mean {s:?}?"))
            .unwrap_or_default();
        let accepted = if allowed.is_empty() {
            "none".to_string()
        } else {
            allowed.join(", ")
        };
        return Err(Failure::usage(
            "secret.invalid_argument",
            format!(
                "unknown argument {k:?} for secret {verb} in scope {scope}{hint} \
                 (accepted: {accepted}); nothing was done"
            ),
        ));
    }
    Ok(())
}

fn parse_deadline(args: &Args) -> VResult<Deadline> {
    let Some(raw) = args.get("timeout_ms") else {
        return Ok(Deadline::none());
    };
    match raw.trim().parse::<u64>() {
        Ok(ms) if (1..=86_400_000).contains(&ms) => Ok(Deadline {
            end: Some(Instant::now() + Duration::from_millis(ms)),
            ms: Some(ms),
        }),
        _ => Err(Failure::usage(
            "secret.invalid_argument",
            format!(
                "timeout_ms={raw:?} is not a whole number of milliseconds from 1 to 86400000; \
                 nothing was done"
            ),
        )),
    }
}

/// Checks the key path: required (except for `ls`), and for local and
/// vault made of non-empty `/`-separated segments other than `.` and `..`.
fn check_key(scope: &str, verb: &str, key: &str) -> VResult<()> {
    if key.is_empty() {
        if verb == "ls" {
            return Ok(());
        }
        return Err(Failure::usage(
            "secret.missing_key",
            format!(
                "secret {verb} needs a key path, as in secret://{scope}/app/db_password.{verb}; \
                 nothing was done"
            ),
        ));
    }
    let bad = |why: &str| {
        Failure::usage(
            "secret.invalid_key",
            format!("key path {key:?} {why}; nothing was done"),
        )
    };
    if key.chars().any(char::is_control) {
        return Err(bad("contains a control character"));
    }
    if scope == "env" {
        if key.contains('=') {
            return Err(bad("contains '=', which no environment variable name can"));
        }
        return Ok(());
    }
    if key.len() > 1024 {
        return Err(bad("is longer than 1024 bytes"));
    }
    for seg in key.split('/') {
        if seg.is_empty() {
            return Err(bad(
                "has an empty segment (a leading, trailing or doubled '/')",
            ));
        }
        if seg == "." || seg == ".." {
            return Err(bad("has a '.' or '..' segment"));
        }
    }
    Ok(())
}

/// The value for `set`: exactly one of `value=` and `from_env=`.
fn secret_input(args: &Args) -> VResult<(String, &'static str)> {
    match (args.get("value"), args.get("from_env")) {
        (Some(_), Some(_)) => Err(Failure::usage(
            "secret.invalid_argument",
            "give either value= or from_env=, not both; nothing was stored",
        )),
        (None, None) => Err(Failure::usage(
            "secret.missing_value",
            "secret set needs value=<secret> or from_env=<VAR_NAME> (preferred: value= is \
             visible in the process list); nothing was stored",
        )),
        (Some(v), None) if v.is_empty() => Err(Failure::usage(
            "secret.missing_value",
            "value= is empty; nothing was stored",
        )),
        (Some(v), None) => Ok((v.clone(), "literal")),
        (None, Some(name)) => {
            if name.is_empty() || name.contains('=') || name.contains('\0') {
                return Err(Failure::usage(
                    "secret.invalid_argument",
                    format!("from_env={name:?} is not an environment variable name"),
                ));
            }
            match std::env::var(name) {
                Ok(v) if v.is_empty() => Err(Failure::usage(
                    "secret.missing_value",
                    format!("environment variable {name} is empty; nothing was stored"),
                )),
                Ok(v) => Ok((v, "env")),
                Err(std::env::VarError::NotUnicode(_)) => Err(Failure::usage(
                    "secret.invalid_argument",
                    format!("environment variable {name} is not valid UTF-8; nothing was stored"),
                )),
                Err(std::env::VarError::NotPresent) => Err(Failure::failed(
                    "secret.env_not_set",
                    format!("environment variable {name} is not set; nothing was stored"),
                )),
            }
        }
    }
}

/// The accepted name closest to `key` (edit distance at most 2, or one is
/// a prefix of the other), for a "did you mean" hint.
fn suggest<'a>(key: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let key = key.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (edit_distance(&key, a), *a))
        .filter(|(d, a)| {
            *d <= 2 || (key.len() >= 3 && (a.starts_with(key.as_str()) || key.starts_with(a)))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// True if `key` equals `prefix` or is nested under it (an empty prefix
/// matches everything).
fn under_prefix(key: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || key == prefix
        || key
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

trait Backend {
    fn get(&self, key: &str, warnings: &mut Vec<String>) -> VResult<Option<String>>;
    fn exists(&self, key: &str, warnings: &mut Vec<String>) -> VResult<bool> {
        Ok(self.get(key, warnings)?.is_some())
    }
    fn set(&self, key: &str, value: &str, warnings: &mut Vec<String>) -> VResult<()>;
    fn rm(&self, key: &str, warnings: &mut Vec<String>) -> VResult<bool>;
    fn ls(&self, prefix: &str, warnings: &mut Vec<String>) -> VResult<Vec<String>>;
    /// Fails if this scope cannot be written.
    fn check_writable(&self) -> VResult<()> {
        Ok(())
    }
}

// --- env --------------------------------------------------------------------

struct EnvScope;

fn read_only() -> Failure {
    Failure::usage(
        "secret.read_only",
        "the env scope is read-only (it is the resh process environment); nothing was changed",
    )
}

impl Backend for EnvScope {
    fn get(&self, key: &str, _: &mut Vec<String>) -> VResult<Option<String>> {
        match std::env::var(key) {
            Ok(v) => Ok(Some(v)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(Failure::failed(
                "secret.store_error",
                format!("environment variable {key} is not valid UTF-8"),
            )),
        }
    }
    fn set(&self, _: &str, _: &str, _: &mut Vec<String>) -> VResult<()> {
        Err(read_only())
    }
    fn rm(&self, _: &str, _: &mut Vec<String>) -> VResult<bool> {
        Err(read_only())
    }
    fn ls(&self, prefix: &str, _: &mut Vec<String>) -> VResult<Vec<String>> {
        let mut keys: Vec<String> = std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .filter(|k| under_prefix(k, prefix))
            .collect();
        keys.sort();
        Ok(keys)
    }
    fn check_writable(&self) -> VResult<()> {
        Err(read_only())
    }
}

// --- local ------------------------------------------------------------------

#[cfg(test)]
thread_local! {
    /// The state directory for unit tests on this thread.
    static TEST_STATE_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

fn state_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(d) = TEST_STATE_DIR.with(|d| d.borrow().clone()) {
        return Some(d);
    }
    dirs::state_dir()
}

/// Keystore index path under a given state directory.
fn keystore_path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("resh").join("secrets").join("local.json")
}

/// The keyring reference written to the index for `key`.
fn keyring_reference(key: &str) -> String {
    format!("keyring:{KEYRING_SERVICE}/{key}")
}

/// What the keystore file holds.
#[derive(Debug, PartialEq)]
enum Stored {
    /// Version 2: key names and keyring references only.
    Index(BTreeMap<String, String>),
    /// The plaintext `{key: value}` map of older releases.
    Legacy(BTreeMap<String, String>),
}

impl Stored {
    fn names(&self) -> impl Iterator<Item = &String> {
        match self {
            Stored::Index(m) | Stored::Legacy(m) => m.keys(),
        }
    }
}

const LEGACY_WARNING: &str = "the local keystore still holds plaintext values written by an \
     older resh release; the next set, rm or rotate moves them into the OS keyring";

fn parse_store(text: &str, path: &Path) -> VResult<Stored> {
    let corrupt = |why: String| {
        Failure::failed(
            "secret.store_error",
            format!("cannot read the keystore index {}: {why}", path.display()),
        )
    };
    if text.trim().is_empty() {
        return Ok(Stored::Index(BTreeMap::new()));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| corrupt(e.to_string()))?;
    let Value::Object(obj) = v else {
        return Err(corrupt("not a JSON object".into()));
    };
    if obj.get("version").is_some_and(Value::is_number) {
        if obj["version"] != json!(2) {
            return Err(corrupt(format!(
                "unknown format version {} (written by a newer resh?)",
                obj["version"]
            )));
        }
        let keys = obj
            .get("keys")
            .and_then(Value::as_object)
            .ok_or_else(|| corrupt("no \"keys\" object".into()))?;
        let mut m = BTreeMap::new();
        for (k, r) in keys {
            let r = r
                .as_str()
                .ok_or_else(|| corrupt(format!("the entry for {k:?} is not a reference")))?;
            m.insert(k.clone(), r.to_string());
        }
        return Ok(Stored::Index(m));
    }
    let mut m = BTreeMap::new();
    for (k, v) in obj {
        let v = v
            .as_str()
            .ok_or_else(|| corrupt(format!("the entry for {k:?} is not a string")))?;
        m.insert(k, v.to_string());
    }
    Ok(Stored::Legacy(m))
}

fn render_index(keys: &BTreeMap<String, String>) -> String {
    let mut s = serde_json::to_string_pretty(&json!({ "version": 2, "keys": keys }))
        .expect("a map of strings serializes");
    s.push('\n');
    s
}

/// Creates the keystore directory (and missing parents) with mode 0700 and
/// tightens the keystore directory itself to 0700 if it already existed.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// `secret://local`: values in the OS keyring, names in the index file.
struct Local {
    path: PathBuf,
    deadline: Deadline,
}

/// An exclusive lock on the keystore, released on drop.
struct StoreLock(fs::File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: flock on a file descriptor this value owns.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Local {
    fn new(deadline: Deadline) -> VResult<Self> {
        let dir = state_dir().ok_or_else(|| {
            Failure::failed(
                "secret.store_error",
                "cannot determine the user state directory (set XDG_STATE_HOME or HOME); \
                 nothing was done",
            )
        })?;
        Ok(Self {
            path: keystore_path_in(&dir),
            deadline,
        })
    }

    fn io_error(&self, what: &str, e: impl std::fmt::Display) -> Failure {
        Failure::failed(
            "secret.store_error",
            format!(
                "cannot {what} the keystore index {}: {e}",
                self.path.display()
            ),
        )
    }

    fn load(&self) -> VResult<Stored> {
        match fs::read_to_string(&self.path) {
            Ok(t) => parse_store(&t, &self.path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Stored::Index(BTreeMap::new()))
            }
            Err(e) => Err(self.io_error("read", e)),
        }
    }

    fn save(&self, keys: &BTreeMap<String, String>) -> VResult<()> {
        crate::core::secure_fs::write_private_file(&self.path, render_index(keys).as_bytes(), true)
            .map_err(|e| self.io_error("write", e))?;
        if let Some(dir) = self.path.parent()
            && let Ok(d) = fs::File::open(dir)
        {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Takes the keystore lock, waiting at most for the deadline (or
    /// [`LOCK_DEFAULT_TIMEOUT`]).
    fn lock(&self) -> VResult<StoreLock> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let dir = self.path.parent().expect("keystore path has a parent");
        ensure_private_dir(dir).map_err(|e| self.io_error("create the directory of", e))?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join("local.lock"))
            .map_err(|e| self.io_error("lock", e))?;
        let wait = self.deadline.budget(LOCK_DEFAULT_TIMEOUT)?;
        let start = Instant::now();
        loop {
            // SAFETY: flock on a file descriptor `file` owns.
            let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if r == 0 {
                return Ok(StoreLock(file));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(self.io_error("lock", err));
            }
            if start.elapsed() >= wait {
                return Err(Failure::timeout(format!(
                    "another resh process held the keystore lock for {} ms; nothing was changed",
                    wait.as_millis()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Runs one keyring call within the deadline. A failure after the
    /// time ran out is a timeout (exit 124).
    fn keyring<T>(
        &self,
        what: &str,
        f: impl FnOnce(&dyn SecretStore) -> Result<T, String>,
    ) -> VResult<T> {
        let budget = self.deadline.budget(secret_store::DEFAULT_TIMEOUT)?;
        let store = secret_store::store_with_timeout(KEYRING_SERVICE, budget);
        let start = Instant::now();
        f(store.as_ref()).map_err(|e| {
            if start.elapsed() >= budget {
                Failure::timeout(format!("cannot {what}: {e}"))
            } else {
                Failure::failed(
                    "secret.keyring_unavailable",
                    format!(
                        "cannot {what}: {e}. local secrets are kept only in the OS keyring \
                         (Secret Service or Keychain); nothing was changed"
                    ),
                )
            }
        })
    }

    /// Moves every legacy plaintext value except `skip` into the keyring
    /// and returns the index entries for them.
    fn migrate(
        &self,
        stored: &Stored,
        skip: &str,
        warnings: &mut Vec<String>,
    ) -> VResult<BTreeMap<String, String>> {
        match stored {
            Stored::Index(m) => Ok(m.clone()),
            Stored::Legacy(m) => {
                let mut index = BTreeMap::new();
                for (k, v) in m.iter().filter(|(k, _)| k.as_str() != skip) {
                    self.keyring("move a legacy plaintext secret into the OS keyring", |s| {
                        s.set(k, v)
                    })?;
                    index.insert(k.clone(), keyring_reference(k));
                }
                warnings.push(format!(
                    "moved {} secret(s) from the plaintext keystore of an older release into \
                     the OS keyring",
                    index.len()
                ));
                Ok(index)
            }
        }
    }
}

impl Backend for Local {
    fn get(&self, key: &str, warnings: &mut Vec<String>) -> VResult<Option<String>> {
        let stored = self.load()?;
        if let Stored::Legacy(m) = &stored
            && let Some(v) = m.get(key)
        {
            warnings.push(LEGACY_WARNING.into());
            return Ok(Some(v.clone()));
        }
        let value = self.keyring("read the OS keyring", |s| s.get(key))?;
        if value.is_none()
            && let Stored::Index(m) = &stored
            && m.contains_key(key)
        {
            warnings.push(format!(
                "{key} is listed in the keystore index but is missing from the OS \
                 keyring (removed outside resh?)"
            ));
        }
        Ok(value)
    }

    fn set(&self, key: &str, value: &str, warnings: &mut Vec<String>) -> VResult<()> {
        let _lock = self.lock()?;
        let stored = self.load()?;
        let mut index = self.migrate(&stored, key, warnings)?;
        self.keyring("store the secret in the OS keyring", |s| s.set(key, value))?;
        index.insert(key.to_string(), keyring_reference(key));
        self.save(&index)
    }

    fn rm(&self, key: &str, warnings: &mut Vec<String>) -> VResult<bool> {
        let _lock = self.lock()?;
        let stored = self.load()?;
        let listed = stored.names().any(|k| k == key);
        let mut index = self.migrate(&stored, key, warnings)?;
        let in_keyring = self
            .keyring("read the OS keyring", |s| s.get(key))?
            .is_some();
        if in_keyring {
            self.keyring("remove the secret from the OS keyring", |s| s.delete(key))?;
        }
        let changed = index.remove(key).is_some() || matches!(stored, Stored::Legacy(_));
        if changed {
            self.save(&index)?;
        }
        Ok(listed || in_keyring)
    }

    fn ls(&self, prefix: &str, warnings: &mut Vec<String>) -> VResult<Vec<String>> {
        let stored = self.load()?;
        if matches!(stored, Stored::Legacy(_)) {
            warnings.push(LEGACY_WARNING.into());
        }
        Ok(stored
            .names()
            .filter(|k| under_prefix(k, prefix))
            .cloned()
            .collect())
    }

    fn check_writable(&self) -> VResult<()> {
        Ok(())
    }
}

// --- vault ------------------------------------------------------------------

/// `secret://vault`: a HashiCorp Vault KV version 2 engine.
struct Vault {
    addr: Url,
    token: String,
    namespace: Option<String>,
    mount: Vec<String>,
    field: String,
    client: reqwest::blocking::Client,
    deadline: Deadline,
}

/// A Vault answer: the HTTP status and the JSON body (`Null` if none).
struct Answer {
    status: u16,
    body: Value,
}

impl Answer {
    /// Vault's `errors` list joined, or an empty string.
    fn errors(&self) -> String {
        self.body["errors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        e.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| e.to_string())
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default()
    }

    /// A 404 with an empty `errors` list: the secret does not exist (a
    /// 404 with errors is an unknown route, such as a wrong mount).
    fn is_missing(&self) -> bool {
        self.status == 404 && self.errors().is_empty()
    }
}

#[cfg(test)]
thread_local! {
    /// The environment the vault scope sees in unit tests on this thread.
    static TEST_VAULT_ENV: std::cell::RefCell<Option<BTreeMap<String, String>>> =
        const { std::cell::RefCell::new(None) };
}

/// An environment variable for the vault configuration.
fn vault_env(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(v) = TEST_VAULT_ENV.with(|e| e.borrow().as_ref().map(|m| m.get(name).cloned())) {
        return v;
    }
    std::env::var(name).ok()
}

fn not_configured(msg: impl Into<String>) -> Failure {
    Failure::usage("secret.vault_not_configured", msg)
}

impl Vault {
    fn from_args(args: &Args, deadline: Deadline) -> VResult<Self> {
        Self::configure(args, deadline, vault_env)
    }

    fn configure(
        args: &Args,
        deadline: Deadline,
        env: impl Fn(&str) -> Option<String>,
    ) -> VResult<Self> {
        let raw_addr = env("VAULT_ADDR").filter(|a| !a.trim().is_empty()).ok_or_else(|| {
            not_configured("set VAULT_ADDR to the Vault server URL (for example https://vault.example.com:8200); nothing was done")
        })?;
        let addr = Url::parse(raw_addr.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| {
                not_configured(format!(
                    "VAULT_ADDR={raw_addr:?} is not an http:// or https:// URL; nothing was done"
                ))
            })?;
        let token = match env("VAULT_TOKEN").filter(|t| !t.trim().is_empty()) {
            Some(t) => t.trim().to_string(),
            None => env("HOME")
                .map(PathBuf::from)
                .or_else(dirs::home_dir)
                .map(|h| h.join(".vault-token"))
                .and_then(|p| fs::read_to_string(p).ok())
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    not_configured(
                        "no Vault token: set VAULT_TOKEN or log in with `vault login` \
                         (~/.vault-token); nothing was done",
                    )
                })?,
        };
        let namespace = env("VAULT_NAMESPACE").filter(|n| !n.trim().is_empty());
        let mount_raw = args.get("mount").map(String::as_str).unwrap_or("secret");
        let mount: Vec<String> = mount_raw
            .trim_matches('/')
            .split('/')
            .map(str::to_string)
            .collect();
        if mount
            .iter()
            .any(|s| s.is_empty() || s == "." || s == ".." || s.chars().any(char::is_control))
        {
            return Err(Failure::usage(
                "secret.invalid_argument",
                format!("mount={mount_raw:?} is not a Vault mount path; nothing was done"),
            ));
        }
        let field = args.get("field").cloned().unwrap_or_else(|| "value".into());
        if field.is_empty() {
            return Err(Failure::usage(
                "secret.invalid_argument",
                "field= is empty; nothing was done",
            ));
        }

        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(None);
        let ca_file = args
            .get("ca_file")
            .cloned()
            .or_else(|| env("VAULT_CACERT").filter(|c| !c.trim().is_empty()));
        if let Some(ca) = ca_file {
            let pem = fs::read(&ca).map_err(|e| {
                Failure::usage(
                    "secret.invalid_argument",
                    format!("cannot read ca_file {ca}: {e}; nothing was done"),
                )
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .ok()
                .filter(|c| !c.is_empty())
                .ok_or_else(|| {
                    Failure::usage(
                        "secret.invalid_argument",
                        format!("ca_file {ca} holds no PEM certificate; nothing was done"),
                    )
                })?;
            for c in certs {
                builder = builder.add_root_certificate(c);
            }
        }
        let client = builder.build().map_err(|e| {
            Failure::failed(
                "secret.vault_error",
                format!("cannot set up the Vault client: {e}"),
            )
        })?;
        Ok(Self {
            addr,
            token,
            namespace,
            mount,
            field,
            client,
            deadline,
        })
    }

    /// `<addr>/v1/<mount>/<kind>/<key...>`, every segment percent-encoded.
    fn url(&self, kind: &str, key: &str) -> Url {
        let mut u = self.addr.clone();
        {
            let mut segs = u.path_segments_mut().expect("http(s) URLs have a path");
            segs.pop_if_empty().push("v1");
            for m in &self.mount {
                segs.push(m);
            }
            segs.push(kind);
            for k in key.split('/').filter(|s| !s.is_empty()) {
                segs.push(k);
            }
        }
        u
    }

    fn send(&self, method: reqwest::Method, url: Url, body: Option<Value>) -> VResult<Answer> {
        let budget = self.deadline.budget(VAULT_DEFAULT_TIMEOUT)?;
        let mut req = self
            .client
            .request(method, url)
            .timeout(budget)
            .header("X-Vault-Token", &self.token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().map_err(|e| self.transport_error(e, budget))?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| self.transport_error(e, budget))?;
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        let answer = Answer { status, body };
        if status == 403 {
            return Err(Failure::failed(
                "secret.vault_denied",
                format!(
                    "Vault refused the request (403): {}; check VAULT_TOKEN and its policy",
                    answer.errors()
                ),
            ));
        }
        Ok(answer)
    }

    fn transport_error(&self, e: reqwest::Error, budget: Duration) -> Failure {
        let e = e.without_url();
        if e.is_timeout() {
            match self.deadline.ms {
                Some(_) => self.deadline.expired(),
                None => Failure::timeout(format!(
                    "Vault at {} did not answer within {} ms",
                    self.addr,
                    budget.as_millis()
                )),
            }
        } else {
            let mut msg = format!("cannot reach Vault at {}: {e}", self.addr);
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(&format!(": {s}"));
                src = s.source();
            }
            Failure::failed("secret.vault_error", msg)
        }
    }

    fn unexpected(&self, what: &str, a: &Answer) -> Failure {
        let errors = a.errors();
        Failure::failed(
            "secret.vault_error",
            format!(
                "Vault could not {what} (HTTP {}){}",
                a.status,
                if errors.is_empty() {
                    String::new()
                } else {
                    format!(": {errors}")
                }
            ),
        )
    }

    /// The secret's fields and version, or `None` if it does not exist.
    fn read(&self, key: &str) -> VResult<Option<(Map<String, Value>, u64)>> {
        let a = self.send(reqwest::Method::GET, self.url("data", key), None)?;
        if a.is_missing() {
            return Ok(None);
        }
        if a.status != 200 {
            return Err(self.unexpected(&format!("read {key}"), &a));
        }
        // A deleted (but not destroyed) latest version reads as data null.
        let Some(fields) = a.body["data"]["data"].as_object() else {
            return Ok(None);
        };
        let version = a.body["data"]["metadata"]["version"].as_u64().unwrap_or(0);
        Ok(Some((fields.clone(), version)))
    }

    /// The current version number from the metadata, or `None` if the
    /// secret does not exist.
    fn current_version(&self, key: &str) -> VResult<Option<u64>> {
        let a = self.send(reqwest::Method::GET, self.url("metadata", key), None)?;
        if a.is_missing() {
            return Ok(None);
        }
        if a.status != 200 {
            return Err(self.unexpected(&format!("read the metadata of {key}"), &a));
        }
        Ok(Some(
            a.body["data"]["current_version"].as_u64().unwrap_or(0),
        ))
    }

    /// Lists the entries directly under `dir` ("" for the root).
    fn list(&self, dir: &str) -> VResult<Vec<String>> {
        // A list request names a directory: the path ends with '/'.
        let mut url = self.url("metadata", dir);
        let p = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&p);
        url.set_query(Some("list=true"));
        let a = self.send(reqwest::Method::GET, url, None)?;
        if a.is_missing() {
            return Ok(Vec::new());
        }
        if a.status != 200 {
            return Err(self.unexpected("list secrets", &a));
        }
        Ok(a.body["data"]["keys"]
            .as_array()
            .map(|k| {
                k.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn walk(&self, dir: &str, out: &mut Vec<String>) -> VResult<()> {
        for entry in self.list(dir)? {
            let full = if dir.is_empty() {
                entry.clone()
            } else {
                format!("{dir}/{entry}")
            };
            match full.strip_suffix('/') {
                Some(sub) => self.walk(sub, out)?,
                None => out.push(full),
            }
        }
        Ok(())
    }
}

impl Backend for Vault {
    fn get(&self, key: &str, _: &mut Vec<String>) -> VResult<Option<String>> {
        let Some((fields, _)) = self.read(key)? else {
            return Ok(None);
        };
        match fields.get(&self.field) {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(other) => Ok(Some(other.to_string())),
            None => {
                let mut names: Vec<&String> = fields.keys().collect();
                names.sort();
                Err(Failure::failed(
                    "secret.vault_field_missing",
                    format!(
                        "secret {key} has no field {:?} (fields: {}); choose one with field=",
                        self.field,
                        names
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ))
            }
        }
    }

    fn exists(&self, key: &str, _: &mut Vec<String>) -> VResult<bool> {
        Ok(self.read(key)?.is_some())
    }

    /// Writes `field` and keeps the secret's other fields, with
    /// check-and-set so a concurrent change is not overwritten.
    fn set(&self, key: &str, value: &str, _: &mut Vec<String>) -> VResult<()> {
        let (mut fields, version) = match self.read(key)? {
            Some(x) => x,
            None => (Map::new(), self.current_version(key)?.unwrap_or(0)),
        };
        fields.insert(self.field.clone(), json!(value));
        let body = json!({ "options": { "cas": version }, "data": fields });
        let a = self.send(reqwest::Method::POST, self.url("data", key), Some(body))?;
        if a.status == 200 || a.status == 204 {
            return Ok(());
        }
        if a.status == 400 && a.errors().contains("check-and-set") {
            return Err(Failure::failed(
                "secret.vault_conflict",
                format!("{key} was changed by someone else during the write; nothing was stored"),
            ));
        }
        Err(self.unexpected(&format!("write {key}"), &a))
    }

    fn rm(&self, key: &str, _: &mut Vec<String>) -> VResult<bool> {
        if self.current_version(key)?.is_none() {
            return Ok(false);
        }
        let a = self.send(reqwest::Method::DELETE, self.url("metadata", key), None)?;
        if a.status == 200 || a.status == 204 {
            return Ok(true);
        }
        Err(self.unexpected(&format!("delete {key}"), &a))
    }

    fn ls(&self, prefix: &str, _: &mut Vec<String>) -> VResult<Vec<String>> {
        let mut keys = Vec::new();
        if !prefix.is_empty() && self.current_version(prefix)?.is_some() {
            keys.push(prefix.to_string());
        }
        self.walk(prefix, &mut keys)?;
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// rotate: generated secrets
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Strategy {
    Random,
    Uuid,
    Aes,
    Rsa,
}

impl Strategy {
    fn name(self) -> &'static str {
        match self {
            Strategy::Random => "random",
            Strategy::Uuid => "uuid",
            Strategy::Aes => "aes",
            Strategy::Rsa => "rsa",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Encoding {
    Hex,
    Base64,
    Base64Url,
}

impl Encoding {
    fn name(self) -> &'static str {
        match self {
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
            Encoding::Base64Url => "base64url",
        }
    }

    fn encode(self, bytes: &[u8]) -> String {
        use base64::Engine;
        match self {
            Encoding::Hex => hex::encode(bytes),
            Encoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
            Encoding::Base64Url => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        }
    }
}

#[derive(Debug, PartialEq)]
struct RotateSpec {
    strategy: Strategy,
    /// Bits.
    length: u32,
    /// For random and aes only.
    encoding: Option<Encoding>,
}

struct Generated {
    value: String,
    public_key: Option<String>,
}

impl RotateSpec {
    fn from_args(args: &Args) -> VResult<Self> {
        let bad = |m: String| Failure::usage("secret.invalid_argument", m);
        let strategy = match args.get("strategy").map(String::as_str) {
            None | Some("random") => Strategy::Random,
            Some("uuid") => Strategy::Uuid,
            Some("aes") => Strategy::Aes,
            Some("rsa") => Strategy::Rsa,
            Some(other) => {
                return Err(bad(format!(
                    "strategy={other:?} is not one of random, uuid, aes, rsa; nothing was changed"
                )));
            }
        };
        let length = match args.get("length") {
            None => None,
            Some(raw) => Some(raw.trim().parse::<u32>().map_err(|_| {
                bad(format!(
                    "length={raw:?} is not a whole number of bits; nothing was changed"
                ))
            })?),
        };
        let encoding = match args.get("encoding").map(String::as_str) {
            None => None,
            Some("hex") => Some(Encoding::Hex),
            Some("base64") => Some(Encoding::Base64),
            Some("base64url") => Some(Encoding::Base64Url),
            Some(other) => {
                return Err(bad(format!(
                    "encoding={other:?} is not one of hex, base64, base64url; nothing was changed"
                )));
            }
        };
        let (length, encoding) = match strategy {
            Strategy::Random => {
                let l = length.unwrap_or(256);
                if !(64..=8192).contains(&l) || l % 8 != 0 {
                    return Err(bad(format!(
                        "length={l} for strategy=random must be a multiple of 8 from 64 to \
                         8192 bits; nothing was changed"
                    )));
                }
                (l, Some(encoding.unwrap_or(Encoding::Hex)))
            }
            Strategy::Aes => {
                let l = length.unwrap_or(256);
                if ![128, 192, 256].contains(&l) {
                    return Err(bad(format!(
                        "length={l} for strategy=aes must be 128, 192 or 256 bits; nothing \
                         was changed"
                    )));
                }
                (l, Some(encoding.unwrap_or(Encoding::Hex)))
            }
            Strategy::Uuid => {
                if length.is_some() || encoding.is_some() {
                    return Err(bad(
                        "strategy=uuid takes no length= or encoding= (a version 4 UUID); \
                         nothing was changed"
                            .into(),
                    ));
                }
                (128, None)
            }
            Strategy::Rsa => {
                let l = length.unwrap_or(3072);
                if ![2048, 3072, 4096].contains(&l) {
                    return Err(bad(format!(
                        "length={l} for strategy=rsa must be 2048, 3072 or 4096 bits; nothing \
                         was changed"
                    )));
                }
                if encoding.is_some() {
                    return Err(bad(
                        "strategy=rsa takes no encoding= (the key is PKCS#8 PEM); nothing was \
                         changed"
                            .into(),
                    ));
                }
                (l, None)
            }
        };
        Ok(Self {
            strategy,
            length,
            encoding,
        })
    }

    fn generate(&self, deadline: Deadline) -> VResult<Generated> {
        use rand::RngCore;
        match self.strategy {
            Strategy::Random | Strategy::Aes => {
                let mut bytes = vec![0u8; (self.length / 8) as usize];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                let value = self.encoding.unwrap_or(Encoding::Hex).encode(&bytes);
                Ok(Generated {
                    value,
                    public_key: None,
                })
            }
            Strategy::Uuid => Ok(Generated {
                value: uuid::Uuid::new_v4().to_string(),
                public_key: None,
            }),
            Strategy::Rsa => {
                let bits = self.length as usize;
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(generate_rsa(bits));
                });
                let received = match deadline.end {
                    None => rx.recv().ok(),
                    Some(_) => match rx.recv_timeout(deadline.budget(Duration::ZERO)?) {
                        Ok(r) => Some(r),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            return Err(deadline.expired());
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
                    },
                };
                match received {
                    Some(Ok(g)) => Ok(g),
                    Some(Err(e)) => Err(Failure::failed(
                        "secret.store_error",
                        format!("cannot generate the RSA key: {e}; nothing was changed"),
                    )),
                    None => Err(Failure::failed(
                        "secret.store_error",
                        "the RSA key generator stopped; nothing was changed",
                    )),
                }
            }
        }
    }
}

fn generate_rsa(bits: usize) -> Result<Generated, String> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).map_err(|e| e.to_string())?;
    let private = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();
    let public = key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok(Generated {
        value: private,
        public_key: Some(public),
    })
}

#[cfg(test)]
#[path = "secreth_tests.rs"]
mod tests;
