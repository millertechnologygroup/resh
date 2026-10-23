use anyhow::{Context, Result, bail};
use serde_json::{self, json};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("secret", |u| Ok(Box::new(SecretHandle::from_url(u)?)));
    reg.set_probe_url("secret", "secret://local/resh-help-probe");
}

/// Metadata for `resh secret --help` and `resh secret <verb> --help`.
static SECRET_HELP: HandleHelp = HandleHelp {
    description: "The secret handle reads and stores secrets in one of three scopes: local, an \
        unencrypted JSON keystore created with 0600 permissions under the user's state \
        directory, env, the \
        read-only process environment, and vault, which is reserved but not implemented. \
        The scope is the URL host and the key path follows it, as in secret://local/app/db_password. \
        Every verb prints a single JSON object describing the result.",
    usage: "resh secret://<scope>/<key-path>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "get",
            definition: "Reads one secret from the local keystore or the environment and prints \
                it as JSON, optionally withholding the value.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|env>/<key-path>.get [redact=true|false]",
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
"redacted": true field is added; a missing key gives exists false."#,
                ),
            }),
        },
        VerbHelp {
            name: "ls",
            definition: "Lists the keys equal to the key path or nested under it, or every key \
                when the path is empty, in sorted order.",
            detail: Some(VerbDetail {
                usage: "resh secret://<local|env>/[<prefix>].ls",
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
            definition: "Stores a secret in the local keystore from a literal value or from an \
                environment variable (local scope only).",
            detail: Some(VerbDetail {
                usage: "resh secret://local/<key-path>.set value=<secret>|from_env=<VAR_NAME>",
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
The keystore is plain JSON (not encrypted) at
<state-dir>/resh/secrets/local.json, written atomically with mode 0600
in a 0700 directory. If no state directory can be determined, local
scope verbs fail with an error instead of using another location."#,
                ),
            }),
        },
        VerbHelp {
            name: "rm",
            definition: "Removes a secret from the local keystore and reports whether it existed \
                (local scope only).",
            detail: Some(VerbDetail {
                usage: "resh secret://local/<key-path>.rm",
                example: "resh --json-pretty secret://local/app/old_token.rm",
                example_output: Some(
                    r#"{
  "backend": "local",
  "key": "app/old_token",
  "removed": true,
  "scope": "local"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "rotate",
            definition: "Not implemented; prints a JSON error object and exits with status 2.",
            detail: Some(VerbDetail {
                usage: "resh secret://<scope>/<key-path>.rotate",
                example: "resh --json-pretty secret://local/app/api_key.rotate",
                example_output: Some(
                    r#"{
  "backend": "local",
  "error": "rotate operation not implemented yet",
  "key": "app/api_key",
  "scope": "local"
}

Shown with --json-pretty."#,
                ),
            }),
        },
    ],
};

pub struct SecretHandle {
    scope: String,
    key_path: String,
    is_help_request: bool,
    help_verb: Option<String>,
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

        // Extract verb-specific help if provided (e.g., --help=get)
        let help_verb = u.query_pairs().find_map(|(k, v)| {
            if k == "help" || (k == "--help" && !v.is_empty()) {
                Some(v.to_string())
            } else {
                None
            }
        });

        // If this is a help request, return early with minimal validation
        if is_help_request || help_verb.is_some() {
            return Ok(SecretHandle {
                scope: "local".to_string(), // Default scope for help
                key_path: String::new(),
                is_help_request: true,
                help_verb,
            });
        }

        // The URL format is secret://scope/key_path
        // where scope can be in the host position or path position
        let (scope, key_path) = if let Some(host) = u.host_str() {
            // Case: secret://scope/key_path (scope in host position)
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            (host.to_string(), path.to_string())
        } else {
            // Case: secret:///scope/key_path (scope in path position)
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            let parts: Vec<&str> = path.split('/').collect();
            if parts.is_empty() || parts[0].is_empty() {
                bail!("secret URL must contain a scope");
            }
            let scope = parts[0].to_string();
            let key_path = if parts.len() > 1 {
                parts[1..].join("/")
            } else {
                String::new()
            };
            (scope, key_path)
        };

        // Validate scope
        match scope.as_str() {
            "local" | "env" | "vault" => {}
            _ => bail!(
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

    /// Location of the local keystore: `<state_dir>/resh/secrets/local.json`.
    /// There is deliberately no fallback (such as `/tmp`): if the state
    /// directory cannot be determined, this is an error.
    fn get_keystore_path() -> Result<PathBuf> {
        let state_dir = dirs::state_dir().ok_or_else(|| {
            anyhow::anyhow!(
                "cannot determine the user state directory (set XDG_STATE_HOME or HOME); \
                 refusing to store secrets elsewhere"
            )
        })?;
        Ok(keystore_path_in(&state_dir))
    }

    fn load_keystore() -> Result<HashMap<String, String>> {
        load_keystore_from(&Self::get_keystore_path()?)
    }

    fn save_keystore(keystore: &HashMap<String, String>) -> Result<()> {
        save_keystore_to(&Self::get_keystore_path()?, keystore)
    }

    fn write_error_json(&self, io: &mut IoStreams, error: &str) -> Result<()> {
        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "error": error
        });
        write!(io.stdout, "{}", response)?;
        Ok(())
    }

    fn handle_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for get operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        let redact = args.get("redact").map(|s| s.as_str()).unwrap_or("false") == "true";

        let (exists, value) = match self.scope.as_str() {
            "local" => {
                let keystore = Self::load_keystore().map_err(|e| {
                    let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
                    e
                })?;
                match keystore.get(&self.key_path) {
                    Some(v) => (true, Some(v.clone())),
                    None => (false, None),
                }
            }
            "env" => match std::env::var(&self.key_path) {
                Ok(v) => (true, Some(v)),
                Err(_) => (false, None),
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            }
            _ => unreachable!(),
        };

        let mut response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "exists": exists
        });

        if exists {
            if redact {
                response["value"] = json!(null);
                response["redacted"] = json!(true);
            } else {
                response["value"] = json!(value.unwrap());
            }
        } else {
            response["value"] = json!(null);
        }

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_set(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for set operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        match self.scope.as_str() {
            "env" => {
                self.write_error_json(io, "env backend is read-only")?;
                return Ok(Status::err(1, "env backend is read-only"));
            }
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            }
            "local" => {
                // Continue with local implementation
            }
            _ => unreachable!(),
        }

        // Resolve secret value
        let (secret_value, source) = if let Some(value) = args.get("value") {
            (value.clone(), "literal")
        } else if let Some(env_name) = args.get("from_env") {
            match std::env::var(env_name) {
                Ok(value) => (value, "env"),
                Err(_) => {
                    self.write_error_json(
                        io,
                        &format!("environment variable '{}' not found", env_name),
                    )?;
                    return Ok(Status::err(1, "environment variable not found"));
                }
            }
        } else {
            self.write_error_json(io, "must provide either 'value' or 'from_env' argument")?;
            return Ok(Status::err(1, "missing required argument"));
        };

        // Load, update, and save keystore
        let mut keystore = Self::load_keystore().map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
            e
        })?;

        keystore.insert(self.key_path.clone(), secret_value);

        Self::save_keystore(&keystore).map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to save keystore: {}", e));
            e
        })?;

        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "set": true,
            "source": source
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_rm(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for rm operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        match self.scope.as_str() {
            "env" => {
                self.write_error_json(io, "env backend is read-only")?;
                return Ok(Status::err(1, "env backend is read-only"));
            }
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            }
            "local" => {
                // Continue with local implementation
            }
            _ => unreachable!(),
        }

        let mut keystore = Self::load_keystore().map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
            e
        })?;

        let removed = keystore.remove(&self.key_path).is_some();

        Self::save_keystore(&keystore).map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to save keystore: {}", e));
            e
        })?;

        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "removed": removed
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_ls(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        let keys = match self.scope.as_str() {
            "local" => {
                let keystore = Self::load_keystore().map_err(|e| {
                    let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
                    e
                })?;

                let prefix = &self.key_path;
                let mut matching_keys: Vec<String> = keystore
                    .keys()
                    .filter(|k| {
                        if prefix.is_empty() {
                            true // List all keys
                        } else {
                            k.starts_with(&format!("{}/", prefix)) || *k == prefix
                        }
                    })
                    .cloned()
                    .collect();
                matching_keys.sort();
                matching_keys
            }
            "env" => {
                let prefix = &self.key_path;
                let mut matching_keys: Vec<String> = std::env::vars()
                    .map(|(k, _)| k)
                    .filter(|k| {
                        if prefix.is_empty() {
                            true // List all env vars
                        } else {
                            k.starts_with(&format!("{}/", prefix)) || k == prefix
                        }
                    })
                    .collect();
                matching_keys.sort();
                matching_keys
            }
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            }
            _ => unreachable!(),
        };

        let response = json!({
            "scope": &self.scope,
            "backend": &self.scope,
            "prefix": &self.key_path,
            "keys": keys
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    /// Writes the approved help for the in-URL help forms (`secret://--help`,
    /// `secret://local/x?help=get`).
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> Result<Status> {
        let text = help::render_legacy("secret", &SECRET_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text)?;
        if !text.ends_with('\n') {
            writeln!(io.stdout)?;
        }
        Ok(Status::ok())
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
        // Check if this is a help request
        // In-URL help: secret://--help, secret://--help=get (the parser
        // passes the verb as verb=get), ?help=get, or a help verb.
        if self.is_help_request || help::HELP_ALIASES.contains(&verb) {
            let wanted = self
                .help_verb
                .as_deref()
                .or(args.get("verb").map(String::as_str));
            return self.display_help(wanted, io);
        }

        // Normal operation - dispatch to appropriate verb
        match verb {
            "get" => self.handle_get(args, io),
            "set" => self.handle_set(args, io),
            "rm" => self.handle_rm(args, io),
            "ls" => self.handle_ls(args, io),
            "rotate" => {
                // Not implemented in this version, return error
                let response = json!({
                    "scope": &self.scope,
                    "key": &self.key_path,
                    "backend": &self.scope,
                    "error": "rotate operation not implemented yet"
                });
                write!(io.stdout, "{}", response)?;
                Ok(Status::err(2, "rotate operation not implemented yet"))
            }
            _ => bail!("unknown verb for secret://: {}", verb),
        }
    }
}

/// Keystore file path under a given state directory.
fn keystore_path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("resh").join("secrets").join("local.json")
}

fn load_keystore_from(path: &Path) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read keystore at {}", path.display()))?;

    if contents.trim().is_empty() {
        return Ok(HashMap::new());
    }

    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse keystore JSON at {}", path.display()))
}

/// Creates the keystore directory (and missing parents) with mode 0700 and
/// tightens the keystore directory itself to 0700 if it already existed.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("failed to create directory {}", dir.display()))?;
        let mode = fs::metadata(dir)
            .with_context(|| format!("failed to stat {}", dir.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to set permissions on {}", dir.display()))?;
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create directory {}", dir.display()))?;
    }
    Ok(())
}

/// Writes the keystore atomically. The data goes to a new temporary file in
/// the same directory that is created with mode 0600 (never readable by
/// others, at any point), is flushed to disk, and is then renamed over the
/// keystore. The keystore is plain JSON; it is not encrypted.
fn save_keystore_to(path: &Path, keystore: &HashMap<String, String>) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("keystore path {} has no parent", path.display()))?;
    ensure_private_dir(dir)?;

    let json = serde_json::to_string(keystore).context("failed to serialize keystore to JSON")?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "local.json".to_string());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let temp_path = dir.join(format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        nanos
    ));

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = opts
            .open(&temp_path)
            .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
        // The mode passed to open() is filtered by the umask, which can only
        // remove bits; enforce exactly 0600 in case the file was created
        // with fewer bits than that.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", temp_path.display()))?;
        }
        file.write_all(json.as_bytes())
            .with_context(|| format!("failed to write temp file {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temp file {}", temp_path.display()))?;
        drop(file);
        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to rename {} to {}",
                temp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;

    // Make the rename durable.
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(url: &str) -> SecretHandle {
        SecretHandle::from_url(&Url::parse(url).unwrap()).unwrap()
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    #[cfg(unix)]
    fn save_creates_private_dir_and_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = keystore_path_in(tmp.path());
        let mut ks = HashMap::new();
        ks.insert("app/db".to_string(), "s3cr3t".to_string());
        save_keystore_to(&path, &ks).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().unwrap()), 0o700);
        assert_eq!(load_keystore_from(&path).unwrap(), ks);

        // No temp files are left behind.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "local.json")
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {:?}", leftovers);
    }

    #[test]
    #[cfg(unix)]
    fn save_replaces_world_readable_store_and_tightens_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = keystore_path_in(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let mut ks = HashMap::new();
        ks.insert("k".to_string(), "v".to_string());
        save_keystore_to(&path, &ks).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().unwrap()), 0o700);
        assert_eq!(load_keystore_from(&path).unwrap(), ks);
    }

    #[test]
    fn load_missing_store_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            load_keystore_from(&keystore_path_in(tmp.path()))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn keystore_path_has_no_tmp_fallback() {
        let p = keystore_path_in(Path::new("/state"));
        assert_eq!(p, PathBuf::from("/state/resh/secrets/local.json"));
        // get_keystore_path either uses the real state dir or fails.
        if let Ok(real) = SecretHandle::get_keystore_path() {
            assert!(!real.starts_with("/tmp/resh"));
        }
    }

    #[test]
    fn help_text_does_not_claim_encryption() {
        let text = help::render_legacy(
            "secret",
            &SECRET_HELP,
            &["get", "set", "rm", "ls", "rotate"],
            None,
        );
        assert!(text.starts_with("Handle: secret"));
        assert!(!text.to_lowercase().contains(" encrypted "));
        for v in SECRET_HELP.verbs {
            let d = v
                .detail
                .as_ref()
                .and_then(|d| d.example_output)
                .unwrap_or("");
            assert!(!d.contains("is encrypted"));
        }
    }

    #[test]
    fn in_url_help_forms_are_exact() {
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
    }

    #[test]
    fn in_url_help_renders_approved_help() {
        let h = handle("secret://--help");
        let mut out = Vec::new();
        let mut err = Vec::new();
        {
            let mut stdin = std::io::empty();
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut out,
                stderr: &mut err,
            };
            let st = h.call("get", &Args::new(), &mut io).unwrap();
            assert!(st.ok);
        }
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Handle: secret"), "{}", text);

        let h = handle("secret://local/x?help=set");
        let mut out = Vec::new();
        {
            let mut stdin = std::io::empty();
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut out,
                stderr: &mut err,
            };
            h.call("get", &Args::new(), &mut io).unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Handle: secret\nVerb: set"), "{}", text);

        // secret://--help=rm reaches call() as verb "help" with verb=rm.
        let h = handle("secret://--help");
        let mut args = Args::new();
        args.insert("verb".to_string(), "rm".to_string());
        let mut out = Vec::new();
        {
            let mut stdin = std::io::empty();
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut out,
                stderr: &mut err,
            };
            h.call("help", &args, &mut io).unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Handle: secret\nVerb: rm"), "{}", text);
    }
}
