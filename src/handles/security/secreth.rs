use anyhow::{Context, Result, bail};
use serde_json::{self, json};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("secret", |u| Ok(Box::new(SecretHandle::from_url(u)?)));
}

pub struct SecretHandle {
    scope: String,
    key_path: String,
}

impl SecretHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
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
            "local" | "env" | "vault" => {},
            _ => bail!("unsupported scope '{}'; supported scopes: local, env, vault", scope),
        }

        Ok(SecretHandle { scope, key_path })
    }

    fn get_keystore_path() -> Result<PathBuf> {
        let state_dir = dirs::state_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(state_dir.join("resh").join("secrets").join("local.json"))
    }

    fn load_keystore() -> Result<HashMap<String, String>> {
        let path = Self::get_keystore_path()?;
        
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read keystore at {}", path.display()))?;

        if contents.trim().is_empty() {
            return Ok(HashMap::new());
        }

        let keystore: HashMap<String, String> = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse keystore JSON at {}", path.display()))?;

        Ok(keystore)
    }

    fn save_keystore(keystore: &HashMap<String, String>) -> Result<()> {
        let path = Self::get_keystore_path()?;
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        // Write to temporary file first for atomic operation
        let temp_path = path.with_extension("tmp");
        
        let json = serde_json::to_string(keystore)
            .context("failed to serialize keystore to JSON")?;

        fs::write(&temp_path, json)
            .with_context(|| format!("failed to write temp file {}", temp_path.display()))?;

        // Set restrictive permissions (0600) on the temp file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&temp_path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&temp_path, permissions)
                .with_context(|| format!("failed to set permissions on {}", temp_path.display()))?;
        }

        // Atomic rename
        fs::rename(&temp_path, &path)
            .with_context(|| format!("failed to rename {} to {}", temp_path.display(), path.display()))?;

        Ok(())
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
            },
            "env" => {
                match std::env::var(&self.key_path) {
                    Ok(v) => (true, Some(v)),
                    Err(_) => (false, None),
                }
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
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
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            "local" => {
                // Continue with local implementation
            },
            _ => unreachable!(),
        }

        // Resolve secret value
        let (secret_value, source) = if let Some(value) = args.get("value") {
            (value.clone(), "literal")
        } else if let Some(env_name) = args.get("from_env") {
            match std::env::var(env_name) {
                Ok(value) => (value, "env"),
                Err(_) => {
                    self.write_error_json(io, &format!("environment variable '{}' not found", env_name))?;
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
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            "local" => {
                // Continue with local implementation
            },
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
                let mut matching_keys: Vec<String> = keystore.keys()
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
            },
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
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
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
}

impl Handle for SecretHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "set", "rm", "ls", "rotate"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
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
            },
            _ => bail!("unknown verb for secret://: {}", verb),
        }
    }
}