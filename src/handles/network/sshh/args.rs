//! The arguments each ssh verb accepts, and strict readers for their values.
//!
//! Every option a verb reads is listed once in [`options_for`]; anything else
//! is refused before the verb acts, and the help usage of each verb lists
//! exactly these names (checked by tests).

use super::types::SshError;
use crate::core::registry::Args;

/// Connection, authentication and host key options shared by every verb
/// that connects.
const CONN: [&str; 12] = [
    "host",
    "port",
    "username",
    "auth_method",
    "password",
    "identity_path",
    "identity_data",
    "identity_passphrase",
    "agent_socket",
    "known_hosts_mode",
    "known_hosts_path",
    "connect_timeout_ms",
];

macro_rules! with_conn {
    ($($extra:literal),* $(,)?) => {
        &[
            "host",
            "port",
            "username",
            "auth_method",
            "password",
            "identity_path",
            "identity_data",
            "identity_passphrase",
            "agent_socket",
            "known_hosts_mode",
            "known_hosts_path",
            "connect_timeout_ms",
            $($extra,)*
            "timeout_ms",
            "dry_run",
            "format",
        ]
    };
}

const EXEC: &[&str] = with_conn!(
    "command",
    "command_args",
    "shell_mode",
    "env",
    "cwd",
    "allocate_pty",
    "command_timeout_ms",
    "max_output_bytes",
    "trim_trailing_newlines",
    "capture_output",
    "output_encoding",
);

const UPLOAD: &[&str] = with_conn!(
    "source",
    "source_mode",
    "source_encoding",
    "dest",
    "overwrite",
    "atomic",
    "mkdir_parents",
    "file_mode",
    "preserve_times",
    "mtime_epoch_ms",
    "max_size_bytes",
    "verify_checksum",
    "checksum_algorithm",
    "transfer_timeout_ms",
);

const DOWNLOAD: &[&str] = with_conn!(
    "source",
    "dest",
    "dest_mode",
    "return_content",
    "return_encoding",
    "overwrite",
    "mkdir_parents",
    "max_size_bytes",
    "verify_checksum",
    "checksum_algorithm",
    "transfer_timeout_ms",
);

const TUNNEL: &[&str] = with_conn!(
    "mode",
    "local_bind_host",
    "local_bind_port",
    "remote_bind_host",
    "remote_bind_port",
    "remote_dest_host",
    "remote_dest_port",
    "local_dest_host",
    "local_dest_port",
    "socks_version",
    "allow_wildcard_binds",
    "tunnel_timeout_ms",
    "idle_timeout_ms",
    "max_connections",
    "max_bytes_in",
    "max_bytes_out",
);

const KEYS_LIST: &[&str] = with_conn!(
    "scope",
    "authorized_user",
    "authorized_paths",
    "host_key_paths",
    "custom_paths",
    "key_types",
    "fingerprint_algorithm",
    "include_options",
    "include_raw_key",
    "max_keys",
    "max_bytes",
    "read_timeout_ms",
);

const KEY_ADD: &[&str] = with_conn!(
    "scope",
    "authorized_user",
    "authorized_paths",
    "custom_paths",
    "public_key",
    "public_key_source",
    "public_key_path",
    "on_duplicate",
    "create_if_missing",
    "backup_existing",
    "backup_suffix",
    "ensure_permissions",
    "file_mode",
    "dir_mode",
    "max_file_bytes",
    "read_timeout_ms",
    "write_timeout_ms",
);

const TEST: &[&str] = with_conn!(
    "tests",
    "exec_command",
    "handshake_timeout_ms",
    "auth_timeout_ms",
    "sftp_timeout_ms",
    "exec_timeout_ms",
    "overall_timeout_ms",
    "allow_insecure_hostkey",
);

/// config.get reads local files only: no connection options, no timeout.
const CONFIG_GET: &[&str] = &[
    "host",
    "user_config_path",
    "system_config_path",
    "extra_config_paths",
    "follow_includes",
    "include_raw_entries",
    "include_origin",
    "user_home",
    "max_config_bytes",
    "max_includes",
    "max_hosts",
    "dry_run",
    "format",
];

/// The verbs of the ssh handle, in help order.
pub const VERBS: &[&str] = &[
    "exec",
    "upload",
    "download",
    "test",
    "config.get",
    "keys.list",
    "key.add",
    "tunnel",
];

/// Every argument `verb` accepts, or `None` for an unknown verb.
pub fn options_for(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "exec" => EXEC,
        "upload" => UPLOAD,
        "download" => DOWNLOAD,
        "tunnel" => TUNNEL,
        "keys.list" => KEYS_LIST,
        "key.add" => KEY_ADD,
        "test" => TEST,
        "config.get" => CONFIG_GET,
        _ => return None,
    })
}

/// True for the connection options every connecting verb shares.
pub fn is_conn_option(name: &str) -> bool {
    CONN.contains(&name)
}

/// Refuses an argument `verb` does not take, naming it with a "did you
/// mean" hint for likely typos.
pub fn check_known(verb: &str, args: &Args) -> Result<(), SshError> {
    let allowed = options_for(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let Some(bad) = keys.into_iter().find(|k| !allowed.contains(&k.as_str())) else {
        // Read before anything else, so a bad value is never ignored.
        let r = ArgReader::new(args);
        r.choice("format", super::types::OutputFormat::VALUES)?;
        r.bool("dry_run", false)?;
        return Ok(());
    };
    if bad == "timeout_ms" {
        return Err(SshError::InvalidArgument(format!(
            "ssh {verb} does not take timeout_ms: it only reads local files"
        )));
    }
    Err(SshError::InvalidArgument(format!(
        "unknown argument for ssh {verb}: {bad}{}",
        did_you_mean(bad, allowed)
    )))
}

/// " (did you mean `x`?)" when `bad` looks like a typo of an accepted name.
pub fn did_you_mean(bad: &str, allowed: &[&str]) -> String {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| format!(" (did you mean `{a}`?)"))
        .unwrap_or_default()
}

fn invalid(key: &str, value: &str, expected: &str) -> SshError {
    SshError::InvalidArgument(format!(
        "invalid value for {key}: {value:?} (expected {expected})"
    ))
}

/// Typed, strict access to the arguments of one call.
#[derive(Clone, Copy)]
pub struct ArgReader<'a> {
    args: &'a Args,
}

impl<'a> ArgReader<'a> {
    pub fn new(args: &'a Args) -> Self {
        ArgReader { args }
    }

    pub fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    /// The raw value, if given.
    pub fn raw(&self, key: &str) -> Option<&'a str> {
        self.args.get(key).map(String::as_str)
    }

    /// A text value with no control characters. An empty value is refused.
    pub fn text(&self, key: &str) -> Result<Option<String>, SshError> {
        match self.raw(key) {
            None => Ok(None),
            Some("") => Err(SshError::InvalidArgument(format!(
                "{key} must not be empty"
            ))),
            Some(v) if v.chars().any(char::is_control) => Err(SshError::InvalidArgument(format!(
                "{key} must not contain line breaks or other control characters"
            ))),
            Some(v) => Ok(Some(v.to_string())),
        }
    }

    /// A value that may hold anything (commands, data); only refused when
    /// empty and `allow_empty` is false.
    pub fn data(&self, key: &str, allow_empty: bool) -> Result<Option<String>, SshError> {
        match self.raw(key) {
            Some("") if !allow_empty => Err(SshError::InvalidArgument(format!(
                "{key} must not be empty"
            ))),
            v => Ok(v.map(str::to_string)),
        }
    }

    pub fn bool(&self, key: &str, default: bool) -> Result<bool, SshError> {
        crate::core::lenient::bool_arg(self.args, key)
            .map(|v| v.unwrap_or(default))
            .map_err(|e| SshError::InvalidArgument(e.to_string()))
    }

    /// A non-negative decimal integer.
    pub fn u64(&self, key: &str) -> Result<Option<u64>, SshError> {
        match self.raw(key) {
            None => Ok(None),
            Some(v) => {
                if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid(key, v, "a non-negative integer"));
                }
                v.parse::<u64>()
                    .map(Some)
                    .map_err(|_| invalid(key, v, "a non-negative integer"))
            }
        }
    }

    pub fn u64_or(&self, key: &str, default: u64) -> Result<u64, SshError> {
        Ok(self.u64(key)?.unwrap_or(default))
    }

    /// A signed decimal integer.
    pub fn i64(&self, key: &str) -> Result<Option<i64>, SshError> {
        match self.raw(key) {
            None => Ok(None),
            Some(v) => {
                let digits = v.strip_prefix('-').unwrap_or(v);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid(key, v, "an integer"));
                }
                v.parse::<i64>()
                    .map(Some)
                    .map_err(|_| invalid(key, v, "an integer"))
            }
        }
    }

    /// A TCP port; 0 only when `allow_zero`.
    pub fn port(&self, key: &str, allow_zero: bool) -> Result<Option<u16>, SshError> {
        let expected = if allow_zero {
            "a port number 0-65535"
        } else {
            "a port number 1-65535"
        };
        match self.u64(key) {
            Ok(None) => Ok(None),
            Ok(Some(n)) if n <= 65535 && (allow_zero || n > 0) => Ok(Some(n as u16)),
            _ => Err(invalid(key, self.raw(key).unwrap_or(""), expected)),
        }
    }

    /// One of `values`, matched exactly.
    pub fn choice<T: Copy>(&self, key: &str, values: &[(&str, T)]) -> Result<Option<T>, SshError> {
        match self.raw(key) {
            None => Ok(None),
            Some(v) => match values.iter().find(|(name, _)| *name == v) {
                Some((_, t)) => Ok(Some(*t)),
                None => {
                    let names: Vec<&str> = values.iter().map(|(n, _)| *n).collect();
                    let hint = did_you_mean(v, &names);
                    Err(SshError::InvalidArgument(format!(
                        "invalid value for {key}: {v:?} (expected one of: {}){hint}",
                        names.join(", ")
                    )))
                }
            },
        }
    }

    /// A comma-separated list; items are trimmed and must not be empty or
    /// hold control characters.
    pub fn list(&self, key: &str) -> Result<Option<Vec<String>>, SshError> {
        let Some(v) = self.raw(key) else {
            return Ok(None);
        };
        let items: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
        if items.iter().any(|s| s.is_empty()) {
            return Err(SshError::InvalidArgument(format!(
                "{key} has an empty item: {v:?}"
            )));
        }
        if v.chars().any(char::is_control) {
            return Err(SshError::InvalidArgument(format!(
                "{key} must not contain line breaks or other control characters"
            )));
        }
        Ok(Some(items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn every_verb_has_an_option_list_with_dry_run_and_format() {
        for verb in VERBS {
            let opts = options_for(verb).unwrap();
            assert!(opts.contains(&"dry_run"), "{verb}");
            assert!(opts.contains(&"format"), "{verb}");
            let mut sorted = opts.to_vec();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), opts.len(), "{verb}: duplicate option");
        }
        assert!(options_for("nope").is_none());
        assert!(!options_for("config.get").unwrap().contains(&"timeout_ms"));
        for verb in VERBS.iter().filter(|v| **v != "config.get") {
            assert!(options_for(verb).unwrap().contains(&"timeout_ms"), "{verb}");
            for c in CONN {
                assert!(options_for(verb).unwrap().contains(&c), "{verb}: {c}");
            }
        }
    }

    #[test]
    fn unknown_arguments_get_a_hint() {
        let e = check_known("exec", &args(&[("comand", "ls")])).unwrap_err();
        assert_eq!(
            e.to_string(),
            "unknown argument for ssh exec: comand (did you mean `command`?)"
        );
        assert_eq!(e.exit_code(), 2);
        let e = check_known("exec", &args(&[("zzzzzz", "1")])).unwrap_err();
        assert_eq!(e.to_string(), "unknown argument for ssh exec: zzzzzz");
        let e = check_known("config.get", &args(&[("timeout_ms", "1")])).unwrap_err();
        assert!(e.to_string().contains("does not take timeout_ms"));
        assert!(check_known("exec", &args(&[("command", "ls"), ("timeout_ms", "5")])).is_ok());
    }

    #[test]
    fn readers_refuse_bad_values() {
        let a = args(&[
            ("b", "maybe"),
            ("n", "-1"),
            ("p", "70000"),
            ("z", "0"),
            ("c", "sh2"),
            ("l", "a,,b"),
            ("t", "a\nb"),
            ("e", ""),
            ("i", "-5"),
        ]);
        let r = ArgReader::new(&a);
        assert!(r.bool("b", false).is_err());
        assert!(r.u64("n").is_err());
        assert!(r.port("p", true).is_err());
        assert!(r.port("z", false).is_err());
        assert_eq!(r.port("z", true).unwrap(), Some(0));
        let e = r.choice("c", crate::handles::network::sshh::types::ShellMode::VALUES);
        assert!(e.unwrap_err().to_string().contains("did you mean `sh`"));
        assert!(r.list("l").is_err());
        assert!(r.text("t").is_err());
        assert!(r.text("e").is_err());
        assert_eq!(r.i64("i").unwrap(), Some(-5));
        assert_eq!(r.u64_or("missing", 7).unwrap(), 7);
        assert!(r.bool("missing", true).unwrap());
    }
}
