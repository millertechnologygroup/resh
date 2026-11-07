//! The ssh handle: remote commands, file transfer, key management, port
//! forwarding and connection checks through the system OpenSSH client, and
//! local ssh_config lookups.

use anyhow::Result;
use serde::Serialize;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub mod args;
mod config_get;
pub mod conn;
mod exec;
mod keys;
mod probe;
pub mod runner;
mod transfer;
mod tunnel;
pub mod types;

#[cfg(test)]
mod tests;

pub use args::{VERBS, options_for};
pub use conn::SshTarget;
use types::OutputFormat;

/// Metadata for `resh ssh --help` and `resh ssh <verb> --help`.
static SSH_HELP: HandleHelp = HandleHelp {
    description: "The ssh handle runs commands, copies files, lists and adds public keys, \
        forwards ports, and checks connections on remote hosts through the system ssh client \
        (with sshpass for password logins), and reads the local OpenSSH client \
        configuration. The target is written as ssh://[user[:password]@]host[:port] followed \
        by a dot and the verb, such as ssh://alice@192.0.2.10.exec. Every verb validates all \
        of its arguments before connecting, supports dry_run=true, and exits 0 on success, 1 \
        on failure, 2 for invalid arguments, and 124 on a timeout.",
    usage: "resh ssh://[user@]host[:port].<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "exec",
            definition: "Runs a command on the remote host through the system ssh client and \
                reports its exit code, stdout, and stderr as JSON.",
            detail: Some(VerbDetail {
                usage: "resh ssh://[user@]host[:port].exec command=<cmd>\n  \
                    [command_args=<a,b,...>] [shell_mode=none|sh|bash|cmd|powershell]\n  \
                    [env=<NAME=value,...>] [cwd=<dir>] [allocate_pty=true|false]\n  \
                    [command_timeout_ms=<ms>] [max_output_bytes=<n>]\n  \
                    [trim_trailing_newlines=true|false] [capture_output=true|false]\n  \
                    [output_encoding=utf8|base64] [host=<host>] [port=<n>]\n  \
                    [username=<name>] [auth_method=auto|key|agent|password]\n  \
                    [password=<pw>] [identity_path=<file>] [identity_data=<key>]\n  \
                    [identity_passphrase=<pp>] [agent_socket=<path>]\n  \
                    [known_hosts_mode=strict|accept-new|insecure] [known_hosts_path=<file>]\n  \
                    [connect_timeout_ms=<ms>] [timeout_ms=<ms>] [dry_run=true|false]\n  \
                    [format=json|text]",
                example: "resh --json-pretty ssh://alice@192.0.2.10.exec command=hostname",
                example_output: Some(
                    r#"{
  "command": {
    "allocate_pty": false,
    "cwd": null,
    "raw": "hostname",
    "shell_mode": "none"
  },
  "connection": {
    "backend": "system",
    "host": "192.0.2.10",
    "port": 22,
    "username": "alice"
  },
  "dry_run": false,
  "ok": true,
  "result": {
    "executed": true,
    "exit_code": 0,
    "output_truncated": false,
    "signal": null,
    "stderr": null,
    "stdout": "web01",
    "timed_out": false
  },
  "timing": {
    "command_ms": 412,
    "connect_ms": 0
  }
}

Shown with --json-pretty. A non-zero remote exit code gives ok false,
error.code ssh.remote_exit_nonzero and exit status 1 (the remote code is in
result.exit_code); command_timeout_ms (default 60000) stops the remote
command and exits 124."#,
                ),
            }),
        },
        VerbHelp {
            name: "upload",
            definition: "Copies a local file or inline data to a remote path by piping it into \
                a remote POSIX shell over ssh, writing a temporary file and renaming it into \
                place when atomic=true.",
            detail: Some(VerbDetail {
                usage: "resh ssh://[user@]host[:port].upload source=<path|data> dest=<path>\n  \
                    [source_mode=file|inline] [source_encoding=utf8|base64]\n  \
                    [overwrite=true|false] [atomic=true|false] [mkdir_parents=true|false]\n  \
                    [file_mode=<0644>] [preserve_times=true|false] [mtime_epoch_ms=<ms>]\n  \
                    [max_size_bytes=<n>] [verify_checksum=true|false]\n  \
                    [checksum_algorithm=sha256|sha1|md5] [transfer_timeout_ms=<ms>]\n  \
                    [host=<host>] [port=<n>] [username=<name>]\n  \
                    [auth_method=auto|key|agent|password] [password=<pw>]\n  \
                    [identity_path=<file>] [identity_data=<key>] [identity_passphrase=<pp>]\n  \
                    [agent_socket=<path>] [known_hosts_mode=strict|accept-new|insecure]\n  \
                    [known_hosts_path=<file>] [connect_timeout_ms=<ms>] [timeout_ms=<ms>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh ssh://alice@web01.upload source=app.conf dest=/srv/app.conf \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "web01",
    "port": 22,
    "username": "alice",
    "backend": "system"
  },
  "source": {
    "mode": "file",
    "path": "app.conf",
    "size_bytes": 512
  },
  "dest": {
    "path": "/srv/app.conf",
    "overwrite": false,
    "atomic": true,
    "mkdir_parents": true,
    "size_bytes": 512
  },
  "result": {
    "uploaded": false,
    "planned": true,
    "verify_checksum": false,
    "checksum_algorithm": "sha256"
  },
  "warnings": [
    "Dry run: no SSH connection was made and no file was uploaded."
  ]
}

Printed as indented JSON in field order; --json-pretty sorts the keys.
A refused overwrite returns ssh.upload_dest_exists and a missing directory
with mkdir_parents=false returns ssh.upload_remote_dir_missing; an
interrupted transfer never leaves a partial file at dest when atomic=true."#,
                ),
            }),
        },
        VerbHelp {
            name: "download",
            definition: "Copies a remote file through the system ssh client into a temporary \
                file next to the local dest and renames it into place, or only returns the \
                content when dest_mode=none.",
            detail: Some(VerbDetail {
                usage: "resh ssh://[user@]host[:port].download source=<remote-path>\n  \
                    [dest=<local-path>] [dest_mode=file|none] [return_content=true|false]\n  \
                    [return_encoding=utf8|base64] [overwrite=true|false]\n  \
                    [mkdir_parents=true|false] [max_size_bytes=<n>]\n  \
                    [verify_checksum=true|false] [checksum_algorithm=sha256|sha1|md5]\n  \
                    [transfer_timeout_ms=<ms>] [host=<host>] [port=<n>]\n  \
                    [username=<name>] [auth_method=auto|key|agent|password]\n  \
                    [password=<pw>] [identity_path=<file>] [identity_data=<key>]\n  \
                    [identity_passphrase=<pp>] [agent_socket=<path>]\n  \
                    [known_hosts_mode=strict|accept-new|insecure] [known_hosts_path=<file>]\n  \
                    [connect_timeout_ms=<ms>] [timeout_ms=<ms>] [dry_run=true|false]\n  \
                    [format=json|text]",
                example: "resh ssh://alice@web01.download source=/etc/hosts dest=hosts \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "web01",
    "port": 22,
    "username": "alice",
    "backend": "system"
  },
  "source": {
    "path": "/etc/hosts"
  },
  "dest": {
    "mode": "file",
    "path": "hosts",
    "overwrite": false,
    "mkdir_parents": true
  },
  "result": {
    "downloaded": false,
    "planned": true,
    "return_content": true,
    "return_encoding": "utf8",
    "verify_checksum": false,
    "checksum_algorithm": "sha256"
  },
  "warnings": [
    "Dry run: no SSH connection was made and no file was downloaded."
  ]
}

Printed as indented JSON in field order; --json-pretty sorts the keys.
dest is required when dest_mode=file (the default) and refused when
dest_mode=none. The local dest is left untouched when the transfer, the size
limit, or verify_checksum=true fails, and an existing dest is replaced only
with overwrite=true."#,
                ),
            }),
        },
        VerbHelp {
            name: "test",
            definition: "Checks through the system ssh client that the host is reachable \
                (connect), that the login works (auth), that exec_command exits with 0 (exec), \
                that the SFTP subsystem answers (sftp), and that the host key is known and \
                matches (hostkey).",
            detail: Some(VerbDetail {
                usage: "resh ssh://user@host[:port].test\n  \
                    [tests=connect,auth,exec,sftp,hostkey] [exec_command=<cmd>]\n  \
                    [handshake_timeout_ms=<ms>] [auth_timeout_ms=<ms>]\n  \
                    [sftp_timeout_ms=<ms>] [exec_timeout_ms=<ms>]\n  \
                    [overall_timeout_ms=<ms>] [allow_insecure_hostkey=true|false]\n  \
                    [host=<host>] [port=<n>] [username=<name>]\n  \
                    [auth_method=auto|key|agent|password] [password=<pw>]\n  \
                    [identity_path=<file>] [identity_data=<key>] [identity_passphrase=<pp>]\n  \
                    [agent_socket=<path>] [known_hosts_mode=strict|accept-new|insecure]\n  \
                    [known_hosts_path=<file>] [connect_timeout_ms=<ms>] [timeout_ms=<ms>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh --json-pretty ssh://alice@192.0.2.10.test",
                example_output: Some(
                    r#"{
  "dry_run": false,
  "ok": true,
  "security": {
    "insecure_hostkey_allowed": false,
    "known_hosts_mode": "strict"
  },
  "summary": {
    "overall_duration_ms": 101,
    "tests_failed": 0,
    "tests_passed": 2,
    "tests_requested": [
      "connect",
      "auth"
    ],
    "tests_run": 2,
    "tests_skipped": 0
  },
  "target": {
    "host": "192.0.2.10",
    "port": 22,
    "username": "alice"
  },
  "tests": [
    {
      "duration_ms": 50,
      "name": "connect",
      "status": "passed"
    },
    {
      "details": {
        "method": "key"
      },
      "duration_ms": 50,
      "name": "auth",
      "status": "passed"
    }
  ],
  "warnings": []
}

Shown with --json-pretty. The default tests are connect and auth. Each check
opens its own ssh connection; auth is skipped when a requested connect check
failed, and exec and sftp when a requested auth check failed. Exit status 1
means a check failed, 124 that overall_timeout_ms (default 15000) passed."#,
                ),
            }),
        },
        VerbHelp {
            name: "config.get",
            definition: "Parses the local OpenSSH client config files and reports the settings \
                that apply to a host (the URL host or host=), using OpenSSH's first-match \
                rules.",
            detail: Some(VerbDetail {
                usage: "resh ssh://<host>.config.get [host=<name>] [user_config_path=<path>]\n  \
                    [system_config_path=<path>] [extra_config_paths=<path,...>]\n  \
                    [follow_includes=true|false] [include_raw_entries=true|false]\n  \
                    [include_origin=true|false] [user_home=<dir>]\n  \
                    [max_config_bytes=<n>] [max_includes=<n>] [max_hosts=<n>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh ssh://web01.config.get user_config_path=cfg \
                    system_config_path=/dev/null",
                example_output: Some(
                    r#"{
  "ok": true,
  "dry_run": false,
  "host": "web01",
  "sources": {
    "extra_config_paths": [],
    "follow_includes": true,
    "system_config_path": "/dev/null",
    "user_config_path": "cfg"
  },
  "effective": {
    "HostName": {
      "value": "192.0.2.10",
      "origin": {
        "file": "cfg",
        "line": 2,
        "block": "Host web01"
      }
    },
    "User": {
      "value": "alice",
      "origin": {
        "file": "cfg",
        "line": 3,
        "block": "Host web01"
      }
    }
  },
  "raw_entries": [
    {
      "file": "cfg",
      "line": 2,
      "block_type": "Host",
      "block_pattern": "web01",
      "option": "HostName",
      "value": "192.0.2.10"
    },
    {
      "file": "cfg",
      "line": 3,
      "block_type": "Host",
      "block_pattern": "web01",
      "option": "User",
      "value": "alice"
    }
  ],
  "summary": {
    "total_files": 2,
    "total_entries": 2,
    "matched_blocks": [
      "Host web01 (cfg:1)"
    ],
    "truncated": false
  }
}

Printed as indented JSON in field order for a file cfg holding HostName and
User under Host web01 (/dev/null stands in for an empty system config). The
first value obtained for an option wins, as in ssh; include_raw_entries=false
drops raw_entries."#,
                ),
            }),
        },
        VerbHelp {
            name: "keys.list",
            definition: "Reads authorized_keys, host key, or other public key files on the \
                remote host over ssh and reports each key's type, fingerprint, comment, and \
                options.",
            detail: Some(VerbDetail {
                usage: "resh ssh://user@host[:port].keys.list [scope=authorized|host|custom]\n  \
                    [authorized_user=<name>] [authorized_paths=<path,...>]\n  \
                    [host_key_paths=<path,...>] [custom_paths=<path,...>]\n  \
                    [key_types=<rsa,ecdsa,ed25519,dsa>] [fingerprint_algorithm=sha256|md5]\n  \
                    [include_options=true|false] [include_raw_key=true|false]\n  \
                    [max_keys=<n>] [max_bytes=<n>] [read_timeout_ms=<ms>]\n  \
                    [host=<host>] [port=<n>] [username=<name>]\n  \
                    [auth_method=auto|key|agent|password] [password=<pw>]\n  \
                    [identity_path=<file>] [identity_data=<key>] [identity_passphrase=<pp>]\n  \
                    [agent_socket=<path>] [known_hosts_mode=strict|accept-new|insecure]\n  \
                    [known_hosts_path=<file>] [connect_timeout_ms=<ms>] [timeout_ms=<ms>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh --json-pretty ssh://alice@192.0.2.10.keys.list \
                    include_raw_key=false",
                example_output: Some(
                    r#"{
  "connection": {
    "backend": "system",
    "host": "192.0.2.10",
    "port": 22,
    "username": "alice"
  },
  "dry_run": false,
  "files": [
    {
      "exists": true,
      "keys": [
        {
          "bits": 256,
          "comment": "alice@laptop",
          "fingerprint": "SHA256:3xDjK+bg/gX0dncBKmABpUGbcOI6xx9mMC3MDjssIBU",
          "fingerprint_algorithm": "sha256",
          "index": 0,
          "source_line": 1,
          "type": "ed25519",
          "type_raw": "ssh-ed25519"
        }
      ],
      "path": "/home/alice/.ssh/authorized_keys",
      "readable": true,
      "size_bytes": 94
    },
    {
      "exists": false,
      "path": "/home/alice/.ssh/authorized_keys2",
      "readable": false
    }
  ],
  "ok": true,
  "scope": "authorized",
  "summary": {
    "matched_keys": 1,
    "total_keys": 1,
    "truncated": false
  }
}

Shown with --json-pretty. A missing file is reported with exists false and
is not an error; a file that exists but cannot be read exits 1 with
ssh.keys_list_remote_read_failed."#,
                ),
            }),
        },
        VerbHelp {
            name: "key.add",
            definition: "Adds an OpenSSH public key to a remote authorized_keys (or another) \
                file over ssh, skipping, refusing, or replacing a key that is already present.",
            detail: Some(VerbDetail {
                usage: "resh ssh://user@host[:port].key.add public_key=<key-line>\n  \
                    [public_key_source=inline|file] [public_key_path=<file>]\n  \
                    [scope=authorized|custom] [authorized_user=<name>]\n  \
                    [authorized_paths=<path>] [custom_paths=<path>]\n  \
                    [on_duplicate=skip|error|replace] [create_if_missing=true|false]\n  \
                    [backup_existing=true|false] [backup_suffix=<suffix>]\n  \
                    [ensure_permissions=true|false] [file_mode=<0600>] [dir_mode=<0700>]\n  \
                    [max_file_bytes=<n>] [read_timeout_ms=<ms>] [write_timeout_ms=<ms>]\n  \
                    [host=<host>] [port=<n>] [username=<name>]\n  \
                    [auth_method=auto|key|agent|password] [password=<pw>]\n  \
                    [identity_path=<file>] [identity_data=<key>] [identity_passphrase=<pp>]\n  \
                    [agent_socket=<path>] [known_hosts_mode=strict|accept-new|insecure]\n  \
                    [known_hosts_path=<file>] [connect_timeout_ms=<ms>] [timeout_ms=<ms>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh --json-pretty ssh://bob@web01.key.add public_key_path=id.pub \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "connection": {
    "backend": "system",
    "host": "web01",
    "port": 22,
    "username": "bob"
  },
  "dry_run": true,
  "key": {
    "comment": "bob@laptop",
    "fingerprint": "SHA256:3xDjK+bg/gX0dncBKmABpUGbcOI6xx9mMC3MDjssIBU",
    "fingerprint_algorithm": "sha256",
    "type": "ed25519",
    "type_raw": "ssh-ed25519"
  },
  "ok": true,
  "operation": {
    "backup_created": false,
    "created_file": false,
    "duplicates_found": 0,
    "on_duplicate": "skip",
    "status": "dry_run"
  },
  "scope": "authorized",
  "target_file": "~bob/.ssh/authorized_keys",
  "warnings": [
    "Dry run: no SSH connection was made and no file was changed."
  ]
}

Shown with --json-pretty. public_key_path is read from the local machine and
implies public_key_source=file. Without dry_run the file is replaced
atomically (with a .bak backup by default) and status is added,
already_present, or replaced."#,
                ),
            }),
        },
        VerbHelp {
            name: "tunnel",
            definition: "Runs a local, remote, or dynamic (SOCKS) port forward through the \
                system ssh client until a limit, a timeout, or an interrupt ends it, and \
                reports the traffic it carried.",
            detail: Some(VerbDetail {
                usage: "resh ssh://user@host[:port].tunnel mode=local|remote|dynamic\n  \
                    [local_bind_host=<addr>] [local_bind_port=<n>]\n  \
                    [remote_bind_host=<addr>] [remote_bind_port=<n>]\n  \
                    [remote_dest_host=<host>] [remote_dest_port=<n>]\n  \
                    [local_dest_host=<host>] [local_dest_port=<n>]\n  \
                    [socks_version=socks5|socks4] [allow_wildcard_binds=true|false]\n  \
                    [tunnel_timeout_ms=<ms>] [idle_timeout_ms=<ms>]\n  \
                    [max_connections=<n>] [max_bytes_in=<n>] [max_bytes_out=<n>]\n  \
                    [host=<host>] [port=<n>] [username=<name>]\n  \
                    [auth_method=auto|key|agent|password] [password=<pw>]\n  \
                    [identity_path=<file>] [identity_data=<key>] [identity_passphrase=<pp>]\n  \
                    [agent_socket=<path>] [known_hosts_mode=strict|accept-new|insecure]\n  \
                    [known_hosts_path=<file>] [connect_timeout_ms=<ms>] [timeout_ms=<ms>]\n  \
                    [dry_run=true|false] [format=json|text]",
                example: "resh ssh://alice@bastion.tunnel mode=dynamic local_bind_port=1080 \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "bastion",
    "port": 22,
    "username": "alice",
    "backend": "system"
  },
  "tunnel": {
    "mode": "dynamic",
    "local_bind_host": "127.0.0.1",
    "local_bind_port": 1080,
    "remote_bind_host": null,
    "remote_bind_port": null,
    "remote_dest_host": null,
    "remote_dest_port": null,
    "local_dest_host": null,
    "local_dest_port": null,
    "socks_version": "socks5"
  },
  "lifetime": {
    "connect_timeout_ms": 10000,
    "tunnel_timeout_ms": null,
    "idle_timeout_ms": 300000,
    "max_connections": null,
    "max_bytes_in": null,
    "max_bytes_out": null,
    "closed_reason": null
  },
  "stats": {
    "connections_accepted": 0,
    "bytes_in": 0,
    "bytes_out": 0,
    "uptime_ms": 0
  },
  "warnings": [
    "Dry run: no SSH connection was made and no tunnel was created."
  ]
}

Printed as indented JSON in field order; --json-pretty sorts the keys.
Without dry_run a one-line "ready" event is printed when the forward is up
and this report when it closes (closed_reason: tunnel_timeout, idle_timeout,
max_connections, max_bytes_in, max_bytes_out, or interrupted)."#,
                ),
            }),
        },
    ],
};

/// The report format and requested dry-run mode of one call, read before
/// the arguments are validated so that even a refusal is printed in the
/// requested shape.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub format: OutputFormat,
    pub dry_run: bool,
}

impl Out {
    pub fn from_args(args: &Args) -> Self {
        let r = args::ArgReader::new(args);
        Out {
            format: r
                .choice("format", OutputFormat::VALUES)
                .ok()
                .flatten()
                .unwrap_or_default(),
            dry_run: crate::core::lenient::dry_run(args).unwrap_or(false),
        }
    }
}

/// A failure status whose reason is printed as `Error: [<code>] <message>`.
pub fn coded(exit: i32, code: &str, message: &str) -> Status {
    Status::coded(exit, code, message)
}

/// Prints `response` as indented JSON or with `text`.
pub fn write_response<T: Serialize>(
    io: &mut IoStreams,
    format: OutputFormat,
    response: &T,
    text: fn(&T) -> String,
) -> Result<()> {
    match format {
        OutputFormat::Json => writeln!(io.stdout, "{}", serde_json::to_string_pretty(response)?)?,
        OutputFormat::Text => write!(io.stdout, "{}", text(response))?,
    }
    io.stdout.flush()?;
    Ok(())
}

/// SSH handle: holds what the URL says about the target.
#[derive(Debug)]
pub struct SshHandle {
    target: SshTarget,
}

impl SshHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(SshHandle {
            target: SshTarget::from_url(url),
        })
    }

    /// The in-URL help forms (`ssh://--help`, `ssh://--help=VERB`, the
    /// `help` verb, and `ssh://host.VERB(help=1)`).
    fn help_text(&self, verb: &str, args: &Args) -> Option<String> {
        let requested = if crate::core::help::HELP_ALIASES.contains(&verb)
            || crate::core::help::is_help_flag(verb)
        {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else if args.contains_key("help") && options_for(verb).is_some() {
            Some(verb)
        } else {
            return None;
        };
        Some(crate::core::help::render_legacy(
            "ssh",
            &SSH_HELP,
            self.verbs(),
            requested,
        ))
    }
}

impl Handle for SshHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "exec",
            "upload",
            "download",
            "test",
            "config.get",
            "keys.list",
            "key.add",
            "tunnel",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&SSH_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(text) = self.help_text(verb, args) {
            write!(io.stdout, "{text}")?;
            return Ok(Status::ok());
        }
        let out = Out::from_args(args);
        let t = &self.target;
        match verb {
            "exec" => exec::run(t, args, &out, io),
            "upload" => transfer::run_upload(t, args, &out, io),
            "download" => transfer::run_download(t, args, &out, io),
            "tunnel" => tunnel::run(t, args, &out, io),
            "keys.list" => keys::run_list(t, args, &out, io),
            "key.add" => keys::run_add(t, args, &out, io),
            "config.get" => config_get::run(t, args, &out, io),
            "test" => probe::run(t, args, &out, io),
            _ => Ok(coded(
                2,
                "ssh.unknown_verb",
                &format!(
                    "unknown verb for ssh://: {verb} (verbs: {}){}",
                    VERBS.join(", "),
                    args::did_you_mean(verb, VERBS)
                ),
            )),
        }
    }
}

/// Register the ssh handle with the registry.
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("ssh", |u| Ok(Box::new(SshHandle::from_url(u)?)));
}
