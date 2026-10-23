# Resource Shell (resh): SSH Handle

## 1. Overview

The `ssh` handle runs commands on remote hosts and copies files by driving the
**system OpenSSH client** (`ssh`), with `sshpass` for password logins. It
also reads the local OpenSSH client configuration. It does not contain its own
SSH implementation.

What works and what does not:

| Verb         | Status |
| ------------ | ------ |
| `exec`       | Works. Runs a remote command and reports exit code, stdout and stderr. |
| `upload`     | Works. Pipes the data into `cat` on the remote host (no SFTP/SCP). |
| `download`   | Works. Reads the file with `cat` over ssh. |
| `test`       | Works for the `connect`, `auth` and `exec` checks. The `sftp` and `hostkey` checks are not implemented and always fail. |
| `config.get` | Works. Local file parsing only; no connection. |
| `key.add`    | **Stub.** Validates a key and, with `dry_run=true`, reports the file it would change. Without `dry_run` it exits 1 with `ssh.not_implemented` and writes nothing. |
| `keys.list`  | **Stub.** With `dry_run=true` it lists the files it would read. Without `dry_run` it exits 1 with `ssh.not_implemented`. |
| `tunnel`     | **Stub.** With `dry_run=true` it validates and reports the forward. Without `dry_run` it exits 1; no tunnel is created. |

Requirements: `ssh` on `PATH`; `sshpass` for password authentication; on the
remote host a POSIX shell and `cat` (plus `mkdir`, `mv`, `chmod`, `touch` as
used by `upload`, and `sha256sum`, `sha1sum` or `md5sum` for checksums).
Linux is the only supported and verified local platform. Each `resh` run is a
separate process and opens its own ssh connection(s); nothing is kept open.

```bash
resh ssh --help
resh ssh exec --help
```

## 2. Command syntax

```text
resh ssh://[user[:password]@]host[:port].<verb> key=value ...
resh 'ssh://[user@]host[:port].<verb>(key=value,...)'
```

```bash
resh ssh://alice@192.0.2.10.exec command=hostname
resh ssh://deploy@web01.example.com:2222.test
resh ssh://web01.config.get host=web01
```

The verb follows the last dot; dotted verbs (`config.get`, `keys.list`,
`key.add`) are recognized as a whole. A URL without a verb is an error.

* When no user is given, `exec`, `upload` and `download` use `$USER` (then
  `$USERNAME`, then `root`). `test`, `tunnel`, `keys.list` and `key.add`
  require a user name.
* A password in the URL (`ssh://alice:secret@host...`) is used by `exec`,
  `upload`, `download` and `tunnel`, but it is visible in the process list and
  shell history. `test` reads only the `password=` argument.
* `host=`, `port=` and `username=` arguments may repeat the URL values; a
  conflicting value is an error (`ssh.target_conflict`) for `exec`.

## 3. Authentication and host keys

| Argument         | Values | Notes |
| ---------------- | ------ | ----- |
| `auth_method`    | `auto` (default), `key`, `agent`, `password` | `auto` picks password if one is given, then key if `identity_path` is given, then agent if `SSH_AUTH_SOCK` or `agent_socket` is set, otherwise ssh's default key lookup. |
| `identity_path`  | file   | Passed to `ssh -i` for key authentication. |
| `password`       | text   | Needs `sshpass`. It is passed in the `SSHPASS` environment variable (`sshpass -e`), not on the command line. |
| `agent_socket`   | path   | Sets `SSH_AUTH_SOCK` for the ssh process. |
| `known_hosts_mode` | `strict` (default), `accept-new`, `insecure` | Maps to `StrictHostKeyChecking=yes`, `accept-new`, `no`. |
| `known_hosts_path` | file | Sets `UserKnownHostsFile`. |

The value is spelled **`accept-new`** with a hyphen. In `exec`, `upload`,
`download`, `keys.list`, `key.add` and `tunnel` any other value (including
`accept_new`) is silently treated as `strict`. In `test` an unknown value is
an error, and `insecure` additionally requires `allow_insecure_hostkey=true`.
`insecure` disables host key checking and exposes you to man-in-the-middle
attacks.

`BatchMode=yes` is set for every method except password, so ssh never
prompts. `identity_data` and `identity_passphrase` are accepted but **not
used**: a key must be a file, and an encrypted key needs an agent.

## 4. Verb reference

### exec

```bash
resh ssh://alice@192.0.2.10.exec command=hostname
resh ssh://alice@192.0.2.10.exec command='systemctl is-active nginx' command_timeout_ms=10000
resh ssh://alice@192.0.2.10.exec command=ls command_args=-l,/var/log shell_mode=sh cwd=/tmp
resh ssh://alice@192.0.2.10.exec command='rm -rf /srv/cache/*' dry_run=true
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `command`            | (required) | Command text. |
| `command_args`       | (none)  | Extra arguments, **split on commas**. An argument cannot contain a comma. |
| `shell_mode`         | `none`  | `none`, `sh`, `bash`, `cmd`, `powershell`. Unknown values mean `none`. |
| `cwd`                | (none)  | Remote working directory (quoted). |
| `allocate_pty`       | `false` | `ssh -t`. |
| `connect_timeout_ms` | `10000` | ssh `ConnectTimeout`, rounded up to whole seconds. |
| `command_timeout_ms` | `60000` | Kills the ssh process after this long; `0` means no limit. |
| `max_output_bytes`   | `1048576` | Per stream; longer output is truncated (`output_truncated`). |
| `trim_trailing_newlines` | `true` | |
| `capture_output`     | `true`  | `false` omits stdout and stderr from the JSON. |
| `output_encoding`    | `utf8`  | `utf8` or `base64`. |
| `dry_run`            | `false` | Builds and reports the command without running ssh. |
| `format`             | `json`  | `json` or `text`. |

**How the remote command is quoted.** ssh sends one command string to the
remote user's login shell, which parses it again. resh does not make that
safe for you:

* `shell_mode=none`: the string is `command` followed by `command_args`
  joined with spaces, with **no quoting**. Spaces, `$`, `*`, `;`, `|`, `&`,
  backticks and quotes in either are interpreted by the remote shell. Only
  `cwd` is quoted (`cd '<cwd>' && ...`).
* `shell_mode=sh` or `bash`: an argument is single-quoted only if it contains
  a space or a quote character. Other shell metacharacters (`$`, `*`, `;`,
  `|`, `&`, `>`, backticks) are left as is and are interpreted by the inner
  `sh -c`/`bash -c`. The whole script is then single-quoted for the login
  shell.
* `shell_mode=cmd` and `powershell`: no quoting at all.

Never build `command` or `command_args` from untrusted input. Use
`dry_run=true` to see exactly what would run: the `command.raw` field shows the
final string.

`env=KEY=value,KEY2=value2` is accepted, but the variables are set on the
**local** ssh process. They reach the remote command only if your ssh
configuration sends them (`SendEnv`) and the server accepts them
(`AcceptEnv`); normally they do not.

Output:

```json
{
  "ok": true,
  "dry_run": false,
  "connection": { "host": "192.0.2.10", "port": 22, "username": "alice", "backend": "system" },
  "command": { "raw": "hostname", "shell_mode": "none", "cwd": null, "allocate_pty": false },
  "result": { "executed": true, "exit_code": 0, "signal": null, "timed_out": false, "output_truncated": false, "stdout": "web01", "stderr": null },
  "timing": { "connect_ms": 0, "command_ms": 412 }
}
```

`connect_ms` is always 0 (connection and command are not timed separately).

Exit status:

* The remote command's exit code 0 gives `ok: true` and exit 0.
* A non-zero remote exit code gives `ok: false`,
  `error.code: "REMOTE_EXIT_NONZERO"`, and **resh exits with the same code**
  (1-255).
* ssh's own failures exit 255 (`error.code: "SSH_FAILED"` with ssh's stderr),
  which is indistinguishable by exit code from a remote command that exits
  255; read `error.code`.
* A command timeout, a missing `sshpass`, or an argument error exits 1.

### upload

```bash
resh ssh://alice@web01.upload source=app.conf dest=/srv/app/app.conf dry_run=true
resh ssh://alice@web01.upload source=app.conf dest=/srv/app/app.conf overwrite=true file_mode=0640 verify_checksum=true
resh ssh://alice@web01.upload source_mode=inline source='hello world' dest=/tmp/hello.txt
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `source`             | (required) | Local path, or the data itself with `source_mode=inline`. |
| `source_mode`        | `file`  | `file` or `inline`. |
| `source_encoding`    | `utf8`  | `utf8` or `base64` (inline data). |
| `dest`               | (required) | Remote path; a leading `~/` is expanded by the remote shell. |
| `overwrite`          | `false` | Refuses an existing file (`ssh.upload_dest_exists`). |
| `atomic`             | `true`  | Writes `<dest>.resh.tmp.<n>` and renames it over `dest`. |
| `mkdir_parents`      | `true`  | `false` fails when the directory is missing (`ssh.upload_remote_dir_missing`). |
| `file_mode`          | (none)  | Four-digit octal such as `0644`, applied with `chmod`. |
| `preserve_times`, `mtime_epoch_ms` | (none) | Set the remote modification time with `touch -d`. |
| `max_size_bytes`     | `104857600` | Larger sources are refused. |
| `verify_checksum`    | `false` | Compares the local checksum with the remote tool's output. |
| `checksum_algorithm` | `sha256` | `sha256`, `sha1`, `md5`. |
| `connect_timeout_ms` | `10000` | |
| `transfer_timeout_ms`| `600000` | Kills the transfer after this long; `0` means no limit. |
| `dry_run`, `format`  |         | |

### download

```bash
resh ssh://alice@web01.download source=/etc/hosts dest=hosts dry_run=true
resh ssh://alice@web01.download source=/var/log/app.log dest=./app.log overwrite=true
resh ssh://alice@web01.download source=/etc/os-release dest_mode=none
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `source`             | (required) | Remote path. |
| `dest`               | (required unless `dest_mode=none`) | Local path. Written to a temporary file next to it and renamed into place. |
| `dest_mode`          | `file`  | `none` returns the content only. |
| `return_content`     | `true`  | Include the content in the JSON. |
| `return_encoding`    | `utf8`  | `utf8` or `base64`. |
| `overwrite`          | `false` | An existing `dest` is replaced only with `true`. |
| `mkdir_parents`      | `true`  | Create local parent directories. |
| `max_size_bytes`     | `104857600` | Larger files fail and leave `dest` untouched. |
| `verify_checksum`, `checksum_algorithm` | `false`, `sha256` | |
| `connect_timeout_ms`, `transfer_timeout_ms` | `10000`, `600000` | |
| `dry_run`, `format`  |         | |

The local `dest` is left unchanged when the transfer, the size limit or the
checksum check fails.

### test

```bash
resh ssh://alice@192.0.2.10.test
resh ssh://alice@192.0.2.10.test tests=connect,auth,exec exec_command=uptime
resh ssh://alice@192.0.2.10.test known_hosts_mode=accept-new
```

| Argument            | Default | Notes |
| ------------------- | ------- | ----- |
| `tests`             | `connect,auth` | Any of `connect`, `auth`, `exec`, `sftp`, `hostkey`. `sftp` and `hostkey` always fail (not implemented). |
| `exec_command`      | `echo ok` | Command for the `exec` check; must exit 0. |
| `connect_timeout_ms`| `10000` | |
| `auth_timeout_ms`   | `10000` | The connect and auth probes each get `connect_timeout_ms + auth_timeout_ms`. |
| `exec_timeout_ms`   | `10000` | The exec probe gets `connect_timeout_ms + exec_timeout_ms`. |
| `overall_timeout_ms`| `15000` | Remaining checks are skipped once exceeded. |
| `allow_insecure_hostkey` | `false` | Required with `known_hosts_mode=insecure`. |
| `dry_run`, `format` |         | |

Each check opens its own ssh connection. `auth`, `exec` and `sftp` are
skipped when the check they depend on did not pass. `handshake_timeout_ms` and
`sftp_timeout_ms` are accepted but unused.

### config.get

```bash
resh --json-pretty ssh://web01.config.get host=web01
resh ssh://web01.config.get host=web01 user_config_path=./ssh_config include_raw_entries=false
```

Reads `~/.ssh/config` and `/etc/ssh/ssh_config` (or the paths given with
`user_config_path`, `system_config_path`, `extra_config_paths`) and reports
the settings that apply to the `host` argument. The URL host is ignored; the
`host` argument is required. Options: `follow_includes` (default true),
`include_raw_entries`, `include_origin`, `user_home`, `format`.

Limitation: when several blocks set the same option, the **later** match wins.
OpenSSH uses the **first** match, so results can differ from what `ssh` really
uses (`ssh -G host` shows the real values).

### key.add (stub)

```bash
resh ssh://bob@web01.key.add public_key_path=./id_ed25519.pub dry_run=true
```

Validates the public key (from `public_key` or the local file
`public_key_path`), reports its type and SHA256 fingerprint, and names the
target file (`~<authorized_user>/.ssh/authorized_keys` for
`scope=authorized`, or `custom_paths` for `scope=custom`). It does **not**
connect to the host. Without `dry_run=true` it exits 1 with error code
`ssh.not_implemented` and changes nothing. Use `ssh-copy-id` to install a key.

### keys.list (stub)

```bash
resh ssh://alice@192.0.2.10.keys.list dry_run=true
```

With `dry_run=true` it reports the files it would read (`planned_files`) for
`scope=authorized` (default), `host` or `custom`. It never connects or reads a
key: without `dry_run` it exits 1 with `ssh.not_implemented`.

### tunnel (stub)

```bash
resh ssh://alice@bastion.tunnel mode=local local_bind_port=5433 remote_dest_host=db.internal remote_dest_port=5432 dry_run=true
resh ssh://alice@bastion.tunnel mode=dynamic local_bind_port=1080 dry_run=true
```

Validates `mode` (`local` needs `remote_dest_host` and `remote_dest_port`;
`remote` needs `local_dest_host` and `local_dest_port`; `dynamic` is a SOCKS
proxy) and the bind addresses, and reports the plan with `dry_run=true`.
**No tunnel is ever created**: without `dry_run` the verb exits 1
(`Tunnel execution failed`). The lifetime options (`connect_timeout_ms`,
`tunnel_timeout_ms`, `idle_timeout_ms`, `max_connections`, `max_bytes_in`,
`max_bytes_out`) are only echoed. Use `ssh -L`, `-R` or `-D` directly.

## 5. Timeouts

The ssh handle has **no `timeout_ms` option**; a `timeout_ms` argument is
ignored by every verb. Use the verb-specific options:

| Verb         | Enforced | Accepted but unused |
| ------------ | -------- | ------------------- |
| `exec`       | `connect_timeout_ms` (ssh ConnectTimeout), `command_timeout_ms` | |
| `upload`, `download` | `connect_timeout_ms`, `transfer_timeout_ms` | |
| `test`       | `connect_timeout_ms`, `auth_timeout_ms`, `exec_timeout_ms`, `overall_timeout_ms` | `handshake_timeout_ms`, `sftp_timeout_ms` |
| `config.get` | (local, none) | |
| `key.add`, `keys.list`, `tunnel` | (stubs, no connection) | all timeout options |

## 6. Errors and exit codes

* Responses are JSON on stdout, also on failure, with `ok: false` and
  `error: {"code", "message"}` (plus `details` when there are any).
* Error codes are mostly `ssh.*` (for example `ssh.host_required`,
  `ssh.auth_missing_password`, `ssh.agent_unavailable`,
  `ssh.upload_dest_exists`, `ssh.download_too_large`,
  `ssh.hostkey_verification_failed`, `ssh.not_implemented`). `exec` uses
  `REMOTE_EXIT_NONZERO`, `SSH_FAILED`, `EXEC_TIMEOUT`, `PARSE_ERROR` and
  similar upper-case codes for its own failures.
* `exec` exits with the remote command's exit code; other failures exit 1.
* resh prints `Error: <reason>` on stderr for failures.

## 7. Security notes

* Prefer key or agent authentication. Passwords on the command line or in the
  URL are visible to other local users through the process list.
* Keep `known_hosts_mode=strict` (the default) for production hosts.
* Treat `command`, `command_args`, `cwd` and `shell_mode` as code: see the
  quoting rules under `exec`.
