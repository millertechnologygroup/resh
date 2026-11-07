# Resource Shell (resh): SSH Handle

## 1. Overview

The `ssh` handle runs commands on remote hosts, copies files, lists and adds
public keys, forwards ports and checks connections by driving the **system
OpenSSH client** (`ssh`), with `sshpass` for password logins. It also reads
the local OpenSSH client configuration. It does not contain its own SSH
implementation.

| Verb         | What it does |
| ------------ | ------------ |
| `exec`       | Runs a remote command and reports exit code, stdout and stderr. |
| `upload`     | Pipes local data into a remote POSIX shell (`cat`) and installs it atomically. |
| `download`   | Reads a remote file with `cat` and installs it locally atomically, or only returns it. |
| `test`       | `connect`, `auth`, `exec`, `sftp` and `hostkey` checks. |
| `config.get` | Local file parsing only; no connection. |
| `keys.list`  | Reads authorized_keys, host keys or other public key files on the remote host. |
| `key.add`    | Adds a public key to a remote authorized_keys (or another) file. |
| `tunnel`     | Runs a local, remote or dynamic (SOCKS) forward until a limit ends it. |

Requirements: `ssh` on `PATH`; `sshpass` for password authentication; on the
remote host a POSIX login shell with `cat`, `wc`, `mkdir`, `mv`, `ln`,
`chmod`, `rm` (plus `touch -d @N` for modification times, `cksum`, `cp`,
`ls`, `id` and `chown` for `key.add`, and `sha256sum`, `sha1sum` or `md5sum`
for checksums). Linux is the only supported local platform. Each verb opens
its own ssh connection(s); nothing is kept open between runs.

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
resh ssh://web01.config.get
```

* When no user is given, `exec`, `upload` and `download` use `$USER` (then
  `$USERNAME`, then `root`). `test`, `tunnel`, `keys.list` and `key.add`
  require a user name (`ssh.username_required`).
* A password in the URL is used by every connecting verb, but it is visible
  in the process list and shell history; prefer `password=` or a key.
* `host=`, `port=`, `username=` and `password=` may repeat the URL values; a
  different value is refused (`ssh.target_conflict`, exit 2).
* Host and user names that are not plain names or addresses (for example
  starting with `-`, or containing spaces or shell characters) are refused.

## 3. Arguments, exit codes and errors (all verbs)

* **Strict arguments.** Every verb refuses an argument it does not take,
  with a "did you mean" hint for likely typos, a boolean that is not one of
  `true/false`, `1/0`, `yes/no`, `on/off`, a number that is not a
  non-negative integer, and an unknown enum value. Options that do not apply
  to the chosen mode (for example `socks_version` with `mode=local`, or
  `dest` with `dest_mode=none`) are refused too. Nothing runs and nothing
  connects (exit 2, `ssh.invalid_argument` unless a more specific code is
  listed). This is stricter than v1.0.6-beta, which ignored such arguments.
* **Dry run.** Every verb takes `dry_run=true`: all arguments and local
  inputs (source files, key files, identity files, the agent socket,
  `sshpass`) are checked and the plan is reported, but no connection is made.
* **Output.** Reports are JSON on stdout (`format=json`, the default,
  indented) or text (`format=text`), on success and on failure. A failure
  has `ok: false` and `error: {"code", "message"}` (plus `details` when
  useful), and resh prints `Error: [<code>] <message>` on stderr.
* **Exit status.** 0 success; 1 the operation failed (remote command failed,
  connection, login or host key refused, file not found, partial failure);
  2 invalid arguments (nothing was done); 124 a timeout or an interrupt
  (SIGINT/SIGTERM), when the outcome may be unknown.

### Authentication and host keys

| Argument         | Values | Notes |
| ---------------- | ------ | ----- |
| `auth_method`    | `auto` (default), `key`, `agent`, `password` | `auto` uses password if one is given, then key if `identity_path`/`identity_data` is given, then the agent if `agent_socket` or `SSH_AUTH_SOCK` is set, otherwise ssh's default key lookup. |
| `password`       | text   | Needs `sshpass`; passed in the `SSHPASS` environment variable (`sshpass -e`), never on the command line. Only with `auth_method=password` or `auto`. |
| `identity_path`  | file   | Passed to `ssh -i` with `IdentitiesOnly=yes`. Must be a readable file (`ssh.identity_not_found`). |
| `identity_data`  | key text | A private key as text (`-----BEGIN ... PRIVATE KEY-----`) or the same text base64-encoded. It is written to a mode-0600 file in a private (0700) temporary directory for the run and removed afterwards. Anything else is refused (`ssh.identity_invalid`, exit 2). |
| `identity_passphrase` | text | Passphrase of an encrypted key (needs `identity_path` or `identity_data`). Given to ssh through an `SSH_ASKPASS` helper (OpenSSH 8.4 or later) and an environment variable, never on the command line; password and keyboard-interactive logins are turned off so the helper only answers the passphrase prompt. |
| `agent_socket`   | path   | Sets `SSH_AUTH_SOCK` for ssh. Must exist (`ssh.agent_unavailable`). Only with `auth_method=agent` or `auto`. |
| `known_hosts_mode` | `strict` (default), `accept-new`, `insecure` | `StrictHostKeyChecking=yes`, `accept-new`, `no`. Any other value (including `accept_new`) is refused. |
| `known_hosts_path` | file | Sets `UserKnownHostsFile` (quoted, so spaces work). |
| `connect_timeout_ms` | ms, default 10000 | ssh `ConnectTimeout`, rounded up to whole seconds; 0 leaves ssh's default. |

A credential given for a method that does not use it (for example
`password` with `auth_method=key`, or `identity_path` with
`auth_method=agent`) is refused. `BatchMode=yes` is set except for password
logins and passphrase-protected keys, so ssh never waits for input.
`insecure` disables host key checking and exposes you to
man-in-the-middle attacks; `test` additionally requires
`allow_insecure_hostkey=true` for it.

### Timeouts

Every connecting verb takes `timeout_ms`: an overall deadline for all of its
ssh runs (no default; 0 means none). It is combined with the verb's own
limits below; whichever passes first stops the run with exit 124.
`config.get` reads only local files and refuses `timeout_ms`.

| Verb | Own limits (default) |
| ---- | -------------------- |
| `exec` | `command_timeout_ms` (60000, 0 = none) |
| `upload`, `download` | `transfer_timeout_ms` (600000, 0 = none) |
| `test` | `handshake_timeout_ms`, `auth_timeout_ms`, `sftp_timeout_ms`, `exec_timeout_ms` (10000 each, plus `connect_timeout_ms` per check), `overall_timeout_ms` (15000) |
| `keys.list` | `read_timeout_ms` (10000) |
| `key.add` | `read_timeout_ms` (10000), `write_timeout_ms` (10000) |
| `tunnel` | `tunnel_timeout_ms`, `idle_timeout_ms` (300000): these end the tunnel normally (exit 0) |

A stopped ssh is killed with its whole local process group.

## 4. Verb reference

### exec

```bash
resh ssh://alice@192.0.2.10.exec command=hostname
resh ssh://alice@192.0.2.10.exec command='systemctl is-active nginx' command_timeout_ms=10000
resh ssh://alice@192.0.2.10.exec command=ls command_args=-l,/var/log shell_mode=sh cwd=/tmp
resh ssh://alice@192.0.2.10.exec command=env env=APP_ENV=prod,LOG_LEVEL=debug
resh ssh://alice@192.0.2.10.exec command='rm -rf /srv/cache/*' dry_run=true
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `command`            | (required) | Command text (`ssh.command_required` when missing or blank). |
| `command_args`       | (none)  | Extra arguments, **split on commas** (each trimmed; empty items dropped). An argument cannot contain a comma. |
| `shell_mode`         | `none`  | `none`, `sh`, `bash`, `cmd`, `powershell`. |
| `env`                | (none)  | `NAME=value,NAME2=value2`. Names are letters, digits and `_`. The variables are exported **on the remote host** before the command runs. |
| `cwd`                | (none)  | Remote working directory. |
| `allocate_pty`       | `false` | Forces a remote pseudo-terminal (`ssh -tt`); stdout and stderr are then merged by the remote side. |
| `command_timeout_ms` | `60000` | Stops the command after this long (exit 124); 0 means no limit. |
| `max_output_bytes`   | `1048576` | Per stream; further output is read and discarded (`output_truncated: true`). |
| `trim_trailing_newlines` | `true` | Removes trailing `\n`/`\r\n` only (other whitespace stays). |
| `capture_output`     | `true`  | `false` omits stdout and stderr from the report. |
| `output_encoding`    | `utf8`  | `utf8` (invalid bytes replaced) or `base64` (of the raw bytes). |
| connection options, `timeout_ms`, `dry_run`, `format` | | See section 3. |

The remote command's stdin is empty (end of file).

**How the remote command is built.** ssh sends one command string to the
remote user's login shell, which parses it again. `command` is a command
line and is sent **as written**: treat it as code. `command_args` are
arguments, and each one reaches the remote program as exactly one argument:

* `shell_mode=none`: `[export NAME='value' ... && ][cd '<cwd>' && ]command
  args...`, each `command_args` element single-quoted unless it consists only
  of letters, digits and `_ @ % + : , . / -`.
* `shell_mode=sh` or `bash`: the same script, single-quoted as a whole for
  `sh -c`/`bash -c`.
* The quoting relies only on POSIX single-quote rules (tested against sh,
  bash and dash). It is **not** guaranteed for a login shell that is fish,
  csh or tcsh; do not pass untrusted arguments to such accounts.
* `shell_mode=cmd` and `powershell` (Windows OpenSSH): every
  `command_args` element, `cwd` and `env` value may only contain letters,
  digits and `_ . : / \ + @ -`. Anything else is refused with
  `ssh.command_refused` (exit 2) and ssh is not run; put the complete command
  line in `command` instead. `env` becomes `set NAME=value&&` (cmd) or
  `$env:NAME='value';` (PowerShell).
* A line break or other control character in `command_args`, `cwd` or an
  `env` value is refused (`ssh.command_refused`) in every mode.

`command.raw` in the report is the command line above. In the POSIX modes
resh puts `printf 'RESH-PID:%s\n' $$ >&2;` in front of it on the wire: sshd
starts every session in its own process group, and this tells resh which
one. When the command times out or resh is interrupted, resh closes its ssh
and then stops that remote process group (`kill -s TERM`, then `KILL`) over
a second connection, and says so in `warnings`. The marker line is removed
from the reported stderr. The cmd and PowerShell modes cannot be stopped
this way; a warning says the command may still be running.

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

Exit status and error codes:

* Remote exit code 0: `ok: true`, exit 0.
* A non-zero remote exit code: `ok: false`, `ssh.remote_exit_nonzero`,
  **exit 1** (the remote code is in `result.exit_code` and
  `error.details.exit_code`). Until v1.0.6-beta resh exited with the remote
  code itself.
* ssh's own failure (exit status 255): `ssh.ssh_failed`, exit 1; a
  `warnings` entry says whether the connection, the login or the host key
  failed. (A remote command that exits 255 looks the same.)
* `ssh.exec_signaled` (the remote command was killed by a signal) and
  `ssh.exec_no_exit_code`: exit 1.
* `ssh.exec_timeout`: `command_timeout_ms` or `timeout_ms` passed, exit 124;
  `result` is omitted because resh cannot tell how much of the command ran.
* `ssh.interrupted`: SIGINT or SIGTERM, exit 124.
* `ssh.tool_not_found` (ssh or sshpass missing): exit 1, `result` omitted.

In an error envelope, `dry_run` is the mode the request asked for. A request
refused before ssh starts reports `result.executed: false` and omits
`command`; the refusal names the offending field, not its value.

### upload

```bash
resh ssh://alice@web01.upload source=app.conf dest=/srv/app/app.conf dry_run=true
resh ssh://alice@web01.upload source=app.conf dest=/srv/app/app.conf overwrite=true file_mode=0640 verify_checksum=true
resh ssh://alice@web01.upload source_mode=inline source='hello world' dest=/tmp/hello.txt
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `source`             | (required) | Local path (a `file://` prefix is removed), or the data itself with `source_mode=inline` (may be empty). |
| `source_mode`        | `file`  | `file` or `inline`. |
| `source_encoding`    | `utf8`  | `utf8` or `base64`; only with `source_mode=inline`. |
| `dest`               | (required) | Remote file path, not ending in `/` and not starting with `-`; a leading `~/` or `~user/` is expanded by the remote shell. |
| `overwrite`          | `false` | Without it an existing `dest` is refused (`ssh.upload_dest_exists`), also when it appears during the upload. |
| `atomic`             | `true`  | Writes `<dest>.resh.tmp.<n>` (created with noclobber), checks its size (and checksum), then renames it over `dest`. |
| `mkdir_parents`      | `true`  | `false` fails when the directory is missing (`ssh.upload_remote_dir_missing`). |
| `file_mode`          | (none)  | Four octal digits starting with 0, such as `0644`, applied with `chmod`. Without it a new file gets the remote umask. |
| `preserve_times`     | `false` | Copies the local file's modification time (`source_mode=file` only). |
| `mtime_epoch_ms`     | (none)  | Sets the modification time (whole seconds). Not together with `preserve_times`. |
| `max_size_bytes`     | `104857600` | Larger sources are refused (`ssh.upload_too_large`). |
| `verify_checksum`    | `false` | The remote checksum of the written file must equal the local one before it is installed (atomic) (`ssh.upload_checksum_mismatch`). |
| `checksum_algorithm` | `sha256` | `sha256`, `sha1`, `md5`. |
| `transfer_timeout_ms`| `600000` | Stops the transfer after this long (exit 124); 0 means no limit. |
| connection options, `timeout_ms`, `dry_run`, `format` | | See section 3. |

A symlink at `dest` is replaced, never written through. A `dest` that is a
directory is refused (`ssh.upload_dest_is_directory`). If the connection
drops part-way, the remote side sees fewer bytes than were sent and removes
its temporary file; with `atomic=true` nothing is installed at `dest`
(`ssh.upload_timeout` or `ssh.upload_remote_write_failed`). With
`atomic=false` the data is written to `dest` directly and a failed transfer
can leave a partial file there.

Other codes: `ssh.upload_source_missing`, `ssh.upload_dest_missing`
(exit 2), `ssh.upload_source_not_found`, `ssh.upload_source_read_error`
(exit 1), `ssh.upload_invalid_source_encoding` (exit 2),
`ssh.upload_remote_write_failed` (exit 1).

### download

```bash
resh ssh://alice@web01.download source=/etc/hosts dest=hosts dry_run=true
resh ssh://alice@web01.download source=/var/log/app.log dest=./app.log overwrite=true
resh ssh://alice@web01.download source=/etc/os-release dest_mode=none
```

| Argument             | Default | Notes |
| -------------------- | ------- | ----- |
| `source`             | (required) | Remote path. |
| `dest`               | (required with `dest_mode=file`) | Local path. Refused with `dest_mode=none`. |
| `dest_mode`          | `file`  | `none` returns the content only (`overwrite` and `mkdir_parents` are then refused). |
| `return_content`     | `true`  | Include the content in the report. |
| `return_encoding`    | `utf8`  | `utf8` (content that is not valid UTF-8 fails with `ssh.download_invalid_utf8`) or `base64`. |
| `overwrite`          | `false` | An existing `dest` is replaced only with `true` (`ssh.download_dest_exists`). |
| `mkdir_parents`      | `true`  | Create local parent directories (`ssh.download_local_dir_missing`). |
| `max_size_bytes`     | `104857600` | ssh is stopped as soon as more arrives (`ssh.download_too_large`). |
| `verify_checksum`, `checksum_algorithm` | `false`, `sha256` | The remote checksum is computed in the same connection right after the read (`ssh.download_checksum_mismatch`). |
| `transfer_timeout_ms`| `600000` | `ssh.download_timeout`, exit 124. |
| connection options, `timeout_ms`, `dry_run`, `format` | | See section 3. |

The local `dest` is checked before connecting and written last: the data
goes to a new mode-0600 temporary file next to it (an existing file's
permission bits are kept), which is renamed over `dest` (with
`overwrite=true`) or hard-linked to it (without, so a file that appeared
meanwhile is not replaced). A symlink at `dest` is replaced, never written
through. `dest` is left untouched when the transfer, the size limit or the
checksum check fails. A remote directory gives
`ssh.download_source_is_directory`, a missing file
`ssh.download_source_not_found`, other remote errors
`ssh.download_remote_read_failed`, local write errors (including a `dest`
that is a directory) `ssh.download_local_write_failed`.

### test

```bash
resh ssh://alice@192.0.2.10.test
resh ssh://alice@192.0.2.10.test tests=connect,auth,exec exec_command=uptime
resh ssh://alice@192.0.2.10.test tests=hostkey,sftp known_hosts_path=./known_hosts
```

| Argument            | Default | Notes |
| ------------------- | ------- | ----- |
| `tests`             | `connect,auth` | Any of `connect`, `auth`, `exec`, `sftp`, `hostkey`, in the order given (duplicates ignored). An unknown name is refused (`ssh.test_invalid_test_name`, exit 2). |
| `exec_command`      | `echo ok` | Command for the `exec` check; must exit 0. Only with `exec` in `tests`. |
| `handshake_timeout_ms`| `10000` | Limit of the `connect` and `hostkey` checks (plus `connect_timeout_ms`). |
| `auth_timeout_ms`   | `10000` | Limit of the `auth` check (plus `connect_timeout_ms`). |
| `sftp_timeout_ms`   | `10000` | Limit of the `sftp` check (plus `connect_timeout_ms`). |
| `exec_timeout_ms`   | `10000` | Limit of the `exec` check (plus `connect_timeout_ms`). |
| `overall_timeout_ms`| `15000` | Deadline of the whole verb (0 = none); with `timeout_ms` the earlier one applies. Running checks are stopped and the rest skipped; exit 124 (`ssh.test_overall_timeout`). |
| `allow_insecure_hostkey` | `false` | Required with `known_hosts_mode=insecure` (`ssh.test_insecure_hostkey_forbidden`); refused otherwise. |
| connection options, `timeout_ms`, `dry_run`, `format` | | See section 3. |

The checks, each over its own ssh connection:

* `connect`: the server is reachable and its host key is accepted (a
  refused login still passes). Failures: `ssh.test_connect_failed`,
  `ssh.test_hostkey_failed`.
* `auth`: a login with the given credentials works (`ssh.test_auth_failed`).
* `exec`: `exec_command` exits 0 (`ssh.test_exec_failed`; details give the
  exit status).
* `sftp`: the SFTP subsystem answers an SFTP version handshake
  (`ssh.test_sftp_failed`; details give the protocol version).
* `hostkey`: `ssh -v` without authentication; reports the server's host key
  type and fingerprint (also in `security.hostkey_algorithm` and
  `hostkey_fingerprint`) and whether it matched known_hosts (`matched`),
  was added (`accept-new`), or was not checked (`insecure`). An unknown key
  in `strict` mode or a changed key fails (`ssh.test_hostkey_failed`).

`auth` is skipped when a requested `connect` check failed; `exec` and
`sftp` when a requested `connect` or `auth` check failed
(`ssh.test_dependency_failed`). A check that runs out of time fails with
`ssh.test_check_timeout`. The verb exits 0 when every check passed, 1 when
any failed (`ssh.test_failed`), 124 on the overall deadline.

### config.get

```bash
resh --json-pretty ssh://web01.config.get
resh ssh://web01.config.get user_config_path=./ssh_config system_config_path=/dev/null include_raw_entries=false
```

Reports the settings that apply to a host: the URL host, or `host=` (a
different value from the URL host is `ssh.target_conflict`). The URL user,
if any, is used for `Match user`; a URL port or password is refused (exit
2). No connection is made and `timeout_ms` is refused.

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `host` | URL host | |
| `user_config_path` | `~/.ssh/config` | |
| `system_config_path` | `/etc/ssh/ssh_config` | |
| `extra_config_paths` | (none) | Comma-separated, read after the other two. |
| `follow_includes` | `true` | Follow `Include` (globs; relative paths are under `~/.ssh`, or `/etc/ssh` for the system file). |
| `include_raw_entries` | `true` | Add every parsed entry. |
| `include_origin` | `true` | Add file, line and block of each setting. |
| `user_home` | `$HOME` | Used for `~`. |
| `max_config_bytes` | `1048576` | `ssh.config_get_too_large`. |
| `max_includes` | `64` | `ssh.config_get_too_many_includes`. |
| `max_hosts` | `1024` | Host and Match blocks, `ssh.config_get_too_many_hosts`. |
| `dry_run`, `format` | | |

The files are read in OpenSSH's order (user file, then system file, then
extra files) and **the first value obtained for an option wins**, as in
ssh; options that may be repeated (`IdentityFile`, `CertificateFile`,
`LocalForward`, `RemoteForward`, `DynamicForward`, `SendEnv`) keep every
value, joined by newlines. `Host` patterns use `*`, `?` and `!` negation;
keywords are case-insensitive and may be written `Key value` or `Key=value`.
`Match` blocks with `all`, `host`, `originalhost`, `user`, `localuser`,
`canonical` (never true: resh does not canonicalize) and `final` are
evaluated; a `Match` with any other criterion (`exec`, `localnetwork`,
`tagged`, ...) is skipped with a warning. A default file that does not
exist is skipped; a file given explicitly that cannot be read fails
(`ssh.config_get_read_failed`, exit 1). `summary.matched_blocks` lists the
matching Host/Match lines. `ssh -G host` shows what ssh really uses.

### keys.list

```bash
resh ssh://alice@192.0.2.10.keys.list
resh ssh://root@192.0.2.10.keys.list scope=host
resh ssh://alice@192.0.2.10.keys.list scope=custom custom_paths=/etc/ssh/ca.pub key_types=ed25519
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `scope` | `authorized` | `authorized`, `host` or `custom`. |
| `authorized_user` | URL user | `scope=authorized`: reads `~<user>/.ssh/authorized_keys` and `authorized_keys2`. Not with `authorized_paths`. |
| `authorized_paths` | | `scope=authorized`: these files instead. |
| `host_key_paths` | `/etc/ssh/ssh_host_{rsa,ecdsa,ed25519,dsa}_key.pub` | `scope=host`. |
| `custom_paths` | (required) | `scope=custom` (`ssh.keys_list_custom_paths_required`). |
| `key_types` | all | Comma-separated subset of `rsa`, `ecdsa`, `ed25519`, `dsa` (security-key types count as ecdsa/ed25519). |
| `fingerprint_algorithm` | `sha256` | `sha256` (`SHA256:...`) or `md5` (`MD5:aa:bb:...`), as `ssh-keygen -l`. |
| `include_options` | `true` | authorized_keys options of each key. |
| `include_raw_key` | `true` | `type base64` of each key. |
| `max_keys` | `1024` | Further matching keys are counted but not listed (`truncated: true`). |
| `max_bytes` | `1048576` | Per file; a larger file fails (`ssh.keys_list_too_large`). |
| `read_timeout_ms` | `10000` | `ssh.keys_list_timeout`, exit 124. |
| connection options, `timeout_ms`, `dry_run`, `format` | | |

Options of another scope are refused. All files are read in one ssh run;
the report gives each file's path as the remote shell expanded it, whether
it exists and is readable, its size, every key (type, bits, fingerprint,
comment, options, index, line) and the lines that are not valid keys
(`parse_errors`; a key whose data does not match its type is invalid). A
missing file is not an error. A file that exists but cannot be read makes
the verb fail with `ssh.keys_list_remote_read_failed` (exit 1, the other
files are still reported). With `dry_run=true`, `planned_files` lists the
paths as written (for example `~alice/.ssh/authorized_keys`).

### key.add

```bash
resh ssh://bob@web01.key.add public_key_path=./id_ed25519.pub
resh ssh://root@web01.key.add authorized_user=deploy public_key='ssh-ed25519 AAAA... ci@build' on_duplicate=replace
resh ssh://bob@web01.key.add scope=custom custom_paths=/etc/ssh/keys/bob public_key_path=id.pub dry_run=true
```

| Argument | Default | Notes |
| -------- | ------- | ----- |
| `public_key` | | One public key line (options before the type are kept). |
| `public_key_path` | | Local file with exactly one key line. Not together with `public_key`. |
| `public_key_source` | from the above | `inline` (needs `public_key`) or `file` (needs `public_key_path`). |
| `scope` | `authorized` | `authorized` or `custom`. |
| `authorized_user` | URL user | `scope=authorized`: changes `~<user>/.ssh/authorized_keys`. |
| `authorized_paths` | | `scope=authorized`: exactly one file instead. |
| `custom_paths` | (required) | `scope=custom`: exactly one file (`ssh.key_add_custom_paths_required`). |
| `on_duplicate` | `skip` | When a line with the same key exists: `skip` (status `already_present`, nothing written), `error` (`ssh.key_add_duplicate`, exit 1), `replace` (those lines are removed and the new line appended; status `replaced`). |
| `create_if_missing` | `true` | Create the file (and its directory, with `dir_mode`); `false` fails with `ssh.key_add_target_missing`. |
| `backup_existing` | `true` | Copy the old file to `<file><backup_suffix>` first (`ssh.key_add_backup_failed`). |
| `backup_suffix` | `.bak` | Must not contain `/`. |
| `ensure_permissions` | `true` | Set `file_mode` on the file and `dir_mode` on its directory even when they exist; with `false` an existing file keeps its mode. |
| `file_mode`, `dir_mode` | `0600`, `0700` | Four octal digits starting with 0. |
| `max_file_bytes` | `1048576` | A larger existing file is refused (`ssh.key_add_file_too_large`). |
| `read_timeout_ms`, `write_timeout_ms` | `10000` | `ssh.key_add_timeout`, exit 124. |
| connection options, `timeout_ms`, `dry_run`, `format` | | |

The key is validated locally first: its base64 data must decode and name
the same key type as the line (`ssh.key_add_invalid_public_key`, exit 2); a
private key or a file with several keys is refused; a missing local file is
`ssh.key_add_public_key_file_not_found` (`..._read_failed` for other read
errors). Then two ssh runs: the first reads the target file (its expanded
path, size, `cksum`, owner and mode); resh computes the new content; the
second checks that `cksum` is unchanged (otherwise
`ssh.key_add_concurrent_change` and nothing is written), makes the backup,
writes a private temporary file in the same directory, sets its mode (and,
when connected as root, the owner of the old file or of `authorized_user`)
and renames it over the target, so the file is never half-written. A
symlink at the target is refused (`ssh.key_add_target_is_symlink`), not
followed. Other failures: `ssh.key_add_remote_read_failed`,
`ssh.key_add_remote_write_failed`, `ssh.key_add_permissions_failed`.
`operation` reports `status` (`added`, `already_present`, `replaced` or
`dry_run`), `duplicates_found`, `created_file`, `backup_created` and
`backup_file`. A dry run makes no connection and reports the target as
written (`~bob/.ssh/authorized_keys`).

### tunnel

```bash
resh ssh://alice@bastion.tunnel mode=local local_bind_port=5433 remote_dest_host=db.internal remote_dest_port=5432
resh ssh://alice@bastion.tunnel mode=dynamic local_bind_port=1080 idle_timeout_ms=0
resh ssh://alice@web01.tunnel mode=remote remote_bind_port=8080 local_dest_host=127.0.0.1 local_dest_port=3000 tunnel_timeout_ms=3600000
```

| Argument | Default | Modes | Notes |
| -------- | ------- | ----- | ----- |
| `mode` | (required) | | `local`, `remote` or `dynamic` (`ssh.tunnel_mode_required`). |
| `local_bind_host`, `local_bind_port` | `127.0.0.1`, `0` | local, dynamic | Where resh listens; port 0 picks a free port (reported). |
| `remote_dest_host`, `remote_dest_port` | (required) | local | `ssh.tunnel_missing_remote_dest`. |
| `remote_bind_host`, `remote_bind_port` | `127.0.0.1`, `0` | remote | Where the server listens; port 0 lets the server pick (reported). Non-loopback addresses need `GatewayPorts` on the server. |
| `local_dest_host`, `local_dest_port` | (required) | remote | `ssh.tunnel_missing_local_dest`. |
| `socks_version` | `socks5` | dynamic | Connections that do not start with this SOCKS version are refused. |
| `allow_wildcard_binds` | `false` | | Required for `0.0.0.0`, `::` or `*` as bind address (`ssh.tunnel_wildcard_bind_forbidden`); refused otherwise. |
| `tunnel_timeout_ms` | (none) | | Close after this long (`closed_reason: tunnel_timeout`). |
| `idle_timeout_ms` | `300000` | | Close after this long with no open connection and no traffic (`idle_timeout`); 0 means never. |
| `max_connections` | (none) | | Accept this many connections, refuse further ones, close when they are done (`max_connections`). |
| `max_bytes_in`, `max_bytes_out` | (none) | | Close when this many bytes went from clients to the destination (`in`) or back (`out`); the data is cut at the limit (`max_bytes_in`/`max_bytes_out`). |
| connection options, `timeout_ms`, `dry_run`, `format` | | | Options of another mode are refused. |

resh accepts the connections itself and relays them to ssh's forward (a
Unix socket in a private 0700 directory for `local` and `remote`, a
loopback port for the SOCKS proxy of `dynamic`), so it can count them and
enforce the limits. ssh runs with `-N -o ExitOnForwardFailure=yes`, so the
remote account needs no shell. The verb runs in the foreground:

1. When the forward is up it prints one line, `{"event":"ready","mode":
   ...,"listen":"127.0.0.1:5433","forward_to":"db.internal:5432"}` (text:
   `Tunnel ready: listening on ..., forwarding to ...`), and flushes it.
2. When the tunnel closes it prints the report: `tunnel` (with the actual
   ports), `lifetime` (with `closed_reason`) and `stats`
   (`connections_accepted`, `bytes_in`, `bytes_out`, `uptime_ms`).

`closed_reason` `tunnel_timeout`, `idle_timeout`, `max_connections`,
`max_bytes_in`, `max_bytes_out` and `interrupted` (SIGINT/SIGTERM, the
normal way to stop an open-ended tunnel) are a normal end: `ok: true`, exit
0. `timeout_ms` passing gives `ssh.tunnel_timeout`, exit 124. Failures
(exit 1): `ssh.tunnel_bind_failed` (resh cannot listen on the local
address), `ssh.tunnel_forward_failed` (ssh could not set up the forward, for
example the remote port is in use), `ssh.connect_failed`,
`ssh.auth_failed`, `ssh.hostkey_verification_failed` (before the forward was
up), `ssh.tunnel_closed` (the ssh connection ended while forwarding; the
report has the stats so far). With `dry_run=true` the plan is reported and
nothing listens.

## 5. Error codes

Shared by several verbs:

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `ssh.invalid_argument` | 2 | Unknown argument, bad value, or an option that does not apply. |
| `ssh.unknown_verb` | 2 | Not an ssh verb. |
| `ssh.target_conflict` | 2 | URL and argument disagree. |
| `ssh.host_required` | 2 | No host. |
| `ssh.username_required` | 2 | No user for test, tunnel, keys.list, key.add. |
| `ssh.auth_missing_password` | 2 | `auth_method=password` without a password. |
| `ssh.identity_invalid` | 2 | `identity_data` is not a private key. |
| `ssh.identity_not_found` | 1 | `identity_path` is not a readable file. |
| `ssh.agent_unavailable` | 1 | No agent socket for `auth_method=agent`. |
| `ssh.tool_not_found` | 1 | `ssh` or `sshpass` is not installed. |
| `ssh.connect_failed` | 1 | ssh could not connect. |
| `ssh.auth_failed` | 1 | The login was refused. |
| `ssh.hostkey_verification_failed` | 1 | The host key is unknown (strict) or changed. |
| `ssh.io_error` | 1 | A local I/O error. |
| `ssh.interrupted` | 124 | SIGINT or SIGTERM while ssh ran. |

Verb codes are listed in each verb's section: exec (`ssh.command_required`,
`ssh.command_refused`, `ssh.remote_exit_nonzero`, `ssh.ssh_failed`,
`ssh.exec_signaled`, `ssh.exec_no_exit_code`, `ssh.exec_timeout`), upload
(`ssh.upload_source_missing`, `ssh.upload_source_not_found`,
`ssh.upload_source_read_error`, `ssh.upload_invalid_source_encoding`,
`ssh.upload_too_large`, `ssh.upload_dest_missing`,
`ssh.upload_dest_exists`, `ssh.upload_dest_is_directory`,
`ssh.upload_remote_dir_missing`, `ssh.upload_remote_write_failed`,
`ssh.upload_timeout`, `ssh.upload_checksum_mismatch`), download
(`ssh.download_source_missing`, `ssh.download_source_not_found`,
`ssh.download_source_is_directory`, `ssh.download_remote_read_failed`,
`ssh.download_too_large`, `ssh.download_dest_missing`,
`ssh.download_dest_exists`, `ssh.download_local_dir_missing`,
`ssh.download_local_write_failed`, `ssh.download_invalid_utf8`,
`ssh.download_timeout`, `ssh.download_checksum_mismatch`), tunnel
(`ssh.tunnel_mode_required`, `ssh.tunnel_missing_remote_dest`,
`ssh.tunnel_missing_local_dest`, `ssh.tunnel_wildcard_bind_forbidden`,
`ssh.tunnel_bind_failed`, `ssh.tunnel_forward_failed`,
`ssh.tunnel_closed`, `ssh.tunnel_timeout`), keys.list
(`ssh.keys_list_custom_paths_required`, `ssh.keys_list_remote_read_failed`,
`ssh.keys_list_too_large`, `ssh.keys_list_timeout`), key.add
(`ssh.key_add_missing_public_key`, `ssh.key_add_invalid_public_key`,
`ssh.key_add_custom_paths_required`, `ssh.key_add_target_missing`,
`ssh.key_add_target_is_symlink`, `ssh.key_add_file_too_large`,
`ssh.key_add_remote_read_failed`, `ssh.key_add_remote_write_failed`,
`ssh.key_add_backup_failed`, `ssh.key_add_permissions_failed`,
`ssh.key_add_duplicate`, `ssh.key_add_concurrent_change`,
`ssh.key_add_public_key_file_not_found`,
`ssh.key_add_public_key_file_read_failed`, `ssh.key_add_timeout`),
config.get (`ssh.config_get_host_required`, `ssh.config_get_read_failed`,
`ssh.config_get_too_large`, `ssh.config_get_too_many_includes`,
`ssh.config_get_too_many_hosts`) and test (`ssh.test_invalid_test_name`,
`ssh.test_insecure_hostkey_forbidden`, `ssh.test_connect_failed`,
`ssh.test_auth_failed`, `ssh.test_sftp_failed`, `ssh.test_exec_failed`,
`ssh.test_hostkey_failed`, `ssh.test_dependency_failed`,
`ssh.test_check_timeout`, `ssh.test_overall_timeout`, `ssh.test_failed`).
Codes ending in `_timeout` (other than `ssh.test_check_timeout`, a failed
check) exit 124; the `_missing`/`_required`/`invalid` usage codes listed as
exit 2 above exit 2; every other code exits 1.

## 6. Security notes

* Prefer key or agent authentication. Passwords in the URL or as
  arguments are visible to other local users through the process list of
  `resh` (never of `ssh`).
* Keep `known_hosts_mode=strict` (the default) for production hosts.
* Treat `command`, `command_args`, `cwd`, `env` and `shell_mode` as code:
  see the quoting rules under `exec`.
* `identity_data` and passphrases are written only to a private temporary
  directory that is removed after the run.
