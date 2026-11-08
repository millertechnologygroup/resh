# Resource Shell (resh) – User Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `user://` handle creates, deletes, and inspects local Linux user accounts, groups, and group memberships, changes passwords, and locks or unlocks accounts.

### How it works

* The default **system** backend reads the account database through NSS (`getpwnam`, `getgrnam`, `getgrouplist`) and the shadow file, and makes changes by running `useradd`, `groupadd`, `usermod`, `userdel`, `groupdel`, `gpasswd`, or `chpasswd`. Every change needs root: without it the verb fails with `user.permission_denied` before running anything.
* Every shadow-utils command gets the user and group names as operands after `--`, so no name can be read as an option. Commands run without a shell.
* Passwords are hashed by resh and the hash is written to `chpasswd -e` on standard input. No password or hash is ever put on a command line, in the output, or in an error message.
* `dry_run=true` runs no changing command; the planned commands are reported in `planned_commands` (standard input shown as `<<< (redacted)`).
* `backend=mock` uses an empty in-memory store that exists only for the life of the one `resh` process. It is useful for checking argument handling, not for persisting anything.
* `backend=file` and `backend=ldap` are accepted names but are refused with `user.backend_not_supported` (exit 2).

Each verb prints one JSON object (pretty-printed) on stdout, or text with `format=text`.

---

## 2. Command Syntax

```text
resh user://<name>.<verb> [key=value ...]
```

Targets:

| Target form                 | Meaning                          |
| --------------------------- | -------------------------------- |
| `user://alice`              | User `alice`                     |
| `user://group/admins`       | Group `admins` (for `mode=group`) |
| `user://membership/alice`   | Memberships of `alice` (for `mode=membership`) |

The three-slash forms (`user:///alice`) also work. The name can instead be passed as `username=`, `group_name=`, or `member=`; when both the target and the argument name something, they must agree. A target that does not fit the verb or mode (for example `user://group/dev.lock`, `user://alice.add mode=group`, or `user://alice/extra`) is refused with `user.invalid_target` (exit 2).

Built-in help:

```bash
resh user --help
resh user add --help
resh help user passwd
```

---

## 3. Verbs

| Verb     | Purpose                                                         | Changes the system | `timeout_ms` |
| -------- | --------------------------------------------------------------- | ------------------ | ------------ |
| `exists` | Report whether a user exists (by username and/or `uid`)          | No                 | refused      |
| `groups` | List a user's groups, marked primary / supplementary / system   | No                 | refused      |
| `add`    | Create a user, a group, or memberships (`mode=user\|group\|membership`, default `user`) | Yes | default 60000 |
| `delete` | Remove a user, a group, or memberships (same `mode` values)      | Yes                | default 60000 |
| `passwd` | Set a password                                                   | Yes                | default 60000 |
| `lock`   | Lock an account (`usermod -L`)                                   | Yes                | default 60000 |
| `unlock` | Unlock an account (`usermod -U`)                                 | Yes                | default 60000 |

Every verb accepts `backend=system|mock` and `format=json|text`.

### exists

```bash
resh user://alice.exists
resh user://alice.exists uid=1001
resh user://.exists uid=1001
```

Options: `username=`, `uid=<n>`. A missing user is **not** a failure: the command exits 0 with `"ok": true`, `"exists": false`, and a warning. Test the `user.exists` field. With only `uid=`, the account with that UID is looked up. If both a name and `uid=` are given and the user exists with a different UID, the command fails with `user.exists_mismatch`.

```json
{
  "ok": true,
  "backend": "system",
  "query": { "username": "nosuch", "uid": null },
  "user": { "exists": false, "username": null, "uid": null },
  "warnings": ["User nosuch does not exist in backend system."]
}
```

### groups

```bash
resh user://alice.groups include_system_groups=false
```

Options: `username=`, `include_primary`, `include_supplementary`, `include_system_groups` (all default `true`), `min_gid_for_system=<n>` (default 1000; a group below it is a system group), `group_name_filter=<group>` (exact name), `ignore_if_missing` (default `true`: a missing user is reported with `"missing": true`). The primary group is listed first, then the supplementary groups from `getgrouplist`.

### add

```bash
resh user://alice.add shell=/bin/zsh dry_run=true
resh user://alice.add supplementary_groups=dev,docker
resh user://group/dev.add mode=group
resh user://membership/alice.add mode=membership groups=dev,docker
```

`mode=user` options:

| Option                    | Meaning                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `username=`               | The user (instead of the target)                                     |
| `uid=<n>`                 | UID. Must be 1000-65533, or 0-65533 with `force=true`. A UID already in use is `user.uid_conflict`. Default: the first free UID from 1000. |
| `primary_group=<group>`   | Primary group (default: a group named after the user). A missing group is created with `groupadd`; its GID is the UID when that is free, otherwise the first free GID from 1000. |
| `supplementary_groups=<g1,g2>` (or `groups=`) | Extra groups, passed to `useradd -G`. Each must already exist; checked before anything changes. |
| `home=<path>`             | Home directory, an absolute path (default `/home/<user>`)              |
| `create_home`             | Default `true` (`useradd -m`); `false` uses `useradd -M`. An existing directory is kept (a warning says so). |
| `shell=<path>`            | Login shell, an absolute path (default `/bin/bash`)                    |
| `gecos=<text>`            | Comment field (no `:` or control characters)                          |
| `password_hash=<hash>`    | A precomputed crypt hash (see `passwd`), stored with `chpasswd -e` after the account is created; the result has `"password_set": true`. |
| `ignore_if_exists`        | Default `true`: an existing user is reported with `"existed": true`, its real UID, primary group, groups, home, shell and comment, and nothing changes. `false` makes it `user.username_conflict`. |

`mode=group` options: `group_name=`, `gid=<n>` (same range rule as `uid`; a GID in use is `user.gid_conflict`), `ignore_if_exists` (`user.group_conflict` when `false`).

`mode=membership` options: `member=`, `groups=<g1,g2>` (required). The user and every group must exist (`user.not_found`, `user.group_not_found`). Groups the user already belongs to (including its primary group) are reported with `"already_member": true` and a warning, or refused with `user.membership_exists` when `ignore_if_exists=false`. The rest are added with one `usermod -a -G` command.

An option of another mode (for example `shell=` with `mode=group`) is refused (exit 2). `force` applies only to `mode=user` and `mode=group`.

Everything is checked before the first change. If `useradd` fails after `add` created the primary group, the group is removed again. If storing `password_hash` fails after the account was created, the verb fails with `user.partial_failure` and the account stays.

### delete

```bash
resh user://alice.delete remove_home=true dry_run=true
resh user://group/dev.delete mode=group
resh user://membership/alice.delete mode=membership groups=docker
```

`mode=user` options: `username=`, `remove_home` (default `false`; uses `userdel -r`, which also removes the mail spool), `remove_mail` (default `false`; `rm -f -- /var/mail/<user>` after `userdel`), `remove_from_all_groups` (default `true`; `userdel` always removes the account from every group, so `false` is refused), `protect_system_users` (default `true`), `min_uid_for_delete` (default 1000), `ignore_if_missing` (default `true`: a missing user is reported, not an error).

`remove_home=true` is refused (exit 2) when the home directory is not below a parent directory (for example `/` or `/root`), whatever `force` says.

The output reports the account's groups in `memberships`, and with `remove_home` / `remove_mail` the `home` and `mail` objects: `was_present` is checked on the filesystem before the change, `removed` after it. When `userdel` fails but the account is gone (for example the home directory could not be removed), the verb fails with `user.partial_failure`.

`mode=group` options: `group_name=`, `only_if_empty` (default `true`), `protect_system_groups` (default `true`), `min_gid_for_delete` (default 1000), `ignore_if_missing`. A group that is still some user's primary group is refused by `groupdel` (`user.backend_operation_failed`).

`mode=membership` options: `member=`, and `groups=<g1,g2>` or `all_groups=true` (not both). The user's primary group is not a removable membership: naming it is `user.primary_group_membership`, and `all_groups=true` leaves it alone. Every group is checked before the first `gpasswd -d`; with `ignore_if_missing=true` (the default) a missing group or a group the user is not in is reported with a warning, otherwise it is `user.group_not_found` / `user.membership_not_found`. If one removal fails after others succeeded, the verb fails with `user.partial_failure`.

### passwd

```bash
NEW_PW='S3cr3t' resh user://alice.passwd new_password_env=NEW_PW
printf '%s\n' "$pw" | resh user://alice.passwd new_password_stdin=true
resh user://alice.passwd new_password_hash='$6$...'
resh user://alice.passwd new_password_plain=S3cr3t dry_run=true
```

Exactly one new-password source is required (`user.passwd_missing_new_password`, `user.passwd_conflicting_sources`):

| Source                     | Meaning |
| -------------------------- | ------- |
| `new_password_env=<VAR>`   | Read from the environment variable `VAR` (`"source": "env"`) |
| `new_password_stdin=true`  | Read all of standard input; one trailing newline is dropped (`"source": "stdin"`) |
| `new_password_plain=<pw>`  | Given inline (`"source": "plain"`). **It is visible in the process list and shell history**; prefer the two above. |
| `new_password_hash=<hash>` | A precomputed crypt hash (`"source": "hash"`) |

A plaintext password must not be empty or contain a line break or NUL. It is hashed with `hash_scheme`:

| `hash_scheme`     | Hash                                   | system backend | mock backend |
| ----------------- | -------------------------------------- | -------------- | ------------ |
| `backend_default` | same as `sha512_crypt`                 | yes            | yes          |
| `sha512_crypt`    | `$6$` SHA-512 crypt, 16-character random salt, 5000 rounds | yes | yes |
| `bcrypt`          | `$2b$` bcrypt, cost 12 (passwords over 72 bytes are refused) | yes | yes |
| `argon2id`        | `$argon2id$` PHC string                | refused: `user.hash_scheme_unsupported` (exit 2), because the system `crypt()` library and PAM cannot verify it | yes |

`new_password_hash` must be a well-formed `$6$` (sha512_crypt), `$5$` (sha256_crypt), `$2a$`/`$2b$`/`$2y$` (bcrypt), `$y$` (yescrypt) or `$argon2id$` hash (otherwise `user.hash_params_invalid`). `hash_scheme`, if also given, must match it.

The system backend writes `<user>:<hash>` to `chpasswd -e` on standard input, then reads the shadow entry back (when it can) and fails with `user.passwd_backend_failure` if it does not hold the new hash.

`require_old_password=true` with `old_password_plain=` or `old_password_env=<VAR>` checks the current password first. The system backend reads `/etc/shadow` for it (root only). sha512_crypt, sha256_crypt, bcrypt and argon2 hashes can be checked (a `!` lock prefix is ignored); yescrypt, MD5 and DES hashes give `user.old_password_verification_unsupported`. A wrong password is `user.old_password_mismatch`. An old password without `require_old_password=true` is refused (exit 2).

Other options: `username=`, `ignore_if_missing` (default `true`). `passwd` has no system-account protection and refuses `force`.

### lock / unlock

```bash
resh user://alice.lock
resh user://alice.unlock dry_run=true
```

Options: `username=`, `protect_system_users` (default `true`), `min_uid_for_lock` / `min_uid_for_unlock` (default 1000), `force`, `ignore_if_missing`. The current lock state comes from `/etc/shadow` or `passwd -S`; if neither can be read the verb fails (a dry run reports `was_locked: null` with a warning). After the change the state is read again and the verb fails (`user.lock_backend_failure` / `user.unlock_backend_failure`) if it did not change. Locking an already locked account, or unlocking an already unlocked one, succeeds with `"changed": false`. An account without a password (a new account before `passwd`) cannot be unlocked: `usermod -U` refuses, because that would leave it without a password.

---

## 4. Safety Controls

### Strict arguments

Every verb refuses (exit 2, nothing done) an argument it does not accept, naming it and suggesting a likely intended name (`did you mean`), an option of another mode, and any invalid value: booleans accept only `true/false`, `1/0`, `yes/no`, `on/off` (any case; a bare `dry_run` word means `true`); numbers must be whole numbers in range; `format` must be `json` or `text`; `timeout_ms` must be 1-86400000. `exists` and `groups` refuse `timeout_ms` and `dry_run`.

### dry_run

`dry_run` is accepted by `add`, `delete`, `passwd`, `lock`, and `unlock`. In a dry run no changing command is executed and the commands are listed in `planned_commands`. Lookups (does the user exist, which groups) and all checks (protection, conflicts) still run.

### timeout_ms

`add`, `delete`, `passwd`, `lock`, and `unlock` accept `timeout_ms` (default 60000). It bounds every tool the verb runs, together; at the deadline the tool's process group is stopped and the verb exits 124 (`user.timeout`): the change may be partly applied, so check before retrying.

### System-account protection and force

* `delete`, `lock`, and `unlock` refuse a user whose UID is below `min_uid_for_delete` / `min_uid_for_lock` / `min_uid_for_unlock` (default 1000). That includes `root` (UID 0). The error is `user.system_user_protected`; the check runs in dry runs too.
* `delete mode=group` refuses a group whose GID is below `min_gid_for_delete` (default 1000) (`user.group_system_protected`) and a group that still has members (`only_if_empty`, `user.group_not_empty`).
* **`force=true` overrides all of these protections**, and on `add` it also allows a UID/GID below 1000. The operation then proceeds with a warning. Use it only deliberately, never as a default in scripts.
* Setting `protect_system_users=false`, or lowering `min_uid_for_*`, also disables the user protection.

### Names

* A user name, and a group name that `add` creates (`mode=group`, or a missing `primary_group`), follows the shadow-utils rule: 1-32 characters of ASCII letters, digits, `_`, `-` and `.`, optionally ending in `$`; not starting with `-`; not `.`, `..` or all digits (`user.username_invalid`, `user.group_name_invalid`, exit 2). The tools may apply a stricter local rule (for example Debian's `NAME_REGEX`); their refusal is reported as `user.backend_operation_failed`.
* Names of existing groups (`primary_group`, `supplementary_groups`, `groups`, `group_name_filter`) must not start with `-` or contain `:`, `,`, `/`, spaces or control characters.
* `home` and `shell` must be absolute paths; `home`, `shell` and `gecos` must not contain `:` or control characters.

---

## 5. Output and Errors

Successful output is the verb's JSON object on stdout (see `resh user <verb> --help` for full examples). Example for `add` with `dry_run=true`:

```json
{
  "ok": true,
  "mode": "user",
  "backend": "system",
  "dry_run": true,
  "planned_commands": [
    "groupadd -g 1001 -- alice",
    "useradd -u 1001 -g alice -d /home/alice -m -s /bin/zsh -- alice"
  ],
  "user": {
    "username": "alice",
    "uid": 1001,
    "primary_group": "alice",
    "supplementary_groups": [],
    "home": "/home/alice",
    "shell": "/bin/zsh",
    "gecos": null,
    "created": false,
    "existed": false
  },
  "groups": [
    { "name": "alice", "gid": 1001, "created": false, "existed": false }
  ]
}
```

(Abbreviated field order; `planned_commands` is omitted when empty.)

A failure prints `Error: [<code>] <message>` on stderr. With `format=json` (the default) the JSON error object is also printed on stdout:

```json
{
  "error": {
    "code": "user.system_user_protected",
    "details": { "min_uid_for_delete": 1000, "uid": 0, "username": "root" },
    "message": "refusing to delete system user 'root' (uid=0) because protect_system_users=true and force=false"
  },
  "ok": false
}
```

### Exit codes

| Exit status | Meaning                                                    |
| ----------- | ---------------------------------------------------------- |
| 0           | Success (including `exists` for a missing user, and missing accounts with `ignore_if_missing=true`) |
| 1           | The operation failed or was refused (not found, conflict, protection, tool error, partial failure) |
| 2           | Invalid usage or arguments; nothing was done               |
| 124         | `timeout_ms` passed; the outcome is unknown                |

### Error codes

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `user.invalid_argument` | 2 | Unknown argument, invalid value, or conflicting options |
| `user.invalid_target` | 2 | The target does not fit the verb or mode |
| `user.invalid_mode` | 2 | `mode` is not `user`, `group` or `membership` |
| `user.backend_not_supported` | 2 | `backend=file` or `backend=ldap` |
| `user.username_required` | 2 | No user name |
| `user.group_name_required` | 2 | No group name (`mode=group`) |
| `user.member_required` | 2 | No member (`mode=membership`) |
| `user.groups_required` | 2 | No `groups=` (`mode=membership`) |
| `user.identity_required` | 2 | `exists` without a name or `uid=` |
| `user.username_invalid` | 2 | The user name breaks the name rule |
| `user.group_name_invalid` | 2 | A group name breaks the name rule |
| `user.uid_out_of_range` | 2 | `uid` outside 1000-65533 (0-65533 with `force`) |
| `user.gid_out_of_range` | 2 | `gid` outside 1000-65533 (0-65533 with `force`) |
| `user.passwd_conflicting_sources` | 2 | More than one new-password source |
| `user.passwd_missing_new_password` | 2 | No new-password source |
| `user.hash_scheme_unsupported` | 2 | `argon2id` on the system backend |
| `user.hash_params_invalid` | 2 | A malformed hash, or a password bcrypt would truncate |
| `user.old_password_required` | 2 | `require_old_password=true` without an old password |
| `user.username_conflict` | 1 | The user exists and `ignore_if_exists=false` |
| `user.group_conflict` | 1 | The group exists and `ignore_if_exists=false` |
| `user.uid_conflict` | 1 | `uid` is in use |
| `user.gid_conflict` | 1 | `gid` is in use |
| `user.no_free_id` | 1 | No free UID/GID from 1000 to 65533 |
| `user.group_not_found` | 1 | A named group does not exist |
| `user.membership_exists` | 1 | Already a member and `ignore_if_exists=false` |
| `user.not_found` | 1 | The user does not exist (and `ignore_if_missing=false`, or `mode=membership add`) |
| `user.system_user_protected` | 1 | A system account (`min_uid_for_*`) without `force` |
| `user.group_system_protected` | 1 | A system group (`min_gid_for_delete`) without `force` |
| `user.group_not_empty` | 1 | The group has members and `only_if_empty=true` |
| `user.membership_not_found` | 1 | Not a member and `ignore_if_missing=false` |
| `user.primary_group_membership` | 1 | Removing a user's primary group as a membership |
| `user.old_password_verification_unsupported` | 1 | The stored hash cannot be checked (yescrypt, MD5, DES) |
| `user.old_password_mismatch` | 1 | The old password is wrong |
| `user.passwd_backend_failure` | 1 | Storing the password failed, or reading the shadow entry for the old password failed |
| `user.lock_backend_failure` | 1 | Locking failed, or the account is still unlocked afterwards |
| `user.unlock_backend_failure` | 1 | Unlocking failed (for example no password), or the account is still locked |
| `user.groups_backend_failure` | 1 | Listing the groups failed |
| `user.exists_mismatch` | 1 | The user exists with another UID |
| `user.exists_backend_failure` | 1 | The lookup itself failed |
| `user.backend_operation_failed` | 1 | A tool exited with an error (its message is included), or a lookup failed |
| `user.permission_denied` | 1 | A change was asked for without root; nothing was run |
| `user.tool_not_found` | 1 | A shadow-utils tool is not installed |
| `user.partial_failure` | 1 | Part of the change was made (see the message) |
| `user.failed` | 1 | Any other handle error (for example stdout closed) |
| `user.timeout` | 124 | `timeout_ms` passed; outcome unknown |

---

## 6. Platform Support

Linux only. The system backend needs the shadow-utils tools (`useradd`, `usermod`, `userdel`, `groupadd`, `groupdel`, `gpasswd`, `chpasswd`, `passwd`) and root for any change. It is tested on Debian 13 and Fedora 42. macOS, BSD, and Windows are not supported.

---

## 7. Usage Guidance

* Preview every change with `dry_run=true` and review `planned_commands`.
* Pass passwords with `new_password_env=` or `new_password_stdin=true`, not `new_password_plain=`.
* Keep `protect_system_users=true` and avoid `force=true` in automation.
* For idempotent provisioning, rely on the defaults `ignore_if_exists=true` (add) and `ignore_if_missing=true` (delete), and check `existed` / `missing` in the output.
* Check `ok` and the exit status; for `exists`, check `user.exists`.
* Lock an account (`lock`) before deleting it if you may need to restore access.

Typical workflow:

```bash
resh user://deploy.exists
resh user://deploy.add shell=/bin/bash supplementary_groups=docker dry_run=true
resh user://deploy.add shell=/bin/bash supplementary_groups=docker
DEPLOY_PW=... resh user://deploy.passwd new_password_env=DEPLOY_PW
resh user://deploy.groups
```
