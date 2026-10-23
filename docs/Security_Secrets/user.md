# Resource Shell (resh) – User Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `user://` handle creates, deletes, and inspects local Linux user accounts, groups, and group memberships, changes passwords, and locks or unlocks accounts.

### How it works

* The default **system** backend reads the user database with `getpwnam`, `getgrnam`, and `getgrouplist`, and makes changes by running `useradd`, `groupadd`, `usermod`, `userdel`, `groupdel`, `gpasswd`, or `chpasswd`. Changes normally need root.
* `dry_run=true` runs no changing command; the planned commands are reported in `planned_commands`.
* `backend=mock` uses an empty in-memory store that exists only for the life of the one `resh` process. It is useful for checking argument handling, not for persisting anything.
* `backend=file` and `backend=ldap` are accepted names but fail with `user.backend_not_supported`.

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

The three-slash forms (`user:///alice`) also work. The name can instead be passed as `username=`, `group_name=`, or `member=`.

Built-in help:

```bash
resh user --help
resh user add --help
```

---

## 3. Verbs

| Verb     | Purpose                                                         | Changes the system |
| -------- | --------------------------------------------------------------- | ------------------ |
| `exists` | Report whether a user exists (by username, optionally checking `uid`) | No |
| `groups` | List a user's groups, marked primary / supplementary / system   | No                 |
| `add`    | Create a user, a group, or memberships (`mode=user\|group\|membership`, default `user`) | Yes |
| `delete` | Remove a user, a group, or memberships (same `mode` values)      | Yes                |
| `passwd` | Set a password from `new_password_plain` or `new_password_hash`  | Yes                |
| `lock`   | Lock an account (`usermod -L`)                                   | Yes                |
| `unlock` | Unlock an account (`usermod -U`)                                 | Yes                |

### exists

```bash
resh user://alice.exists
resh user://alice.exists uid=1001
```

A missing user is **not** a failure: the command exits 0 with `"ok": true`, `"exists": false`, and a warning. Test the `user.exists` field. If `uid=` is given and the user exists with a different UID, the command fails.

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

Options: `include_primary`, `include_supplementary`, `include_system_groups` (all default `true`), `min_gid_for_system=<n>` (default 1000; a group below it is a system group), `group_name_filter=<group>`, `ignore_if_missing`.

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
| `uid=<n>`                 | UID. Must be 1000-65533 unless `force=true` (which allows < 1000). An unparsable value is ignored and the next free UID is used. |
| `primary_group=<group>`   | Primary group (default: a group named after the user, created if missing) |
| `supplementary_groups=<g1,g2>` (or `groups=`) | Extra groups. Each must already exist; checked before anything changes. |
| `home=<path>`             | Home directory (default `/home/<user>`). It is always created (`useradd -m`). |
| `shell=<path>`            | Login shell (default `/bin/bash`)                                     |
| `gecos=<text>`            | Comment field                                                         |
| `ignore_if_exists`        | Default `true`: an existing user is reported with `"existed": true` and nothing changes. `false` makes it an error. |

`mode=group` options: `group_name=`, `gid=<n>` (same range rule as `uid`). `mode=membership` options: `member=`, `groups=<g1,g2>`.

Not supported on `add` (parsed but ignored, do not rely on them):

* `create_home`: the home directory is always created.
* `password_hash`: no password is set by `add`. Use `passwd` afterwards.

When `ignore_if_exists` returns an existing user, only `uid` is read from the system; the reported `primary_group`, `home`, and `shell` are defaults, not the account's real values.

### delete

```bash
resh user://alice.delete remove_home=true dry_run=true
resh user://group/dev.delete mode=group
resh user://membership/alice.delete mode=membership groups=docker
```

`mode=user` options: `remove_home` (default `false`; uses `userdel -r`, which also removes the mail spool), `remove_mail` (default `false`), `remove_from_all_groups` (default `true`), `protect_system_users` (default `true`), `min_uid_for_delete` (default 1000), `ignore_if_missing` (default `true`: a missing user is reported, not an error).

`mode=group` options: `group_name=`, `only_if_empty` (default `true`), `protect_system_groups` (default `true`), `min_gid_for_delete` (default 1000).

`mode=membership` options: `member=`, `groups=<g1,g2>` or `all_groups=true`.

In the output, `home.was_present` (and the mail spool's) is always `true`; it is not checked against the filesystem.

### passwd

```bash
resh user://alice.passwd new_password_plain=S3cr3t dry_run=true
```

Options: `new_password_plain=` or `new_password_hash=` (exactly one), `hash_scheme=backend_default|sha512_crypt|bcrypt|argon2id`, `require_old_password=true` with `old_password_plain=`, `ignore_if_missing`.

* The system backend passes the password to `chpasswd` on stdin and rejects `argon2id`.
* `require_old_password` needs read access to `/etc/shadow` and can verify only bcrypt and argon2 hashes; others give an unsupported error.
* **The password is on the `resh` command line** and is visible in the process list and shell history. There is no environment-variable or file alternative.

### lock / unlock

```bash
resh user://alice.lock
resh user://alice.unlock dry_run=true
```

Options: `protect_system_users` (default `true`), `min_uid_for_lock` / `min_uid_for_unlock` (default 1000), `force`, `ignore_if_missing`. The current lock state comes from `/etc/shadow` or `passwd -S`; if neither can be read the verb fails (a dry run reports `was_locked: null` with a warning). Locking an already locked account, or unlocking an already unlocked one, succeeds with `"changed": false`.

---

## 4. Safety Controls

### dry_run

`dry_run` is accepted by `add`, `delete`, `passwd`, `lock`, and `unlock`. It accepts `true/false`, `1/0`, `yes/no`, `on/off` (any case); a bare `dry_run` word means `true`; any other value is an error and nothing runs. In a dry run no changing command is executed and the commands are listed in `planned_commands`. Lookups (does the user exist, which groups) still run.

### System-account protection and force

* `delete`, `lock`, and `unlock` refuse a user whose UID is below `min_uid_for_delete` / `min_uid_for_lock` / `min_uid_for_unlock` (default 1000). That includes `root` (UID 0). The error is `user.system_user_protected`; the check runs in dry runs too.
* `delete mode=group` refuses a group whose GID is below `min_gid_for_delete` (default 1000) and a group that still has members (`only_if_empty`).
* **`force=true` overrides all of these protections**, and on `add` it also allows a UID/GID below 1000. The operation then proceeds with a warning. Use it only deliberately, never as a default in scripts.
* `force` is parsed strictly, like `dry_run`: `force=maybe` is an error, not a silent `false`.
* Setting `protect_system_users=false`, or lowering `min_uid_for_*`, also disables the user protection.

### Other booleans

Only `dry_run` and `force` accept the `1/0/yes/no/on/off` spellings. Every other boolean option (`remove_home`, `ignore_if_missing`, `protect_system_users`, `include_*`, ...) accepts only the literal `true` or `false`; any other value silently falls back to that option's default. For example `remove_home=yes` is treated as `false`, and `protect_system_users=no` is treated as `true`.

### Validation

* Usernames and group names (for `mode=group`) must be 1-32 characters of ASCII letters, digits, `_` or `-`, and must not start with `-`.
* **`primary_group=` is not validated.** Its value is passed to `groupadd` and `useradd -g` as given. Use only trusted values.

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
    "groupadd -g 1001 alice",
    "useradd -u 1001 -g alice -d /home/alice -m -s /bin/zsh alice"
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

Errors are printed as JSON on **stderr**:

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
| 0           | Success (including `exists` for a missing user)            |
| 1           | Any failure; the `error.code` field says which             |

The user handle uses no other exit codes. Distinguish failures by `error.code` (for example `user.not_found`, `user.system_user_protected`, `user.invalid_mode`, `user.backend_not_supported`).

---

## 6. Options That Are Not Supported

* `timeout_ms`: ignored. The system commands (`useradd`, `userdel`, ...) run with no deadline.
* `create_home`, `password_hash` on `add`: parsed but ignored (see above).
* `force` on `passwd`: parsed but ignored.
* `format=` values other than `json` and `text` silently fall back to JSON.

---

## 7. Platform Support

Linux only. The system backend needs the shadow-utils tools (`useradd`, `usermod`, `userdel`, `groupadd`, `groupdel`, `gpasswd`, `chpasswd`) and root for any change. macOS, BSD, and Windows are not supported.

---

## 8. Usage Guidance

* Preview every change with `dry_run=true` and review `planned_commands`.
* Keep `protect_system_users=true` and avoid `force=true` in automation.
* For idempotent provisioning, rely on the defaults `ignore_if_exists=true` (add) and `ignore_if_missing=true` (delete), and check `existed` / `missing` in the output.
* Check `ok` and the exit status; for `exists`, check `user.exists`.
* Lock an account (`lock`) before deleting it if you may need to restore access.

Typical workflow:

```bash
resh user://deploy.exists
resh user://deploy.add shell=/bin/bash supplementary_groups=docker dry_run=true
resh user://deploy.add shell=/bin/bash supplementary_groups=docker
resh user://deploy.groups
```
