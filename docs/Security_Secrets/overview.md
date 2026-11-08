# Resource Shell (resh) – Security & Secrets Overview

## 1. Overview

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands and prints structured (JSON) results.

The Security & Secrets category has four handles:

| Handle        | Domain                                   | Details                |
| ------------- | ---------------------------------------- | ---------------------- |
| `user://`     | Local user, group, and membership management, passwords, account locking | [user.md](user.md) |
| `secret://`   | Secrets in the OS keyring or HashiCorp Vault (KV v2), and read-only environment lookup | [secret.md](secret.md) |
| `cert://`     | X.509 certificates, keys, and CSRs in local files | [cert.md](cert.md) |
| `firewall://` | Rules and state of iptables, nftables, ufw, firewalld | [firewall.md](firewall.md) |

Each `resh` invocation is a separate process. Nothing persists between invocations except what a handle writes: the secret index file (names only) and OS keyring entries, certificate/key files, firewall backups and saved rule files, and the system changes made by `user` and `firewall`.

---

## 2. Command Syntax

```text
resh <scheme>://<target>.<verb> [key=value ...]
```

The verb is the text after the last dot of the URL (dotted verbs such as `rules.add`, `csr.create`, and `chain.info` are recognized as a whole). A URL with no target still needs the dot, as in `firewall://.status`. The alternative form `resh 'svc://x.verb(key=value)'` also works; quote it for the shell.

```bash
resh user://alice.exists
resh secret://local/db_password.get redact=true
resh cert:///etc/ssl/certs/server.pem.info
resh firewall://.status
```

Help: `resh <handle> --help` and `resh <handle> <verb> --help` (also `-h`, `help`, or `resh help <handle> [verb]`). The global flag `--json-pretty` goes before the stage.

All four handles follow the shared conventions in [resh_overview.md 3.5](../resh_overview.md#35-shared-conventions): strict arguments (an unknown argument, an option of another mode, or an invalid value is refused with exit 2 before anything is done), exit codes 0/1/2/124, and the error line `Error: [<handle>.<code>] <message>`.

### Registered verbs

| Handle     | Verbs                                                                                   |
| ---------- | --------------------------------------------------------------------------------------- |
| `user`     | `exists`, `groups`, `add`, `delete`, `passwd`, `lock`, `unlock`                          |
| `secret`   | `get`, `set`, `rm`, `ls`, `rotate`                                                       |
| `cert`     | `info`, `verify`, `chain.info`, `generate`, `csr.create`, `sign`, `renew`, `csr.sign` (not reachable from the CLI; use `sign mode=csr`) |
| `firewall` | `status`, `rules.list`, `rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, `disable` |

---

## 3. Examples

```bash
# Users
resh user://alice.add shell=/bin/bash dry_run=true
resh user://alice.groups
resh user://alice.lock

# Secrets (values go to the OS keyring; prefer from_env= or from_stdin=true over value=)
resh secret://local/db_password.set from_env=DB_PASSWORD
resh secret://local/db_password.get redact=true
resh secret://local/.ls

# Certificates
resh cert://./server.generate mode=self_signed algorithm=ecdsa subject='{"common_name":"example.com"}'
resh cert://./server.pem.verify hostname=example.com allow_self_signed=true

# Firewall
resh firewall://.rules.list dport=443
resh firewall://.rules.add proto=tcp dport=443 dry_run=true
```

---

## 4. Safety Model

### dry_run

`dry_run` is supported by `user` (`add`, `delete`, `passwd`, `lock`, `unlock`) and `firewall` (`rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, `disable`). It accepts `true/false/1/0/yes/no/on/off` (any case); a bare `dry_run` means `true`; any other value is an error and nothing runs. `secret` and `cert` have no dry run: `dry_run=true` is refused (exit 2) and nothing is written.

### Protections

* **user:** `delete`, `lock`, and `unlock` refuse accounts with UID below 1000 (including root) unless `force=true`, `protect_system_users=false`, or a lower `min_uid_for_*`; `passwd` refuses them (`user.protected_account`, exit 2) unless `force=true`. `force` overrides these protections. Passwords are hashed by resh (sha512-crypt or bcrypt on the system backend) and passed to `chpasswd -e` on stdin. A change without root is refused before any tool runs. See [user.md](user.md).
* **firewall:** `enable`, `disable`, and file-based `rules.reload` on iptables/nftables write a 0600 backup to `/var/backups/firewall/` before any change and change nothing if the backup fails. ufw and firewalld take no backup (a warning says so). See [firewall.md](firewall.md).
* **cert:** existing files are not overwritten unless `overwrite=true`, and no output is written through a symbolic link; keys are written 0600. RSA keys below 2048 bits are rejected. Private keys can be passphrase-encrypted (PKCS#8, PBES2).
* **secret:** `local` values are kept in the OS keyring, never in a file; the index file (`<state-dir>/resh/secrets/local.json`) holds only key names and keyring references (mode 0600 in a 0700 directory, written atomically, symlinks refused, writers locked). Without a keyring, writes are refused. See [secret.md](secret.md).

### Timeouts (`timeout_ms`)

| Handle     | `timeout_ms`                                                                   |
| ---------- | ------------------------------------------------------------------------------ |
| `firewall` | Every verb: one deadline for the whole verb (default 30000 for `status` and `rules.*`, 60000 for `rules.reload`, `enable`, `disable`); each backend command gets the time left and is stopped (with its children) at the deadline; exit 124 with a report of the steps applied and not applied |
| `user`     | `add`, `delete`, `passwd`, `lock`, `unlock` (default 60000; bounds every tool the verb runs; exit 124); `exists` and `groups` refuse it |
| `secret`   | Enforced on `local` and `vault` (keystore lock, keyring calls, Vault requests, RSA generation; exit 124); refused on `env` |
| `cert`     | `generate`, `csr.create`, `sign`, `renew` (default 300000; at the deadline nothing is written, exit 124); `info`, `verify` and `chain.info` refuse it |

---

## 5. Output and Exit Codes

* Output is a single JSON object per invocation (or text where a handle offers `format=text` / `format_output=text`). Field names are handle-specific; there is no shared envelope. See each handle's document and `--help` for real output.
* Exit status is the same for all four handles: 0 success, 1 the operation failed, 2 invalid usage (nothing was done), 124 timeout (the outcome may be unknown). The codes are listed in [user.md](user.md), [secret.md](secret.md), [cert.md](cert.md) and [firewall.md](firewall.md).
* Every failure prints `Error: [<handle>.<code>] <message>` on stderr and, with JSON output, a JSON object with `"error": {"code", "message"}` on stdout (`user` and `cert` with `format=json`, the default).
* Query verbs report absence as data, not failure: `user exists` and `secret get` for a missing name exit 0 with `exists: false`.

---

## 6. Known Limitations

* **`secret://local` needs an OS keyring** (a Secret Service provider on Linux); without one its verbs fail (exit 1) except `ls`. The plaintext store of earlier releases is still read, with a warning, and moved into the keyring by the next write. The macOS Keychain path is not tested.
* **Secrets on the command line.** `secret ... value=`, `user ... new_password_plain=`, the plain `cert` passphrase options, and similar arguments are visible in the process list and shell history. Use the alternatives: `secret set from_stdin=true` or `from_env=`; `user passwd new_password_env=` or `new_password_stdin=true`; `cert` `<name>_env=` or `<name>_stdin=true`. The plain `user` and `cert` forms print a warning every time.
* **`secret get` prints the value** unless `redact=true`; `secret rotate` prints it only with `expose_value=true`.
* **cert:** no revocation checking (CRL/OCSP); legacy `Proc-Type: 4,ENCRYPTED` keys, PBES1 and scrypt-encrypted keys are refused (convert them to PKCS#8); `csr.sign` is not reachable from the CLI (use `sign mode=csr`).
* **secret vault:** token authentication and KV version 2 only.
* **firewall:** no backups for ufw/firewalld; firewalld rules are added to the runtime configuration only; ufw refuses NAT and firewalld refuses `snat`.

---

## 7. Platform Support

Linux is the only supported and tested platform. The `user` and `firewall` handles drive Linux tools (shadow-utils, iptables/nft/ufw/firewalld) and need root to make changes. The secret index location comes from the XDG state directory, which is not defined on macOS or Windows. macOS, BSD, and Windows are not supported.

---

## 8. Usage Guidance

* Preview `user` and `firewall` changes with `dry_run=true`.
* Check both the exit status and the JSON (`ok`, `exists`, `error`) in automation.
* Do not log `secret get` output without `redact=true`.
* Keep private keys in directories only the owning user can read.
* Persist firewall rules with `rules.save` after changing them.

Typical provisioning flow:

```bash
resh user://deploy.add shell=/bin/bash dry_run=true
resh user://deploy.add shell=/bin/bash
resh secret://local/deploy/db_password.set from_env=DB_PASSWORD
resh cert://./deploy-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=deploy-key.pem subject='{"common_name":"deploy.example.com"}'
resh firewall://.rules.add proto=tcp dport=443 dry_run=true
```
