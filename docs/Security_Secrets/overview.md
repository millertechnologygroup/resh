# Resource Shell (resh) – Security & Secrets Overview

## 1. Overview

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands and prints structured (JSON) results.

The Security & Secrets category has four handles:

| Handle        | Domain                                   | Details                |
| ------------- | ---------------------------------------- | ---------------------- |
| `user://`     | Local user, group, and membership management, passwords, account locking | [user.md](user.md) |
| `secret://`   | Plaintext local keystore and read-only environment lookup | [secret.md](secret.md) |
| `cert://`     | X.509 certificates, keys, and CSRs in local files | [cert.md](cert.md) |
| `firewall://` | Rules and state of iptables, nftables, ufw, firewalld | [firewall.md](firewall.md) |

Each `resh` invocation is a separate process. Nothing persists between invocations except what a handle writes to disk: the secret keystore file, certificate/key files, firewall backups and saved rule files, and the system changes made by `user` and `firewall`.

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

Help: `resh <handle> --help` and `resh <handle> <verb> --help`. The global flag `--json-pretty` goes before the stage.

### Registered verbs

| Handle     | Verbs                                                                                   |
| ---------- | --------------------------------------------------------------------------------------- |
| `user`     | `exists`, `groups`, `add`, `delete`, `passwd`, `lock`, `unlock`                          |
| `secret`   | `get`, `set`, `rm`, `ls`, `rotate` (not implemented)                                     |
| `cert`     | `info`, `verify`, `chain.info`, `generate`, `csr.create`, `sign`, `renew`, `csr.sign` (not reachable from the CLI; use `sign mode=csr`) |
| `firewall` | `status`, `rules.list`, `rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, `disable` |

---

## 3. Examples

```bash
# Users
resh user://alice.add shell=/bin/bash dry_run=true
resh user://alice.groups
resh user://alice.lock

# Secrets (stored in plaintext; prefer from_env= over value=)
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

`dry_run` is supported by `user` (`add`, `delete`, `passwd`, `lock`, `unlock`) and `firewall` (`rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, `disable`). It accepts `true/false/1/0/yes/no/on/off` (any case); a bare `dry_run` means `true`; any other value is an error and nothing runs. `secret` and `cert` have no dry run (`dry_run` is ignored there).

### Protections

* **user:** `delete`, `lock`, and `unlock` refuse accounts with UID below 1000 (including root) unless `force=true`, `protect_system_users=false`, or a lower `min_uid_for_*`. `force` is parsed strictly and overrides these protections. See [user.md](user.md).
* **firewall:** `enable`, `disable`, and file-based `rules.reload` on iptables/nftables write a 0600 backup to `/var/backups/firewall/` before any change and change nothing if the backup fails. ufw and firewalld take no backup (a warning says so). See [firewall.md](firewall.md).
* **cert:** existing files are not overwritten unless `overwrite=true`; RSA keys below 2048 bits are rejected.
* **secret:** the keystore file is mode 0600 in a 0700 directory and written atomically, but it is **not encrypted**.

### Timeouts (`timeout_ms`)

| Handle     | `timeout_ms`                                                                   |
| ---------- | ------------------------------------------------------------------------------ |
| `firewall` | Enforced on every backend command (child killed at the deadline), except the `iptables-restore` step of file-based `rules.reload` |
| `user`     | Ignored; system commands run with no deadline                                  |
| `secret`   | Ignored                                                                        |
| `cert`     | Ignored (local work only)                                                      |

---

## 5. Output and Exit Codes

* Output is a single JSON object per invocation (or text where a handle offers `format=text` / `format_output=text`). Field names are handle-specific; there is no shared envelope. See each handle's document and `--help` for real output.
* Exit status is 0 on success. On failure it is the handle's code: always 1 for `user` and `firewall`; 1 or 2 for `secret` (2 for not-implemented `rotate` and `vault`); 1-7 for `cert`, depending on the verb (see [cert.md](cert.md)).
* Where errors go: `user` writes error JSON to stderr; `secret`, `cert`, and `firewall` write it to stdout. resh also prints `Error: <reason>` on stderr.
* Query verbs report absence as data, not failure: `user exists` and `secret get` for a missing name exit 0 with `exists: false`.

---

## 6. Known Limitations

* **Secrets are stored in plaintext** (`<state-dir>/resh/secrets/local.json`), with no locking between concurrent writers. `secret rotate` and the `vault` scope are not implemented.
* **Secrets on the command line.** `secret ... value=`, `user ... new_password_plain=`, and similar arguments are visible in the process list and shell history. Only `secret set` offers an alternative (`from_env=`).
* **`secret get` prints the value** unless `redact=true`.
* **No encrypted private keys** in `cert`; `key_passphrase` is rejected. CMS signatures are not implemented. `chain.info` does not build chains; use `verify`.
* **`user add`:** `create_home` and `password_hash` are ignored; `primary_group` is not validated.
* **firewall:** nftables `status` ignores `table inet`; no backups for ufw/firewalld.

---

## 7. Platform Support

Linux is the only supported and tested platform. The `user` and `firewall` handles drive Linux tools (shadow-utils, iptables/nft/ufw/firewalld) and need root to make changes. The secret keystore location comes from the XDG state directory, which is not defined on macOS or Windows. macOS, BSD, and Windows are not supported.

---

## 8. Usage Guidance

* Preview `user` and `firewall` changes with `dry_run=true`.
* Check both the exit status and the JSON (`ok`, `exists`, `error`) in automation.
* Do not log `secret get` output without `redact=true`.
* Keep private keys and the secret keystore in directories only the owning user can read.
* Persist firewall rules with `rules.save` after changing them.

Typical provisioning flow:

```bash
resh user://deploy.add shell=/bin/bash dry_run=true
resh user://deploy.add shell=/bin/bash
resh secret://local/deploy/db_password.set from_env=DB_PASSWORD
resh cert://./deploy-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=deploy-key.pem subject='{"common_name":"deploy.example.com"}'
resh firewall://.rules.add proto=tcp dport=443 dry_run=true
```
