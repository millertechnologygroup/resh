# Resource Shell (resh) – Firewall Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `firewall://` handle lists, adds, and deletes firewall rules, saves and reloads rule sets, and reports, enables, or disables the host firewall on Linux.

It drives the existing command-line tools of four backends:

* `iptables` (`iptables`, `ip6tables`, `iptables-save`, `iptables-restore`, ...)
* `nftables` (`nft`)
* `ufw`
* `firewalld` (`firewall-cmd`, `systemctl`)

`backend=auto` (the default) detects an available backend. Every change needs root, as the underlying tools do.

Each verb prints one JSON object (pretty-printed) on stdout, or text with `format_output=text`.

---

## 2. Command Syntax

The URL has no target, but the dot before the verb is required:

```text
resh firewall://.<verb> [key=value ...]
```

```bash
resh firewall://.status
resh firewall://.rules.list family=ipv4 dport=22
resh firewall://.rules.add proto=tcp dport=22 dry_run=true
```

Built-in help (authoritative for every option, with full example output):

```bash
resh firewall --help
resh firewall rules.add --help
```

---

## 3. Verbs

| Verb           | Purpose                                                                 | Changes the system |
| -------------- | ----------------------------------------------------------------------- | ------------------ |
| `status`       | Report each backend's availability, active/enabled state, default policy, and rule counts | No |
| `rules.list`   | List one backend's rules, optionally filtered                           | No                 |
| `rules.add`    | Add a rule (skipped if an identical rule exists, unless `idempotent=false`) | Yes            |
| `rules.delete` | Delete the rule given by `rule_id`, or every rule matching the filters  | Yes                |
| `rules.save`   | Write a snapshot of the current rules to `path`                         | Writes a file      |
| `rules.reload` | Run the backend's own reload (ufw, firewalld) or apply a saved rules file (iptables, nftables) | Yes |
| `enable`       | Start ufw/firewalld, or load a rules file for iptables/nftables         | Yes                |
| `disable`      | Stop ufw/firewalld, or flush iptables/nftables (or load a rules file)   | Yes                |

There are no `add`, `list`, or `delete` verbs without the `rules.` prefix.

### status

```bash
resh firewall://.status backend=nftables include_metrics=false
```

Options: `backend=auto|all|iptables|nftables|ufw|firewalld`, `family=any|ipv4|ipv6`, `include_metrics` (default `true`), `include_rules_summary` (default `false`), `timeout_ms` (default 5000).

### rules.list

```bash
resh firewall://.rules.list backend=iptables family=ipv4
```

Filters: `table`, `chain`, `direction`, `action`, `proto`, `sport`, `dport`, `saddr`, `daddr`, `in_iface`, `out_iface`, `comment_contains`. Other options: `include_backend_raw`, `include_counters`, `max_rules` (default 10000), `timeout_ms` (default 5000).

Output (abbreviated):

```json
{
  "ok": true,
  "rules": [
    {
      "backend": "iptables",
      "table": "filter",
      "chain": "INPUT",
      "direction": "input",
      "action": "accept",
      "proto": "tcp",
      "dport": "22",
      "family": "ipv4",
      "saddr": "203.0.113.0/24"
    }
  ],
  "summary": { "backend": "iptables", "family": "ipv4", "filtered_rules": 1, "total_rules": 6 },
  "warnings": []
}
```

### rules.add

```bash
resh firewall://.rules.add backend=iptables direction=input action=accept proto=tcp dport=22 dry_run=true
resh firewall://.rules.add backend=firewalld zone=public proto=tcp dport=443
```

Options: `family=ipv4|ipv6|any` (default `ipv4`), `direction=input|output|forward|prerouting|postrouting`, `action=accept|drop|reject|log|masquerade|dnat|snat|redirect`, `table`, `chain`, `proto`, `sport`, `dport`, `saddr`, `daddr`, `in_iface`, `out_iface`, `zone` (firewalld only), `log_prefix`, `rate_limit`, `comment`, `position=append|insert`, `idempotent` (default `true`), `dry_run`, `timeout_ms` (default 5000).

* `sport`/`dport` need `proto=tcp` or `proto=udp`.
* With `family=any` and no address, iptables and nftables get one rule per family.
* A `saddr`/`daddr` sets the family; an explicit family that differs is rejected (`firewall.rules_add_family_mismatch`).
* A dry run reports the exact `backend_commands` and changes nothing.

### rules.delete

```bash
resh firewall://.rules.delete rule_id=INPUT:3 dry_run=true
resh firewall://.rules.delete backend=iptables direction=input proto=tcp dport=22 dry_run=true
```

* `rule_id` is the id that `rules.delete` reports in `matched_rules` (run it with filters and `dry_run=true` to see the ids; `rules.list` does not print them): `CHAIN:LINE` for iptables, the handle for nftables, the rule number for ufw, `ZONE:KIND:VALUE` for firewalld.
* Without `rule_id`, at least one filter is required. `match_mode=exact` (default) selects rules whose fields equal the given ones and that have no other match conditions; `match_mode=subset` selects every rule the filters fit. **Review a `subset` delete with `dry_run=true` first.**
* Other options: `limit=<n>`, `require_match` (default `true`), `zone` (firewalld only), `family`, `table`, `timeout_ms`.

### rules.save

```bash
resh firewall://.rules.save backend=iptables path=/var/backups/firewall.json
```

Options: `path` (required unless `dry_run`), `format=normalized_json|backend_native|both`, `compress=none|gzip`, `include_metadata`, `include_all_backends`, `family`, `overwrite` (default `false`; an existing file is an error), `create_dirs` (default `true`), `dry_run`, `timeout_ms`. `format` is the file content; `format_output` is the response format.

The file is written to a temporary name and renamed into place. Its permissions follow your umask (typically world-readable); choose a protected directory if rule sets are sensitive.

### rules.reload

```bash
resh firewall://.rules.reload backend=ufw dry_run=true
resh firewall://.rules.reload backend=iptables family=ipv4 source_format=backend_native path=/var/backups/iptables.rules dry_run=true
```

* Without `path`: runs `ufw reload` or `firewall-cmd --reload`. iptables and nftables require `path` (`firewall.rules_reload_path_required`).
* With `path` (iptables and nftables only): applies a backend-native file, or a `normalized_json` snapshot from `rules.save` that contains native data (`format=both` or `backend_native`). iptables needs `family=ipv4` or `family=ipv6`, not `any`.
* `backup_before_apply` (default `true`) backs up the current rules first, as for enable/disable below.
* `validate_only=true` changes nothing: for nftables it runs `nft -c -f <path>`; for iptables, ufw, and firewalld it only adds a warning that real validation is not available.

### enable / disable

```bash
resh firewall://.enable backend=ufw dry_run=true
resh firewall://.enable backend=nftables path=/etc/nftables.conf dry_run=true
resh firewall://.disable backend=iptables family=ipv4 dry_run=true
```

| Backend    | `enable`                                              | `disable`                                               |
| ---------- | ----------------------------------------------------- | ------------------------------------------------------- |
| ufw        | `ufw --force enable`                                  | `ufw --force disable`                                   |
| firewalld  | `systemctl enable firewalld` and `systemctl start firewalld` | `systemctl stop firewalld`                      |
| iptables   | `iptables-restore` / `ip6tables-restore` of `path`    | without `path`: set INPUT/OUTPUT/FORWARD policy to ACCEPT and flush the filter, nat, and mangle tables; with `path`: restore that file |
| nftables   | `nft -f <path>`                                       | without `path`: `nft flush ruleset`; with `path`: `nft -f <path>` |

* `enable` on iptables or nftables needs `path` when no rules are active.
* If the backend is already enabled (or disabled), nothing is changed and the result has `already_enabled` (`already_disabled`) `true`, even if `path` was given. `fail_if_already_enabled=true` / `fail_if_already_disabled=true` turn that into a failure.
* **`disable` on iptables with the default `family=any` acts on IPv4 only** (backup, flush, or restore). Run it again with `family=ipv6` for ip6tables.
* **`disable` without `path` removes all filtering.** On a remote host make sure that is what you want.
* `validate_only=true` runs no validation command: enable reports a planned `"<backend> status (validation only)"` action, and disable only checks that `path` exists.
* In an `enable` dry run the previous and current states are assumed (`active: false`, `enabled: false`), not queried. A `disable` dry run does query the current state.

---

## 4. Backups (`backup_before_apply`)

`enable`, `disable`, and `rules.reload` (file mode) on **iptables and nftables**:

* With `backup_before_apply=true` (the default), the current rules (`iptables-save`, `ip6tables-save`, or `nft list ruleset`) are written to a **new** file in `/var/backups/firewall/` **before anything is changed**. The reported `result.backup_path` is that file, and it exists on disk.
* The backup file is created with mode 0600, never overwrites an existing file (`create_new`), and is not opened through a symlink. The directory is created with mode 0700 if missing; a symlinked or non-directory `/var/backups/firewall` is refused.
* **If the backup cannot be written, nothing is changed** and the command fails (`firewall.rules_save_failed` or `firewall.io_error`).
* A dry run writes no backup; its `actions` say "new backup in /var/backups/firewall/ (not written in dry run)".
* `backup_before_apply` accepts `true/false/1/0/yes/no/on/off` (any case); any other value is an error.

**ufw and firewalld take no backup.** `enable`/`disable` on them add the warning "backup_before_apply is not supported for ufw; no backup was taken" (or firewalld). Save the configuration yourself first if you need it.

---

## 5. Timeouts

`timeout_ms` is accepted by every verb and is **enforced**: each backend command is a child process that is killed when the deadline passes, and the verb fails with "Command timed out after <n>ms".

| Verbs                                              | Default  |
| -------------------------------------------------- | -------- |
| `status`, `rules.list`, `rules.add`, `rules.delete`, `rules.save` | 5000 ms |
| `rules.reload`, `enable`, `disable`                | 10000 ms |

Exceptions and parsing:

* The `iptables-restore` / `ip6tables-restore` step of `rules.reload` with a file runs **without** a deadline.
* `rules.*` reject `timeout_ms=0` and non-numbers. `enable` and `status` silently use the default for a non-number; `disable` rejects a non-number.
* The timeout applies to each command separately, not to the whole verb.

---

## 6. Booleans and dry_run

* `dry_run`, `backup_before_apply`, and `overwrite` (`rules.save`) accept `true/false/1/0/yes/no/on/off` (any case); a bare `dry_run` means `true`; anything else is an error and nothing runs.
* Other booleans (`idempotent`, `validate_only`, `create_dirs`, `include_*`, `require_match`, `fail_if_already_*`) accept only the literal `true`/`false`; other values silently fall back to a default.
* `dry_run` is accepted by `rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, and `disable`.

---

## 7. Output, Errors, and Exit Codes

Failures produce a JSON object with `"ok": false` and an `error` object on stdout, for example:

```json
{
  "ok": false,
  "error": {
    "code": "firewall.internal_error",
    "details": { "message": "Invalid backend: bogus. Must be 'auto', 'iptables', 'nftables', 'ufw', or 'firewalld'" },
    "message": "Internal error: Invalid backend: bogus. Must be 'auto', 'iptables', 'nftables', 'ufw', or 'firewalld'"
  },
  "warnings": []
}
```

(Abbreviated; each verb's error object also carries its usual top-level fields.) resh also prints `Error: <reason>` on stderr.

| Exit status | Meaning                                                   |
| ----------- | --------------------------------------------------------- |
| 0           | Success (`"ok": true`)                                    |
| 1           | Any failure; `error.code` says which                       |

The firewall handle uses no other exit codes. A response with `"ok": false` exits with status 1 for every verb that reports `ok`, including `enable` and `disable`.

---

## 8. Limitations

* **nftables `status`** counts only `table ip` and `table ip6`; rules in `table inet` (and other families) are not counted.
* **`rules.reload` from a normalized JSON snapshot** writes the native data to a securely created temporary file (random name, mode 0600, in the system temp directory, removed afterwards) before applying it, also in a dry run.
* **`validate_only`** on enable/disable does not validate the rules file.
* **`disable` on iptables** with `family=any` covers IPv4 only.
* **No backups for ufw/firewalld.**
* **`rules.save` native data** for iptables with `family=any` contains `iptables-save` output only (IPv4).
* Only tested at the command-construction and mock-executable level; no live firewall was changed while verifying this document.

---

## 9. Platform Support

Linux only. Which backends work depends on the tools installed (iptables, nft, ufw, firewalld). BSD, macOS, and Windows are not supported.

---

## 10. Usage Guidance

* Allow SSH before applying restrictive rules on a remote host.
* Preview every change with `dry_run=true` and read `backend_commands` / `actions`.
* Keep `backup_before_apply=true` on iptables and nftables; for ufw/firewalld save the configuration yourself.
* After changing rules, persist them with `rules.save` (resh does not make rules survive a reboot by itself).
* Check `ok` and the exit status in automation.

Typical workflow:

```bash
resh firewall://.status
resh firewall://.rules.add proto=tcp dport=443 dry_run=true
resh firewall://.rules.add proto=tcp dport=443
resh firewall://.rules.save path=/var/backups/firewall.json overwrite=true
resh firewall://.rules.list dport=443
```
