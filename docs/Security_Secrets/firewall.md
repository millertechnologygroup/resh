# Resource Shell (resh) – Firewall Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `firewall://` handle lists, adds, and deletes firewall rules, saves and reloads rule sets, and reports, enables, or disables the host firewall on Linux.

It drives the existing command-line tools of four backends:

* `iptables` (`iptables`, `ip6tables`, `iptables-save`, `iptables-restore`, ...)
* `nftables` (`nft`)
* `ufw`
* `firewalld` (`firewall-cmd`, `systemctl`)

The tools are looked up on `PATH` and in `/usr/local/sbin`, `/usr/sbin` and `/sbin`. Every change needs root, as the underlying tools do; reading the rules usually does too.

`backend=auto` (the default) picks, in this order: firewalld when it is running, ufw when it is active, nftables when `nft list ruleset` works, an inactive ufw, and iptables. When none qualifies the command fails with `firewall.no_backend_available`, and the message says why each installed tool was passed over (for example `nftables: Operation not permitted`).

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

### Strict arguments

Every verb accepts exactly the options its help lists. An unknown option (with a "did you mean" hint), a value outside an option's accepted set, a malformed number or boolean, or two options that rule each other out is refused with exit status 2 and `firewall.invalid_argument` before anything runs. An unknown verb is `firewall.unknown_verb` (exit 2). `status` and `rules.list` change nothing and have no dry-run mode: `dry_run=true` is refused there (`dry_run=false` is accepted).

* Booleans accept `true/false/1/0/yes/no/on/off` (any case).
* Enumerated values (`backend`, `family`, `direction`, `action`, `position`, `match_mode`, `format`, `compress`, `source_format`, `format_output`) accept the listed words in any case.
* `timeout_ms` is an integer from 1 to 3600000; `max_rules` from 1 to 1000000; `limit` from 1 to 100000.
* Values may not contain control characters.
* Refused combinations: `dry_run=true` with `validate_only=true`; `log_prefix` without `action=log`; `match_mode` with `rule_id`; `include_all_backends=true` with a `backend` other than `auto`; `source_format` without `path`.

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
| `disable`      | Stop ufw/firewalld, or open and flush iptables/nftables (or load a rules file) | Yes         |

There are no `add`, `list`, or `delete` verbs without the `rules.` prefix.

### status

```bash
resh firewall://.status backend=nftables include_metrics=false
```

Options: `backend=auto|all|iptables|nftables|ufw|firewalld`, `family=any|ipv4|ipv6`, `include_metrics` (default `true`), `include_rules_summary` (default `false`), `timeout_ms` (default 30000), `format_output`.

* `available` is whether the backend's tool is installed. A backend that is not installed is reported with `available: false` and a warning; a tool that is installed but fails (for example without root) is an error (`firewall.permission_denied` or `firewall.command_failed`). With `backend=all`, such a failure becomes a warning on that backend instead.
* `active`/`enabled`: iptables has rules or a filter policy other than ACCEPT; nftables has at least one table; ufw reports `Status: active`; firewalld is running.
* `default_policy`: the filter INPUT policy (iptables, per family when they differ), the policy of the filter chain hooked on input (nftables, inet table first), ufw's `Default:` line, or the target of firewalld's default zone.
* `rule_count_ipv4`/`rule_count_ipv6` count the listed rules. A rule that serves both families (an nftables `inet` rule without an address or `meta nfproto`, a ufw or firewalld rule without an address) counts for both. `family=ipv4` or `family=ipv6` counts that family only and reports `null` for the other.
* `include_metrics=true` fills `details` with a one-line summary. `include_rules_summary=true` adds `rules_summary` with `total`, `by_action` and `by_direction` counts.

### rules.list

```bash
resh firewall://.rules.list backend=iptables family=ipv4
```

Filters: `table`, `chain`, `direction`, `action`, `proto`, `sport`, `dport`, `saddr`, `daddr`, `in_iface`, `out_iface`, `to` (the NAT target of dnat/snat rules), `comment_contains`. Other options: `backend` (not `all`), `family`, `include_backend_raw`, `include_counters`, `max_rules` (default 10000; more matching rules is `firewall.max_rules_exceeded`), `timeout_ms` (default 30000), `format_output`. Every listed rule has a `to` field (`null` unless it is a NAT rule with a target). Filter values are validated as for `rules.add`.

`family=ipv4`/`ipv6` also lists rules that serve both families (see `status`). With `family=any`, iptables lists both families; a family whose save tool is not installed is skipped. A listing that fails is an error, never an empty list.

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

Options: `family=ipv4|ipv6|any` (default `ipv4`), `direction=input|output|forward|prerouting|postrouting`, `action=accept|drop|reject|log|masquerade|dnat|snat|redirect`, `table`, `chain`, `proto`, `sport`, `dport`, `saddr`, `daddr`, `in_iface`, `out_iface`, `to` (with `action=dnat` or `snat`, see [NAT](#nat)), `zone` (firewalld only, and required there), `log_prefix` (with `action=log`), `rate_limit`, `comment`, `position=append|insert`, `idempotent` (default `true`), `dry_run`, `timeout_ms` (default 30000), `format_output`.

* `sport`/`dport` need `proto=tcp` or `proto=udp`.
* With `family=any` and no address, iptables gets one rule per family; ufw and firewalld write one rule that covers both.
* A `saddr`/`daddr` sets the family; an explicit family that differs is rejected (`firewall.rules_add_family_mismatch`).
* **nftables:** the rule goes into a chain of the live ruleset: the given `table`/`chain`, or else the first base chain hooked on `direction` (type `nat` for pre/postrouting and NAT actions, `filter` otherwise), looking first at `inet` tables and then at `ip`/`ip6`. A one-family rule in an `inet` table without an address carries `meta nfproto ipv4` (or `ipv6`); `family=any` puts one rule into an `inet` chain when there is one. With no such chain the command fails with `firewall.chain_not_found` (exit 1); create the table and chain first, or give `table=` and `chain=`.
* `rate_limit` (`10/m`, `5/second`, ...) is written with the unit spelled out (`10/minute`). `log_prefix` (up to 29 characters, the `comment` character set) is written as `--log-prefix` (iptables) or `log prefix "..."` (nftables).
* A dry run reports the exact `backend_commands` and changes nothing; it still reads the rules (for the idempotence check and, on nftables, the target chain).
* Every value is validated before any backend command is built, also in a dry run (see [Input validation](#input-validation)).
* `idempotent=true` skips the add only when an existing rule matches the request exactly: same table/chain (firewalld: zone), direction, action, protocol, ports, addresses and interfaces, and no other match conditions. An existing rule with extra match conditions that resh does not model (for example `conntrack --ctstate NEW` or `multiport`) is narrower than the request, so it does not count, and the requested rule is added. A request with `rate_limit` is never considered present. An inactive ufw lists no rules; ufw itself skips a duplicate, which is reported as `already_exists: true`.
* If a later command fails after earlier ones succeeded (`family=any` on iptables), `backend_commands` lists the commands that were applied and a warning says how many.
* firewalld rules are added to the runtime configuration only; `firewall-cmd --reload` (and `rules.reload` on firewalld) discards them.

#### NAT

`action=dnat` (destination NAT) and `action=snat` (source NAT) need `to=<addr>[:port]`; `to` is refused with any other action (both `firewall.invalid_argument`, exit 2). `to` is one IPv4 address, or one IPv6 address (in brackets when a port follows), with an optional port or port range `low-high` in plain decimal: `10.0.0.5`, `10.0.0.5:8080`, `[2001:db8::5]:8443`. Anything else is `firewall.invalid_field` (exit 2). A port in `to` needs `proto=tcp` or `proto=udp`. The address family of `to` sets the rule's family like `saddr`/`daddr` do.

NAT rules use the NAT hooks: `dnat` and `redirect` default to `direction=prerouting` (also allowed: `output`), `snat` and `masquerade` to `direction=postrouting` (`snat` also allows `input`); another direction is `firewall.invalid_argument`. What each backend writes:

| Backend | `dnat` | `snat` | `masquerade` |
| ------- | ------ | ------ | ------------ |
| iptables | `-t nat -A PREROUTING ... -j DNAT --to-destination <to>` (ip6tables for an IPv6 target) | `-t nat -A POSTROUTING ... -j SNAT --to-source <to>` | `-t nat -A POSTROUTING ... -j MASQUERADE` |
| nftables | `... dnat [ip\|ip6] to <to>` in a NAT chain hooked on the direction | `... snat [ip\|ip6] to <to>` | `... masquerade` |
| firewalld | rich rule `forward-port port="<dport>" protocol="<proto>" [to-port="<port>"] to-addr="<addr>"` (needs `proto=tcp\|udp` and `dport`) | refused: firewalld cannot translate to a given source address; use `masquerade` | rich rule `[source address=...] masquerade` (no ports or protocol) |
| ufw | refused | refused | refused |

On nftables the rule goes into the first existing NAT chain hooked on the direction (an `inet` table first, then `ip`/`ip6`). If there is none and no `table`/`chain` is given, resh creates its own table and chain first: `nft add table inet resh` and `nft add chain inet resh <direction> { type nat hook <direction> priority dstnat|srcnat ; }`; these commands are listed first in `backend_commands`.

Idempotence and `rules.delete` compare `to` too (`10.0.0.5:8080` and the backend's own spelling of the same target are equal); `rules.delete action=dnat to=...` selects NAT rules by their target, and `rule_id` works for NAT rules like for any other rule.

#### Input validation

Since v1.0.6-beta, `rules.add` and `rules.delete` (and the `rules.list` filters) refuse a value that could be read as anything other than the single token it claims to be. Nothing is run, and resh exits 2 with the error code shown.

| Field | Accepted | Error code |
| ----- | -------- | ---------- |
| `dport`, `sport` | A port 1-65535 or a range `low-high`, in plain decimal | `firewall.invalid_port` |
| `proto` | `tcp`, `udp`, `icmp`, `icmpv6`, `any`, `all`, or a protocol number 0-255 in plain decimal | `firewall.rules_add_invalid_proto` |
| `saddr`, `daddr` | An IPv4 or IPv6 address, optionally with `/prefix` in plain decimal (at most 32 or 128) | `firewall.rules_add_invalid_cidr` |
| `table`, `chain` | Up to 64 characters: letters, digits, `_`, `-`, `.`, starting with a letter or `_` | `firewall.invalid_field` |
| `zone` | As `table`, up to 32 characters | `firewall.invalid_field` |
| `in_iface`, `out_iface` | Up to 15 characters: letters, digits, `_`, `-`, `.`, `:`, `@` | `firewall.invalid_field` |
| `comment` | Up to 128 characters: letters, digits, space and `_.,:/=+@-` | `firewall.invalid_field` |
| `log_prefix` | 1 to 29 characters of the `comment` set | `firewall.invalid_field` |
| `rate_limit` | `<count>/<unit>`, unit `second`, `minute`, `hour`, `day` or `sec`, `min`, `s`, `m`, `h`, `d` | `firewall.invalid_field` |
| `rule_id` | Up to 1024 characters, no control characters | `firewall.invalid_field` |
| `to` | One address with an optional plain-decimal port or range (see [NAT](#nat)) | `firewall.invalid_field` |

"Plain decimal" means digits only, with no leading zero: `22` and `/10` are accepted, `022` and `/010` are refused. Backends read a leading-zero number as octal (`022` is port 18), so resh does not guess.

A rule that the chosen backend cannot write in full is refused with `firewall.unsupported_option` (exit 2), instead of being written without the option, which would make it broader than requested:

* `sport`/`dport` need `proto=tcp` or `proto=udp`.
* NAT rules as described in [NAT](#nat) (ufw refuses NAT; firewalld refuses `snat`).
* `zone` is refused outside firewalld; firewalld requires it (`firewall.rules_add_zone_required`).
* On ufw and firewalld: `sport`, `in_iface`, `out_iface`, `rate_limit`, `log_prefix`, `table`, `chain` and `position=insert` are refused, `direction` must be `input` (ufw also allows `output`), and `action` must be `accept`, `drop` or `reject`, except firewalld's `dnat` (prerouting) and `masquerade` (postrouting). firewalld also refuses `comment`.

### rules.delete

```bash
resh firewall://.rules.delete rule_id=INPUT:3 dry_run=true
resh firewall://.rules.delete backend=iptables direction=input proto=tcp dport=22 dry_run=true
```

* `rule_id` is the id that `rules.delete` reports in `matched_rules` (run it with filters and `dry_run=true` to see the ids; `rules.list` does not print them): `CHAIN:LINE` for iptables, the handle for nftables, the rule number for ufw, `ZONE:KIND:VALUE` for firewalld. Any filters given with it must also hold. An id found in more than one family or table is refused (`firewall.rules_delete_ambiguous_rule_id`, exit 1); add `family=` or `table=`. A malformed id is `firewall.rules_delete_invalid_rule_id` (exit 2).
* Without `rule_id`, at least one filter is required (`firewall.rules_delete_missing_criteria`, exit 2). `match_mode=exact` (default) selects rules whose fields equal the given ones and that have no other match conditions; `match_mode=subset` selects every rule the filters fit. `match_mode` cannot be given with `rule_id`. **Review a `subset` delete with `dry_run=true` first.**
* Other options: `limit=<n>` (delete at most n of the matches), `require_match` (default `true`; no match is then `firewall.rules_delete_no_match`, exit 1), `zone` (firewalld only), `family`, `table`, `to` (NAT target filter), `timeout_ms` (default 30000), `format_output`.
* iptables rules are deleted by their full rule specification; ufw rules by number, highest first; nftables rules by handle; firewalld rules by their rich-rule, service, port or source text.
* A rule's `action` is read from the rule itself, never from its comment, so `action=accept` cannot select a `drop` rule whose comment mentions "accept".
* If a delete command fails, `result.deleted_count` says how many were deleted before it.
* Filter values are validated as for `rules.add` (see [Input validation](#input-validation)).

### rules.save

```bash
resh firewall://.rules.save backend=iptables path=/var/backups/firewall.json
```

Options: `path` (required unless `dry_run`; `firewall.path_required`, exit 2), `format=normalized_json|backend_native|both` (default `normalized_json`), `compress=none|gzip`, `include_metadata` (default `true`), `include_all_backends` (default `false`), `backend`, `family`, `overwrite` (default `false`; an existing file is `firewall.rules_save_path_exists`, exit 1), `create_dirs` (default `true`; otherwise a missing directory is `firewall.rules_save_missing_directory`), `dry_run`, `timeout_ms` (default 30000), `format_output`. `format` is the file content; `format_output` is the response format.

* The snapshot is `{"version": 1, "backend_mode": "single"|"multi", "backends": [...], "metadata": {...}}`. Each `backends` entry has `backend`, `family`, `host`, `timestamp_unix_ms`, `rules` (normalized) and, with `backend_native` or `both`, `native: {"format", "data"}` (`iptables-save`/`ip6tables-save` output, `nft list ruleset`, `ufw status numbered`, or `firewall-cmd --list-all-zones`).
* iptables with `family=any` gives one entry per family (`ipv4`, `ipv6`), each with its own native data. `include_all_backends=true` saves every installed backend (firewalld only when running).
* The file is written owner-only (mode 0600) to a new temporary file in the same directory and renamed into place. A directory it creates is mode 0700. A symlink at `path` is replaced, never written through. Path checks (`overwrite`, `create_dirs`) happen before any backend is read.

### rules.reload

```bash
resh firewall://.rules.reload backend=ufw dry_run=true
resh firewall://.rules.reload backend=iptables family=ipv4 source_format=backend_native path=/var/backups/iptables.rules dry_run=true
```

* Without `path`: runs `ufw reload` or `firewall-cmd --reload`. iptables and nftables need `path` (`firewall.path_required`, exit 2).
* With `path` (iptables and nftables only; on ufw/firewalld `path` is `firewall.unsupported_option`): `source_format=auto` (default) reads a `rules.save` snapshot (also gzip-compressed) as `normalized_json` and anything else as `backend_native`.
  * A backend-native iptables file holds one family: give `family=ipv4` or `family=ipv6` (`firewall.invalid_argument` otherwise). It is applied with `iptables-restore <file>` / `ip6tables-restore <file>`.
  * A backend-native nftables file is applied with `nft -f <file>`, as written (put `flush ruleset` at its top to replace the ruleset). `family` must stay `any`.
  * A snapshot is applied from its native data: for iptables every family it holds (or the one asked for), for nftables the whole ruleset, preceded by `flush ruleset` so it replaces the live ruleset. A snapshot without native data for the backend is `firewall.snapshot_native_missing`; a file that is not a snapshot with `source_format=normalized_json` is `firewall.invalid_snapshot` (both exit 1). The data is passed through an owner-only temporary file in `/var/backups/firewall/` that is removed afterwards (never in `/tmp`).
  * A missing file is `firewall.path_not_found` (exit 1).
* `backup_before_apply` (default `true`) backs up the current rules first (see section 4).
* `validate_only=true` checks without applying: `iptables-restore --test`, `nft -c -f`, or `firewall-cmd --check-config` (firewalld without path). ufw has no check (`firewall.unsupported_option`).

### enable / disable

```bash
resh firewall://.enable backend=ufw dry_run=true
resh firewall://.enable backend=nftables path=/etc/nftables.conf dry_run=true
resh firewall://.disable backend=iptables family=ipv4 dry_run=true
```

Options: `path`, `backend`, `family`, `source_format`, `dry_run`, `validate_only`, `backup_before_apply` (default `true`), `fail_if_already_enabled` / `fail_if_already_disabled` (default `false`), `timeout_ms` (default 60000), `format_output`.

| Backend    | `enable`                                              | `disable`                                               |
| ---------- | ----------------------------------------------------- | ------------------------------------------------------- |
| ufw        | `ufw --force enable`                                  | `ufw --force disable`                                   |
| firewalld  | `systemctl enable firewalld`, then `systemctl start firewalld` | `systemctl stop firewalld`                     |
| iptables   | load `path` (as `rules.reload`)                       | without `path`: set INPUT/OUTPUT/FORWARD policy to ACCEPT and flush the filter, nat, and mangle tables, for each family `family` covers whose tool is installed; with `path`: load it |
| nftables   | load `path` (as `rules.reload`)                       | without `path`: `nft flush ruleset`; with `path`: load it |

* The previous state is read first, also in a dry run, and reported as `previous_state`; `current_state` is read again after a change.
* `enable` on iptables or nftables with no rules active needs `path` (`firewall.path_required`, exit 2).
* If the backend is already enabled (disabled) and no `path` is given, nothing is changed and the result has `already_enabled` (`already_disabled`) `true`. With `path`, the file is loaded anyway. `fail_if_already_enabled=true` / `fail_if_already_disabled=true` turn an already-enabled (disabled) backend into a failure (`firewall.already_enabled` / `firewall.already_disabled`, exit 1), with or without `path`.
* ufw and firewalld take no `path`, `validate_only` or `family` other than `any` (`firewall.unsupported_option`).
* `source_format` and `family` with `path` work as for `rules.reload`; `validate_only=true` checks `path` with the backend's own tool and changes nothing.
* **`disable` without `path` removes all filtering.** On a remote host make sure that is what you want.
* After `disable` on firewalld, `backend=auto` no longer finds firewalld (it is not running); give `backend=firewalld` to enable it again.

---

## 4. Backups (`backup_before_apply`)

`enable`, `disable`, and file-based `rules.reload` on **iptables and nftables**:

* With `backup_before_apply=true` (the default), the current rules (`iptables-save`, `ip6tables-save` for each family about to change, or `nft list ruleset`) are written to a **new** file in `/var/backups/firewall/` **before anything is changed**. `actions` lists each backup and `result.backup_path` is the first one; it exists on disk.
* An nftables backup starts with `flush ruleset`, so `rules.reload path=<backup>` replaces the ruleset with it. An iptables backup is `iptables-save` output; reload it with `family=ipv4` or `family=ipv6`.
* The backup file is created with mode 0600, never overwrites an existing file (`create_new`), and is not opened through a symlink. The directory is created with mode 0700 if missing; a symlinked or non-directory `/var/backups/firewall` is refused.
* **If the backup cannot be taken, nothing is changed** and the command fails: `firewall.rules_save_failed` when the rules cannot be read, `firewall.io_error` when the file cannot be written.
* If the change fails after the backup, the failure still reports `result.backup_path`.
* A dry run writes no backup; its `actions` say "backup -> new file in /var/backups/firewall/ (not written in dry run)". `validate_only` takes no backup.

**ufw and firewalld take no backup.** `enable`, `disable` and `rules.reload` on them add the warning "backup_before_apply is not supported for ufw; no backup was taken" (or firewalld) unless `backup_before_apply=false`. Save the configuration yourself first if you need it.

---

## 5. Timeouts

`timeout_ms` is accepted by every verb and is **one deadline for the whole verb**: every backend command gets only the time that is left. Each command runs in its own process group, and when the deadline passes resh stops the command and every process it started; a command that would start after the deadline is not started. resh then exits with status **124** and prints `Error: [firewall.timeout] outcome unknown: <tool> was stopped; it may already have made changes, so check before retrying` (or `was not started; nothing was done`) on stderr; the JSON result carries `firewall.timeout`.

When the deadline (or a failure) hits a change that was under way, `error.details` reports its progress:

* `applied`: the steps that completed (for `enable`/`disable`/`rules.reload` including `backup -> <path>` entries);
* `stopped_at`: the step that was running (after a timeout its outcome is unknown);
* `not_applied`: the steps that were never started;
* `backup_taken` and `backup_path` (`enable`, `disable`, `rules.reload`).

`rules.add` and `rules.delete` report the same `applied`/`stopped_at`/`not_applied` for their backend commands. A timeout while the state or rules were still being read changed nothing and has no progress report. Check the firewall state before you retry.

| Verbs                                              | Default  |
| -------------------------------------------------- | -------- |
| `status`, `rules.list`, `rules.add`, `rules.delete`, `rules.save` | 30000 ms |
| `rules.reload`, `enable`, `disable`                | 60000 ms |

firewalld listings run several `firewall-cmd` calls per zone, so give firewalld verbs room.

---

## 6. dry_run

`dry_run` is accepted by `rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `enable`, and `disable`. A dry run reads the current state and rules (so it also needs the privileges to read them) but changes nothing and writes no file or backup. `status` and `rules.list` refuse `dry_run=true` (exit 2).

---

## 7. Output, Errors, and Exit Codes

Failures produce a JSON object with `"ok": false` and an `error` object on stdout, and the line `Error: [<code>] <message>` on stderr, for example:

```json
{
  "ok": false,
  "error": {
    "code": "firewall.invalid_argument",
    "details": {},
    "message": "invalid value for backend: \"bogus\" (expected auto, iptables, nftables, ufw, firewalld)"
  },
  "warnings": []
}
```

```text
Error: [firewall.invalid_argument] invalid value for backend: "bogus" (expected auto, iptables, nftables, ufw, firewalld)
```

The error object is `{"code", "message", "details"}`; for a change that failed or timed out part-way, `details` carries the progress report of section 5. Verbs that fail after they started also report their usual fields (`query`, `actions`, `previous_state`, `result`, ...); a refusal of the arguments carries only `ok`, `error` and `warnings`.

| Exit status | Meaning                                                   |
| ----------- | --------------------------------------------------------- |
| 0           | Success (`"ok": true`)                                    |
| 1           | The operation failed: refused or failed by the system or backend, not found, partial failure |
| 2           | Invalid arguments or a request the backend cannot express; nothing was done |
| 124         | A backend command reached its deadline and was stopped; the outcome is unknown (see section 5) |

### Error codes

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `firewall.invalid_argument` | 2 | Unknown option, bad value or combination (section 2), or a native iptables file without `family=ipv4`/`ipv6` |
| `firewall.unknown_verb` | 2 | No such verb |
| `firewall.invalid_port` | 2 | Bad `sport`/`dport` |
| `firewall.rules_add_invalid_proto` | 2 | Bad `proto` |
| `firewall.rules_add_invalid_cidr` | 2 | Bad `saddr`/`daddr` |
| `firewall.invalid_field` | 2 | Bad `table`, `chain`, `zone`, interface, `comment`, `log_prefix`, `rate_limit` or `rule_id` |
| `firewall.rules_add_zone_required` | 2 | A firewalld rule needs `zone` |
| `firewall.rules_add_family_mismatch` | 2 | `family` differs from the address family |
| `firewall.rules_delete_invalid_rule_id` | 2 | `rule_id` does not have the backend's id form |
| `firewall.rules_delete_missing_criteria` | 2 | `rules.delete` without `rule_id` or a filter |
| `firewall.unsupported_option` | 2 | The backend cannot carry out an option (section 3) |
| `firewall.path_required` | 2 | `path` is needed (`rules.save`, file reload, `enable` with no rules active, `validate_only`) |
| `firewall.no_backend_available` | 1 | `backend=auto` found none (the message says why) |
| `firewall.backend_unavailable` | 1 | The given backend's tool is not installed |
| `firewall.tool_not_found` | 1 | A tool needed for this step is not installed |
| `firewall.command_failed` | 1 | A backend command exited non-zero (`details` has the command, exit code and stderr) |
| `firewall.permission_denied` | 1 | A backend command failed for lack of privileges |
| `firewall.chain_not_found` | 1 | nftables has no chain for the rule |
| `firewall.max_rules_exceeded` | 1 | More rules match than `max_rules` |
| `firewall.rules_add_idempotency_check_failed` | 1 | The existing rules could not be read for `idempotent=true` |
| `firewall.rules_delete_no_match` | 1 | Nothing matched and `require_match=true` |
| `firewall.rules_delete_list_failed` | 1 | The rules could not be read for the delete |
| `firewall.rules_delete_ambiguous_rule_id` | 1 | `rule_id` matches more than one rule |
| `firewall.rules_delete_rule_id_unavailable` | 1 | A matched rule cannot be addressed by a delete command |
| `firewall.rules_save_path_exists` | 1 | `path` exists and `overwrite=false` |
| `firewall.rules_save_missing_directory` | 1 | The directory is missing and `create_dirs=false` |
| `firewall.rules_save_failed` | 1 | The rules could not be read for a backup |
| `firewall.io_error` | 1 | A file could not be written or read (snapshot, backup, temporary file) |
| `firewall.path_not_found` | 1 | The rules file given by `path` does not exist or cannot be read |
| `firewall.invalid_snapshot` | 1 | The file is not a usable `rules.save` snapshot |
| `firewall.snapshot_native_missing` | 1 | The snapshot has no native data for the backend (and family) |
| `firewall.already_enabled` | 1 | Already enabled and `fail_if_already_enabled=true` |
| `firewall.already_disabled` | 1 | Already disabled and `fail_if_already_disabled=true` |
| `firewall.internal_error` | 1 | An unexpected internal failure |
| `firewall.timeout` | 124 | A backend command reached its deadline; the outcome is unknown |

---

## 8. Limitations

* Rule matching and idempotence use the fields resh models (table/chain, direction, action, protocol, ports, addresses, interfaces, NAT target). iptables rules with other match extensions are recognized as narrower; nftables rules with other expressions (`ct state`, sets) are compared on the modeled fields only.
* firewalld `rules.add` changes the runtime configuration only.
* `rules.save` native data for ufw and firewalld is their status listing, which `rules.reload` cannot apply (it reloads ufw/firewalld from their own configuration).
* Input validation, `rules.add`, `rules.delete`, `rules.save`, `rules.reload`, `status`, `enable` and `disable` are tested against real nftables, iptables (nf_tables) and ufw in disposable containers, and against firewalld running in a container (with and without systemd). iptables-legacy needs the kernel's legacy `ip_tables` modules; it is tested only where the test host provides them.

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
