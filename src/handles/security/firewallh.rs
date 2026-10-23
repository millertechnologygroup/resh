use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// ===========================================================================
// Error Code Constants
// ===========================================================================

// Status operation error codes
const FIREWALL_STATUS_INVALID_BACKEND: &str = "firewall.status_invalid_backend";
const FIREWALL_STATUS_INVALID_FAMILY: &str = "firewall.status_invalid_family";
const FIREWALL_STATUS_NO_BACKEND_AVAILABLE: &str = "firewall.status_no_backend_available";
const FIREWALL_STATUS_BACKEND_UNAVAILABLE: &str = "firewall.status_backend_unavailable";
const FIREWALL_STATUS_COMMAND_FAILED: &str = "firewall.status_command_failed";
const FIREWALL_STATUS_TIMEOUT: &str = "firewall.status_timeout";
const FIREWALL_STATUS_METRICS_ERROR: &str = "firewall.status_metrics_error";
const FIREWALL_STATUS_INTERNAL_ERROR: &str = "firewall.status_internal_error";

// Enable operation error codes
const FIREWALL_ENABLE_INVALID_BACKEND: &str = "firewall.enable_invalid_backend";
const FIREWALL_ENABLE_INVALID_FAMILY: &str = "firewall.enable_invalid_family";
const FIREWALL_ENABLE_INVALID_SOURCE_FORMAT: &str = "firewall.enable_invalid_source_format";
const FIREWALL_ENABLE_PATH_REQUIRED: &str = "firewall.enable_path_required";
const FIREWALL_ENABLE_PATH_NOT_FOUND: &str = "firewall.enable_path_not_found";
const FIREWALL_ENABLE_NO_BACKEND_AVAILABLE: &str = "firewall.enable_no_backend_available";
const FIREWALL_ENABLE_BACKEND_UNAVAILABLE: &str = "firewall.enable_backend_unavailable";
const FIREWALL_ENABLE_ALREADY_ENABLED: &str = "firewall.enable_already_enabled";
const FIREWALL_ENABLE_FIREWALLD_START_FAILED: &str = "firewall.enable_firewalld_start_failed";
const FIREWALL_ENABLE_COMMAND_FAILED: &str = "firewall.enable_command_failed";
const FIREWALL_ENABLE_TIMEOUT: &str = "firewall.enable_timeout";
const FIREWALL_ENABLE_SERIALIZE_ERROR: &str = "firewall.enable_serialize_error";
const FIREWALL_ENABLE_FORMAT_MISMATCH: &str = "firewall.enable_format_mismatch";
const FIREWALL_ENABLE_BACKEND_NATIVE_MISSING: &str = "firewall.enable_backend_native_missing";
const FIREWALL_ENABLE_INTERNAL_ERROR: &str = "firewall.enable_internal_error";

// Disable operation error codes
const FIREWALL_DISABLE_INVALID_BACKEND: &str = "firewall.disable_invalid_backend";
const FIREWALL_DISABLE_INVALID_FAMILY: &str = "firewall.disable_invalid_family";
const FIREWALL_DISABLE_INVALID_SOURCE_FORMAT: &str = "firewall.disable_invalid_source_format";
const FIREWALL_DISABLE_PATH_NOT_FOUND: &str = "firewall.disable_path_not_found";
const FIREWALL_DISABLE_NO_BACKEND_AVAILABLE: &str = "firewall.disable_no_backend_available";
const FIREWALL_DISABLE_BACKEND_UNAVAILABLE: &str = "firewall.disable_backend_unavailable";
const FIREWALL_DISABLE_ALREADY_DISABLED: &str = "firewall.disable_already_disabled";
const FIREWALL_DISABLE_COMMAND_FAILED: &str = "firewall.disable_command_failed";
const FIREWALL_DISABLE_TIMEOUT: &str = "firewall.disable_timeout";
const FIREWALL_DISABLE_FIREWALLD_STOP_FAILED: &str = "firewall.disable_firewalld_stop_failed";
const FIREWALL_DISABLE_SERIALIZE_ERROR: &str = "firewall.disable_serialize_error";
const FIREWALL_DISABLE_FORMAT_MISMATCH: &str = "firewall.disable_format_mismatch";
const FIREWALL_DISABLE_BACKEND_NATIVE_MISSING: &str = "firewall.disable_backend_native_missing";
const FIREWALL_DISABLE_BACKUP_FAILED: &str = "firewall.disable_backup_failed";
const FIREWALL_DISABLE_BACKUP_RESTORE_FAILED: &str = "firewall.disable_backup_restore_failed";
const FIREWALL_DISABLE_INTERNAL_ERROR: &str = "firewall.disable_internal_error";

// ===========================================================================
// Registration Function
// ===========================================================================

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("firewall", |u| Ok(Box::new(FirewallHandle::from_url(u)?)));
}

/// Metadata for `resh firewall --help` and `resh firewall <verb> --help`.
static FIREWALL_HELP: HandleHelp = HandleHelp {
    description: "The firewall handle lists, adds, and deletes firewall rules, saves and \
        reloads rule sets, and reports, enables, or disables the host firewall. It drives \
        the iptables, nftables, ufw, and firewalld command-line tools, detecting an \
        available backend automatically unless backend is given. The URL has no target, \
        so every stage takes the form firewall://.<verb> followed by key=value arguments.",
    usage: "resh firewall://.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "status",
            definition: "Reports whether firewall backends are available, active, and \
                enabled, with their default policy and rule counts, as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.status\n  \
                    [backend=auto|all|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6] [include_metrics=true|false]\n  \
                    [include_rules_summary=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.status backend=nftables \
                    include_metrics=false",
                example_output: Some(
                    r#"{
  "backends": [
    {
      "active": true,
      "available": true,
      "backend": "nftables",
      "default_policy": "DROP",
      "details": null,
      "enabled": true,
      "rule_count_ipv4": 4,
      "rule_count_ipv6": 2,
      "warnings": []
    }
  ],
  "error": null,
  "ok": true,
  "query": {
    "backend": "nftables",
    "family": "any",
    "include_metrics": false,
    "include_rules_summary": false,
    "timeout_ms": 5000
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": []
}

Shown for an nftables host with --json-pretty. With include_metrics=true,
details holds a one-line summary of the ruleset."#,
                ),
            }),
        },
        VerbHelp {
            name: "rules.list",
            definition: "Lists the rules of one backend as JSON, optionally filtered by \
                table, chain, direction, action, protocol, port, address, interface, or \
                comment text.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.rules.list\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6] [table=<table>] [chain=<chain>]\n  \
                    [direction=<direction>] [action=<action>] [proto=<proto>]\n  \
                    [sport=<port>] [dport=<port>] [saddr=<cidr>] [daddr=<cidr>]\n  \
                    [in_iface=<iface>] [out_iface=<iface>] [comment_contains=<text>]\n  \
                    [include_backend_raw=true|false] [include_counters=true|false]\n  \
                    [max_rules=<n>] [timeout_ms=<ms>] [format_output=json|text]",
                example: "resh --json-pretty firewall://.rules.list family=ipv4 dport=22",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "action": null,
    "backend": "auto",
    "chain": null,
    "comment_contains": null,
    "daddr": null,
    "direction": null,
    "dport": "22",
    "family": "ipv4",
    "format_output": "json",
    "in_iface": null,
    "include_backend_raw": false,
    "include_counters": false,
    "max_rules": 10000,
    "out_iface": null,
    "proto": null,
    "saddr": null,
    "sport": null,
    "table": null,
    "timeout_ms": 5000
  },
  "rules": [
    {
      "action": "accept",
      "backend": "iptables",
      "bytes": null,
      "chain": "INPUT",
      "comment": null,
      "daddr": null,
      "direction": "input",
      "dport": "22",
      "family": "ipv4",
      "in_iface": null,
      "out_iface": null,
      "packets": null,
      "priority": 3,
      "proto": "tcp",
      "raw": null,
      "saddr": "203.0.113.0/24",
      "sport": null,
      "table": "filter"
    }
  ],
  "summary": {
    "backend": "iptables",
    "family": "ipv4",
    "filtered_rules": 1,
    "total_rules": 6
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": []
}

Shown for a host where iptables is detected, with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "rules.add",
            definition: "Adds a rule to the selected backend, for IPv4 and IPv6 alike when \
                family=any is given without an address, skipping any rule that already \
                exists unless idempotent=false is given.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.rules.add\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=ipv4|ipv6|any]\n  \
                    [direction=input|output|forward|prerouting|postrouting]\n  \
                    [action=accept|drop|reject|log|masquerade|dnat|snat|redirect]\n  \
                    [table=<table>] [chain=<chain>] [proto=<proto>] [sport=<port>]\n  \
                    [dport=<port>] [saddr=<cidr>] [daddr=<cidr>] [in_iface=<iface>]\n  \
                    [out_iface=<iface>] [zone=<zone>] [log_prefix=<text>]\n  \
                    [rate_limit=<rate>] [comment=<text>] [position=append|insert]\n  \
                    [dry_run=true|false] [idempotent=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.rules.add proto=tcp dport=22 \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "backend_commands": [
    "iptables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT"
  ],
  "error": null,
  "ok": true,
  "query": {
    "action": "accept",
    "backend": "auto",
    "chain": null,
    "comment": null,
    "daddr": null,
    "direction": "input",
    "dport": "22",
    "dry_run": true,
    "family": "ipv4",
    "format_output": "json",
    "idempotent": true,
    "in_iface": null,
    "log_prefix": null,
    "out_iface": null,
    "position": "append",
    "proto": "tcp",
    "rate_limit": null,
    "saddr": null,
    "sport": null,
    "table": null,
    "timeout_ms": 5000,
    "zone": null
  },
  "result": {
    "already_exists": false,
    "changed": false
  },
  "rule": {
    "action": "accept",
    "backend": "iptables",
    "chain": "INPUT",
    "comment": null,
    "daddr": "0.0.0.0/0",
    "direction": "input",
    "dport": "22",
    "family": "ipv4",
    "in_iface": null,
    "log_prefix": null,
    "out_iface": null,
    "proto": "tcp",
    "rate_limit": null,
    "saddr": "0.0.0.0/0",
    "sport": null,
    "table": "filter",
    "zone": null
  },
  "rules": [
    {
      "action": "accept",
      "backend": "iptables",
      "chain": "INPUT",
      "comment": null,
      "daddr": "0.0.0.0/0",
      "direction": "input",
      "dport": "22",
      "family": "ipv4",
      "in_iface": null,
      "log_prefix": null,
      "out_iface": null,
      "proto": "tcp",
      "rate_limit": null,
      "saddr": "0.0.0.0/0",
      "sport": null,
      "table": "filter",
      "zone": null
    }
  ],
  "timestamp_unix_ms": 1792166145850,
  "warnings": [
    "Dry run: no firewall changes applied."
  ]
}

Shown for a host where iptables is detected, with --json-pretty. family
defaults to ipv4. With family=any and no address, iptables and nftables get
one rule per family: rules lists both and rule is null. A saddr or daddr sets
the family; an explicit family that differs is rejected
(firewall.rules_add_family_mismatch). sport and dport need proto=tcp or
proto=udp, and zone applies only to firewalld (firewall.unsupported_option)."#,
                ),
            }),
        },
        VerbHelp {
            name: "rules.delete",
            definition: "Deletes the rule given by rule_id or every rule that matches the \
                given filters, or only reports them and the backend commands when \
                dry_run=true is given.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.rules.delete\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6] [rule_id=<id>] [match_mode=exact|subset]\n  \
                    [zone=<zone>] [table=<table>] [chain=<chain>]\n  \
                    [direction=<direction>] [action=<action>] [proto=<proto>]\n  \
                    [sport=<port>] [dport=<port>] [saddr=<cidr>] [daddr=<cidr>]\n  \
                    [in_iface=<iface>] [out_iface=<iface>] [comment_contains=<text>]\n  \
                    [limit=<n>] [dry_run=true|false] [require_match=true|false]\n  \
                    [timeout_ms=<ms>] [format_output=json|text]",
                example: "resh --json-pretty firewall://.rules.delete rule_id=INPUT:3 \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "backend_commands": [
    "iptables -t filter -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT"
  ],
  "error": null,
  "matched_rules": [
    {
      "action": "accept",
      "backend": "iptables",
      "chain": "INPUT",
      "comment": null,
      "daddr": null,
      "direction": "input",
      "dport": "22",
      "family": "ipv4",
      "in_iface": null,
      "out_iface": null,
      "proto": "tcp",
      "rule_id": "INPUT:3",
      "saddr": null,
      "sport": null,
      "table": "filter"
    }
  ],
  "ok": true,
  "query": {
    "action": null,
    "backend": "auto",
    "chain": null,
    "comment_contains": null,
    "daddr": null,
    "direction": null,
    "dport": null,
    "dry_run": true,
    "family": "any",
    "format_output": "json",
    "in_iface": null,
    "limit": null,
    "match_mode": "exact",
    "out_iface": null,
    "proto": null,
    "require_match": true,
    "rule_id": "INPUT:3",
    "saddr": null,
    "sport": null,
    "table": null,
    "timeout_ms": 5000,
    "zone": null
  },
  "result": {
    "deleted_count": 0,
    "skipped_count": 0
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": [
    "Dry run: no firewall changes applied."
  ]
}

Shown for a host where iptables is detected, with --json-pretty. rule_id is
the id rules.delete reports: CHAIN:LINE for iptables (the line within its
table and chain), the handle for nftables, the rule number for ufw, and
ZONE:KIND:VALUE for firewalld. iptables rules are deleted by their full rule
specification. Without rule_id, match_mode=exact (the default) selects rules
whose proto, ports, addresses and interfaces equal the given ones and that
have no other match conditions; subset selects every rule the filters fit.
zone limits a firewalld delete to one zone and is rejected for other
backends. At least one filter or rule_id is required. A rule_id found in
more than one family or table is rejected; add family= or table=."#,
                ),
            }),
        },
        VerbHelp {
            name: "rules.save",
            definition: "Saves a snapshot of the current rules to the file given by path, as \
                normalized JSON, backend-native data, or both.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.rules.save path=<file>\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6] [include_all_backends=true|false]\n  \
                    [format=normalized_json|backend_native|both] [compress=none|gzip]\n  \
                    [include_metadata=true|false] [dry_run=true|false]\n  \
                    [overwrite=true|false] [create_dirs=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.rules.save \
                    path=/var/backups/firewall.json",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "backend": "auto",
    "compress": "none",
    "create_dirs": true,
    "dry_run": false,
    "family": "any",
    "format": "normalized_json",
    "format_output": "json",
    "include_all_backends": false,
    "include_metadata": true,
    "overwrite": false,
    "path": "/var/backups/firewall.json",
    "timeout_ms": 5000
  },
  "summary": {
    "backends": [
      {
        "backend": "iptables",
        "family": "any",
        "has_native": false,
        "rules_count": 12
      }
    ],
    "bytes_written": 4821,
    "compressed": false,
    "path": "/var/backups/firewall.json"
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": []
}

Shown for a host where iptables is detected, with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "rules.reload",
            definition: "Reloads rules through the backend's own reload command for ufw or \
                firewalld, or applies the saved rules file given by path.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.rules.reload [path=<file>]\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6]\n  \
                    [source_format=auto|backend_native|normalized_json]\n  \
                    [dry_run=true|false] [validate_only=true|false]\n  \
                    [backup_before_apply=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.rules.reload backend=ufw \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "actions": [
    "ufw reload"
  ],
  "backend": "ufw",
  "error": null,
  "family": "any",
  "mode": "backend_reload",
  "ok": true,
  "query": {
    "backend": "ufw",
    "backup_before_apply": true,
    "dry_run": true,
    "family": "any",
    "format_output": "json",
    "path": null,
    "source_format": "auto",
    "timeout_ms": 10000,
    "validate_only": false
  },
  "result": {
    "backup_path": null,
    "changed": false
  },
  "source": {
    "path": null,
    "source_format": null
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": [
    "Dry run: ufw reload not executed."
  ]
}

Shown for a ufw host with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "enable",
            definition: "Enables the firewall backend, starting ufw or firewalld or loading \
                the rules file given by path for iptables or nftables.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.enable [path=<file>]\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6]\n  \
                    [source_format=auto|backend_native|normalized_json]\n  \
                    [dry_run=true|false] [validate_only=true|false]\n  \
                    [backup_before_apply=true|false]\n  \
                    [fail_if_already_enabled=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.enable backend=ufw dry_run=true",
                example_output: Some(
                    r#"{
  "actions": [
    "backup ufw configuration",
    "ufw --force enable"
  ],
  "backend": "ufw",
  "current_state": {
    "active": false,
    "available": true,
    "enabled": false
  },
  "error": null,
  "ok": true,
  "previous_state": {
    "active": false,
    "available": true,
    "enabled": false
  },
  "query": {
    "backend": "ufw",
    "backup_before_apply": true,
    "dry_run": true,
    "fail_if_already_enabled": false,
    "family": "any",
    "path": null,
    "source_format": "auto",
    "timeout_ms": 10000,
    "validate_only": false
  },
  "result": {
    "already_enabled": false,
    "backup_path": null,
    "changed": false
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": []
}

Shown with --json-pretty. In a dry run the states are assumed, not queried."#,
                ),
            }),
        },
        VerbHelp {
            name: "disable",
            definition: "Disables the firewall backend, stopping ufw or firewalld or \
                flushing iptables or nftables rules unless a rules file is given by path.",
            detail: Some(VerbDetail {
                usage: "resh firewall://.disable [path=<file>]\n  \
                    [backend=auto|iptables|nftables|ufw|firewalld]\n  \
                    [family=any|ipv4|ipv6]\n  \
                    [source_format=auto|backend_native|normalized_json]\n  \
                    [dry_run=true|false] [validate_only=true|false]\n  \
                    [backup_before_apply=true|false]\n  \
                    [fail_if_already_disabled=true|false] [timeout_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh --json-pretty firewall://.disable backend=ufw dry_run=true",
                example_output: Some(
                    r#"{
  "actions": [
    "ufw --force disable"
  ],
  "backend": "ufw",
  "current_state": {
    "active": true,
    "available": true,
    "enabled": true
  },
  "error": null,
  "ok": true,
  "previous_state": {
    "active": true,
    "available": true,
    "enabled": true
  },
  "query": {
    "backend": "ufw",
    "backup_before_apply": true,
    "dry_run": true,
    "fail_if_already_disabled": false,
    "family": "any",
    "format_output": "json",
    "path": null,
    "source_format": "auto",
    "timeout_ms": 10000,
    "validate_only": false
  },
  "result": {
    "already_disabled": false,
    "backup_path": null,
    "changed": false
  },
  "timestamp_unix_ms": 1792166145850,
  "warnings": []
}

Shown for a host with ufw active, with --json-pretty."#,
                ),
            }),
        },
    ],
};

// ===========================================================================
// Core Handle Structure
// ===========================================================================

pub struct FirewallHandle {
    _url: Url,
}

impl FirewallHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(FirewallHandle { _url: url.clone() })
    }

    /// Handles the in-URL help forms (`firewall://--help`, `firewall://-h`,
    /// `firewall://--help=VERB`, and a `help` verb with optional `verb=`),
    /// rendering the same text as `resh firewall [<verb>] --help`.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let requested: Option<String> = if verb == "help" || crate::core::help::is_help_flag(verb) {
            Some(args.get("verb").cloned().unwrap_or_default())
        } else {
            verb.strip_prefix("--help=").map(|v| v.to_string())
        };
        let Some(requested) = requested else {
            return Ok(None);
        };
        let verb_opt = if requested.is_empty() {
            None
        } else {
            Some(requested.as_str())
        };
        let text =
            crate::core::help::render_legacy("firewall", &FIREWALL_HELP, self.verbs(), verb_opt);
        write!(io.stdout, "{}", text)?;
        Ok(Some(Status::ok()))
    }
}

impl Handle for FirewallHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "rules.list",
            "rules.add",
            "rules.delete",
            "rules.save",
            "rules.reload",
            "status",
            "enable",
            "disable",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&FIREWALL_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }

        match verb {
            "rules.list" => self.handle_rules_list(args, io),
            "rules.add" => self.handle_rules_add(args, io),
            "rules.delete" => self.handle_rules_delete(args, io),
            "rules.save" => self.handle_rules_save(args, io),
            "rules.reload" => self.handle_rules_reload(args, io),
            "status" => self.handle_status(args, io),
            "enable" => self.handle_enable(args, io),
            "disable" => self.handle_disable(args, io),
            _ => {
                let error_msg = format!("unsupported verb: {}", verb);
                writeln!(io.stderr, "Error: {}", error_msg)?;
                Ok(Status::err(1, &error_msg))
            }
        }
    }
}

// ===========================================================================
// Core Enumerations
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FirewallBackend {
    Auto,
    Iptables,
    Nftables,
    Ufw,
    Firewalld,
}

impl FirewallBackend {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "iptables" => Ok(Self::Iptables),
            "nftables" => Ok(Self::Nftables),
            "ufw" => Ok(Self::Ufw),
            "firewalld" => Ok(Self::Firewalld),
            _ => bail!(
                "Invalid backend: {}. Must be 'auto', 'iptables', 'nftables', 'ufw', or 'firewalld'",
                s
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IpFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl IpFamily {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => bail!("Invalid family: {}. Must be 'any', 'ipv4', or 'ipv6'", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => bail!("Invalid format: {}. Must be 'json' or 'text'", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RulesSaveFormat {
    NormalizedJson,
    BackendNative,
    Both,
}

impl RulesSaveFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "normalized_json" => Ok(Self::NormalizedJson),
            "backend_native" => Ok(Self::BackendNative),
            "both" => Ok(Self::Both),
            _ => bail!(
                "Invalid format: {}. Must be 'normalized_json', 'backend_native', or 'both'",
                s
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NormalizedJson => "normalized_json",
            Self::BackendNative => "backend_native",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompressMode {
    None,
    Gzip,
}

impl CompressMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            _ => bail!("Invalid compression mode: {}. Must be 'none' or 'gzip'", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RulesReloadSourceFormat {
    Auto,
    BackendNative,
    NormalizedJson,
}

impl RulesReloadSourceFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "backend_native" => Ok(Self::BackendNative),
            "normalized_json" => Ok(Self::NormalizedJson),
            _ => bail!(
                "Invalid source format: {}. Must be 'auto', 'backend_native', or 'normalized_json'",
                s
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::BackendNative => "backend_native",
            Self::NormalizedJson => "normalized_json",
        }
    }
}

// Type alias for enable operation source format (same as reload)
pub type RulesSourceFormat = RulesReloadSourceFormat;

// ===========================================================================
// Status-related Types
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum StatusBackend {
    Auto,
    All,
    Iptables,
    Nftables,
    Ufw,
    Firewalld,
}

impl StatusBackend {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "all" => Ok(Self::All),
            "iptables" => Ok(Self::Iptables),
            "nftables" => Ok(Self::Nftables),
            "ufw" => Ok(Self::Ufw),
            "firewalld" => Ok(Self::Firewalld),
            _ => Err(FirewallError::StatusInvalidBackend {
                backend: s.to_string(),
            }
            .into()),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::All => "all",
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatusFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl StatusFamily {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Self::Any),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(FirewallError::StatusInvalidFamily {
                family: s.to_string(),
            }
            .into()),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirewallBackendStatus {
    pub backend: String,
    pub available: bool,
    pub active: bool,
    pub enabled: bool,
    pub default_policy: Option<String>,
    pub rule_count_ipv4: Option<u64>,
    pub rule_count_ipv6: Option<u64>,
    pub details: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusOptions {
    pub backend: StatusBackend,
    pub family: StatusFamily,
    pub include_metrics: bool,
    pub include_rules_summary: bool,
    pub timeout_ms: u64,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: StatusOptions,
    pub backends: Vec<FirewallBackendStatus>,
    pub error: Option<FirewallError>,
    pub warnings: Vec<String>,
    pub output_format: OutputFormat,
}

impl StatusResponse {
    pub fn success(options: StatusOptions, backends: Vec<FirewallBackendStatus>) -> Self {
        let output_format = options.output_format.clone();
        Self {
            ok: true,
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            query: options,
            backends,
            error: None,
            warnings: Vec::new(),
            output_format,
        }
    }

    pub fn with_error(options: StatusOptions, error: FirewallError) -> Self {
        let output_format = options.output_format.clone();
        Self {
            ok: false,
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64,
            query: options,
            backends: Vec::new(),
            error: Some(error),
            warnings: Vec::new(),
            output_format,
        }
    }

    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    pub fn json_format(&self) -> serde_json::Value {
        let query_json = json!({
            "backend": self.query.backend.as_str(),
            "family": self.query.family.as_str(),
            "include_metrics": self.query.include_metrics,
            "include_rules_summary": self.query.include_rules_summary,
            "timeout_ms": self.query.timeout_ms
        });

        let error_json = self.error.as_ref().map(|e| {
            let full_json = e.to_json();
            // Extract the inner "error" object to avoid double nesting
            full_json.get("error").cloned().unwrap_or(full_json)
        });

        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": query_json,
            "backends": self.backends,
            "error": error_json,
            "warnings": self.warnings
        })
    }

    pub fn text_format(&self) -> String {
        let mut output = String::new();
        output.push_str("Firewall Status\n");
        output.push_str("===============\n\n");

        if !self.ok {
            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                let error_json = error.to_json();
                if let Some(code) = error_json.get("code") {
                    if let Some(message) = error_json.get("message") {
                        output.push_str(&format!(
                            "  [{}] {}\n",
                            code.as_str().unwrap_or("unknown"),
                            message.as_str().unwrap_or("Unknown error")
                        ));
                    }
                }
            }
            return output;
        }

        for backend in &self.backends {
            output.push_str(&format!("Backend: {}\n", backend.backend));
            output.push_str(&format!(
                "  Available : {}\n",
                if backend.available { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Active    : {}\n",
                if backend.active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Enabled   : {}\n",
                if backend.enabled { "yes" } else { "no" }
            ));

            if let Some(policy) = &backend.default_policy {
                output.push_str(&format!("  Default   : {}\n", policy));
            } else {
                output.push_str("  Default   : (n/a)\n");
            }

            if let Some(count) = backend.rule_count_ipv4 {
                output.push_str(&format!("  IPv4 Rules: {}\n", count));
            } else {
                output.push_str("  IPv4 Rules: (n/a)\n");
            }

            if let Some(count) = backend.rule_count_ipv6 {
                output.push_str(&format!("  IPv6 Rules: {}\n", count));
            } else {
                output.push_str("  IPv6 Rules: (n/a)\n");
            }

            if let Some(details) = &backend.details {
                output.push_str(&format!("  Details   : {}\n", details));
            } else {
                output.push_str("  Details   : (none)\n");
            }

            if backend.warnings.is_empty() {
                output.push_str("  Warnings  : (none)\n");
            } else {
                output.push_str("  Warnings  :\n");
                for warning in &backend.warnings {
                    output.push_str(&format!("    - {}\n", warning));
                }
            }

            output.push('\n');
        }

        output
    }
}

// ===========================================================================
// Error Handling
// ===========================================================================

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FirewallError {
    // Parameter validation errors
    #[error("Invalid backend: {backend}")]
    InvalidBackend { backend: String },

    #[error("Invalid family: {family}")]
    InvalidFamily { family: String },

    #[error("Invalid direction: {direction}")]
    InvalidDirection { direction: String },

    #[error("Invalid action: {action}")]
    InvalidAction { action: String },

    #[error("Invalid port: {port}")]
    InvalidPort { port: String },

    #[error("Invalid timeout: {timeout_ms}ms")]
    InvalidTimeout { timeout_ms: u64 },

    #[error("Invalid max_rules: {max_rules}")]
    InvalidMaxRules { max_rules: u64 },

    #[error("Invalid CIDR: {cidr}")]
    InvalidCidr { cidr: String },

    #[error("Invalid protocol: {proto}")]
    InvalidProto { proto: String },

    #[error("Invalid position: {position}")]
    InvalidPosition { position: String },

    #[error("Zone required for firewalld backend")]
    ZoneRequired,

    // Backend availability errors
    #[error("No firewall backend available")]
    NoBackendAvailable,

    #[error("Firewall backend '{backend}' is not available")]
    BackendUnavailable { backend: String },

    #[error("Command '{command}' failed with exit code {code}: {stderr}")]
    CommandFailed {
        command: String,
        code: i32,
        stderr: String,
    },

    #[error("Failed to parse output from '{backend}': {message}")]
    ParseError { backend: String, message: String },

    // Limits
    #[error("Too many rules: {count} exceeds maximum of {max}")]
    MaxRulesExceeded { count: u64, max: u64 },

    // Positioning / Idempotency
    #[error("Position not supported: {message}")]
    PositionNotSupported { message: String },

    #[error("Idempotency check failed: {message}")]
    IdempotencyCheckFailed { message: String },

    // Delete-specific errors
    #[error("Invalid match mode: {match_mode}")]
    InvalidMatchMode { match_mode: String },

    #[error("Invalid rule ID: {rule_id}")]
    InvalidRuleId { rule_id: String },

    #[error("Invalid zone: {zone}")]
    InvalidZone { zone: String },

    #[error("No firewall rules matched the specified criteria")]
    NoRulesMatched,

    #[error("Failed to list rules for deletion: {message}")]
    ListFailedForDelete { message: String },

    #[error("rule_id {rule_id} matches {count} rules; add family= or table= to select one")]
    AmbiguousRuleId { rule_id: String, count: usize },

    #[error("rules.delete needs rule_id or at least one match criterion")]
    MissingDeleteCriteria,

    #[error("Cannot build a delete command for a matched rule: {message}")]
    RuleIdUnavailable { message: String },

    #[error("Option '{option}' is not supported for backend '{backend}': {message}")]
    UnsupportedOption {
        option: String,
        backend: String,
        message: String,
    },

    #[error("Address {address} does not belong to family {family}")]
    FamilyMismatch { family: String, address: String },

    // Rules save specific errors
    #[error("Invalid save format: {format}")]
    InvalidSaveFormat { format: String },

    #[error("Invalid compression mode: {compress}")]
    InvalidCompress { compress: String },

    #[error("Missing path: path is required when dry_run is false")]
    MissingPath,

    #[error("Path already exists: {path}")]
    PathExists { path: String },

    #[error("Missing directory: {path}")]
    MissingDirectory { path: String },

    #[error("Failed to save rules: {message}")]
    SaveFailed { message: String },

    #[error("Failed to compress data: {message}")]
    CompressFailed { message: String },

    #[error("Failed to serialize data: {message}")]
    SerializeFailed { message: String },

    // Status operation errors
    #[error("Invalid backend specified: {backend}")]
    StatusInvalidBackend { backend: String },
    #[error("Invalid IP family specified: {family}")]
    StatusInvalidFamily { family: String },
    #[error("No supported firewall backend available")]
    StatusNoBackendAvailable,
    #[error("Backend unavailable: {backend}")]
    StatusBackendUnavailable { backend: String },
    #[error("Command failed for backend {backend}: {message}")]
    StatusCommandFailed { backend: String, message: String },
    #[error("Command timeout for backend {backend}")]
    StatusTimeout { backend: String },
    #[error("Metrics collection error for backend {backend}: {message}")]
    StatusMetricsError { backend: String, message: String },
    #[error("Internal status error: {message}")]
    StatusInternalError { message: String },

    #[error("I/O error: {message}")]
    IoError { message: String },

    // Rules reload specific errors
    #[error("Invalid reload source format: {format}")]
    InvalidReloadSourceFormat { format: String },

    #[error("Path is required for file-based reload with backend '{backend}'")]
    ReloadPathRequired { backend: String },

    #[error("Path not found or not readable: {path}")]
    ReloadPathNotFound { path: String },

    #[error("File-based reload is not supported for backend '{backend}'")]
    ReloadFileModeNotSupported { backend: String },

    #[error("Failed to reload rules: {message}")]
    ReloadFailed { message: String },

    #[error("Snapshot format mismatch: expected {expected}, found {found}")]
    ReloadFormatMismatch { expected: String, found: String },

    #[error("Backend-native data missing in snapshot for backend '{backend}'")]
    ReloadBackendNativeMissing { backend: String },

    #[error("Reload command timed out after {timeout_ms}ms")]
    ReloadTimeout { timeout_ms: u64 },

    // Disable operation errors
    #[error("Invalid backend specified for disable: {backend}")]
    DisableInvalidBackend { backend: String },
    #[error("Invalid IP family specified for disable: {family}")]
    DisableInvalidFamily { family: String },
    #[error("Invalid source format for disable: {format}")]
    DisableInvalidSourceFormat { format: String },
    #[error("Path not found for disable: {path}")]
    DisablePathNotFound { path: String },
    #[error("No supported firewall backend available for disable")]
    DisableNoBackendAvailable,
    #[error("Backend unavailable for disable: {backend}")]
    DisableBackendUnavailable { backend: String },
    #[error("Firewall backend '{backend}' is already disabled")]
    DisableAlreadyDisabled { backend: String },
    #[error("Disable command failed for backend {backend}: {message}")]
    DisableCommandFailed { backend: String, message: String },
    #[error("Disable operation timed out for backend {backend}")]
    DisableTimeout { backend: String },
    #[error("Failed to stop firewalld: {message}")]
    DisableFirewalldStopFailed { message: String },
    #[error("Failed to serialize disable data: {message}")]
    DisableSerializeError { message: String },
    #[error("Disable format mismatch: expected {expected}, found {found}")]
    DisableFormatMismatch { expected: String, found: String },
    #[error("Backend-native data missing for disable: {backend}")]
    DisableBackendNativeMissing { backend: String },
    #[error("Backup failed during disable: {message}")]
    DisableBackupFailed { message: String },
    #[error("Backup restore failed during disable: {message}")]
    DisableBackupRestoreFailed { message: String },
    #[error("Internal disable error: {message}")]
    DisableInternalError { message: String },

    // Generic
    #[error("Internal error: {message}")]
    InternalError { message: String },
}

impl FirewallError {
    pub fn to_error_code(&self) -> &'static str {
        match self {
            Self::InvalidBackend { .. } => "firewall.invalid_backend",
            Self::InvalidFamily { .. } => "firewall.invalid_family",
            Self::InvalidDirection { .. } => "firewall.invalid_direction",
            Self::InvalidAction { .. } => "firewall.invalid_action",
            Self::InvalidPort { .. } => "firewall.invalid_port",
            Self::InvalidTimeout { .. } => "firewall.invalid_timeout",
            Self::InvalidMaxRules { .. } => "firewall.invalid_max_rules",
            Self::InvalidCidr { .. } => "firewall.rules_add_invalid_cidr",
            Self::InvalidProto { .. } => "firewall.rules_add_invalid_proto",
            Self::InvalidPosition { .. } => "firewall.rules_add_invalid_position",
            Self::ZoneRequired => "firewall.rules_add_zone_required",
            Self::NoBackendAvailable => "firewall.no_backend_available",
            Self::BackendUnavailable { .. } => "firewall.backend_unavailable",
            Self::CommandFailed { .. } => "firewall.command_failed",
            Self::ParseError { .. } => "firewall.parse_error",
            Self::MaxRulesExceeded { .. } => "firewall.max_rules_exceeded",
            Self::PositionNotSupported { .. } => "firewall.rules_add_position_not_supported",
            Self::IdempotencyCheckFailed { .. } => "firewall.rules_add_idempotency_check_failed",
            Self::InvalidMatchMode { .. } => "firewall.rules_delete_invalid_match_mode",
            Self::InvalidRuleId { .. } => "firewall.rules_delete_invalid_rule_id",
            Self::InvalidZone { .. } => "firewall.rules_delete_invalid_zone",
            Self::NoRulesMatched => "firewall.rules_delete_no_match",
            Self::ListFailedForDelete { .. } => "firewall.rules_delete_list_failed",
            Self::AmbiguousRuleId { .. } => "firewall.rules_delete_ambiguous_rule_id",
            Self::MissingDeleteCriteria => "firewall.rules_delete_missing_criteria",
            Self::RuleIdUnavailable { .. } => "firewall.rules_delete_rule_id_unavailable",
            Self::UnsupportedOption { .. } => "firewall.unsupported_option",
            Self::FamilyMismatch { .. } => "firewall.rules_add_family_mismatch",
            Self::InvalidSaveFormat { .. } => "firewall.rules_save_invalid_format",
            Self::InvalidCompress { .. } => "firewall.rules_save_invalid_compress",
            Self::MissingPath => "firewall.rules_save_missing_path",
            Self::PathExists { .. } => "firewall.rules_save_path_exists",
            Self::MissingDirectory { .. } => "firewall.rules_save_missing_directory",
            Self::SaveFailed { .. } => "firewall.rules_save_failed",
            Self::CompressFailed { .. } => "firewall.rules_save_compress_error",
            Self::SerializeFailed { .. } => "firewall.rules_save_serialize_error",
            Self::IoError { .. } => "firewall.rules_save_io_error",
            Self::InvalidReloadSourceFormat { .. } => "firewall.rules_reload_invalid_source_format",
            Self::ReloadPathRequired { .. } => "firewall.rules_reload_path_required",
            Self::ReloadPathNotFound { .. } => "firewall.rules_reload_path_not_found",
            Self::ReloadFileModeNotSupported { .. } => {
                "firewall.rules_reload_file_mode_not_supported"
            }
            Self::ReloadFailed { .. } => "firewall.rules_reload_command_failed",
            Self::ReloadFormatMismatch { .. } => "firewall.rules_reload_format_mismatch",
            Self::ReloadBackendNativeMissing { .. } => {
                "firewall.rules_reload_backend_native_missing"
            }
            Self::ReloadTimeout { .. } => "firewall.rules_reload_timeout",

            // Disable operation error codes
            Self::DisableInvalidBackend { .. } => FIREWALL_DISABLE_INVALID_BACKEND,
            Self::DisableInvalidFamily { .. } => FIREWALL_DISABLE_INVALID_FAMILY,
            Self::DisableInvalidSourceFormat { .. } => FIREWALL_DISABLE_INVALID_SOURCE_FORMAT,
            Self::DisablePathNotFound { .. } => FIREWALL_DISABLE_PATH_NOT_FOUND,
            Self::DisableNoBackendAvailable => FIREWALL_DISABLE_NO_BACKEND_AVAILABLE,
            Self::DisableBackendUnavailable { .. } => FIREWALL_DISABLE_BACKEND_UNAVAILABLE,
            Self::DisableAlreadyDisabled { .. } => FIREWALL_DISABLE_ALREADY_DISABLED,
            Self::DisableCommandFailed { .. } => FIREWALL_DISABLE_COMMAND_FAILED,
            Self::DisableTimeout { .. } => FIREWALL_DISABLE_TIMEOUT,
            Self::DisableFirewalldStopFailed { .. } => FIREWALL_DISABLE_FIREWALLD_STOP_FAILED,
            Self::DisableSerializeError { .. } => FIREWALL_DISABLE_SERIALIZE_ERROR,
            Self::DisableFormatMismatch { .. } => FIREWALL_DISABLE_FORMAT_MISMATCH,
            Self::DisableBackendNativeMissing { .. } => FIREWALL_DISABLE_BACKEND_NATIVE_MISSING,
            Self::DisableBackupFailed { .. } => FIREWALL_DISABLE_BACKUP_FAILED,
            Self::DisableBackupRestoreFailed { .. } => FIREWALL_DISABLE_BACKUP_RESTORE_FAILED,
            Self::DisableInternalError { .. } => FIREWALL_DISABLE_INTERNAL_ERROR,

            Self::InternalError { .. } => "firewall.internal_error",

            // Status operation error codes
            Self::StatusInvalidBackend { .. } => FIREWALL_STATUS_INVALID_BACKEND,
            Self::StatusInvalidFamily { .. } => FIREWALL_STATUS_INVALID_FAMILY,
            Self::StatusNoBackendAvailable => FIREWALL_STATUS_NO_BACKEND_AVAILABLE,
            Self::StatusBackendUnavailable { .. } => FIREWALL_STATUS_BACKEND_UNAVAILABLE,
            Self::StatusCommandFailed { .. } => FIREWALL_STATUS_COMMAND_FAILED,
            Self::StatusTimeout { .. } => FIREWALL_STATUS_TIMEOUT,
            Self::StatusMetricsError { .. } => FIREWALL_STATUS_METRICS_ERROR,
            Self::StatusInternalError { .. } => FIREWALL_STATUS_INTERNAL_ERROR,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "error": {
                "code": self.to_error_code(),
                "message": self.to_string(),
                "details": match self {
                    Self::InvalidBackend { backend } => json!({ "backend": backend }),
                    Self::InvalidFamily { family } => json!({ "family": family }),
                    Self::InvalidDirection { direction } => json!({ "direction": direction }),
                    Self::InvalidAction { action } => json!({ "action": action }),
                    Self::InvalidPort { port } => json!({ "port": port }),
                    Self::InvalidTimeout { timeout_ms } => json!({ "timeout_ms": timeout_ms }),
                    Self::InvalidMaxRules { max_rules } => json!({ "max_rules": max_rules }),
                    Self::InvalidCidr { cidr } => json!({ "cidr": cidr }),
                    Self::InvalidProto { proto } => json!({ "proto": proto }),
                    Self::InvalidPosition { position } => json!({ "position": position }),
                    Self::ZoneRequired => json!({}),
                    Self::BackendUnavailable { backend } => json!({ "backend": backend }),
                    Self::CommandFailed { command, code, stderr } => json!({
                        "command": command,
                        "exit_code": code,
                        "stderr": stderr
                    }),
                    Self::ParseError { backend, message } => json!({
                        "backend": backend,
                        "parse_message": message
                    }),
                    Self::MaxRulesExceeded { count, max } => json!({
                        "rule_count": count,
                        "max_rules": max
                    }),
                    Self::PositionNotSupported { message } => json!({ "message": message }),
                    Self::IdempotencyCheckFailed { message } => json!({ "message": message }),
                    Self::InvalidMatchMode { match_mode } => json!({ "match_mode": match_mode }),
                    Self::InvalidRuleId { rule_id } => json!({ "rule_id": rule_id }),
                    Self::InvalidZone { zone } => json!({ "zone": zone }),
                    Self::NoRulesMatched => json!({}),
                    Self::ListFailedForDelete { message } => json!({ "message": message }),
                    Self::AmbiguousRuleId { rule_id, count } => json!({ "rule_id": rule_id, "count": count }),
                    Self::MissingDeleteCriteria => json!({}),
                    Self::RuleIdUnavailable { message } => json!({ "message": message }),
                    Self::UnsupportedOption { option, backend, message } => json!({
                        "option": option,
                        "backend": backend,
                        "message": message
                    }),
                    Self::FamilyMismatch { family, address } => json!({ "family": family, "address": address }),
                    Self::InvalidSaveFormat { format } => json!({ "format": format }),
                    Self::InvalidCompress { compress } => json!({ "compress": compress }),
                    Self::MissingPath => json!({}),
                    Self::PathExists { path } => json!({ "path": path }),
                    Self::MissingDirectory { path } => json!({ "path": path }),
                    Self::SaveFailed { message } => json!({ "message": message }),
                    Self::CompressFailed { message } => json!({ "message": message }),
                    Self::SerializeFailed { message } => json!({ "message": message }),

                    // Status operation error details
                    Self::StatusInvalidBackend { backend } => json!({ "backend": backend }),
                    Self::StatusInvalidFamily { family } => json!({ "family": family }),
                    Self::StatusNoBackendAvailable => json!({}),
                    Self::StatusBackendUnavailable { backend } => json!({ "backend": backend }),
                    Self::StatusCommandFailed { backend, message } => json!({ "backend": backend, "message": message }),
                    Self::StatusTimeout { backend } => json!({ "backend": backend }),
                    Self::StatusMetricsError { backend, message } => json!({ "backend": backend, "message": message }),
                    Self::StatusInternalError { message } => json!({ "message": message }),
                    Self::IoError { message } => json!({ "message": message }),
                    Self::InvalidReloadSourceFormat { format } => json!({ "format": format }),
                    Self::ReloadPathRequired { backend } => json!({ "backend": backend }),
                    Self::ReloadPathNotFound { path } => json!({ "path": path }),
                    Self::ReloadFileModeNotSupported { backend } => json!({ "backend": backend }),
                    Self::ReloadFailed { message } => json!({ "message": message }),
                    Self::ReloadFormatMismatch { expected, found } => json!({
                        "expected": expected,
                        "found": found
                    }),
                    Self::ReloadBackendNativeMissing { backend } => json!({ "backend": backend }),
                    Self::ReloadTimeout { timeout_ms } => json!({ "timeout_ms": timeout_ms }),

                    // Disable operation error details
                    Self::DisableInvalidBackend { backend } => json!({ "backend": backend }),
                    Self::DisableInvalidFamily { family } => json!({ "family": family }),
                    Self::DisableInvalidSourceFormat { format } => json!({ "format": format }),
                    Self::DisablePathNotFound { path } => json!({ "path": path }),
                    Self::DisableNoBackendAvailable => json!({}),
                    Self::DisableBackendUnavailable { backend } => json!({ "backend": backend }),
                    Self::DisableAlreadyDisabled { backend } => json!({ "backend": backend }),
                    Self::DisableCommandFailed { backend, message } => json!({ "backend": backend, "message": message }),
                    Self::DisableTimeout { backend } => json!({ "backend": backend }),
                    Self::DisableFirewalldStopFailed { message } => json!({ "message": message }),
                    Self::DisableSerializeError { message } => json!({ "message": message }),
                    Self::DisableFormatMismatch { expected, found } => json!({
                        "expected": expected,
                        "found": found
                    }),
                    Self::DisableBackendNativeMissing { backend } => json!({ "backend": backend }),
                    Self::DisableBackupFailed { message } => json!({ "message": message }),
                    Self::DisableBackupRestoreFailed { message } => json!({ "message": message }),
                    Self::DisableInternalError { message } => json!({ "message": message }),

                    Self::InternalError { message } => json!({ "message": message }),
                    Self::NoBackendAvailable => json!({}),
                }
            }
        })
    }
}

// ===========================================================================
// Core Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RulesListOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,

    // Filters
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: Option<String>,
    pub action: Option<String>,
    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
    pub comment_contains: Option<String>,

    // Behavior
    pub include_backend_raw: bool,
    pub include_counters: bool,
    pub max_rules: u64,
    pub timeout_ms: u64,

    // Output
    pub format_output: OutputFormat,
}

impl Default for RulesListOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            table: None,
            chain: None,
            direction: None,
            action: None,
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment_contains: None,
            include_backend_raw: false,
            include_counters: false,
            max_rules: 10000,
            timeout_ms: 5000,
            format_output: OutputFormat::Json,
        }
    }
}

// ===========================================================================
// Rules Save Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RulesSaveOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,
    pub include_all_backends: bool,

    pub format: RulesSaveFormat,
    pub path: Option<String>,
    pub compress: CompressMode,
    pub include_metadata: bool,

    pub dry_run: bool,
    pub overwrite: bool,
    pub create_dirs: bool,

    pub timeout_ms: u64,
    pub format_output: OutputFormat,
}

impl Default for RulesSaveOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            include_all_backends: false,
            format: RulesSaveFormat::NormalizedJson,
            path: None,
            compress: CompressMode::None,
            include_metadata: true,
            dry_run: false,
            overwrite: false,
            create_dirs: true,
            timeout_ms: 5000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesSaveBackendSummary {
    pub backend: String,
    pub family: String,
    pub rules_count: u64,
    pub has_native: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesSaveSummary {
    pub backends: Vec<RulesSaveBackendSummary>,
    pub bytes_written: u64,
    pub compressed: bool,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesSaveResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<RulesSaveSummary>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl RulesSaveResponse {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: Value::Null,
            summary: None,
            error: None,
            warnings: Vec::new(),
            format_output: OutputFormat::Json,
        }
    }

    pub fn with_error(error: FirewallError) -> Self {
        let mut response = Self::new();
        response.error = Some(error.to_json());
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "summary": self.summary,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::from("Firewall Rules Save\n===================\n\n");

        if self.ok {
            if let Some(summary) = &self.summary {
                output.push_str(&format!("Status: success\n"));
                output.push_str(&format!(
                    "Path: {}\n",
                    summary.path.as_deref().unwrap_or("(dry run)")
                ));
                output.push_str(&format!(
                    "Compressed: {}\n",
                    if summary.compressed { "yes" } else { "no" }
                ));
                output.push_str(&format!("Bytes Written: {}\n\n", summary.bytes_written));

                output.push_str("Backends:\n");
                for backend in &summary.backends {
                    output.push_str(&format!("  - {} ({})\n", backend.backend, backend.family));
                    output.push_str(&format!("      Rules     : {}\n", backend.rules_count));
                    output.push_str(&format!(
                        "      Native    : {}\n",
                        if backend.has_native { "yes" } else { "no" }
                    ));
                }
            }
        } else if let Some(error) = &self.error {
            output.push_str("Error:\n");
            if let Some(error_obj) = error.as_object() {
                if let Some(error_details) = error_obj.get("error") {
                    if let Some(code) = error_details.get("code") {
                        if let Some(message) = error_details.get("message") {
                            output.push_str(&format!(
                                "  [{}] {}\n",
                                code.as_str().unwrap_or("unknown"),
                                message.as_str().unwrap_or("unknown error")
                            ));
                        }
                    }
                }
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeSaveData {
    pub format: String,
    pub data: String,
}

#[derive(Clone, Debug)]
pub struct BackendSaveData {
    pub backend: String,
    pub family: String,
    pub timestamp_unix_ms: i64,
    pub host: String,
    pub rules: Vec<FirewallRule>,
    pub native_data: Option<NativeSaveData>,
}

impl BackendSaveData {
    pub fn to_json(&self) -> Value {
        let mut json_obj = json!({
            "backend": self.backend,
            "family": self.family,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "host": self.host
        });

        if !self.rules.is_empty() {
            json_obj["rules"] = json!(self.rules);
        }

        if let Some(native) = &self.native_data {
            json_obj["native"] = json!(native);
        }

        json_obj
    }
}

// ===========================================================================
// Enable Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct EnableOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,

    // Optional rules source (primarily for iptables/nftables)
    pub path: Option<String>,
    pub source_format: RulesSourceFormat,

    // Behavior flags
    pub dry_run: bool,
    pub validate_only: bool,
    pub backup_before_apply: bool,
    pub fail_if_already_enabled: bool,

    pub timeout_ms: u64,

    // Output
    pub format_output: OutputFormat,
}

impl Default for EnableOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            path: None,
            source_format: RulesSourceFormat::Auto,
            dry_run: false,
            validate_only: false,
            backup_before_apply: true,
            fail_if_already_enabled: false,
            timeout_ms: 10000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallStateSnapshot {
    pub available: bool,
    pub active: bool,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnableResult {
    pub changed: bool,
    pub already_enabled: bool,
    pub backup_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub backend: String,

    pub previous_state: Option<FirewallStateSnapshot>,
    pub current_state: Option<FirewallStateSnapshot>,

    pub actions: Vec<String>,
    pub result: Option<EnableResult>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl EnableResponse {
    pub fn new(backend: &str, format_output: OutputFormat) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: Value::Null,
            backend: backend.to_string(),
            previous_state: None,
            current_state: None,
            actions: Vec::new(),
            result: None,
            error: None,
            warnings: Vec::new(),
            format_output,
        }
    }

    pub fn with_error(backend: &str, error: FirewallError, format_output: OutputFormat) -> Self {
        let mut response = Self::new(backend, format_output);
        response.error = Some(error.to_json());
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "backend": self.backend,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "actions": self.actions,
            "result": self.result,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::from("Firewall Enable\n===============\n\n");

        output.push_str(&format!("Backend : {}\n\n", self.backend));

        if let Some(prev) = &self.previous_state {
            output.push_str("Previous State:\n");
            output.push_str(&format!(
                "  Available : {}\n",
                if prev.available { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Active    : {}\n",
                if prev.active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Enabled   : {}\n\n",
                if prev.enabled { "yes" } else { "no" }
            ));
        }

        if let Some(current) = &self.current_state {
            output.push_str("Current State:\n");
            output.push_str(&format!(
                "  Available : {}\n",
                if current.available { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Active    : {}\n",
                if current.active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Enabled   : {}\n\n",
                if current.enabled { "yes" } else { "no" }
            ));
        }

        if let Some(result) = &self.result {
            output.push_str(&format!(
                "Changed         : {}\n",
                if result.changed { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Already Enabled : {}\n",
                if result.already_enabled { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Backup Path     : {}\n\n",
                result.backup_path.as_deref().unwrap_or("(none)")
            ));
        }

        if !self.actions.is_empty() {
            output.push_str("Actions:\n");
            for action in &self.actions {
                output.push_str(&format!("  {}\n", action));
            }
            output.push('\n');
        }

        if !self.ok {
            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                if let Some(error_obj) = error.as_object() {
                    if let Some(error_details) = error_obj.get("error") {
                        if let Some(code) = error_details.get("code") {
                            if let Some(message) = error_details.get("message") {
                                output.push_str(&format!(
                                    "  [{}] {}\n",
                                    code.as_str().unwrap_or("unknown"),
                                    message.as_str().unwrap_or("unknown error")
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ===========================================================================
// Disable Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct DisableOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,

    // Optional rules source (primarily for iptables/nftables)
    pub path: Option<String>,
    pub source_format: RulesSourceFormat,

    // Behavior flags
    pub dry_run: bool,
    pub validate_only: bool,
    pub backup_before_apply: bool,
    pub fail_if_already_disabled: bool,

    pub timeout_ms: u64,

    // Output
    pub format_output: OutputFormat,
}

impl Default for DisableOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            path: None,
            source_format: RulesSourceFormat::Auto,
            dry_run: false,
            validate_only: false,
            backup_before_apply: true,
            fail_if_already_disabled: false,
            timeout_ms: 10000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DisableResult {
    pub changed: bool,
    pub already_disabled: bool,
    pub backup_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DisableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub backend: String,

    pub previous_state: Option<FirewallStateSnapshot>,
    pub current_state: Option<FirewallStateSnapshot>,

    pub actions: Vec<String>,
    pub result: Option<DisableResult>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl DisableResponse {
    pub fn new(backend: &str, format_output: OutputFormat) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: Value::Null,
            backend: backend.to_string(),
            previous_state: None,
            current_state: None,
            actions: Vec::new(),
            result: None,
            error: None,
            warnings: Vec::new(),
            format_output,
        }
    }

    pub fn with_error(backend: &str, error: FirewallError, format_output: OutputFormat) -> Self {
        let mut response = Self::new(backend, format_output);
        response.error = Some(error.to_json());
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "backend": self.backend,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "actions": self.actions,
            "result": self.result,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::from("Firewall Disable\n================\n\n");

        output.push_str(&format!("Backend : {}\n\n", self.backend));

        if let Some(prev) = &self.previous_state {
            output.push_str("Previous State:\n");
            output.push_str(&format!(
                "  Available : {}\n",
                if prev.available { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Active    : {}\n",
                if prev.active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Enabled   : {}\n\n",
                if prev.enabled { "yes" } else { "no" }
            ));
        }

        if let Some(current) = &self.current_state {
            output.push_str("Current State:\n");
            output.push_str(&format!(
                "  Available : {}\n",
                if current.available { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Active    : {}\n",
                if current.active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Enabled   : {}\n\n",
                if current.enabled {
                    "yes"
                } else {
                    match self.backend.as_str() {
                        "nftables" => "false (no nftables ruleset loaded)",
                        _ => "no",
                    }
                }
            ));
        }

        if let Some(result) = &self.result {
            output.push_str(&format!(
                "Changed          : {}\n",
                if result.changed { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Already Disabled : {}\n",
                if result.already_disabled { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Backup Path      : {}\n\n",
                result.backup_path.as_deref().unwrap_or("(none)")
            ));
        }

        if !self.actions.is_empty() {
            output.push_str("Actions:\n");
            for action in &self.actions {
                output.push_str(&format!("  {}\n", action));
            }
            output.push('\n');
        }

        if !self.ok {
            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                if let Some(error_obj) = error.as_object() {
                    if let Some(error_details) = error_obj.get("error") {
                        if let Some(code) = error_details.get("code") {
                            if let Some(message) = error_details.get("message") {
                                output.push_str(&format!(
                                    "  [{}] {}\n",
                                    code.as_str().unwrap_or("unknown"),
                                    message.as_str().unwrap_or("unknown error")
                                ));
                            }
                        }
                    }
                }
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ===========================================================================
// Rules Add Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RulesAddOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,
    /// True when family= was given (not the ipv4 default).
    pub family_explicit: bool,

    // High-level rule fields
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: String,
    pub action: String,

    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,

    // Backend-specific extensions
    pub zone: Option<String>,
    pub log_prefix: Option<String>,
    pub rate_limit: Option<String>,
    pub comment: Option<String>,

    // Behavior flags
    pub dry_run: bool,
    pub idempotent: bool,
    pub position: String,
    pub before_rule_id: Option<String>,
    pub after_rule_id: Option<String>,

    pub timeout_ms: u64,
    pub format_output: OutputFormat,
}

impl Default for RulesAddOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Ipv4,
            family_explicit: false,
            table: None,
            chain: None,
            direction: "input".to_string(),
            action: "accept".to_string(),
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            zone: None,
            log_prefix: None,
            rate_limit: None,
            comment: None,
            dry_run: false,
            idempotent: true,
            position: "append".to_string(),
            before_rule_id: None,
            after_rule_id: None,
            timeout_ms: 5000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FirewallRuleSpec {
    pub backend: String,
    pub family: String,
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: String,
    pub action: String,

    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,

    pub in_iface: Option<String>,
    pub out_iface: Option<String>,

    pub zone: Option<String>,
    pub log_prefix: Option<String>,
    pub rate_limit: Option<String>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesAddResult {
    pub changed: bool,
    pub already_exists: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesAddResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    /// The added rule when exactly one rule is involved.
    pub rule: Option<FirewallRuleSpec>,
    /// Every rule involved, one per IP family (two for iptables and
    /// nftables with family=any and no address).
    pub rules: Vec<FirewallRuleSpec>,
    pub backend_commands: Vec<String>,
    pub result: Option<RulesAddResult>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl RulesAddResponse {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({}),
            rule: None,
            rules: Vec::new(),
            backend_commands: Vec::new(),
            result: None,
            error: None,
            warnings: Vec::new(),
            format_output: OutputFormat::Json,
        }
    }

    pub fn with_error(error: FirewallError) -> Self {
        let mut response = Self::new();
        response.error = Some(error.to_json()["error"].clone());
        response
    }

    pub fn success(
        rule: FirewallRuleSpec,
        backend_commands: Vec<String>,
        result: RulesAddResult,
    ) -> Self {
        let mut response = Self::new();
        response.ok = true;
        response.rules = vec![rule.clone()];
        response.rule = Some(rule);
        response.backend_commands = backend_commands;
        response.result = Some(result);
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "rule": self.rule,
            "rules": self.rules,
            "backend_commands": self.backend_commands,
            "result": self.result,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Firewall Rules Add\n");
        output.push_str("==================\n\n");

        if self.ok {
            for rule in &self.rules {
                output.push_str(&format!("Backend   : {}\n", rule.backend));
                output.push_str(&format!("Family    : {}\n", rule.family));
                output.push_str(&format!("Direction : {}\n", rule.direction));
                output.push_str(&format!("Action    : {}\n", rule.action));

                if let Some(proto) = &rule.proto {
                    output.push_str(&format!("Proto     : {}\n", proto));
                }
                if let Some(dport) = &rule.dport {
                    output.push_str(&format!("dport     : {}\n", dport));
                }
                if let Some(sport) = &rule.sport {
                    output.push_str(&format!("sport     : {}\n", sport));
                }
                if let Some(saddr) = &rule.saddr {
                    output.push_str(&format!("saddr     : {}\n", saddr));
                }
                if let Some(daddr) = &rule.daddr {
                    output.push_str(&format!("daddr     : {}\n", daddr));
                }
                if let Some(comment) = &rule.comment {
                    output.push_str(&format!("Comment   : {}\n", comment));
                }

                output.push('\n');
            }

            if let Some(result) = &self.result {
                output.push_str(&format!(
                    "Changed        : {}\n",
                    if result.changed { "yes" } else { "no" }
                ));
                output.push_str(&format!(
                    "Already Exists : {}\n",
                    if result.already_exists { "yes" } else { "no" }
                ));
                output.push('\n');
            }

            if !self.backend_commands.is_empty() {
                output.push_str("Commands:\n");
                for cmd in &self.backend_commands {
                    output.push_str(&format!("  {}\n", cmd));
                }
            }
        } else {
            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                output.push_str(&format!(
                    "  [{}] {}\n",
                    error["code"].as_str().unwrap_or("unknown"),
                    error["message"].as_str().unwrap_or("Unknown error")
                ));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FirewallRule {
    pub backend: String,
    pub family: String,
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: Option<String>,

    pub priority: Option<i64>,
    pub action: Option<String>,

    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,

    pub in_iface: Option<String>,
    pub out_iface: Option<String>,

    pub comment: Option<String>,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,

    pub raw: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesListSummary {
    pub backend: String,
    pub family: String,
    pub total_rules: u64,
    pub filtered_rules: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub summary: Option<RulesListSummary>,
    pub rules: Vec<FirewallRule>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl RulesListResponse {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({}),
            summary: None,
            rules: Vec::new(),
            error: None,
            warnings: Vec::new(),
            format_output: OutputFormat::Json,
        }
    }

    pub fn with_error(error: FirewallError) -> Self {
        let mut response = Self::new();
        response.error = Some(error.to_json()["error"].clone());
        response
    }

    pub fn success(summary: RulesListSummary, rules: Vec<FirewallRule>) -> Self {
        let mut response = Self::new();
        response.ok = true;
        response.summary = Some(summary);
        response.rules = rules;
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "summary": self.summary,
            "rules": self.rules,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        if self.ok {
            output.push_str("Firewall Rules\n");
            output.push_str("==============\n\n");

            if let Some(summary) = &self.summary {
                output.push_str("Summary:\n");
                output.push_str(&format!("  Backend       : {}\n", summary.backend));
                output.push_str(&format!("  Family        : {}\n", summary.family));
                output.push_str(&format!("  Total Rules   : {}\n", summary.total_rules));
                output.push_str(&format!("  Filtered Rules: {}\n\n", summary.filtered_rules));
            }

            output.push_str("Rules:\n");
            for (i, rule) in self.rules.iter().enumerate() {
                output.push_str(&format!("  [{}] ", i + 1));

                if let Some(table) = &rule.table {
                    output.push_str(&format!("{}/", table));
                }

                if let Some(chain) = &rule.chain {
                    output.push_str(chain);
                }

                if let Some(direction) = &rule.direction {
                    output.push_str(&format!(" ({})", direction));
                }

                if let Some(action) = &rule.action {
                    output.push_str(&format!(" {}", action.to_uppercase()));
                }

                if let Some(proto) = &rule.proto {
                    output.push_str(&format!(" {}", proto));
                }

                if let Some(dport) = &rule.dport {
                    output.push_str(&format!(" dport={}", dport));
                }

                if let Some(sport) = &rule.sport {
                    output.push_str(&format!(" sport={}", sport));
                }

                if let Some(saddr) = &rule.saddr {
                    output.push_str(&format!(" saddr={}", saddr));
                }

                if let Some(daddr) = &rule.daddr {
                    output.push_str(&format!(" daddr={}", daddr));
                }

                if let Some(in_iface) = &rule.in_iface {
                    output.push_str(&format!(" in={}", in_iface));
                }

                if let Some(out_iface) = &rule.out_iface {
                    output.push_str(&format!(" out={}", out_iface));
                }

                output.push('\n');

                if let Some(comment) = &rule.comment {
                    output.push_str(&format!("      Comment : {}\n", comment));
                }

                if let (Some(packets), Some(bytes)) = (&rule.packets, &rule.bytes) {
                    output.push_str(&format!(
                        "      Counters: pkts={} bytes={}\n",
                        packets, bytes
                    ));
                }

                if !self.rules.is_empty() && i < self.rules.len() - 1 {
                    output.push('\n');
                }
            }
        } else {
            output.push_str("Firewall Rules\n");
            output.push_str("==============\n\n");

            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                output.push_str(&format!(
                    "  [{}] {}\n",
                    error["code"].as_str().unwrap_or("unknown"),
                    error["message"].as_str().unwrap_or("Unknown error")
                ));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ===========================================================================
// Rules Delete Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RulesDeleteOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,

    // Direct backend rule identifier
    pub rule_id: Option<String>,

    // Normalized match criteria
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: Option<String>,
    pub action: Option<String>,
    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
    pub comment_contains: Option<String>,

    // firewalld-specific
    pub zone: Option<String>,

    // Matching behavior
    pub match_mode: String,
    pub limit: Option<u64>,

    // Behavior flags
    pub dry_run: bool,
    pub require_match: bool,

    pub timeout_ms: u64,
    pub format_output: OutputFormat,
}

impl Default for RulesDeleteOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            rule_id: None,
            table: None,
            chain: None,
            direction: None,
            action: None,
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment_contains: None,
            zone: None,
            match_mode: "exact".to_string(),
            limit: None,
            dry_run: false,
            require_match: true,
            timeout_ms: 5000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MatchedFirewallRule {
    pub backend: String,
    pub family: String,
    pub table: Option<String>,
    pub chain: Option<String>,
    pub direction: Option<String>,
    pub action: Option<String>,
    pub proto: Option<String>,
    pub sport: Option<String>,
    pub dport: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
    pub comment: Option<String>,
    pub rule_id: Option<String>,
    /// iptables: 1-based line number within the rule's table and chain.
    #[serde(skip)]
    pub line_number: Option<i64>,
    /// Backend rule text as listed (iptables-save line, nft rule, ...).
    #[serde(skip)]
    pub raw: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesDeleteResult {
    pub deleted_count: u64,
    pub skipped_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesDeleteResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub matched_rules: Vec<MatchedFirewallRule>,
    pub backend_commands: Vec<String>,
    pub result: Option<RulesDeleteResult>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl RulesDeleteResponse {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({}),
            matched_rules: Vec::new(),
            backend_commands: Vec::new(),
            result: None,
            error: None,
            warnings: Vec::new(),
            format_output: OutputFormat::Json,
        }
    }

    pub fn with_error(error: FirewallError) -> Self {
        let mut response = Self::new();
        response.error = Some(error.to_json()["error"].clone());
        response
    }

    pub fn success(
        matched_rules: Vec<MatchedFirewallRule>,
        backend_commands: Vec<String>,
        result: RulesDeleteResult,
    ) -> Self {
        let mut response = Self::new();
        response.ok = true;
        response.matched_rules = matched_rules;
        response.backend_commands = backend_commands;
        response.result = Some(result);
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "matched_rules": self.matched_rules,
            "backend_commands": self.backend_commands,
            "result": self.result,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Firewall Rules Delete\n");
        output.push_str("=====================\n\n");

        if self.ok {
            if !self.matched_rules.is_empty() {
                if let Some(first_rule) = self.matched_rules.first() {
                    output.push_str(&format!("Backend : {}\n", first_rule.backend));
                    output.push_str(&format!("Family  : {}\n\n", first_rule.family));
                }

                output.push_str("Matched Rules:\n");
                for (i, rule) in self.matched_rules.iter().enumerate() {
                    output.push_str(&format!("  [{}] ", i + 1));

                    if let Some(table) = &rule.table {
                        output.push_str(&format!("{}/", table));
                    }

                    if let Some(chain) = &rule.chain {
                        output.push_str(chain);
                    }

                    if let Some(action) = &rule.action {
                        output.push_str(&format!(" {}", action.to_uppercase()));
                    }

                    if let Some(proto) = &rule.proto {
                        output.push_str(&format!(" {}", proto));
                    }

                    if let Some(dport) = &rule.dport {
                        output.push_str(&format!(" dport={}", dport));
                    }

                    if let Some(saddr) = &rule.saddr {
                        output.push_str(&format!(" saddr={}", saddr));
                    }

                    if let Some(rule_id) = &rule.rule_id {
                        output.push_str(&format!(" (rule_id={})", rule_id));
                    }

                    output.push('\n');
                }
                output.push('\n');
            }

            if let Some(result) = &self.result {
                output.push_str(&format!("Deleted Count : {}\n", result.deleted_count));
                output.push_str(&format!("Skipped Count : {}\n\n", result.skipped_count));
            }

            if !self.backend_commands.is_empty() {
                output.push_str("Commands:\n");
                for cmd in &self.backend_commands {
                    output.push_str(&format!("  {}\n", cmd));
                }
            }
        } else {
            if let Some(error) = &self.error {
                output.push_str("Error:\n");
                output.push_str(&format!(
                    "  [{}] {}\n",
                    error["code"].as_str().unwrap_or("unknown"),
                    error["message"].as_str().unwrap_or("Unknown error")
                ));
            }
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ===========================================================================
// Rules Reload Data Structures
// ===========================================================================

#[derive(Clone, Debug)]
pub struct RulesReloadOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,

    pub path: Option<String>,
    pub source_format: RulesReloadSourceFormat,

    pub dry_run: bool,
    pub validate_only: bool,
    pub backup_before_apply: bool,

    pub timeout_ms: u64,
    pub format_output: OutputFormat,
}

impl Default for RulesReloadOptions {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            family: IpFamily::Any,
            path: None,
            source_format: RulesReloadSourceFormat::Auto,
            dry_run: false,
            validate_only: false,
            backup_before_apply: true,
            timeout_ms: 10000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesReloadSource {
    pub path: Option<String>,
    pub source_format: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesReloadResult {
    pub changed: bool,
    pub backup_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RulesReloadResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub query: Value,
    pub mode: String,
    pub backend: String,
    pub family: String,

    pub source: RulesReloadSource,
    pub actions: Vec<String>,

    pub result: Option<RulesReloadResult>,

    pub error: Option<Value>,
    pub warnings: Vec<String>,

    #[serde(skip)]
    pub format_output: OutputFormat,
}

impl RulesReloadResponse {
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: Value::Null,
            mode: String::new(),
            backend: String::new(),
            family: String::new(),
            source: RulesReloadSource {
                path: None,
                source_format: None,
            },
            actions: Vec::new(),
            result: None,
            error: None,
            warnings: Vec::new(),
            format_output: OutputFormat::Json,
        }
    }

    pub fn with_error(error: FirewallError) -> Self {
        let mut response = Self::new();
        response.error = Some(error.to_json()["error"].clone());
        response
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "mode": self.mode,
            "backend": self.backend,
            "family": self.family,
            "source": self.source,
            "actions": self.actions,
            "result": self.result,
            "error": self.error,
            "warnings": self.warnings
        })
    }

    pub fn to_text(&self) -> String {
        let mut output = String::from("Firewall Rules Reload\n=====================\n\n");

        if self.ok {
            output.push_str(&format!("Mode    : {}\n", self.mode));
            output.push_str(&format!("Backend : {}\n", self.backend));
            output.push_str(&format!("Family  : {}\n\n", self.family));

            if let Some(path) = &self.source.path {
                output.push_str(&format!("Source  : {}\n", path));
            } else {
                output.push_str("Source  : (backend-managed; no file)\n");
            }

            if let Some(result) = &self.result {
                output.push_str(&format!(
                    "Changed : {}\n\n",
                    if result.changed { "yes" } else { "no" }
                ));

                if let Some(backup) = &result.backup_path {
                    output.push_str(&format!("Backup  : {}\n\n", backup));
                }
            }

            if !self.actions.is_empty() {
                output.push_str("Actions:\n");
                for action in &self.actions {
                    output.push_str(&format!("  {}\n", action));
                }
            }
        } else if let Some(error) = &self.error {
            output.push_str("Error:\n");
            output.push_str(&format!(
                "  [{}] {}\n",
                error["code"].as_str().unwrap_or("unknown"),
                error["message"].as_str().unwrap_or("unknown error")
            ));
        }

        if !self.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }
}

// ===========================================================================
// Main Implementation
// ===========================================================================

impl FirewallHandle {
    fn handle_rules_list(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.rules_list_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }

                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(1, "firewall rules list failed"))
                }
            }
            Err(e) => {
                let error_response = RulesListResponse::with_error(FirewallError::InternalError {
                    message: e.to_string(),
                });
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.to_json())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn rules_list_async(&self, args: &Args) -> Result<RulesListResponse> {
        // Parse options from arguments
        let opts = self.parse_rules_list_options(args)?;

        // Set query for response
        let mut response = RulesListResponse::new();
        response.query = json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "table": opts.table,
            "chain": opts.chain,
            "direction": opts.direction,
            "action": opts.action,
            "proto": opts.proto,
            "sport": opts.sport,
            "dport": opts.dport,
            "saddr": opts.saddr,
            "daddr": opts.daddr,
            "in_iface": opts.in_iface,
            "out_iface": opts.out_iface,
            "comment_contains": opts.comment_contains,
            "include_backend_raw": opts.include_backend_raw,
            "include_counters": opts.include_counters,
            "max_rules": opts.max_rules,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });
        response.format_output = opts.format_output.clone();

        // Determine which backend to use
        let backend_to_use = if opts.backend == FirewallBackend::Auto {
            self.detect_available_backend(opts.timeout_ms).await?
        } else {
            self.check_backend_availability(&opts.backend, opts.timeout_ms)
                .await?;
            opts.backend.clone()
        };

        // Retrieve rules from the determined backend
        let mut all_rules = self.get_rules_from_backend(&backend_to_use, &opts).await?;

        // Apply filtering
        let total_rules = all_rules.len() as u64;
        all_rules = self.apply_filters(all_rules, &opts)?;

        // Check max rules limit
        if all_rules.len() as u64 > opts.max_rules {
            return Ok(RulesListResponse::with_error(
                FirewallError::MaxRulesExceeded {
                    count: all_rules.len() as u64,
                    max: opts.max_rules,
                },
            ));
        }

        // Create successful response
        let summary = RulesListSummary {
            backend: backend_to_use.as_str().to_string(),
            family: opts.family.as_str().to_string(),
            total_rules,
            filtered_rules: all_rules.len() as u64,
        };

        response.ok = true;
        response.summary = Some(summary);
        response.rules = all_rules;

        Ok(response)
    }

    fn parse_rules_list_options(&self, args: &Args) -> Result<RulesListOptions> {
        let mut opts = RulesListOptions::default();

        // Parse backend
        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        // Parse family
        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        // Parse filters
        opts.table = args.get("table").cloned();
        opts.chain = args.get("chain").cloned();
        opts.direction = args.get("direction").cloned();
        opts.action = args.get("action").cloned();
        opts.proto = args.get("proto").cloned();
        opts.sport = args.get("sport").cloned();
        opts.dport = args.get("dport").cloned();
        opts.saddr = args.get("saddr").cloned();
        opts.daddr = args.get("daddr").cloned();
        opts.in_iface = args.get("in_iface").cloned();
        opts.out_iface = args.get("out_iface").cloned();
        opts.comment_contains = args.get("comment_contains").cloned();

        // Parse behavior options
        if let Some(raw_str) = args.get("include_backend_raw") {
            opts.include_backend_raw = raw_str.to_lowercase() == "true";
        }

        if let Some(counters_str) = args.get("include_counters") {
            opts.include_counters = counters_str.to_lowercase() == "true";
        }

        if let Some(max_rules_str) = args.get("max_rules") {
            let max_rules: u64 = max_rules_str
                .parse()
                .with_context(|| format!("Invalid max_rules: {}", max_rules_str))?;
            if max_rules == 0 {
                return Err(FirewallError::InvalidMaxRules { max_rules }.into());
            }
            opts.max_rules = max_rules;
        }

        if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout_ms == 0 {
                return Err(FirewallError::InvalidTimeout { timeout_ms }.into());
            }
            opts.timeout_ms = timeout_ms;
        }

        // Parse format
        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        // Validate direction values
        if let Some(direction) = &opts.direction {
            match direction.to_lowercase().as_str() {
                "input" | "output" | "forward" | "prerouting" | "postrouting" => {}
                _ => {
                    return Err(FirewallError::InvalidDirection {
                        direction: direction.clone(),
                    }
                    .into());
                }
            }
        }

        // Validate action values
        if let Some(action) = &opts.action {
            match action.to_lowercase().as_str() {
                "accept" | "drop" | "reject" | "log" | "masquerade" | "dnat" | "snat"
                | "redirect" => {}
                _ => {
                    return Err(FirewallError::InvalidAction {
                        action: action.clone(),
                    }
                    .into());
                }
            }
        }

        // Validate port values
        if let Some(port) = &opts.sport {
            self.validate_port_value(port)?;
        }
        if let Some(port) = &opts.dport {
            self.validate_port_value(port)?;
        }

        Ok(opts)
    }

    pub fn validate_port_value(&self, port: &str) -> Result<()> {
        // Handle port ranges like "1000-2000" or single ports like "80"
        if port.contains('-') {
            let parts: Vec<&str> = port.split('-').collect();
            if parts.len() != 2 {
                return Err(FirewallError::InvalidPort {
                    port: port.to_string(),
                }
                .into());
            }
            for part in parts {
                let port_num: u16 = part.parse().map_err(|_| FirewallError::InvalidPort {
                    port: port.to_string(),
                })?;
                if port_num == 0 {
                    return Err(FirewallError::InvalidPort {
                        port: port.to_string(),
                    }
                    .into());
                }
            }
        } else {
            let port_num: u16 = port.parse().map_err(|_| FirewallError::InvalidPort {
                port: port.to_string(),
            })?;
            if port_num == 0 {
                return Err(FirewallError::InvalidPort {
                    port: port.to_string(),
                }
                .into());
            }
        }
        Ok(())
    }

    // ===========================================================================
    // Backend Detection and Management
    // ===========================================================================

    async fn detect_available_backend(&self, timeout_ms: u64) -> Result<FirewallBackend> {
        // Try backends in priority order: nftables, firewalld, ufw, iptables

        // Check nftables first
        if self
            .is_backend_available(&FirewallBackend::Nftables, timeout_ms)
            .await
        {
            return Ok(FirewallBackend::Nftables);
        }

        // Check firewalld
        if self
            .is_backend_available(&FirewallBackend::Firewalld, timeout_ms)
            .await
        {
            return Ok(FirewallBackend::Firewalld);
        }

        // Check ufw
        if self
            .is_backend_available(&FirewallBackend::Ufw, timeout_ms)
            .await
        {
            return Ok(FirewallBackend::Ufw);
        }

        // Check iptables last
        if self
            .is_backend_available(&FirewallBackend::Iptables, timeout_ms)
            .await
        {
            return Ok(FirewallBackend::Iptables);
        }

        Err(FirewallError::NoBackendAvailable.into())
    }

    async fn check_backend_availability(
        &self,
        backend: &FirewallBackend,
        timeout_ms: u64,
    ) -> Result<()> {
        if !self.is_backend_available(backend, timeout_ms).await {
            return Err(FirewallError::BackendUnavailable {
                backend: backend.as_str().to_string(),
            }
            .into());
        }
        Ok(())
    }

    async fn is_backend_available(&self, backend: &FirewallBackend, timeout_ms: u64) -> bool {
        match backend {
            FirewallBackend::Nftables => {
                if !is_command_available("nft") {
                    return false;
                }
                // Try to run nft list ruleset to see if it works
                match run_command_with_timeout("nft", &["list", "ruleset"], timeout_ms).await {
                    Ok((0, _, _)) => true,
                    _ => false,
                }
            }
            FirewallBackend::Firewalld => {
                if !is_command_available("firewall-cmd") {
                    return false;
                }
                // Check if firewalld daemon is running
                match run_command_with_timeout("firewall-cmd", &["--state"], timeout_ms).await {
                    Ok((0, stdout, _)) => stdout.trim() == "running",
                    _ => false,
                }
            }
            FirewallBackend::Ufw => {
                if !is_command_available("ufw") {
                    return false;
                }
                // Try to get ufw status
                match run_command_with_timeout("ufw", &["status"], timeout_ms).await {
                    Ok((0, _, _)) => true,
                    _ => false,
                }
            }
            FirewallBackend::Iptables => {
                // Check for both iptables and ip6tables
                is_command_available("iptables") || is_command_available("ip6tables")
            }
            FirewallBackend::Auto => true, // This should not be called for Auto
        }
    }

    // ===========================================================================
    // Rule Retrieval from Backends
    // ===========================================================================

    async fn get_rules_from_backend(
        &self,
        backend: &FirewallBackend,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        match backend {
            FirewallBackend::Iptables => self.get_iptables_rules(opts).await,
            FirewallBackend::Nftables => self.get_nftables_rules(opts).await,
            FirewallBackend::Ufw => self.get_ufw_rules(opts).await,
            FirewallBackend::Firewalld => self.get_firewalld_rules(opts).await,
            FirewallBackend::Auto => Err(anyhow::anyhow!(
                "Auto backend should be resolved before calling get_rules_from_backend"
            )),
        }
    }

    async fn get_iptables_rules(&self, opts: &RulesListOptions) -> Result<Vec<FirewallRule>> {
        let mut all_rules = Vec::new();

        match opts.family {
            IpFamily::Ipv4 | IpFamily::Any => {
                if let Ok(rules) = self
                    .parse_iptables_save("iptables-save", "ipv4", opts)
                    .await
                {
                    all_rules.extend(rules);
                }
            }
            _ => {}
        }

        match opts.family {
            IpFamily::Ipv6 | IpFamily::Any => {
                if let Ok(rules) = self
                    .parse_iptables_save("ip6tables-save", "ipv6", opts)
                    .await
                {
                    all_rules.extend(rules);
                }
            }
            _ => {}
        }

        Ok(all_rules)
    }

    async fn parse_iptables_save(
        &self,
        command: &str,
        family: &str,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, stderr) =
            run_command_with_timeout(command, &[], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::CommandFailed {
                command: command.to_string(),
                code: exit_code,
                stderr,
            }
            .into());
        }

        Ok(self.parse_iptables_save_output(&stdout, family, opts))
    }

    /// Parses `iptables-save` / `ip6tables-save` output. Each rule's
    /// `priority` is its 1-based line number within its own table and chain,
    /// the number `iptables -t <table> -L <chain> --line-numbers` shows.
    fn parse_iptables_save_output(
        &self,
        stdout: &str,
        family: &str,
        opts: &RulesListOptions,
    ) -> Vec<FirewallRule> {
        let mut rules = Vec::new();
        let mut current_table = String::new();
        let mut chain_lines: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();

        for line in stdout.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse table definitions
            if let Some(table) = line.strip_prefix('*') {
                current_table = table.to_string();
                chain_lines.clear();
                continue;
            }

            // Skip COMMIT lines and chain policy lines (starting with :)
            if line == "COMMIT" || line.starts_with(':') {
                continue;
            }

            // Parse rule lines (starting with -A)
            if line.starts_with("-A ") {
                let tokens = tokenize_rule_line(line);
                let Some(chain) = tokens.get(1) else { continue };
                let counter = chain_lines.entry(chain.clone()).or_insert(0);
                *counter += 1;
                let line_number = *counter;
                if let Some(rule) =
                    self.parse_iptables_rule(line, &current_table, family, line_number, opts)
                {
                    rules.push(rule);
                }
            }
        }

        rules
    }

    fn parse_iptables_rule(
        &self,
        line: &str,
        table: &str,
        family: &str,
        priority: i64,
        opts: &RulesListOptions,
    ) -> Option<FirewallRule> {
        let parts = tokenize_rule_line(line);
        if parts.len() < 2 {
            return None;
        }

        let mut rule = FirewallRule {
            backend: "iptables".to_string(),
            family: family.to_string(),
            table: Some(table.to_string()),
            chain: None,
            direction: None,
            priority: Some(priority),
            action: None,
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment: None,
            packets: None,
            bytes: None,
            raw: if opts.include_backend_raw {
                Some(line.to_string())
            } else {
                None
            },
        };

        // Parse chain name (after -A)
        rule.chain = Some(parts[1].to_string());
        rule.direction = self.chain_to_direction(&parts[1]);

        // Parse rule components. A preceding "!" negates the next match;
        // the value is then reported with a leading "!" so filters for the
        // plain value do not select the negated rule.
        let mut i = 2;
        let mut negate = false;
        while i < parts.len() {
            let value = |idx: usize| -> String {
                if negate {
                    format!("!{}", parts[idx])
                } else {
                    parts[idx].clone()
                }
            };
            match parts[i].as_str() {
                "!" => {
                    negate = true;
                    i += 1;
                    continue;
                }
                "-p" if i + 1 < parts.len() => {
                    rule.proto = Some(value(i + 1));
                    i += 2;
                }
                "-s" if i + 1 < parts.len() => {
                    rule.saddr = Some(value(i + 1));
                    i += 2;
                }
                "-d" if i + 1 < parts.len() => {
                    rule.daddr = Some(value(i + 1));
                    i += 2;
                }
                "-i" if i + 1 < parts.len() => {
                    rule.in_iface = Some(value(i + 1));
                    i += 2;
                }
                "-o" if i + 1 < parts.len() => {
                    rule.out_iface = Some(value(i + 1));
                    i += 2;
                }
                "-j" if i + 1 < parts.len() => {
                    rule.action = Some(parts[i + 1].to_lowercase());
                    i += 2;
                }
                "--dport" if i + 1 < parts.len() => {
                    rule.dport = Some(value(i + 1));
                    i += 2;
                }
                "--sport" if i + 1 < parts.len() => {
                    rule.sport = Some(value(i + 1));
                    i += 2;
                }
                "--comment" if i + 1 < parts.len() => {
                    rule.comment = Some(parts[i + 1].clone());
                    i += 2;
                }
                "-c" if i + 2 < parts.len() => {
                    // Parse counters: -c packets bytes
                    if opts.include_counters {
                        if let (Ok(packets), Ok(bytes)) =
                            (parts[i + 1].parse::<u64>(), parts[i + 2].parse::<u64>())
                        {
                            rule.packets = Some(packets);
                            rule.bytes = Some(bytes);
                        }
                    }
                    i += 3;
                }
                _ => i += 1,
            }
            negate = false;
        }

        Some(rule)
    }

    fn chain_to_direction(&self, chain: &str) -> Option<String> {
        match chain.to_uppercase().as_str() {
            "INPUT" => Some("input".to_string()),
            "OUTPUT" => Some("output".to_string()),
            "FORWARD" => Some("forward".to_string()),
            "PREROUTING" => Some("prerouting".to_string()),
            "POSTROUTING" => Some("postrouting".to_string()),
            _ => None,
        }
    }

    async fn get_nftables_rules(&self, opts: &RulesListOptions) -> Result<Vec<FirewallRule>> {
        // -a adds "# handle N" to each rule, the id rules.delete deletes by.
        let (exit_code, stdout, stderr) =
            run_command_with_timeout("nft", &["-a", "list", "ruleset"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::CommandFailed {
                command: "nft -a list ruleset".to_string(),
                code: exit_code,
                stderr,
            }
            .into());
        }

        let mut rules = Vec::new();
        let mut current_table_info: Option<(String, String)> = None; // (family, table)
        let mut current_chain_info: Option<(String, String)> = None; // (chain, type/hook)
        let mut rule_priority = 0i64;

        for line in stdout.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse table definitions: "table ip filter {"
            if line.starts_with("table ") && line.contains(" {") {
                if let Some(captures) = self.parse_nft_table_line(line) {
                    current_table_info = Some(captures);
                }
                rule_priority = 0;
                continue;
            }

            // Parse chain definitions: "chain INPUT {"
            if line.starts_with("chain ") && line.contains(" {") {
                if let Some(captures) = self.parse_nft_chain_line(line) {
                    current_chain_info = Some(captures);
                }
                rule_priority = 0;
                continue;
            }

            // End of table or chain
            if line == "}" {
                if line.matches('}').count() == 1 {
                    current_chain_info = None;
                }
                continue;
            }

            // Chain header statements such as "type filter hook input
            // priority 0; policy accept;" are not rules.
            if line.starts_with("type ") || line.starts_with("policy ") {
                continue;
            }

            // Parse rule lines (not starting with keywords and containing actions)
            if !line.starts_with("table")
                && !line.starts_with("chain")
                && (line.contains(" accept")
                    || line.contains(" drop")
                    || line.contains(" reject")
                    || line.contains(" log")
                    || line.contains(" masquerade")
                    || line.contains(" dnat")
                    || line.contains(" snat")
                    || line.contains(" return")
                    || line.contains(" jump")
                    || line.contains(" goto"))
            {
                rule_priority += 1;
                if let Some(rule) = self.parse_nftables_rule(
                    line,
                    &current_table_info,
                    &current_chain_info,
                    rule_priority,
                    opts,
                ) {
                    rules.push(rule);
                }
            }
        }

        Ok(rules)
    }

    fn parse_nft_table_line(&self, line: &str) -> Option<(String, String)> {
        // Expected format: "table ip filter {"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "table" {
            let family = parts[1].to_string();
            let table = parts[2].to_string();
            return Some((family, table));
        }
        None
    }

    fn parse_nft_chain_line(&self, line: &str) -> Option<(String, String)> {
        // Expected formats:
        // "chain INPUT {" or "chain INPUT { type filter hook input priority 0; policy accept; }"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "chain" {
            let chain_name = parts[1].to_string();

            // Try to extract hook type from the line if present
            let hook_type = if line.contains(" hook ") {
                for (i, part) in parts.iter().enumerate() {
                    if part == &"hook" && i + 1 < parts.len() {
                        return Some((chain_name, parts[i + 1].trim_end_matches(';').to_string()));
                    }
                }
                "custom".to_string() // default for custom chains
            } else {
                "custom".to_string()
            };

            return Some((chain_name, hook_type));
        }
        None
    }

    fn parse_nftables_rule(
        &self,
        line: &str,
        table_info: &Option<(String, String)>,
        chain_info: &Option<(String, String)>,
        priority: i64,
        opts: &RulesListOptions,
    ) -> Option<FirewallRule> {
        let (family, table) = table_info.as_ref()?;
        let (chain, hook_type) = chain_info.as_ref()?;

        // Filter by family if specified
        match opts.family {
            IpFamily::Ipv4 if family != "ip" => return None,
            IpFamily::Ipv6 if family != "ip6" => return None,
            IpFamily::Any => {}
            _ => {}
        }

        let mut rule = FirewallRule {
            backend: "nftables".to_string(),
            family: match family.as_str() {
                "ip" => "ipv4".to_string(),
                "ip6" => "ipv6".to_string(),
                _ => family.clone(),
            },
            table: Some(table.clone()),
            chain: Some(chain.clone()),
            direction: self.nft_hook_to_direction(hook_type),
            priority: Some(priority),
            action: None,
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment: None,
            packets: None,
            bytes: None,
            raw: if opts.include_backend_raw {
                Some(line.to_string())
            } else {
                None
            },
        };

        // Parse rule components from the line
        let line_lower = line.to_lowercase();

        // Extract protocol
        if let Some(proto) = self.extract_nft_protocol(&line_lower) {
            rule.proto = Some(proto);
        }

        // Extract ports
        if let Some(dport) = self.extract_nft_dport(&line_lower) {
            rule.dport = Some(dport);
        }
        if let Some(sport) = self.extract_nft_sport(&line_lower) {
            rule.sport = Some(sport);
        }

        // Extract addresses
        if let Some(saddr) = self.extract_nft_saddr(&line_lower) {
            rule.saddr = Some(saddr);
        }
        if let Some(daddr) = self.extract_nft_daddr(&line_lower) {
            rule.daddr = Some(daddr);
        }

        // Extract interfaces
        if let Some(iface) = self.extract_nft_input_interface(&line_lower) {
            rule.in_iface = Some(iface);
        }
        if let Some(oface) = self.extract_nft_output_interface(&line_lower) {
            rule.out_iface = Some(oface);
        }

        // Extract action (must be last part before any comment/counter)
        if let Some(action) = self.extract_nft_action(&line_lower) {
            rule.action = Some(action);
        }

        // Extract comment
        if let Some(comment) = self.extract_nft_comment(line) {
            rule.comment = Some(comment);
        }

        // Extract counters if requested
        if opts.include_counters {
            if let Some((packets, bytes)) = self.extract_nft_counters(&line_lower) {
                rule.packets = Some(packets);
                rule.bytes = Some(bytes);
            }
        }

        Some(rule)
    }

    fn nft_hook_to_direction(&self, hook: &str) -> Option<String> {
        match hook.to_lowercase().as_str() {
            "input" => Some("input".to_string()),
            "output" => Some("output".to_string()),
            "forward" => Some("forward".to_string()),
            "prerouting" => Some("prerouting".to_string()),
            "postrouting" => Some("postrouting".to_string()),
            _ => None,
        }
    }

    fn extract_nft_protocol(&self, line: &str) -> Option<String> {
        // Look for protocol specifications like "tcp", "udp", "icmp"
        if line.contains(" tcp ") {
            Some("tcp".to_string())
        } else if line.contains(" udp ") {
            Some("udp".to_string())
        } else if line.contains(" icmp ") {
            Some("icmp".to_string())
        } else if line.contains(" icmpv6 ") {
            Some("icmpv6".to_string())
        } else {
            None
        }
    }

    fn extract_nft_dport(&self, line: &str) -> Option<String> {
        // Look for destination port specifications
        if let Some(start) = line.find(" dport ") {
            let after_dport = &line[start + 7..];
            if let Some(port_str) = after_dport.split_whitespace().next() {
                return Some(port_str.to_string());
            }
        }
        if let Some(start) = line.find(" th dport ") {
            let after_dport = &line[start + 10..];
            if let Some(port_str) = after_dport.split_whitespace().next() {
                return Some(port_str.to_string());
            }
        }
        None
    }

    fn extract_nft_sport(&self, line: &str) -> Option<String> {
        // Look for source port specifications
        if let Some(start) = line.find(" sport ") {
            let after_sport = &line[start + 7..];
            if let Some(port_str) = after_sport.split_whitespace().next() {
                return Some(port_str.to_string());
            }
        }
        if let Some(start) = line.find(" th sport ") {
            let after_sport = &line[start + 10..];
            if let Some(port_str) = after_sport.split_whitespace().next() {
                return Some(port_str.to_string());
            }
        }
        None
    }

    fn extract_nft_saddr(&self, line: &str) -> Option<String> {
        // Look for source address specifications
        if let Some(start) = line.find(" saddr ") {
            let after_saddr = &line[start + 7..];
            if let Some(addr_str) = after_saddr.split_whitespace().next() {
                return Some(addr_str.to_string());
            }
        }
        if let Some(start) = line.find(" ip saddr ") {
            let after_saddr = &line[start + 10..];
            if let Some(addr_str) = after_saddr.split_whitespace().next() {
                return Some(addr_str.to_string());
            }
        }
        None
    }

    fn extract_nft_daddr(&self, line: &str) -> Option<String> {
        // Look for destination address specifications
        if let Some(start) = line.find(" daddr ") {
            let after_daddr = &line[start + 7..];
            if let Some(addr_str) = after_daddr.split_whitespace().next() {
                return Some(addr_str.to_string());
            }
        }
        if let Some(start) = line.find(" ip daddr ") {
            let after_daddr = &line[start + 10..];
            if let Some(addr_str) = after_daddr.split_whitespace().next() {
                return Some(addr_str.to_string());
            }
        }
        None
    }

    fn extract_nft_input_interface(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find(" iif ") {
            let after_iif = &line[start + 5..];
            if let Some(iface_str) = after_iif.split_whitespace().next() {
                return Some(iface_str.trim_matches('"').to_string());
            }
        }
        if let Some(start) = line.find(" iifname ") {
            let after_iifname = &line[start + 9..];
            if let Some(iface_str) = after_iifname.split_whitespace().next() {
                return Some(iface_str.trim_matches('"').to_string());
            }
        }
        None
    }

    fn extract_nft_output_interface(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find(" oif ") {
            let after_oif = &line[start + 5..];
            if let Some(iface_str) = after_oif.split_whitespace().next() {
                return Some(iface_str.trim_matches('"').to_string());
            }
        }
        if let Some(start) = line.find(" oifname ") {
            let after_oifname = &line[start + 9..];
            if let Some(iface_str) = after_oifname.split_whitespace().next() {
                return Some(iface_str.trim_matches('"').to_string());
            }
        }
        None
    }

    fn extract_nft_action(&self, line: &str) -> Option<String> {
        // Look for common actions
        let actions = [
            "accept",
            "drop",
            "reject",
            "log",
            "masquerade",
            "dnat",
            "snat",
            "return",
            "jump",
            "goto",
        ];
        for action in &actions {
            if line.contains(&format!(" {} ", action)) || line.ends_with(&format!(" {}", action)) {
                return Some(action.to_string());
            }
        }
        None
    }

    fn extract_nft_comment(&self, line: &str) -> Option<String> {
        // Look for comment in nftables format: comment "text"
        if let Some(start) = line.find("comment \"") {
            let after_comment = &line[start + 9..];
            if let Some(end) = after_comment.find('"') {
                return Some(after_comment[..end].to_string());
            }
        }
        None
    }

    fn extract_nft_counters(&self, line: &str) -> Option<(u64, u64)> {
        // Look for counter format: counter packets 123 bytes 456
        if let Some(start) = line.find("counter packets ") {
            let after_packets = &line[start + 16..];
            let parts: Vec<&str> = after_packets.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "bytes" {
                if let (Ok(packets), Ok(bytes)) = (parts[0].parse::<u64>(), parts[2].parse::<u64>())
                {
                    return Some((packets, bytes));
                }
            }
        }
        None
    }

    async fn get_ufw_rules(&self, opts: &RulesListOptions) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, stderr) =
            run_command_with_timeout("ufw", &["status", "numbered"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::CommandFailed {
                command: "ufw status numbered".to_string(),
                code: exit_code,
                stderr,
            }
            .into());
        }

        let mut rules = Vec::new();
        let mut rule_priority = 0i64;

        for line in stdout.lines() {
            let line = line.trim();

            // Skip empty lines, status lines, and headers
            if line.is_empty()
                || line.starts_with("Status:")
                || line.starts_with("To")
                || line.starts_with("--")
                || line.contains("Action")
            {
                continue;
            }

            // Parse numbered rule lines like: "[ 1] 22/tcp                    ALLOW IN    Anywhere"
            if let Some(rule) = self.parse_ufw_rule(line, rule_priority + 1, opts) {
                rule_priority += 1;
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    fn parse_ufw_rule(
        &self,
        line: &str,
        priority: i64,
        opts: &RulesListOptions,
    ) -> Option<FirewallRule> {
        // Expected format: "[ 1] 22/tcp                    ALLOW IN    Anywhere"
        // or:              "[ 2] Anywhere                 ALLOW OUT   22/tcp on eth0"

        // Remove brackets and split by whitespace
        let line_clean = line.replace(['[', ']'], "");
        let parts: Vec<&str> = line_clean.split_whitespace().collect();

        if parts.len() < 4 {
            return None;
        }

        // The rule number (first part) is what `ufw delete` takes.
        let priority = parts[0].parse::<i64>().unwrap_or(priority);
        let parts = &parts[1..];

        let mut rule = FirewallRule {
            backend: "ufw".to_string(),
            family: "ipv4".to_string(), // Default, will be updated if IPv6 detected
            table: None,                // UFW abstracts this
            chain: None,                // UFW abstracts this
            direction: None,
            priority: Some(priority),
            action: None,
            proto: None,
            sport: None,
            dport: None,
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment: None,
            packets: None,
            bytes: None,
            raw: if opts.include_backend_raw {
                Some(line.to_string())
            } else {
                None
            },
        };

        // Check for IPv6 indicator
        if line.contains("(v6)") || line.contains("Anywhere (v6)") {
            rule.family = "ipv6".to_string();
        }

        // Parse the rule format:
        // Format 1: "22/tcp ALLOW IN Anywhere"
        // Format 2: "Anywhere ALLOW OUT 22/tcp"

        // Find the action (ALLOW, DENY, REJECT)
        let mut action_idx = None;
        let mut action_str = "";
        for (i, part) in parts.iter().enumerate() {
            if part.contains("ALLOW") || part.contains("DENY") || part.contains("REJECT") {
                action_idx = Some(i);
                action_str = if part.contains("ALLOW") {
                    "allow"
                } else if part.contains("DENY") {
                    "deny"
                } else {
                    "reject"
                };
                break;
            }
        }

        let action_idx = action_idx?;
        rule.action = Some(action_str.to_string());

        // Parse direction from the action context
        if action_idx + 1 < parts.len() {
            match parts[action_idx + 1].to_uppercase().as_str() {
                "IN" => {
                    rule.direction = Some("input".to_string());
                    // Format: "22/tcp ALLOW IN Anywhere"
                    let to_spec = parts[0];
                    let from_spec = if parts.len() > action_idx + 2 {
                        parts[action_idx + 2]
                    } else {
                        "Anywhere"
                    };

                    self.parse_ufw_port_spec(to_spec, &mut rule, true); // true = destination
                    self.parse_ufw_address_spec(from_spec, &mut rule, true); // true = source
                }
                "OUT" => {
                    rule.direction = Some("output".to_string());
                    // Format: "Anywhere ALLOW OUT 22/tcp"
                    let from_spec = parts[0];
                    let to_spec = if parts.len() > action_idx + 2 {
                        parts[action_idx + 2]
                    } else {
                        "Anywhere"
                    };

                    self.parse_ufw_address_spec(from_spec, &mut rule, true); // true = source
                    self.parse_ufw_port_spec(to_spec, &mut rule, true); // true = destination
                }
                _ => {}
            }
        }

        // Handle interface specifications
        if let Some(on_idx) = parts.iter().position(|&p| p == "on") {
            if on_idx + 1 < parts.len() {
                match rule.direction.as_deref() {
                    Some("input") => rule.in_iface = Some(parts[on_idx + 1].to_string()),
                    Some("output") => rule.out_iface = Some(parts[on_idx + 1].to_string()),
                    _ => {}
                }
            }
        }

        Some(rule)
    }

    fn parse_ufw_port_spec(&self, spec: &str, rule: &mut FirewallRule, is_destination: bool) {
        if spec == "Anywhere" || spec.contains("Anywhere") {
            return;
        }

        // Handle port/protocol specifications like "22/tcp" or "80,443/tcp"
        if let Some(slash_idx) = spec.find('/') {
            let port_part = &spec[..slash_idx];
            let proto_part = &spec[slash_idx + 1..];

            rule.proto = Some(proto_part.to_string());

            if is_destination {
                rule.dport = Some(port_part.to_string());
            } else {
                rule.sport = Some(port_part.to_string());
            }
        } else if spec
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
        {
            // Just a port number without protocol
            if is_destination {
                rule.dport = Some(spec.to_string());
            } else {
                rule.sport = Some(spec.to_string());
            }
        }
    }

    fn parse_ufw_address_spec(&self, spec: &str, rule: &mut FirewallRule, is_source: bool) {
        if spec == "Anywhere" || spec.contains("Anywhere") {
            // Set default addresses
            if is_source {
                rule.saddr = Some(
                    if rule.family == "ipv6" {
                        "::/0"
                    } else {
                        "0.0.0.0/0"
                    }
                    .to_string(),
                );
            } else {
                rule.daddr = Some(
                    if rule.family == "ipv6" {
                        "::/0"
                    } else {
                        "0.0.0.0/0"
                    }
                    .to_string(),
                );
            }
            return;
        }

        // Parse IP address or CIDR
        if spec.contains(':') || spec.contains('.') || spec.contains('/') {
            if is_source {
                rule.saddr = Some(spec.to_string());
            } else {
                rule.daddr = Some(spec.to_string());
            }
        }
    }

    async fn get_firewalld_rules(&self, opts: &RulesListOptions) -> Result<Vec<FirewallRule>> {
        let mut all_rules = Vec::new();

        // Get all zones
        let zones = self.get_firewalld_zones(opts.timeout_ms).await?;

        for zone in zones {
            // Get rules for this zone
            let mut zone_rules = self.get_firewalld_zone_rules(&zone, opts).await?;
            all_rules.append(&mut zone_rules);
        }

        Ok(all_rules)
    }

    async fn get_firewalld_zones(&self, timeout_ms: u64) -> Result<Vec<String>> {
        let (exit_code, stdout, stderr) =
            run_command_with_timeout("firewall-cmd", &["--list-all-zones"], timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::CommandFailed {
                command: "firewall-cmd --list-all-zones".to_string(),
                code: exit_code,
                stderr,
            }
            .into());
        }

        let mut zones = Vec::new();
        for line in stdout.lines() {
            let line = line.trim();
            // Zone headers look like: "public (active)"
            if !line.is_empty() && !line.starts_with(' ') && line.contains('(') {
                let zone_name = line.split('(').next().unwrap_or("").trim();
                if !zone_name.is_empty() {
                    zones.push(zone_name.to_string());
                }
            }
        }

        // Fallback: get zones with simpler command
        if zones.is_empty() {
            let (exit_code, stdout, _stderr) =
                run_command_with_timeout("firewall-cmd", &["--get-zones"], timeout_ms).await?;

            if exit_code == 0 {
                zones = stdout.split_whitespace().map(|s| s.to_string()).collect();
            }
        }

        Ok(zones)
    }

    async fn get_firewalld_zone_rules(
        &self,
        zone: &str,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let mut rules = Vec::new();
        let mut rule_priority = 0i64;

        // Get services for the zone
        if let Ok(service_rules) = self
            .get_firewalld_services(zone, &mut rule_priority, opts)
            .await
        {
            rules.extend(service_rules);
        }

        // Get ports for the zone
        if let Ok(port_rules) = self
            .get_firewalld_ports(zone, &mut rule_priority, opts)
            .await
        {
            rules.extend(port_rules);
        }

        // Get rich rules for the zone
        if let Ok(rich_rules) = self
            .get_firewalld_rich_rules(zone, &mut rule_priority, opts)
            .await
        {
            rules.extend(rich_rules);
        }

        // Get sources for the zone
        if let Ok(source_rules) = self
            .get_firewalld_sources(zone, &mut rule_priority, opts)
            .await
        {
            rules.extend(source_rules);
        }

        Ok(rules)
    }

    async fn get_firewalld_services(
        &self,
        zone: &str,
        rule_priority: &mut i64,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, _stderr) = run_command_with_timeout(
            "firewall-cmd",
            &["--zone", zone, "--list-services"],
            opts.timeout_ms,
        )
        .await?;

        if exit_code != 0 {
            return Ok(Vec::new()); // Continue with other rule types
        }

        let mut rules = Vec::new();
        for service in stdout.split_whitespace() {
            *rule_priority += 1;

            let rule = FirewallRule {
                backend: "firewalld".to_string(),
                family: "any".to_string(), // Services can apply to both IPv4/IPv6
                table: None,
                chain: Some(format!("zone:{}", zone)),
                direction: Some("input".to_string()), // Services are typically for incoming traffic
                priority: Some(*rule_priority),
                action: Some("accept".to_string()), // Services in allowed list are accepted
                proto: None,                        // Service definitions contain protocol info
                sport: None,
                dport: None,
                saddr: None,
                daddr: None,
                in_iface: None,
                out_iface: None,
                comment: Some(format!("service: {}", service)),
                packets: None,
                bytes: None,
                raw: if opts.include_backend_raw {
                    Some(format!("--zone {} --add-service {}", zone, service))
                } else {
                    None
                },
            };
            rules.push(rule);
        }

        Ok(rules)
    }

    async fn get_firewalld_ports(
        &self,
        zone: &str,
        rule_priority: &mut i64,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, _stderr) = run_command_with_timeout(
            "firewall-cmd",
            &["--zone", zone, "--list-ports"],
            opts.timeout_ms,
        )
        .await?;

        if exit_code != 0 {
            return Ok(Vec::new());
        }

        let mut rules = Vec::new();
        for port_spec in stdout.split_whitespace() {
            *rule_priority += 1;

            // Parse port spec like "80/tcp" or "443/tcp" or "1000-2000/udp"
            let (port, proto) = if let Some(slash_idx) = port_spec.find('/') {
                let port_part = &port_spec[..slash_idx];
                let proto_part = &port_spec[slash_idx + 1..];
                (Some(port_part.to_string()), Some(proto_part.to_string()))
            } else {
                (Some(port_spec.to_string()), None)
            };

            let rule = FirewallRule {
                backend: "firewalld".to_string(),
                family: "any".to_string(),
                table: None,
                chain: Some(format!("zone:{}", zone)),
                direction: Some("input".to_string()),
                priority: Some(*rule_priority),
                action: Some("accept".to_string()),
                proto,
                sport: None,
                dport: port,
                saddr: None,
                daddr: None,
                in_iface: None,
                out_iface: None,
                comment: Some(format!("port: {}", port_spec)),
                packets: None,
                bytes: None,
                raw: if opts.include_backend_raw {
                    Some(format!("--zone {} --add-port {}", zone, port_spec))
                } else {
                    None
                },
            };
            rules.push(rule);
        }

        Ok(rules)
    }

    async fn get_firewalld_rich_rules(
        &self,
        zone: &str,
        rule_priority: &mut i64,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, _stderr) = run_command_with_timeout(
            "firewall-cmd",
            &["--zone", zone, "--list-rich-rules"],
            opts.timeout_ms,
        )
        .await?;

        if exit_code != 0 {
            return Ok(Vec::new());
        }

        let mut rules = Vec::new();
        for rich_rule_line in stdout.lines() {
            let rich_rule_line = rich_rule_line.trim();
            if rich_rule_line.is_empty() {
                continue;
            }

            *rule_priority += 1;

            // Parse rich rule format: 'rule family="ipv4" source address="192.168.1.0/24" accept'
            let mut rule = FirewallRule {
                backend: "firewalld".to_string(),
                family: "any".to_string(),
                table: None,
                chain: Some(format!("zone:{}", zone)),
                direction: Some("input".to_string()), // Most rich rules are for input
                priority: Some(*rule_priority),
                action: None,
                proto: None,
                sport: None,
                dport: None,
                saddr: None,
                daddr: None,
                in_iface: None,
                out_iface: None,
                comment: Some("rich rule".to_string()),
                packets: None,
                bytes: None,
                raw: if opts.include_backend_raw {
                    Some(format!(
                        "--zone {} --add-rich-rule '{}'",
                        zone, rich_rule_line
                    ))
                } else {
                    None
                },
            };

            // Parse family
            if let Some(family) = self.extract_rich_rule_family(rich_rule_line) {
                rule.family = family;
            }

            // Parse source address
            if let Some(source) = self.extract_rich_rule_source(rich_rule_line) {
                rule.saddr = Some(source);
            }

            // Parse destination address
            if let Some(dest) = self.extract_rich_rule_destination(rich_rule_line) {
                rule.daddr = Some(dest);
            }

            // Parse protocol and port
            if let Some((proto, port)) = self.extract_rich_rule_service(rich_rule_line) {
                rule.proto = Some(proto);
                rule.dport = Some(port);
            }

            // Parse action
            if let Some(action) = self.extract_rich_rule_action(rich_rule_line) {
                rule.action = Some(action);
            }

            rules.push(rule);
        }

        Ok(rules)
    }

    async fn get_firewalld_sources(
        &self,
        zone: &str,
        rule_priority: &mut i64,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        let (exit_code, stdout, _stderr) = run_command_with_timeout(
            "firewall-cmd",
            &["--zone", zone, "--list-sources"],
            opts.timeout_ms,
        )
        .await?;

        if exit_code != 0 {
            return Ok(Vec::new());
        }

        let mut rules = Vec::new();
        for source in stdout.split_whitespace() {
            *rule_priority += 1;

            let rule = FirewallRule {
                backend: "firewalld".to_string(),
                family: if source.contains(':') {
                    "ipv6".to_string()
                } else {
                    "ipv4".to_string()
                },
                table: None,
                chain: Some(format!("zone:{}", zone)),
                direction: Some("input".to_string()),
                priority: Some(*rule_priority),
                action: Some("accept".to_string()), // Sources in zone are accepted
                proto: None,
                sport: None,
                dport: None,
                saddr: Some(source.to_string()),
                daddr: None,
                in_iface: None,
                out_iface: None,
                comment: Some(format!("source: {}", source)),
                packets: None,
                bytes: None,
                raw: if opts.include_backend_raw {
                    Some(format!("--zone {} --add-source {}", zone, source))
                } else {
                    None
                },
            };
            rules.push(rule);
        }

        Ok(rules)
    }

    // Helper methods for parsing rich rules

    fn extract_rich_rule_family(&self, rule: &str) -> Option<String> {
        if rule.contains("family=\"ipv4\"") || rule.contains("family='ipv4'") {
            Some("ipv4".to_string())
        } else if rule.contains("family=\"ipv6\"") || rule.contains("family='ipv6'") {
            Some("ipv6".to_string())
        } else {
            None
        }
    }

    fn extract_rich_rule_source(&self, rule: &str) -> Option<String> {
        // Look for: source address="192.168.1.0/24"
        if let Some(start) = rule.find("source address=") {
            let after_source = &rule[start + 15..];
            if let Some(quote_char) = after_source.chars().next() {
                if quote_char == '"' || quote_char == '\'' {
                    if let Some(end) = after_source[1..].find(quote_char) {
                        return Some(after_source[1..end + 1].to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_rich_rule_destination(&self, rule: &str) -> Option<String> {
        // Look for: destination address="10.0.0.0/8"
        if let Some(start) = rule.find("destination address=") {
            let after_dest = &rule[start + 20..];
            if let Some(quote_char) = after_dest.chars().next() {
                if quote_char == '"' || quote_char == '\'' {
                    if let Some(end) = after_dest[1..].find(quote_char) {
                        return Some(after_dest[1..end + 1].to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_rich_rule_service(&self, rule: &str) -> Option<(String, String)> {
        // Look for: service name="http" or port port="80" protocol="tcp"
        if let Some(start) = rule.find("service name=") {
            let after_service = &rule[start + 13..];
            if let Some(quote_char) = after_service.chars().next() {
                if quote_char == '"' || quote_char == '\'' {
                    if let Some(end) = after_service[1..].find(quote_char) {
                        let service_name = after_service[1..end + 1].to_string();
                        // Map common services to protocols/ports
                        return match service_name.as_str() {
                            "http" => Some(("tcp".to_string(), "80".to_string())),
                            "https" => Some(("tcp".to_string(), "443".to_string())),
                            "ssh" => Some(("tcp".to_string(), "22".to_string())),
                            "ftp" => Some(("tcp".to_string(), "21".to_string())),
                            _ => Some(("tcp".to_string(), service_name)),
                        };
                    }
                }
            }
        }

        // Look for: port port="80" protocol="tcp"
        if let Some(port_start) = rule.find("port port=") {
            let after_port = &rule[port_start + 10..];
            if let Some(quote_char) = after_port.chars().next() {
                if quote_char == '"' || quote_char == '\'' {
                    if let Some(end) = after_port[1..].find(quote_char) {
                        let port = after_port[1..end + 1].to_string();

                        // Look for protocol
                        if let Some(proto_start) = rule.find("protocol=") {
                            let after_proto = &rule[proto_start + 9..];
                            if let Some(quote_char) = after_proto.chars().next() {
                                if quote_char == '"' || quote_char == '\'' {
                                    if let Some(end) = after_proto[1..].find(quote_char) {
                                        let proto = after_proto[1..end + 1].to_string();
                                        return Some((proto, port));
                                    }
                                }
                            }
                        }

                        return Some(("tcp".to_string(), port));
                    }
                }
            }
        }

        None
    }

    fn extract_rich_rule_action(&self, rule: &str) -> Option<String> {
        // Actions typically appear at the end: "accept", "reject", "drop"
        if rule.ends_with(" accept") || rule.contains(" accept ") {
            Some("accept".to_string())
        } else if rule.ends_with(" reject") || rule.contains(" reject ") {
            Some("reject".to_string())
        } else if rule.ends_with(" drop") || rule.contains(" drop ") {
            Some("drop".to_string())
        } else {
            None
        }
    }

    // ===========================================================================
    // Rule Filtering
    // ===========================================================================

    fn apply_filters(
        &self,
        mut rules: Vec<FirewallRule>,
        opts: &RulesListOptions,
    ) -> Result<Vec<FirewallRule>> {
        rules.retain(|rule| {
            // Apply family filter
            if opts.family != IpFamily::Any {
                if rule.family != opts.family.as_str() {
                    return false;
                }
            }

            // Apply table filter
            if let Some(table_filter) = &opts.table {
                if rule.table.as_ref().map(|t| t.to_lowercase())
                    != Some(table_filter.to_lowercase())
                {
                    return false;
                }
            }

            // Apply chain filter
            if let Some(chain_filter) = &opts.chain {
                if rule.chain.as_ref().map(|c| c.to_lowercase())
                    != Some(chain_filter.to_lowercase())
                {
                    return false;
                }
            }

            // Apply direction filter
            if let Some(direction_filter) = &opts.direction {
                if rule.direction.as_ref().map(|d| d.to_lowercase())
                    != Some(direction_filter.to_lowercase())
                {
                    return false;
                }
            }

            // Apply action filter
            if let Some(action_filter) = &opts.action {
                if rule.action.as_ref().map(|a| a.to_lowercase())
                    != Some(action_filter.to_lowercase())
                {
                    return false;
                }
            }

            // Apply protocol filter
            if let Some(proto_filter) = &opts.proto {
                if rule.proto.as_ref().map(|p| p.to_lowercase())
                    != Some(proto_filter.to_lowercase())
                {
                    return false;
                }
            }

            // Apply port filters
            if let Some(sport_filter) = &opts.sport {
                if rule.sport.as_ref() != Some(sport_filter) {
                    return false;
                }
            }

            if let Some(dport_filter) = &opts.dport {
                if rule.dport.as_ref() != Some(dport_filter) {
                    return false;
                }
            }

            // Apply address filters
            if let Some(saddr_filter) = &opts.saddr {
                if rule.saddr.as_ref() != Some(saddr_filter) {
                    return false;
                }
            }

            if let Some(daddr_filter) = &opts.daddr {
                if rule.daddr.as_ref() != Some(daddr_filter) {
                    return false;
                }
            }

            // Apply interface filters
            if let Some(in_iface_filter) = &opts.in_iface {
                if rule.in_iface.as_ref() != Some(in_iface_filter) {
                    return false;
                }
            }

            if let Some(out_iface_filter) = &opts.out_iface {
                if rule.out_iface.as_ref() != Some(out_iface_filter) {
                    return false;
                }
            }

            // Apply comment filter
            if let Some(comment_filter) = &opts.comment_contains {
                if let Some(comment) = &rule.comment {
                    if !comment
                        .to_lowercase()
                        .contains(&comment_filter.to_lowercase())
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            true
        });

        Ok(rules)
    }

    // ===========================================================================
    // Rules Save Implementation
    // ===========================================================================

    fn handle_rules_save(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.rules_save_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }

                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(1, "firewall rules save failed"))
                }
            }
            Err(e) => {
                let error_response = RulesSaveResponse::with_error(FirewallError::InternalError {
                    message: e.to_string(),
                });
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.to_json())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn rules_save_async(&self, args: &Args) -> Result<RulesSaveResponse> {
        // Parse options from arguments
        let opts = self.parse_rules_save_options(args)?;

        // Set query for response
        let mut response = RulesSaveResponse::new();
        response.query = json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "include_all_backends": opts.include_all_backends,
            "format": opts.format.as_str(),
            "path": opts.path,
            "compress": opts.compress.as_str(),
            "include_metadata": opts.include_metadata,
            "dry_run": opts.dry_run,
            "overwrite": opts.overwrite,
            "create_dirs": opts.create_dirs,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });
        response.format_output = opts.format_output.clone();

        // Validate that path is provided unless dry_run
        if !opts.dry_run && opts.path.is_none() {
            return Ok(RulesSaveResponse::with_error(FirewallError::MissingPath));
        }

        // Check file existence and overwrite permission
        if let Some(path) = &opts.path {
            if Path::new(path).exists() && !opts.overwrite {
                return Ok(RulesSaveResponse::with_error(FirewallError::PathExists {
                    path: path.clone(),
                }));
            }
        }

        // Determine which backends to snapshot
        let backends_to_save = if opts.include_all_backends && opts.backend == FirewallBackend::Auto
        {
            self.get_all_available_backends(opts.timeout_ms).await?
        } else {
            let backend_to_use = if opts.backend == FirewallBackend::Auto {
                self.detect_available_backend(opts.timeout_ms).await?
            } else {
                self.check_backend_availability(&opts.backend, opts.timeout_ms)
                    .await?;
                opts.backend.clone()
            };
            vec![(backend_to_use, opts.family.clone())]
        };

        // Collect rules and native data for each backend
        let mut backend_summaries = Vec::new();
        let mut save_document = if opts.include_all_backends {
            json!({
                "version": 1,
                "backend_mode": "multi",
                "backends": [],
                "metadata": {}
            })
        } else {
            json!({
                "version": 1,
                "backend_mode": "single",
                "backends": [],
                "metadata": {}
            })
        };

        for (backend, family) in backends_to_save {
            let backend_data = self.collect_backend_data(&backend, &family, &opts).await?;

            backend_summaries.push(RulesSaveBackendSummary {
                backend: backend.as_str().to_string(),
                family: family.as_str().to_string(),
                rules_count: backend_data.rules.len() as u64,
                has_native: backend_data.native_data.is_some(),
            });

            save_document["backends"]
                .as_array_mut()
                .unwrap()
                .push(backend_data.to_json());
        }

        // Add metadata if requested
        if opts.include_metadata {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            save_document["metadata"] = json!({
                "created_unix_ms": timestamp,
                "created_by": "resh.firewall.rules.save",
                "format": opts.format.as_str(),
                "compress": opts.compress.as_str(),
                "include_all_backends": opts.include_all_backends
            });
        }

        // Serialize to JSON
        let json_data = serde_json::to_string_pretty(&save_document).map_err(|e| {
            FirewallError::SerializeFailed {
                message: e.to_string(),
            }
        })?;

        // Apply compression if requested
        let final_data = if opts.compress == CompressMode::Gzip {
            self.compress_gzip(json_data.as_bytes())?
        } else {
            json_data.into_bytes()
        };

        let bytes_written = if opts.dry_run {
            0
        } else {
            // Write file atomically
            let path_ref = opts.path.as_ref().unwrap();
            self.write_file_atomic(path_ref, &final_data, opts.create_dirs)
                .await?
        };

        if opts.dry_run {
            response
                .warnings
                .push("Dry run: no file was created.".to_string());
        }

        // Create successful response
        let summary = RulesSaveSummary {
            backends: backend_summaries,
            bytes_written,
            compressed: opts.compress == CompressMode::Gzip,
            path: opts.path,
        };

        response.ok = true;
        response.summary = Some(summary);

        Ok(response)
    }

    fn parse_rules_save_options(&self, args: &Args) -> Result<RulesSaveOptions> {
        let mut opts = RulesSaveOptions::default();

        // Parse backend
        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        // Parse family
        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        // Parse include_all_backends
        if let Some(include_all_str) = args.get("include_all_backends") {
            opts.include_all_backends = include_all_str.to_lowercase() == "true";
        }

        // Parse format
        if let Some(format_str) = args.get("format") {
            opts.format = RulesSaveFormat::from_str(format_str).map_err(|_e| {
                FirewallError::InvalidSaveFormat {
                    format: format_str.to_string(),
                }
            })?;
        }

        // Parse path
        opts.path = args.get("path").cloned();

        // Parse compression
        if let Some(compress_str) = args.get("compress") {
            opts.compress = CompressMode::from_str(compress_str).map_err(|_e| {
                FirewallError::InvalidCompress {
                    compress: compress_str.to_string(),
                }
            })?;
        }

        // Parse metadata flag
        if let Some(metadata_str) = args.get("include_metadata") {
            opts.include_metadata = metadata_str.to_lowercase() == "true";
        }

        // Parse behavior flags
        if let Some(dry_run_str) = crate::core::lenient::bool_arg(args, "dry_run")? {
            opts.dry_run = dry_run_str;
        }

        if let Some(overwrite) = crate::core::lenient::bool_arg(args, "overwrite")? {
            opts.overwrite = overwrite;
        }

        if let Some(create_dirs_str) = args.get("create_dirs") {
            opts.create_dirs = create_dirs_str.to_lowercase() == "true";
        }

        // Parse timeout
        if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout_ms == 0 {
                return Err(FirewallError::InvalidTimeout { timeout_ms }.into());
            }
            opts.timeout_ms = timeout_ms;
        }

        // Parse output format
        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        Ok(opts)
    }

    async fn get_all_available_backends(
        &self,
        timeout_ms: u64,
    ) -> Result<Vec<(FirewallBackend, IpFamily)>> {
        let backends = vec![
            FirewallBackend::Nftables,
            FirewallBackend::Firewalld,
            FirewallBackend::Ufw,
            FirewallBackend::Iptables,
        ];

        let mut available = Vec::new();

        for backend in backends {
            if let Ok(_) = self.check_backend_availability(&backend, timeout_ms).await {
                // For each available backend, include both IPv4 and IPv6 families
                available.push((backend.clone(), IpFamily::Ipv4));
                available.push((backend, IpFamily::Ipv6));
            }
        }

        if available.is_empty() {
            return Err(FirewallError::NoBackendAvailable.into());
        }

        Ok(available)
    }

    async fn collect_backend_data(
        &self,
        backend: &FirewallBackend,
        family: &IpFamily,
        opts: &RulesSaveOptions,
    ) -> Result<BackendSaveData> {
        let mut backend_data = BackendSaveData {
            backend: backend.as_str().to_string(),
            family: family.as_str().to_string(),
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()),
            rules: Vec::new(),
            native_data: None,
        };

        // Collect normalized rules if requested
        if opts.format == RulesSaveFormat::NormalizedJson || opts.format == RulesSaveFormat::Both {
            let list_opts = RulesListOptions {
                backend: backend.clone(),
                family: family.clone(),
                table: None,
                chain: None,
                direction: None,
                action: None,
                proto: None,
                sport: None,
                dport: None,
                saddr: None,
                daddr: None,
                in_iface: None,
                out_iface: None,
                comment_contains: None,
                include_backend_raw: false,
                include_counters: true,
                max_rules: 100000, // High limit for save operations
                timeout_ms: opts.timeout_ms,
                format_output: OutputFormat::Json,
            };

            backend_data.rules = self.get_rules_from_backend(backend, &list_opts).await?;
        }

        // Collect native data if requested
        if opts.format == RulesSaveFormat::BackendNative || opts.format == RulesSaveFormat::Both {
            backend_data.native_data = Some(
                self.get_native_backend_data(backend, family, opts.timeout_ms)
                    .await?,
            );
        }

        Ok(backend_data)
    }

    async fn get_native_backend_data(
        &self,
        backend: &FirewallBackend,
        family: &IpFamily,
        timeout_ms: u64,
    ) -> Result<NativeSaveData> {
        match backend {
            FirewallBackend::Iptables => {
                let command = match family {
                    IpFamily::Ipv4 => "iptables-save",
                    IpFamily::Ipv6 => "ip6tables-save",
                    IpFamily::Any => {
                        // For "any", we'll just default to ipv4 for now
                        "iptables-save"
                    }
                };

                let (exit_code, stdout, _stderr) =
                    run_command_with_timeout(command, &[], timeout_ms).await?;

                if exit_code != 0 {
                    return Err(FirewallError::CommandFailed {
                        command: command.to_string(),
                        code: exit_code,
                        stderr: _stderr,
                    }
                    .into());
                }

                Ok(NativeSaveData {
                    format: format!("{}-save", command.split('-').next().unwrap()),
                    data: stdout,
                })
            }
            FirewallBackend::Nftables => {
                let (exit_code, stdout, _stderr) =
                    run_command_with_timeout("nft", &["list", "ruleset"], timeout_ms).await?;

                if exit_code != 0 {
                    return Err(FirewallError::CommandFailed {
                        command: "nft list ruleset".to_string(),
                        code: exit_code,
                        stderr: _stderr,
                    }
                    .into());
                }

                Ok(NativeSaveData {
                    format: "nft-list-ruleset".to_string(),
                    data: stdout,
                })
            }
            FirewallBackend::Ufw => {
                let (exit_code, stdout, _stderr) =
                    run_command_with_timeout("ufw", &["status", "numbered"], timeout_ms).await?;

                if exit_code != 0 {
                    return Err(FirewallError::CommandFailed {
                        command: "ufw status numbered".to_string(),
                        code: exit_code,
                        stderr: _stderr,
                    }
                    .into());
                }

                Ok(NativeSaveData {
                    format: "ufw-status".to_string(),
                    data: stdout,
                })
            }
            FirewallBackend::Firewalld => {
                let (exit_code, stdout, _stderr) =
                    run_command_with_timeout("firewall-cmd", &["--list-all-zones"], timeout_ms)
                        .await?;

                if exit_code != 0 {
                    return Err(FirewallError::CommandFailed {
                        command: "firewall-cmd --list-all-zones".to_string(),
                        code: exit_code,
                        stderr: _stderr,
                    }
                    .into());
                }

                Ok(NativeSaveData {
                    format: "firewall-cmd-list-all-zones".to_string(),
                    data: stdout,
                })
            }
            FirewallBackend::Auto => {
                return Err(FirewallError::InternalError {
                    message: "Cannot get native data for Auto backend".to_string(),
                }
                .into());
            }
        }
    }

    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>, FirewallError> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(data)
            .map_err(|e| FirewallError::CompressFailed {
                message: e.to_string(),
            })?;

        encoder.finish().map_err(|e| FirewallError::CompressFailed {
            message: e.to_string(),
        })
    }

    async fn write_file_atomic(
        &self,
        path: &str,
        data: &[u8],
        create_dirs: bool,
    ) -> Result<u64, FirewallError> {
        let target_path = Path::new(path);

        // Create parent directories if requested
        if create_dirs {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|e| FirewallError::IoError {
                    message: format!("Failed to create directories: {}", e),
                })?;
            }
        } else {
            // Check if parent directory exists
            if let Some(parent) = target_path.parent() {
                if !parent.exists() {
                    return Err(FirewallError::MissingDirectory {
                        path: parent.to_string_lossy().to_string(),
                    });
                }
            }
        }

        // Create temporary file in same directory
        let temp_path = {
            let mut temp_name = target_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("temp"))
                .to_string_lossy()
                .to_string();
            temp_name.push_str(".tmp-");
            temp_name.push_str(&format!(
                "{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));

            target_path.with_file_name(temp_name)
        };

        // Write to temporary file
        fs::write(&temp_path, data).map_err(|e| FirewallError::IoError {
            message: format!("Failed to write temp file: {}", e),
        })?;

        // Sync to disk (best effort)
        if let Ok(file) = fs::File::open(&temp_path) {
            let _ = file.sync_all();
        }

        // Atomically rename to target
        fs::rename(&temp_path, target_path).map_err(|e| {
            // Clean up temp file on error
            let _ = fs::remove_file(&temp_path);
            FirewallError::IoError {
                message: format!("Failed to rename temp file: {}", e),
            }
        })?;

        Ok(data.len() as u64)
    }

    // ===========================================================================
    // Rules Add Implementation
    // ===========================================================================

    fn handle_rules_add(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.rules_add_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }

                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(1, "firewall rules add failed"))
                }
            }
            Err(e) => {
                // Try to downcast to FirewallError to preserve specific error codes
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::InternalError {
                        message: e.to_string(),
                    }
                };

                let error_response = RulesAddResponse::with_error(firewall_error);
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.to_json())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn rules_add_async(&self, args: &Args) -> Result<RulesAddResponse> {
        // Parse options from arguments
        let opts = self.parse_rules_add_options(args)?;

        // Set query for response
        let mut response = RulesAddResponse::new();
        response.query = self.build_add_query(&opts);
        response.format_output = opts.format_output.clone();

        // Determine which backend to use
        let backend_to_use = if opts.backend == FirewallBackend::Auto {
            self.detect_available_backend(opts.timeout_ms).await?
        } else {
            self.check_backend_availability(&opts.backend, opts.timeout_ms)
                .await?;
            opts.backend.clone()
        };

        // Normalize the rule specification: one rule per IP family.
        let rule_specs = self.normalize_rule_specs(&opts, &backend_to_use)?;

        // Build commands first so invalid combinations fail before any
        // existence check or change.
        let mut planned: Vec<(FirewallRuleSpec, Vec<Vec<String>>)> = Vec::new();
        for spec in &rule_specs {
            let commands = self.generate_add_commands(spec, &opts)?;
            planned.push((spec.clone(), commands));
        }

        // Skip rules that already exist if idempotent
        let mut existing = 0usize;
        if opts.idempotent {
            let mut to_add = Vec::new();
            for (spec, commands) in planned {
                match self.check_rule_exists(&spec, &opts).await {
                    Ok(true) => existing += 1,
                    Ok(false) => to_add.push((spec, commands)),
                    Err(e) => {
                        return Ok(RulesAddResponse::with_error(
                            FirewallError::IdempotencyCheckFailed {
                                message: e.to_string(),
                            },
                        ));
                    }
                }
            }
            planned = to_add;
        }

        response.rule = if rule_specs.len() == 1 {
            rule_specs.first().cloned()
        } else {
            None
        };
        response.rules = rule_specs;

        if planned.is_empty() {
            response.ok = true;
            response.result = Some(RulesAddResult {
                changed: false,
                already_exists: true,
            });
            response.warnings.push(
                "Matching rule already exists; no changes applied (idempotent=true).".to_string(),
            );
            return Ok(response);
        }
        if existing > 0 {
            response.warnings.push(format!(
                "{} of {} rules already exist and were skipped (idempotent=true).",
                existing,
                response.rules.len()
            ));
        }

        let commands: Vec<Vec<String>> = planned.into_iter().flat_map(|(_, c)| c).collect();
        let command_lines: Vec<String> = commands.iter().map(|c| display_command(c)).collect();

        // Execute commands if not dry run
        if !opts.dry_run {
            for (argv, line) in commands.iter().zip(&command_lines) {
                let (exit_code, _stdout, stderr) = run_argv(argv, opts.timeout_ms).await?;

                if exit_code != 0 {
                    return Ok(RulesAddResponse::with_error(FirewallError::CommandFailed {
                        command: line.clone(),
                        code: exit_code,
                        stderr,
                    }));
                }
            }

            response.result = Some(RulesAddResult {
                changed: true,
                already_exists: false,
            });
        } else {
            response.result = Some(RulesAddResult {
                changed: false,
                already_exists: false,
            });
            response
                .warnings
                .push("Dry run: no firewall changes applied.".to_string());
        }

        response.ok = true;
        response.backend_commands = command_lines;

        Ok(response)
    }

    fn parse_rules_add_options(&self, args: &Args) -> Result<RulesAddOptions> {
        let mut opts = RulesAddOptions::default();

        // Parse backend
        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        // Parse family
        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
            opts.family_explicit = true;
        }

        // Parse rule fields
        opts.table = args.get("table").cloned();
        opts.chain = args.get("chain").cloned();

        if let Some(direction) = args.get("direction") {
            self.validate_direction(direction)?;
            opts.direction = direction.clone();
        }

        if let Some(action) = args.get("action") {
            self.validate_action(action)?;
            opts.action = action.clone();
        }

        opts.proto = args.get("proto").cloned();
        opts.sport = args.get("sport").cloned();
        opts.dport = args.get("dport").cloned();
        opts.saddr = args.get("saddr").cloned();
        opts.daddr = args.get("daddr").cloned();
        opts.in_iface = args.get("in_iface").cloned();
        opts.out_iface = args.get("out_iface").cloned();
        opts.zone = args.get("zone").cloned();
        opts.log_prefix = args.get("log_prefix").cloned();
        opts.rate_limit = args.get("rate_limit").cloned();
        opts.comment = args.get("comment").cloned();

        // Validate ports
        if let Some(port) = &opts.sport {
            self.validate_port_value(port)?;
        }
        if let Some(port) = &opts.dport {
            self.validate_port_value(port)?;
        }

        // Validate CIDRs
        if let Some(cidr) = &opts.saddr {
            self.validate_cidr(cidr)?;
        }
        if let Some(cidr) = &opts.daddr {
            self.validate_cidr(cidr)?;
        }

        // Validate protocol
        if let Some(proto) = &opts.proto {
            self.validate_proto(proto)?;
        }

        // Parse behavior options
        if let Some(dry_run_str) = crate::core::lenient::bool_arg(args, "dry_run")? {
            opts.dry_run = dry_run_str;
        }

        if let Some(idempotent_str) = args.get("idempotent") {
            opts.idempotent = idempotent_str.to_lowercase() == "true";
        }

        if let Some(position) = args.get("position") {
            self.validate_position(position)?;
            opts.position = position.clone();
        }

        opts.before_rule_id = args.get("before_rule_id").cloned();
        opts.after_rule_id = args.get("after_rule_id").cloned();

        if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout_ms == 0 {
                return Err(FirewallError::InvalidTimeout { timeout_ms }.into());
            }
            opts.timeout_ms = timeout_ms;
        }

        // Parse format
        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        Ok(opts)
    }

    fn validate_direction(&self, direction: &str) -> Result<()> {
        match direction.to_lowercase().as_str() {
            "input" | "output" | "forward" | "prerouting" | "postrouting" => Ok(()),
            _ => Err(FirewallError::InvalidDirection {
                direction: direction.to_string(),
            }
            .into()),
        }
    }

    fn validate_action(&self, action: &str) -> Result<()> {
        match action.to_lowercase().as_str() {
            "accept" | "drop" | "reject" | "log" | "masquerade" | "dnat" | "snat" | "redirect" => {
                Ok(())
            }
            _ => Err(FirewallError::InvalidAction {
                action: action.to_string(),
            }
            .into()),
        }
    }

    fn validate_proto(&self, proto: &str) -> Result<()> {
        match proto.to_lowercase().as_str() {
            "tcp" | "udp" | "icmp" | "icmpv6" | "any" | "all" => Ok(()),
            _ => {
                // Allow numeric protocol numbers
                if proto.parse::<u8>().is_ok() {
                    Ok(())
                } else {
                    Err(FirewallError::InvalidProto {
                        proto: proto.to_string(),
                    }
                    .into())
                }
            }
        }
    }

    fn validate_cidr(&self, cidr: &str) -> Result<()> {
        // Basic CIDR validation - check for IP address format and optional /prefix
        if cidr.contains('/') {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(FirewallError::InvalidCidr {
                    cidr: cidr.to_string(),
                }
                .into());
            }
            // Validate prefix length
            if let Ok(prefix) = parts[1].parse::<u8>() {
                // IPv4 max prefix is 32, IPv6 max is 128
                if parts[0].contains(':') && prefix > 128 {
                    return Err(FirewallError::InvalidCidr {
                        cidr: cidr.to_string(),
                    }
                    .into());
                } else if !parts[0].contains(':') && prefix > 32 {
                    return Err(FirewallError::InvalidCidr {
                        cidr: cidr.to_string(),
                    }
                    .into());
                }
            } else {
                return Err(FirewallError::InvalidCidr {
                    cidr: cidr.to_string(),
                }
                .into());
            }
        }
        // Basic IP format check (simplified)
        if !cidr.contains('.') && !cidr.contains(':') {
            return Err(FirewallError::InvalidCidr {
                cidr: cidr.to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn validate_position(&self, position: &str) -> Result<()> {
        match position.to_lowercase().as_str() {
            "append" | "insert" | "before" | "after" => Ok(()),
            _ => Err(FirewallError::InvalidPosition {
                position: position.to_string(),
            }
            .into()),
        }
    }

    /// Builds one normalized rule per IP family the rule must exist in.
    ///
    /// iptables and nftables need one rule per family, so family=any with no
    /// address yields an IPv4 and an IPv6 rule. ufw and firewalld cover both
    /// families with a single rule, reported with family "any". When an
    /// address is given, the family follows the address.
    fn normalize_rule_specs(
        &self,
        opts: &RulesAddOptions,
        backend: &FirewallBackend,
    ) -> Result<Vec<FirewallRuleSpec>> {
        if opts.zone.is_some() && *backend != FirewallBackend::Firewalld {
            return Err(FirewallError::UnsupportedOption {
                option: "zone".to_string(),
                backend: backend.as_str().to_string(),
                message: "zone applies only to firewalld".to_string(),
            }
            .into());
        }

        let families = resolve_add_families(
            &opts.family,
            opts.family_explicit,
            opts.saddr.as_ref(),
            opts.daddr.as_ref(),
        )?;

        let single_rule_backend =
            matches!(backend, FirewallBackend::Ufw | FirewallBackend::Firewalld);
        let families: Vec<&str> = if single_rule_backend && families.len() > 1 {
            vec!["any"]
        } else {
            families
        };

        // Determine default table and chain based on direction
        let (default_table, default_chain) = self.get_default_table_chain(&opts.direction, backend);
        let table = opts.table.clone().or(default_table);
        let chain = opts.chain.clone().or(default_chain);

        let specs = families
            .into_iter()
            .map(|family| {
                let addr = |given: &Option<String>| -> Option<String> {
                    match given {
                        Some(a) if normalize_address(Some(a)).is_some() => Some(a.clone()),
                        _ if family == "any" => None,
                        _ => Some(any_address(family).to_string()),
                    }
                };
                FirewallRuleSpec {
                    backend: backend.as_str().to_string(),
                    family: family.to_string(),
                    table: table.clone(),
                    chain: chain.clone(),
                    direction: opts.direction.clone(),
                    action: opts.action.clone(),
                    proto: opts.proto.clone(),
                    sport: opts.sport.clone(),
                    dport: opts.dport.clone(),
                    saddr: addr(&opts.saddr),
                    daddr: addr(&opts.daddr),
                    in_iface: opts.in_iface.clone(),
                    out_iface: opts.out_iface.clone(),
                    zone: opts.zone.clone(),
                    log_prefix: opts.log_prefix.clone(),
                    rate_limit: opts.rate_limit.clone(),
                    comment: opts.comment.clone(),
                }
            })
            .collect();

        Ok(specs)
    }

    fn get_default_table_chain(
        &self,
        direction: &str,
        backend: &FirewallBackend,
    ) -> (Option<String>, Option<String>) {
        match backend {
            FirewallBackend::Iptables | FirewallBackend::Nftables => {
                match direction.to_lowercase().as_str() {
                    "input" => (Some("filter".to_string()), Some("INPUT".to_string())),
                    "output" => (Some("filter".to_string()), Some("OUTPUT".to_string())),
                    "forward" => (Some("filter".to_string()), Some("FORWARD".to_string())),
                    "prerouting" => (Some("nat".to_string()), Some("PREROUTING".to_string())),
                    "postrouting" => (Some("nat".to_string()), Some("POSTROUTING".to_string())),
                    _ => (Some("filter".to_string()), Some("INPUT".to_string())),
                }
            }
            _ => (None, None),
        }
    }

    async fn check_rule_exists(
        &self,
        rule_spec: &FirewallRuleSpec,
        opts: &RulesAddOptions,
    ) -> Result<bool> {
        let backend = FirewallBackend::from_str(&rule_spec.backend)?;
        let list_opts = RulesListOptions {
            backend: backend.clone(),
            family: IpFamily::from_str(&rule_spec.family)?,
            include_backend_raw: false,
            include_counters: false,
            max_rules: 10000,
            timeout_ms: opts.timeout_ms,
            format_output: OutputFormat::Json,
            ..RulesListOptions::default()
        };

        let existing_rules = self.get_rules_from_backend(&backend, &list_opts).await?;
        Ok(existing_rules
            .iter()
            .any(|rule| self.rules_match(rule_spec, rule)))
    }

    fn rules_match(&self, spec: &FirewallRuleSpec, rule: &FirewallRule) -> bool {
        let eq_ci = |a: Option<&str>, b: Option<&str>| match (a, b) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            (None, None) => true,
            _ => false,
        };
        let canon_action = |a: &str| match a.to_lowercase().as_str() {
            "allow" => "accept".to_string(),
            "deny" => "drop".to_string(),
            other => other.to_string(),
        };
        let proto =
            |p: Option<&String>| p.filter(|p| !matches!(p.as_str(), "any" | "all")).cloned();

        spec.backend == rule.backend
            && (spec.family == rule.family || spec.family == "any" || rule.family == "any")
            && eq_ci(spec.table.as_deref(), rule.table.as_deref())
            && eq_ci(spec.chain.as_deref(), rule.chain.as_deref())
            && eq_ci(Some(spec.direction.as_str()), rule.direction.as_deref())
            && canon_action(&spec.action)
                == canon_action(rule.action.as_deref().unwrap_or_default())
            && proto(spec.proto.as_ref()) == proto(rule.proto.as_ref())
            && spec.sport == rule.sport
            && spec.dport == rule.dport
            && normalize_address(spec.saddr.as_ref()) == normalize_address(rule.saddr.as_ref())
            && normalize_address(spec.daddr.as_ref()) == normalize_address(rule.daddr.as_ref())
            && spec.in_iface == rule.in_iface
            && spec.out_iface == rule.out_iface
    }

    /// Builds the commands (as argument vectors) that add `rule_spec`.
    fn generate_add_commands(
        &self,
        rule_spec: &FirewallRuleSpec,
        opts: &RulesAddOptions,
    ) -> Result<Vec<Vec<String>>> {
        match FirewallBackend::from_str(&rule_spec.backend)? {
            FirewallBackend::Iptables => self.generate_iptables_add_command(rule_spec, opts),
            FirewallBackend::Nftables => self.generate_nftables_add_command(rule_spec, opts),
            FirewallBackend::Ufw => self.generate_ufw_add_command(rule_spec, opts),
            FirewallBackend::Firewalld => self.generate_firewalld_add_command(rule_spec, opts),
            FirewallBackend::Auto => Err(anyhow::anyhow!(
                "Backend should be resolved before generating commands"
            )),
        }
    }

    /// Rejects ports without a port-carrying protocol, which iptables and
    /// nftables cannot express (the port would otherwise be dropped and the
    /// rule would match every port).
    fn require_port_proto(&self, rule_spec: &FirewallRuleSpec) -> Result<()> {
        let has_port = rule_spec.sport.is_some() || rule_spec.dport.is_some();
        let port_proto = matches!(
            rule_spec
                .proto
                .as_deref()
                .map(|p| p.to_lowercase())
                .as_deref(),
            Some("tcp") | Some("udp")
        );
        if has_port && !port_proto {
            return Err(FirewallError::UnsupportedOption {
                option: if rule_spec.dport.is_some() {
                    "dport"
                } else {
                    "sport"
                }
                .to_string(),
                backend: rule_spec.backend.clone(),
                message: "ports require proto=tcp or proto=udp".to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn generate_iptables_add_command(
        &self,
        rule_spec: &FirewallRuleSpec,
        opts: &RulesAddOptions,
    ) -> Result<Vec<Vec<String>>> {
        self.require_port_proto(rule_spec)?;
        let binary = match rule_spec.family.as_str() {
            "ipv4" => "iptables",
            "ipv6" => "ip6tables",
            other => {
                return Err(FirewallError::InternalError {
                    message: format!("iptables rule needs a single family, got '{}'", other),
                }
                .into());
            }
        };
        let mut cmd: Vec<String> = vec![binary.to_string()];
        let mut push = |args: &[&str]| cmd.extend(args.iter().map(|s| s.to_string()));

        if let Some(table) = &rule_spec.table {
            push(&["-t", table]);
        }

        let chain = rule_spec
            .chain
            .clone()
            .unwrap_or_else(|| "INPUT".to_string());
        match opts.position.to_lowercase().as_str() {
            "insert" => push(&["-I", &chain, "1"]),
            _ => push(&["-A", &chain]),
        }

        if let Some(proto) = &rule_spec.proto {
            if proto != "any" && proto != "all" {
                push(&["-p", proto]);
            }
        }
        if let Some(saddr) = normalize_address(rule_spec.saddr.as_ref()) {
            push(&["-s", &saddr]);
        }
        if let Some(daddr) = normalize_address(rule_spec.daddr.as_ref()) {
            push(&["-d", &daddr]);
        }
        if let Some(in_iface) = &rule_spec.in_iface {
            push(&["-i", in_iface]);
        }
        if let Some(out_iface) = &rule_spec.out_iface {
            push(&["-o", out_iface]);
        }
        if let Some(sport) = &rule_spec.sport {
            push(&["--sport", sport]);
        }
        if let Some(dport) = &rule_spec.dport {
            push(&["--dport", dport]);
        }
        if let Some(rate_limit) = &rule_spec.rate_limit {
            push(&["-m", "limit", "--limit", rate_limit]);
        }
        if let Some(comment) = &rule_spec.comment {
            push(&["-m", "comment", "--comment", comment]);
        }
        let action = rule_spec.action.to_uppercase();
        push(&["-j", &action]);

        Ok(vec![cmd])
    }

    fn generate_nftables_add_command(
        &self,
        rule_spec: &FirewallRuleSpec,
        _opts: &RulesAddOptions,
    ) -> Result<Vec<Vec<String>>> {
        self.require_port_proto(rule_spec)?;
        let family = match rule_spec.family.as_str() {
            "ipv4" => "ip",
            "ipv6" => "ip6",
            other => {
                return Err(FirewallError::InternalError {
                    message: format!("nftables rule needs a single family, got '{}'", other),
                }
                .into());
            }
        };
        let table = rule_spec
            .table
            .clone()
            .unwrap_or_else(|| "filter".to_string());
        let chain = rule_spec
            .chain
            .clone()
            .unwrap_or_else(|| "input".to_string())
            .to_lowercase();

        let mut cmd: Vec<String> = ["nft", "add", "rule", family, &table, &chain]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut push = |args: &[&str]| cmd.extend(args.iter().map(|s| s.to_string()));

        let has_port = rule_spec.sport.is_some() || rule_spec.dport.is_some();
        if let Some(proto) = &rule_spec.proto {
            if proto != "any" && proto != "all" {
                if has_port {
                    push(&[proto]);
                } else {
                    push(&["meta", "l4proto", proto]);
                }
            }
        }
        if let Some(dport) = &rule_spec.dport {
            push(&["dport", dport]);
        }
        if let Some(sport) = &rule_spec.sport {
            if rule_spec.dport.is_some() {
                // A second port match needs its own protocol prefix.
                push(&[rule_spec.proto.as_deref().unwrap_or("tcp")]);
            }
            push(&["sport", sport]);
        }
        if let Some(saddr) = normalize_address(rule_spec.saddr.as_ref()) {
            push(&[family, "saddr", &saddr]);
        }
        if let Some(daddr) = normalize_address(rule_spec.daddr.as_ref()) {
            push(&[family, "daddr", &daddr]);
        }
        if let Some(in_iface) = &rule_spec.in_iface {
            push(&["iifname", &format!("\"{}\"", in_iface)]);
        }
        if let Some(out_iface) = &rule_spec.out_iface {
            push(&["oifname", &format!("\"{}\"", out_iface)]);
        }
        if let Some(rate_limit) = &rule_spec.rate_limit {
            push(&["limit", "rate", rate_limit]);
        }
        if let Some(comment) = &rule_spec.comment {
            push(&["comment", &format!("\"{}\"", comment.replace('"', "\\\""))]);
        }
        push(&[&rule_spec.action.to_lowercase()]);

        Ok(vec![cmd])
    }

    fn generate_ufw_add_command(
        &self,
        rule_spec: &FirewallRuleSpec,
        _opts: &RulesAddOptions,
    ) -> Result<Vec<Vec<String>>> {
        let ufw_action = match rule_spec.action.to_lowercase().as_str() {
            "accept" => "allow",
            "drop" => "deny",
            "reject" => "reject",
            _ => "allow",
        };
        let mut cmd: Vec<String> = vec!["ufw".to_string(), ufw_action.to_string()];
        let mut push = |args: &[&str]| cmd.extend(args.iter().map(|s| s.to_string()));

        if rule_spec.direction == "output" {
            push(&["out"]);
        }
        if let Some(proto) = &rule_spec.proto {
            if proto != "any" && proto != "all" {
                push(&["proto", proto]);
            }
        }
        // For a single-family rule without an address, the family's "any"
        // CIDR restricts ufw to that family; "any" covers both.
        let endpoint = |addr: &Option<String>| -> String {
            match addr {
                Some(a) => a.clone(),
                None => "any".to_string(),
            }
        };
        push(&["from", &endpoint(&rule_spec.saddr)]);
        push(&["to", &endpoint(&rule_spec.daddr)]);
        if let Some(dport) = &rule_spec.dport {
            push(&["port", dport]);
        }
        if let Some(comment) = &rule_spec.comment {
            push(&["comment", comment]);
        }

        Ok(vec![cmd])
    }

    fn generate_firewalld_add_command(
        &self,
        rule_spec: &FirewallRuleSpec,
        _opts: &RulesAddOptions,
    ) -> Result<Vec<Vec<String>>> {
        let zone = rule_spec.zone.as_ref().ok_or(FirewallError::ZoneRequired)?;

        let mut rich_rule = String::from("rule");
        if rule_spec.family == "ipv4" || rule_spec.family == "ipv6" {
            rich_rule.push_str(&format!(" family=\"{}\"", rule_spec.family));
        }
        if let Some(saddr) = normalize_address(rule_spec.saddr.as_ref()) {
            rich_rule.push_str(&format!(" source address=\"{}\"", saddr));
        }
        if let Some(daddr) = normalize_address(rule_spec.daddr.as_ref()) {
            rich_rule.push_str(&format!(" destination address=\"{}\"", daddr));
        }
        if let (Some(proto), Some(dport)) = (&rule_spec.proto, &rule_spec.dport) {
            rich_rule.push_str(&format!(" port protocol=\"{}\" port=\"{}\"", proto, dport));
        }
        rich_rule.push_str(&format!(" {}", rule_spec.action.to_lowercase()));

        Ok(vec![vec![
            "firewall-cmd".to_string(),
            format!("--zone={}", zone),
            format!("--add-rich-rule={}", rich_rule),
        ]])
    }

    fn build_add_query(&self, opts: &RulesAddOptions) -> Value {
        json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "table": opts.table,
            "chain": opts.chain,
            "direction": opts.direction,
            "action": opts.action,
            "proto": opts.proto,
            "sport": opts.sport,
            "dport": opts.dport,
            "saddr": opts.saddr,
            "daddr": opts.daddr,
            "in_iface": opts.in_iface,
            "out_iface": opts.out_iface,
            "zone": opts.zone,
            "log_prefix": opts.log_prefix,
            "rate_limit": opts.rate_limit,
            "comment": opts.comment,
            "dry_run": opts.dry_run,
            "idempotent": opts.idempotent,
            "position": opts.position,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        })
    }

    // ===========================================================================
    // Rules Delete Implementation
    // ===========================================================================

    fn handle_rules_delete(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.rules_delete_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }

                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(1, "firewall rules delete failed"))
                }
            }
            Err(e) => {
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::InternalError {
                        message: e.to_string(),
                    }
                };

                let error_response = RulesDeleteResponse::with_error(firewall_error);
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.to_json())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn rules_delete_async(&self, args: &Args) -> Result<RulesDeleteResponse> {
        // Parse options from arguments
        let opts = self.parse_rules_delete_options(args)?;

        // Set query for response
        let mut response = RulesDeleteResponse::new();
        response.query = self.build_delete_query(&opts);
        response.format_output = opts.format_output.clone();

        // Determine which backend to use
        let backend_to_use = if opts.backend == FirewallBackend::Auto {
            self.detect_available_backend(opts.timeout_ms).await?
        } else {
            self.check_backend_availability(&opts.backend, opts.timeout_ms)
                .await?;
            opts.backend.clone()
        };

        // Reject options the backend cannot honor before listing anything.
        self.validate_delete_options_for_backend(&backend_to_use, &opts)?;

        // Get matching rules using rules.list
        let matched_rules = self.find_matching_rules(&backend_to_use, &opts).await?;

        // Check if we have matches
        if matched_rules.is_empty() {
            if opts.require_match {
                return Ok(RulesDeleteResponse::with_error(
                    FirewallError::NoRulesMatched,
                ));
            } else {
                response.ok = true;
                response.result = Some(RulesDeleteResult {
                    deleted_count: 0,
                    skipped_count: 0,
                });
                response
                    .warnings
                    .push("No matching rules found to delete.".to_string());
                if opts.dry_run {
                    response
                        .warnings
                        .push("Dry run: no firewall changes applied.".to_string());
                }
                return Ok(response);
            }
        }

        // Apply limit if specified
        let rules_to_delete: Vec<MatchedFirewallRule> = if let Some(limit) = opts.limit {
            matched_rules.into_iter().take(limit as usize).collect()
        } else {
            matched_rules
        };

        // Generate delete commands (fails if any matched rule cannot be
        // addressed exactly, so nothing is deleted in that case)
        let commands = self.generate_delete_commands(&backend_to_use, &rules_to_delete)?;
        let command_lines: Vec<String> = commands.iter().map(|c| display_command(c)).collect();

        // Execute commands if not dry run
        let deleted_count = if !opts.dry_run {
            for (done, (argv, line)) in commands.iter().zip(&command_lines).enumerate() {
                let (exit_code, _stdout, stderr) = run_argv(argv, opts.timeout_ms).await?;

                if exit_code != 0 {
                    let mut failed =
                        RulesDeleteResponse::with_error(FirewallError::CommandFailed {
                            command: line.clone(),
                            code: exit_code,
                            stderr,
                        });
                    failed.query = response.query.clone();
                    failed.format_output = response.format_output.clone();
                    failed.backend_commands = command_lines.clone();
                    failed.result = Some(RulesDeleteResult {
                        deleted_count: done as u64,
                        skipped_count: (commands.len() - done) as u64,
                    });
                    return Ok(failed);
                }
            }
            commands.len() as u64
        } else {
            response
                .warnings
                .push("Dry run: no firewall changes applied.".to_string());
            0
        };

        response.ok = true;
        response.matched_rules = rules_to_delete;
        response.backend_commands = command_lines;
        response.result = Some(RulesDeleteResult {
            deleted_count,
            skipped_count: 0,
        });

        Ok(response)
    }

    fn parse_rules_delete_options(&self, args: &Args) -> Result<RulesDeleteOptions> {
        let mut opts = RulesDeleteOptions::default();

        // Parse backend
        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        // Parse family
        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        // Parse rule identifier
        opts.rule_id = args.get("rule_id").filter(|s| !s.is_empty()).cloned();

        // Parse match criteria
        opts.table = args.get("table").cloned();
        opts.chain = args.get("chain").cloned();

        if let Some(direction) = args.get("direction") {
            self.validate_direction(direction)?;
            opts.direction = Some(direction.clone());
        }

        if let Some(action) = args.get("action") {
            self.validate_action(action)?;
            opts.action = Some(action.clone());
        }

        opts.proto = args.get("proto").cloned();
        opts.sport = args.get("sport").cloned();
        opts.dport = args.get("dport").cloned();
        opts.saddr = args.get("saddr").cloned();
        opts.daddr = args.get("daddr").cloned();
        opts.in_iface = args.get("in_iface").cloned();
        opts.out_iface = args.get("out_iface").cloned();
        opts.comment_contains = args.get("comment_contains").cloned();
        opts.zone = args.get("zone").cloned();

        // Validate ports
        if let Some(port) = &opts.sport {
            self.validate_port_value(port)?;
        }
        if let Some(port) = &opts.dport {
            self.validate_port_value(port)?;
        }

        // Validate CIDRs
        if let Some(cidr) = &opts.saddr {
            self.validate_cidr(cidr)?;
        }
        if let Some(cidr) = &opts.daddr {
            self.validate_cidr(cidr)?;
        }

        // Validate protocol
        if let Some(proto) = &opts.proto {
            self.validate_proto(proto)?;
        }

        // Parse match_mode
        if let Some(match_mode) = args.get("match_mode") {
            if match_mode != "exact" && match_mode != "subset" {
                return Err(FirewallError::InvalidMatchMode {
                    match_mode: match_mode.clone(),
                }
                .into());
            }
            opts.match_mode = match_mode.clone();
        }

        // Parse limit
        if let Some(limit_str) = args.get("limit") {
            let limit: u64 = limit_str
                .parse()
                .with_context(|| format!("Invalid limit: {}", limit_str))?;
            opts.limit = Some(limit);
        }

        // Parse behavior options
        if let Some(dry_run_str) = crate::core::lenient::bool_arg(args, "dry_run")? {
            opts.dry_run = dry_run_str;
        }

        if let Some(require_match_str) = args.get("require_match") {
            opts.require_match = require_match_str.to_lowercase() == "true";
        }

        if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout_ms == 0 {
                return Err(FirewallError::InvalidTimeout { timeout_ms }.into());
            }
            opts.timeout_ms = timeout_ms;
        }

        // Parse format
        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        // Refuse a delete that names no rule at all, which would otherwise
        // select every rule (subset) or an arbitrary set (exact).
        let has_criteria = [
            &opts.table,
            &opts.chain,
            &opts.direction,
            &opts.action,
            &opts.proto,
            &opts.sport,
            &opts.dport,
            &opts.saddr,
            &opts.daddr,
            &opts.in_iface,
            &opts.out_iface,
            &opts.comment_contains,
            &opts.zone,
        ]
        .iter()
        .any(|v| v.is_some());
        if opts.rule_id.is_none() && !has_criteria {
            return Err(FirewallError::MissingDeleteCriteria.into());
        }

        Ok(opts)
    }

    /// Rejects delete options the resolved backend cannot honor.
    fn validate_delete_options_for_backend(
        &self,
        backend: &FirewallBackend,
        opts: &RulesDeleteOptions,
    ) -> Result<()> {
        if opts.zone.is_some() && *backend != FirewallBackend::Firewalld {
            return Err(FirewallError::UnsupportedOption {
                option: "zone".to_string(),
                backend: backend.as_str().to_string(),
                message: "zone applies only to firewalld".to_string(),
            }
            .into());
        }
        if let Some(rule_id) = &opts.rule_id {
            if !rule_id_is_valid(backend, rule_id) {
                return Err(FirewallError::InvalidRuleId {
                    rule_id: rule_id.clone(),
                }
                .into());
            }
        }
        Ok(())
    }

    fn build_delete_query(&self, opts: &RulesDeleteOptions) -> Value {
        json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "rule_id": opts.rule_id,
            "table": opts.table,
            "chain": opts.chain,
            "direction": opts.direction,
            "action": opts.action,
            "proto": opts.proto,
            "sport": opts.sport,
            "dport": opts.dport,
            "saddr": opts.saddr,
            "daddr": opts.daddr,
            "in_iface": opts.in_iface,
            "out_iface": opts.out_iface,
            "comment_contains": opts.comment_contains,
            "zone": opts.zone,
            "match_mode": opts.match_mode,
            "limit": opts.limit,
            "dry_run": opts.dry_run,
            "require_match": opts.require_match,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        })
    }

    async fn find_matching_rules(
        &self,
        backend: &FirewallBackend,
        opts: &RulesDeleteOptions,
    ) -> Result<Vec<MatchedFirewallRule>> {
        // List every rule of the requested family with raw backend data, so
        // rule ids reflect the backend's own numbering, not the filtered list.
        let list_opts = RulesListOptions {
            backend: backend.clone(),
            family: opts.family.clone(),
            include_backend_raw: true,
            include_counters: false,
            max_rules: 10000,
            timeout_ms: opts.timeout_ms,
            format_output: OutputFormat::Json,
            ..RulesListOptions::default()
        };

        let all_rules = match self.get_rules_from_backend(backend, &list_opts).await {
            Ok(rules) => rules,
            Err(e) => {
                return Err(FirewallError::ListFailedForDelete {
                    message: e.to_string(),
                }
                .into());
            }
        };

        self.select_rules_for_delete(backend, all_rules, opts)
    }

    /// Selects the rules `rules.delete` acts on from a full backend listing.
    ///
    /// - `rule_id` selects the rule with that backend id; any other filters
    ///   given must also hold for it (checked as a subset). An id that
    ///   matches more than one rule (for example the same iptables chain
    ///   line in IPv4 and IPv6) is rejected.
    /// - Otherwise `match_mode=subset` selects every rule for which each
    ///   given filter holds, and `match_mode=exact` additionally requires the
    ///   rule's match fields (proto, ports, addresses, interfaces) to equal
    ///   the given ones, with no other match conditions.
    /// - `zone` (firewalld) limits selection to that zone.
    fn select_rules_for_delete(
        &self,
        backend: &FirewallBackend,
        all_rules: Vec<FirewallRule>,
        opts: &RulesDeleteOptions,
    ) -> Result<Vec<MatchedFirewallRule>> {
        let filter_opts = RulesListOptions {
            backend: backend.clone(),
            family: opts.family.clone(),
            table: opts.table.clone(),
            chain: opts.chain.clone(),
            direction: opts.direction.clone(),
            action: opts.action.clone(),
            proto: opts.proto.clone(),
            sport: opts.sport.clone(),
            dport: opts.dport.clone(),
            saddr: opts.saddr.clone(),
            daddr: opts.daddr.clone(),
            in_iface: opts.in_iface.clone(),
            out_iface: opts.out_iface.clone(),
            comment_contains: opts.comment_contains.clone(),
            ..RulesListOptions::default()
        };

        let zone_chain = opts.zone.as_ref().map(|z| format!("zone:{}", z));
        let candidates: Vec<FirewallRule> = all_rules
            .into_iter()
            .filter(|r| zone_chain.is_none() || r.chain == zone_chain)
            .collect();

        let selected: Vec<FirewallRule> = if let Some(wanted) = &opts.rule_id {
            let by_id: Vec<FirewallRule> = candidates
                .into_iter()
                .filter(|r| rule_id_for(backend, r).as_deref() == Some(wanted.as_str()))
                .collect();
            let by_id = self.apply_filters(by_id, &filter_opts)?;
            if by_id.len() > 1 {
                return Err(FirewallError::AmbiguousRuleId {
                    rule_id: wanted.clone(),
                    count: by_id.len(),
                }
                .into());
            }
            by_id
        } else {
            let subset = self.apply_filters(candidates, &filter_opts)?;
            if opts.match_mode == "exact" {
                subset
                    .into_iter()
                    .filter(|r| rule_matches_exactly(r, opts))
                    .collect()
            } else {
                subset
            }
        };

        Ok(selected
            .into_iter()
            .map(|rule| MatchedFirewallRule {
                rule_id: rule_id_for(backend, &rule),
                backend: rule.backend,
                family: rule.family,
                table: rule.table,
                chain: rule.chain,
                direction: rule.direction,
                action: rule.action,
                proto: rule.proto,
                sport: rule.sport,
                dport: rule.dport,
                saddr: rule.saddr,
                daddr: rule.daddr,
                in_iface: rule.in_iface,
                out_iface: rule.out_iface,
                comment: rule.comment,
                line_number: rule.priority,
                raw: rule.raw,
            })
            .collect())
    }

    /// Builds the commands (argument vectors) that delete exactly `rules`.
    fn generate_delete_commands(
        &self,
        backend: &FirewallBackend,
        rules: &[MatchedFirewallRule],
    ) -> Result<Vec<Vec<String>>> {
        match backend {
            FirewallBackend::Iptables => self.generate_iptables_delete_commands(rules),
            FirewallBackend::Nftables => self.generate_nftables_delete_commands(rules),
            FirewallBackend::Ufw => self.generate_ufw_delete_commands(rules),
            FirewallBackend::Firewalld => self.generate_firewalld_delete_commands(rules),
            FirewallBackend::Auto => Err(FirewallError::InternalError {
                message: "Backend should have been resolved before command generation".to_string(),
            }
            .into()),
        }
    }

    /// iptables rules are deleted by full rule specification
    /// (`iptables -t <table> -D <chain> <spec>`), which does not depend on
    /// line numbers. Without the listed spec, the rule's line number in its
    /// own chain is used, highest first so earlier deletions do not shift
    /// later ones.
    fn generate_iptables_delete_commands(
        &self,
        rules: &[MatchedFirewallRule],
    ) -> Result<Vec<Vec<String>>> {
        let mut ordered: Vec<&MatchedFirewallRule> = rules.iter().collect();
        ordered.sort_by(|a, b| {
            (&a.family, &a.table, &a.chain)
                .cmp(&(&b.family, &b.table, &b.chain))
                .then(b.line_number.cmp(&a.line_number))
        });

        let mut commands = Vec::new();
        for rule in ordered {
            let binary = if rule.family == "ipv6" {
                "ip6tables"
            } else {
                "iptables"
            };
            let table = rule.table.as_deref().unwrap_or("filter");
            let chain = rule
                .chain
                .as_deref()
                .ok_or_else(|| FirewallError::RuleIdUnavailable {
                    message: "iptables rule has no chain".to_string(),
                })?;
            let mut argv: Vec<String> = [binary, "-t", table, "-D", chain]
                .iter()
                .map(|s| s.to_string())
                .collect();

            let spec = rule
                .raw
                .as_deref()
                .map(tokenize_rule_line)
                .filter(|t| t.len() > 2 && t[0] == "-A" && t[1] == chain);
            match (spec, rule.line_number) {
                (Some(tokens), _) => argv.extend(tokens.into_iter().skip(2)),
                (None, Some(line)) if line > 0 => argv.push(line.to_string()),
                _ => {
                    return Err(FirewallError::RuleIdUnavailable {
                        message: format!(
                            "no rule specification or line number for a rule in chain {}",
                            chain
                        ),
                    }
                    .into());
                }
            }
            commands.push(argv);
        }
        Ok(commands)
    }

    fn generate_nftables_delete_commands(
        &self,
        rules: &[MatchedFirewallRule],
    ) -> Result<Vec<Vec<String>>> {
        let mut commands = Vec::new();
        for rule in rules {
            let family = match rule.family.as_str() {
                "ipv4" => "ip",
                "ipv6" => "ip6",
                other => other,
            };
            let table = rule.table.as_deref().unwrap_or("filter");
            let chain = rule
                .chain
                .as_deref()
                .ok_or_else(|| FirewallError::RuleIdUnavailable {
                    message: "nftables rule has no chain".to_string(),
                })?;
            let handle =
                rule.rule_id
                    .as_deref()
                    .ok_or_else(|| FirewallError::RuleIdUnavailable {
                        message: format!("nftables rule in chain {} has no handle", chain),
                    })?;
            commands.push(
                [
                    "nft", "delete", "rule", family, table, chain, "handle", handle,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            );
        }
        Ok(commands)
    }

    /// ufw renumbers after each delete, so rules go highest number first.
    fn generate_ufw_delete_commands(
        &self,
        rules: &[MatchedFirewallRule],
    ) -> Result<Vec<Vec<String>>> {
        let mut numbers = Vec::new();
        for rule in rules {
            let n = rule
                .rule_id
                .as_deref()
                .and_then(|id| id.parse::<u64>().ok())
                .ok_or_else(|| FirewallError::RuleIdUnavailable {
                    message: "ufw rule has no rule number".to_string(),
                })?;
            numbers.push(n);
        }
        numbers.sort_unstable_by(|a, b| b.cmp(a));
        numbers.dedup();
        Ok(numbers
            .into_iter()
            .map(|n| {
                vec![
                    "ufw".to_string(),
                    "--force".to_string(),
                    "delete".to_string(),
                    n.to_string(),
                ]
            })
            .collect())
    }

    /// firewalld rules are removed from their own zone by kind and value,
    /// taken from the rule id `<zone>:<kind>:<value>`.
    fn generate_firewalld_delete_commands(
        &self,
        rules: &[MatchedFirewallRule],
    ) -> Result<Vec<Vec<String>>> {
        let mut commands = Vec::new();
        for rule in rules {
            let id = rule
                .rule_id
                .as_deref()
                .ok_or_else(|| FirewallError::RuleIdUnavailable {
                    message: "firewalld rule has no zone, kind, and value".to_string(),
                })?;
            let mut parts = id.splitn(3, ':');
            let (Some(zone), Some(kind), Some(value)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(FirewallError::RuleIdUnavailable {
                    message: format!("bad firewalld rule id {}", id),
                }
                .into());
            };
            commands.push(vec![
                "firewall-cmd".to_string(),
                format!("--zone={}", zone),
                format!("--remove-{}={}", kind, value),
            ]);
        }
        Ok(commands)
    }

    // ===========================================================================
    // Rules Reload Implementation
    // ===========================================================================

    fn handle_rules_reload(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.rules_reload_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }

                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(1, "firewall rules reload failed"))
                }
            }
            Err(e) => {
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::InternalError {
                        message: e.to_string(),
                    }
                };

                let error_response = RulesReloadResponse::with_error(firewall_error);
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.to_json())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn rules_reload_async(&self, args: &Args) -> Result<RulesReloadResponse> {
        let opts = self.parse_rules_reload_options(args)?;

        let mut response = RulesReloadResponse::new();
        response.query = json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "path": opts.path,
            "source_format": opts.source_format.as_str(),
            "dry_run": opts.dry_run,
            "validate_only": opts.validate_only,
            "backup_before_apply": opts.backup_before_apply,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        });
        response.format_output = opts.format_output.clone();

        // Determine backend to use
        let backend_to_use = if opts.backend == FirewallBackend::Auto {
            self.detect_available_backend(opts.timeout_ms).await?
        } else {
            self.check_backend_availability(&opts.backend, opts.timeout_ms)
                .await?;
            opts.backend.clone()
        };

        response.backend = backend_to_use.as_str().to_string();
        response.family = opts.family.as_str().to_string();

        // Determine reload mode
        if opts.path.is_none() {
            // Backend-managed reload
            self.backend_managed_reload(&backend_to_use, &opts, &mut response)
                .await?;
        } else {
            // File-based reload
            self.file_based_reload(&backend_to_use, &opts, &mut response)
                .await?;
        }

        Ok(response)
    }

    async fn backend_managed_reload(
        &self,
        backend: &FirewallBackend,
        opts: &RulesReloadOptions,
        response: &mut RulesReloadResponse,
    ) -> Result<()> {
        response.mode = "backend_reload".to_string();
        response.source = RulesReloadSource {
            path: None,
            source_format: None,
        };

        match backend {
            FirewallBackend::Iptables | FirewallBackend::Nftables => {
                return Err(FirewallError::ReloadPathRequired {
                    backend: backend.as_str().to_string(),
                }
                .into());
            }
            FirewallBackend::Ufw => {
                let command = "ufw reload";
                response.actions.push(command.to_string());

                if !opts.dry_run && !opts.validate_only {
                    let (exit_code, stdout, stderr) =
                        run_command_with_timeout("ufw", &["reload"], opts.timeout_ms).await?;

                    if exit_code != 0 {
                        return Err(FirewallError::ReloadFailed {
                            message: format!("ufw reload failed: {}", stderr),
                        }
                        .into());
                    }

                    response.result = Some(RulesReloadResult {
                        changed: true,
                        backup_path: None,
                    });
                } else {
                    response.result = Some(RulesReloadResult {
                        changed: false,
                        backup_path: None,
                    });
                    if opts.dry_run {
                        response
                            .warnings
                            .push("Dry run: ufw reload not executed.".to_string());
                    }
                    if opts.validate_only {
                        response.warnings.push(
                            "Validate-only: ufw does not support true validation mode.".to_string(),
                        );
                    }
                }

                response.ok = true;
                Ok(())
            }
            FirewallBackend::Firewalld => {
                let command = "firewall-cmd --reload";
                response.actions.push(command.to_string());

                if !opts.dry_run && !opts.validate_only {
                    let (exit_code, stdout, stderr) =
                        run_command_with_timeout("firewall-cmd", &["--reload"], opts.timeout_ms)
                            .await?;

                    if exit_code != 0 {
                        return Err(FirewallError::ReloadFailed {
                            message: format!("firewall-cmd --reload failed: {}", stderr),
                        }
                        .into());
                    }

                    response.result = Some(RulesReloadResult {
                        changed: true,
                        backup_path: None,
                    });
                } else {
                    response.result = Some(RulesReloadResult {
                        changed: false,
                        backup_path: None,
                    });
                    if opts.dry_run {
                        response
                            .warnings
                            .push("Dry run: firewall-cmd --reload not executed.".to_string());
                    }
                    if opts.validate_only {
                        response.warnings.push(
                            "Validate-only: firewalld does not support true validation mode."
                                .to_string(),
                        );
                    }
                }

                response.ok = true;
                Ok(())
            }
            FirewallBackend::Auto => Err(FirewallError::InternalError {
                message: "Auto backend should have been resolved".to_string(),
            }
            .into()),
        }
    }

    async fn file_based_reload(
        &self,
        backend: &FirewallBackend,
        opts: &RulesReloadOptions,
        response: &mut RulesReloadResponse,
    ) -> Result<()> {
        response.mode = "file_reload".to_string();

        let path = opts.path.as_ref().unwrap();

        // Check if file exists
        if !Path::new(path).exists() {
            return Err(FirewallError::ReloadPathNotFound { path: path.clone() }.into());
        }

        // Detect source format if Auto
        let source_format = if opts.source_format == RulesReloadSourceFormat::Auto {
            self.detect_source_format(path)?
        } else {
            opts.source_format.clone()
        };

        response.source = RulesReloadSource {
            path: Some(path.clone()),
            source_format: Some(source_format.as_str().to_string()),
        };

        // Check if backend supports file-based reload
        match backend {
            FirewallBackend::Ufw | FirewallBackend::Firewalld => {
                return Err(FirewallError::ReloadFileModeNotSupported {
                    backend: backend.as_str().to_string(),
                }
                .into());
            }
            _ => {}
        }

        // Handle backend_native format
        if source_format == RulesReloadSourceFormat::BackendNative {
            match backend {
                FirewallBackend::Iptables => {
                    self.iptables_file_reload(opts, response, path).await?;
                }
                FirewallBackend::Nftables => {
                    self.nftables_file_reload(opts, response, path).await?;
                }
                _ => {
                    return Err(FirewallError::ReloadFileModeNotSupported {
                        backend: backend.as_str().to_string(),
                    }
                    .into());
                }
            }
        } else if source_format == RulesReloadSourceFormat::NormalizedJson {
            // For now, normalized JSON reload is not fully supported
            // This would require converting JSON back to backend commands
            response.warnings.push(
                "Normalized JSON reload support is limited. Backend-native format recommended."
                    .to_string(),
            );
            // Try to extract backend_native from JSON if available
            self.reload_from_normalized_json(backend, opts, response, path)
                .await?;
        }

        Ok(())
    }

    fn detect_source_format(&self, path: &str) -> Result<RulesReloadSourceFormat> {
        // Try to read the file and detect format
        let content = fs::read_to_string(path).map_err(|e| FirewallError::ReloadPathNotFound {
            path: path.to_string(),
        })?;

        // Check if it's JSON
        if content.trim_start().starts_with('{') {
            if let Ok(json_val) = serde_json::from_str::<Value>(&content) {
                if json_val.get("version").is_some() && json_val.get("backends").is_some() {
                    return Ok(RulesReloadSourceFormat::NormalizedJson);
                }
            }
        }

        // Otherwise assume backend_native
        Ok(RulesReloadSourceFormat::BackendNative)
    }

    async fn iptables_file_reload(
        &self,
        opts: &RulesReloadOptions,
        response: &mut RulesReloadResponse,
        path: &str,
    ) -> Result<()> {
        let family = &opts.family;

        // Determine which iptables commands to use
        let (restore_cmd, cmd_family) = match family {
            IpFamily::Ipv4 => ("iptables-restore", "ipv4"),
            IpFamily::Ipv6 => ("ip6tables-restore", "ipv6"),
            IpFamily::Any => {
                return Err(FirewallError::InvalidFamily {
                    family: "any (must specify ipv4 or ipv6 for iptables file reload)".to_string(),
                }
                .into());
            }
        };

        // Create backup if requested
        let backup_path = if opts.backup_before_apply && !opts.dry_run && !opts.validate_only {
            Some(
                self.create_iptables_backup(cmd_family, opts.timeout_ms)
                    .await?,
            )
        } else {
            None
        };

        let command_str = format!("{} < {}", restore_cmd, path);
        response.actions.push(command_str.clone());

        if opts.validate_only {
            // Try to validate if possible (some systems have --test flag)
            response.warnings.push(
                "iptables-restore does not have standard validation mode on all systems."
                    .to_string(),
            );
            response.result = Some(RulesReloadResult {
                changed: false,
                backup_path: None,
            });
            response.ok = true;
            return Ok(());
        }

        if !opts.dry_run {
            // Execute iptables-restore
            let file_content = fs::read_to_string(path).map_err(|e| FirewallError::IoError {
                message: format!("Failed to read file: {}", e),
            })?;

            let mut child = Command::new(resolve_program(restore_cmd))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| FirewallError::ReloadFailed {
                    message: format!("Failed to spawn {}: {}", restore_cmd, e),
                })?;

            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(file_content.as_bytes())
                    .map_err(|e| FirewallError::IoError {
                        message: format!("Failed to write to stdin: {}", e),
                    })?;
            }

            let output = child
                .wait_with_output()
                .map_err(|e| FirewallError::ReloadFailed {
                    message: format!("Failed to wait for {}: {}", restore_cmd, e),
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(FirewallError::ReloadFailed {
                    message: format!("{} failed: {}", restore_cmd, stderr),
                }
                .into());
            }

            response.result = Some(RulesReloadResult {
                changed: true,
                backup_path,
            });
        } else {
            response.result = Some(RulesReloadResult {
                changed: false,
                backup_path: None,
            });
            response
                .warnings
                .push("Dry run: iptables-restore not executed.".to_string());
        }

        response.ok = true;
        Ok(())
    }

    async fn nftables_file_reload(
        &self,
        opts: &RulesReloadOptions,
        response: &mut RulesReloadResponse,
        path: &str,
    ) -> Result<()> {
        // Create backup if requested
        let backup_path = if opts.backup_before_apply && !opts.dry_run && !opts.validate_only {
            Some(self.create_nftables_backup(opts.timeout_ms).await?)
        } else {
            None
        };

        if opts.validate_only {
            // Use nft -c -f for validation
            let command_str = format!("nft -c -f {}", path);
            response.actions.push(command_str.clone());

            let (exit_code, _, stderr) =
                run_command_with_timeout("nft", &["-c", "-f", path], opts.timeout_ms).await?;

            if exit_code != 0 {
                return Err(FirewallError::ReloadFailed {
                    message: format!("nft validation failed: {}", stderr),
                }
                .into());
            }

            response.result = Some(RulesReloadResult {
                changed: false,
                backup_path: None,
            });
            response
                .warnings
                .push("Validate-only: nft ruleset not applied.".to_string());
            response.ok = true;
            return Ok(());
        }

        let command_str = format!("nft -f {}", path);
        response.actions.push(command_str.clone());

        if !opts.dry_run {
            let (exit_code, _, stderr) =
                run_command_with_timeout("nft", &["-f", path], opts.timeout_ms).await?;

            if exit_code != 0 {
                return Err(FirewallError::ReloadFailed {
                    message: format!("nft -f failed: {}", stderr),
                }
                .into());
            }

            response.result = Some(RulesReloadResult {
                changed: true,
                backup_path,
            });
        } else {
            response.result = Some(RulesReloadResult {
                changed: false,
                backup_path: None,
            });
            response
                .warnings
                .push("Dry run: nft -f not executed.".to_string());
        }

        response.ok = true;
        Ok(())
    }

    /// Captures the live iptables rules for `family` ("ipv4"/"ipv6") and
    /// writes them to a new file in the backup directory. Returns the path
    /// only once the backup is on disk.
    async fn create_iptables_backup(&self, family: &str, timeout_ms: u64) -> Result<String> {
        let save_cmd = if family == "ipv6" {
            "ip6tables-save"
        } else {
            "iptables-save"
        };

        let (exit_code, stdout, stderr) =
            run_command_with_timeout(save_cmd, &[], timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::SaveFailed {
                message: format!("{} failed: {}", save_cmd, stderr),
            }
            .into());
        }

        write_rules_backup(
            &firewall_backup_dir(),
            &backup_file_name("iptables", Some(family), "rules"),
            stdout.as_bytes(),
        )
    }

    /// Captures the live nftables ruleset and writes it to a new file in
    /// the backup directory. Returns the path only once it is on disk.
    async fn create_nftables_backup(&self, timeout_ms: u64) -> Result<String> {
        let (exit_code, stdout, stderr) =
            run_command_with_timeout("nft", &["list", "ruleset"], timeout_ms).await?;

        if exit_code != 0 {
            return Err(FirewallError::SaveFailed {
                message: format!("nft list ruleset failed: {}", stderr),
            }
            .into());
        }

        write_rules_backup(
            &firewall_backup_dir(),
            &backup_file_name("nftables", None, "rules"),
            stdout.as_bytes(),
        )
    }

    async fn reload_from_normalized_json(
        &self,
        backend: &FirewallBackend,
        opts: &RulesReloadOptions,
        response: &mut RulesReloadResponse,
        path: &str,
    ) -> Result<()> {
        // Read and parse JSON
        let content = fs::read_to_string(path).map_err(|e| FirewallError::IoError {
            message: format!("Failed to read file: {}", e),
        })?;

        let snapshot: Value =
            serde_json::from_str(&content).map_err(|e| FirewallError::SerializeFailed {
                message: format!("Failed to parse JSON: {}", e),
            })?;

        // Check if backend_native data is present
        if let Some(backends) = snapshot.get("backends").and_then(|b| b.as_array()) {
            for backend_data in backends {
                if backend_data.get("backend").and_then(|b| b.as_str()) == Some(backend.as_str()) {
                    if let Some(native) = backend_data.get("native") {
                        if let Some(native_data) = native.get("data").and_then(|d| d.as_str()) {
                            // Write native data to a temp file and reload. The
                            // file is created securely (random name, O_EXCL,
                            // 0600) rather than at a predictable /tmp path that
                            // a local user could pre-create as a symlink; it is
                            // deleted when `temp` is dropped.
                            let mut temp = tempfile::Builder::new()
                                .prefix(&format!(".resh-reload-{}-", backend.as_str()))
                                .suffix(".rules")
                                .tempfile()
                                .and_then(|mut t| {
                                    t.write_all(native_data.as_bytes())
                                        .and_then(|_| t.flush())
                                        .map(|_| t)
                                })
                                .map_err(|e| FirewallError::IoError {
                                    message: format!("Failed to write temp file: {}", e),
                                })?;
                            let temp_path = temp.path().to_string_lossy().to_string();

                            // Reload using the temp file
                            match backend {
                                FirewallBackend::Iptables => {
                                    self.iptables_file_reload(opts, response, &temp_path)
                                        .await?;
                                }
                                FirewallBackend::Nftables => {
                                    self.nftables_file_reload(opts, response, &temp_path)
                                        .await?;
                                }
                                _ => {}
                            }

                            // Clean up temp file
                            let _ = temp.flush();
                            drop(temp);

                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(FirewallError::ReloadBackendNativeMissing {
            backend: backend.as_str().to_string(),
        }
        .into())
    }

    fn parse_rules_reload_options(&self, args: &Args) -> Result<RulesReloadOptions> {
        let mut opts = RulesReloadOptions::default();

        // Parse backend
        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        // Parse family
        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        // Parse path
        opts.path = args.get("path").cloned();

        // Parse source_format
        if let Some(format_str) = args.get("source_format") {
            opts.source_format = RulesReloadSourceFormat::from_str(format_str).map_err(|_e| {
                FirewallError::InvalidReloadSourceFormat {
                    format: format_str.to_string(),
                }
            })?;
        }

        // Parse behavior flags
        if let Some(dry_run_str) = crate::core::lenient::bool_arg(args, "dry_run")? {
            opts.dry_run = dry_run_str;
        }

        if let Some(validate_only_str) = args.get("validate_only") {
            opts.validate_only = validate_only_str.to_lowercase() == "true";
        }

        if let Some(backup) = crate::core::lenient::bool_arg(args, "backup_before_apply")? {
            opts.backup_before_apply = backup;
        }

        // Parse timeout
        if let Some(timeout_str) = args.get("timeout_ms") {
            let timeout_ms: u64 = timeout_str
                .parse()
                .with_context(|| format!("Invalid timeout_ms: {}", timeout_str))?;
            if timeout_ms == 0 {
                return Err(FirewallError::InvalidTimeout { timeout_ms }.into());
            }
            opts.timeout_ms = timeout_ms;
        }

        // Parse output format
        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        Ok(opts)
    }

    fn handle_status(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.status_async(args).await });

        match result {
            Ok(response) => {
                match response.output_format {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.json_format())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.text_format())?;
                    }
                }
                Ok(Status::ok())
            }
            Err(e) => {
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::StatusInternalError {
                        message: e.to_string(),
                    }
                };

                // Create a default StatusOptions for error response
                let error_opts = StatusOptions {
                    backend: StatusBackend::Auto,
                    family: StatusFamily::Any,
                    include_metrics: true,
                    include_rules_summary: false,
                    timeout_ms: 5000,
                    output_format: OutputFormat::Json,
                };

                let error_response = StatusResponse::with_error(error_opts, firewall_error);
                writeln!(io.stderr, "Error: {}", e)?;
                writeln!(
                    io.stdout,
                    "{}",
                    serde_json::to_string_pretty(&error_response.json_format())?
                )?;
                Ok(Status::err(1, &e.to_string()))
            }
        }
    }

    async fn status_async(&self, args: &Args) -> Result<StatusResponse> {
        let opts = self.parse_status_options(args)?;

        match opts.backend {
            StatusBackend::Auto => self.execute_status_auto(&opts).await,
            StatusBackend::All => self.execute_status_all(&opts).await,
            StatusBackend::Iptables => {
                self.execute_status_specific(&opts, &FirewallBackend::Iptables)
                    .await
            }
            StatusBackend::Nftables => {
                self.execute_status_specific(&opts, &FirewallBackend::Nftables)
                    .await
            }
            StatusBackend::Ufw => {
                self.execute_status_specific(&opts, &FirewallBackend::Ufw)
                    .await
            }
            StatusBackend::Firewalld => {
                self.execute_status_specific(&opts, &FirewallBackend::Firewalld)
                    .await
            }
        }
    }

    fn parse_status_options(&self, args: &Args) -> Result<StatusOptions> {
        let backend_str = args.get("backend").map(|s| s.as_str()).unwrap_or("auto");
        let backend = StatusBackend::from_str(backend_str)?;

        let family_str = args.get("family").map(|s| s.as_str()).unwrap_or("any");
        let family = StatusFamily::from_str(family_str)?;

        let output_format = if args
            .get("format_output")
            .map(|s| s.as_str())
            .unwrap_or("json")
            == "text"
        {
            OutputFormat::Text
        } else {
            OutputFormat::Json
        };

        Ok(StatusOptions {
            backend,
            family,
            include_metrics: args
                .get("include_metrics")
                .map(|s| s.parse().unwrap_or(true))
                .unwrap_or(true),
            include_rules_summary: args
                .get("include_rules_summary")
                .map(|s| s.parse().unwrap_or(false))
                .unwrap_or(false),
            timeout_ms: args
                .get("timeout_ms")
                .map(|s| s.parse().unwrap_or(5000))
                .unwrap_or(5000),
            output_format,
        })
    }

    async fn execute_status_auto(&self, opts: &StatusOptions) -> Result<StatusResponse> {
        // Try to detect the primary active backend
        match self.detect_available_backend(opts.timeout_ms).await {
            Ok(backend) => {
                let backend_status = self.get_backend_status(&backend, opts).await?;
                Ok(StatusResponse::success(opts.clone(), vec![backend_status]))
            }
            Err(_) => Err(FirewallError::StatusNoBackendAvailable.into()),
        }
    }

    async fn execute_status_all(&self, opts: &StatusOptions) -> Result<StatusResponse> {
        let all_backends = vec![
            FirewallBackend::Iptables,
            FirewallBackend::Nftables,
            FirewallBackend::Ufw,
            FirewallBackend::Firewalld,
        ];

        let mut backend_statuses = Vec::new();

        for backend in all_backends {
            let status = self
                .get_backend_status(&backend, opts)
                .await
                .unwrap_or_else(|_| FirewallBackendStatus {
                    backend: backend.as_str().to_string(),
                    available: false,
                    active: false,
                    enabled: false,
                    default_policy: None,
                    rule_count_ipv4: None,
                    rule_count_ipv6: None,
                    details: None,
                    warnings: vec![format!(
                        "{} not available or failed to check",
                        backend.as_str()
                    )],
                });
            backend_statuses.push(status);
        }

        Ok(StatusResponse::success(opts.clone(), backend_statuses))
    }

    async fn execute_status_specific(
        &self,
        opts: &StatusOptions,
        backend: &FirewallBackend,
    ) -> Result<StatusResponse> {
        match self.get_backend_status(backend, opts).await {
            Ok(status) => Ok(StatusResponse::success(opts.clone(), vec![status])),
            Err(e) => {
                if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    Err(fw_err.clone().into())
                } else {
                    Err(FirewallError::StatusInternalError {
                        message: e.to_string(),
                    }
                    .into())
                }
            }
        }
    }

    async fn get_backend_status(
        &self,
        backend: &FirewallBackend,
        opts: &StatusOptions,
    ) -> Result<FirewallBackendStatus> {
        match backend {
            FirewallBackend::Iptables => self.get_iptables_status(opts).await,
            FirewallBackend::Nftables => self.get_nftables_status(opts).await,
            FirewallBackend::Ufw => self.get_ufw_status(opts).await,
            FirewallBackend::Firewalld => self.get_firewalld_status(opts).await,
            FirewallBackend::Auto => Err(FirewallError::StatusInternalError {
                message: "Auto backend should be resolved before getting status".to_string(),
            }
            .into()),
        }
    }

    async fn get_iptables_status(&self, opts: &StatusOptions) -> Result<FirewallBackendStatus> {
        let mut warnings = Vec::new();

        // Check availability
        let available = is_command_available("iptables") || is_command_available("ip6tables");

        if !available {
            return Ok(FirewallBackendStatus {
                backend: "iptables".to_string(),
                available: false,
                active: false,
                enabled: false,
                default_policy: None,
                rule_count_ipv4: None,
                rule_count_ipv6: None,
                details: None,
                warnings: vec!["iptables/ip6tables commands not available".to_string()],
            });
        }

        // Get IPv4 status
        let (ipv4_active, ipv4_count, ipv4_policy) =
            self.get_iptables_family_status("iptables-save", opts).await;

        // Get IPv6 status
        let (ipv6_active, ipv6_count, ipv6_policy) = self
            .get_iptables_family_status("ip6tables-save", opts)
            .await;

        let active = ipv4_active || ipv6_active;
        let enabled = active; // iptables doesn't have separate enabled/active states

        if !active {
            warnings.push(
                "No iptables rules active; system may rely on another firewall backend."
                    .to_string(),
            );
        }

        let default_policy = match (ipv4_policy, ipv6_policy) {
            (Some(p4), Some(p6)) if p4 == p6 => Some(p4),
            (Some(p4), Some(p6)) => Some(format!("IPv4: {}, IPv6: {}", p4, p6)),
            (Some(p), None) | (None, Some(p)) => Some(p),
            (None, None) => Some("ACCEPT".to_string()),
        };

        let details = if opts.include_metrics {
            Some(format!(
                "iptables available {}active rules; default INPUT/OUTPUT/FORWARD policy {}",
                if active { "with " } else { "but no " },
                default_policy.as_ref().unwrap_or(&"ACCEPT".to_string())
            ))
        } else {
            None
        };

        Ok(FirewallBackendStatus {
            backend: "iptables".to_string(),
            available,
            active,
            enabled,
            default_policy,
            rule_count_ipv4: ipv4_count,
            rule_count_ipv6: ipv6_count,
            details,
            warnings,
        })
    }

    async fn get_iptables_family_status(
        &self,
        command: &str,
        opts: &StatusOptions,
    ) -> (bool, Option<u64>, Option<String>) {
        match run_command_with_timeout(command, &[], opts.timeout_ms).await {
            Ok((0, stdout, _)) => {
                let mut rule_count = 0u64;
                let mut default_policy = None;
                let mut has_custom_rules = false;

                for line in stdout.lines() {
                    let line = line.trim();

                    if line.starts_with(":INPUT ")
                        || line.starts_with(":OUTPUT ")
                        || line.starts_with(":FORWARD ")
                    {
                        if let Some(policy_part) = line.split_whitespace().nth(1) {
                            default_policy = Some(policy_part.to_string());
                        }
                    } else if line.starts_with("-A ") {
                        rule_count += 1;
                        if !line.contains("state --state") && !line.contains("RELATED,ESTABLISHED")
                        {
                            has_custom_rules = true;
                        }
                    }
                }

                (has_custom_rules, Some(rule_count), default_policy)
            }
            _ => (false, None, None),
        }
    }

    async fn get_nftables_status(&self, opts: &StatusOptions) -> Result<FirewallBackendStatus> {
        let mut warnings = Vec::new();

        // Check availability
        let available = is_command_available("nft");

        if !available {
            return Ok(FirewallBackendStatus {
                backend: "nftables".to_string(),
                available: false,
                active: false,
                enabled: false,
                default_policy: None,
                rule_count_ipv4: None,
                rule_count_ipv6: None,
                details: None,
                warnings: vec!["nft command not available".to_string()],
            });
        }

        match run_command_with_timeout("nft", &["list", "ruleset"], opts.timeout_ms).await {
            Ok((0, stdout, _)) => {
                let (active, ipv4_count, ipv6_count, tables, default_policy) =
                    self.parse_nftables_status(&stdout, opts).await;

                let enabled = active; // nftables doesn't have separate enabled/active states

                let details = if opts.include_metrics {
                    Some(format!(
                        "nftables ruleset {} (tables: {}; rules: ipv4={}, ipv6={})",
                        if active { "present" } else { "empty" },
                        if tables.is_empty() {
                            "none".to_string()
                        } else {
                            tables.join(",")
                        },
                        ipv4_count.unwrap_or(0),
                        ipv6_count.unwrap_or(0)
                    ))
                } else {
                    None
                };

                Ok(FirewallBackendStatus {
                    backend: "nftables".to_string(),
                    available,
                    active,
                    enabled,
                    default_policy,
                    rule_count_ipv4: ipv4_count,
                    rule_count_ipv6: ipv6_count,
                    details,
                    warnings,
                })
            }
            Ok((code, _, stderr)) => {
                warnings.push(format!(
                    "nft list ruleset failed with exit code {}: {}",
                    code, stderr
                ));
                Ok(FirewallBackendStatus {
                    backend: "nftables".to_string(),
                    available,
                    active: false,
                    enabled: false,
                    default_policy: None,
                    rule_count_ipv4: None,
                    rule_count_ipv6: None,
                    details: None,
                    warnings,
                })
            }
            Err(_) => Err(FirewallError::StatusTimeout {
                backend: "nftables".to_string(),
            }
            .into()),
        }
    }

    async fn parse_nftables_status(
        &self,
        stdout: &str,
        _opts: &StatusOptions,
    ) -> (bool, Option<u64>, Option<u64>, Vec<String>, Option<String>) {
        let mut active = false;
        let mut ipv4_count = 0u64;
        let mut ipv6_count = 0u64;
        let mut tables = Vec::new();
        let mut current_family = None;
        let mut default_policy = None;

        for line in stdout.lines() {
            let line = line.trim();

            if line.starts_with("table ip ") {
                current_family = Some("ip");
                if let Some(table_name) = line.split_whitespace().nth(2) {
                    tables.push(table_name.to_string());
                }
                active = true;
            } else if line.starts_with("table ip6 ") {
                current_family = Some("ip6");
                if let Some(table_name) = line.split_whitespace().nth(2) {
                    tables.push(table_name.to_string());
                }
                active = true;
            } else if line.contains("chain ")
                && (line.contains("type filter") || line.contains("hook input"))
            {
                if line.contains("policy drop") {
                    default_policy = Some("DROP".to_string());
                } else if line.contains("policy accept") {
                    default_policy = Some("ACCEPT".to_string());
                }
            } else if line.starts_with("jump ")
                || line.starts_with("accept")
                || line.starts_with("drop")
                || line.starts_with("reject")
            {
                if let Some(family) = current_family {
                    match family {
                        "ip" => ipv4_count += 1,
                        "ip6" => ipv6_count += 1,
                        _ => {}
                    }
                }
            }
        }

        (
            active,
            Some(ipv4_count),
            Some(ipv6_count),
            tables,
            default_policy,
        )
    }

    async fn get_ufw_status(&self, opts: &StatusOptions) -> Result<FirewallBackendStatus> {
        let mut warnings = Vec::new();

        // Check availability
        let available = is_command_available("ufw");

        if !available {
            return Ok(FirewallBackendStatus {
                backend: "ufw".to_string(),
                available: false,
                active: false,
                enabled: false,
                default_policy: None,
                rule_count_ipv4: None,
                rule_count_ipv6: None,
                details: None,
                warnings: vec!["ufw command not available".to_string()],
            });
        }

        // Check if UFW is active
        match run_command_with_timeout("ufw", &["status"], opts.timeout_ms).await {
            Ok((0, stdout, _)) => {
                let active = stdout.contains("Status: active");
                let enabled = active; // UFW doesn't distinguish active vs enabled

                let (default_policy, rule_counts, details_msg) = if active && opts.include_metrics {
                    self.get_ufw_detailed_status(opts).await
                } else {
                    (
                        None,
                        (None, None),
                        if active {
                            None
                        } else {
                            Some("UFW installed but inactive.".to_string())
                        },
                    )
                };

                Ok(FirewallBackendStatus {
                    backend: "ufw".to_string(),
                    available,
                    active,
                    enabled,
                    default_policy,
                    rule_count_ipv4: rule_counts.0,
                    rule_count_ipv6: rule_counts.1,
                    details: details_msg,
                    warnings,
                })
            }
            Ok((code, _, stderr)) => {
                warnings.push(format!(
                    "ufw status failed with exit code {}: {}",
                    code, stderr
                ));
                Ok(FirewallBackendStatus {
                    backend: "ufw".to_string(),
                    available,
                    active: false,
                    enabled: false,
                    default_policy: None,
                    rule_count_ipv4: None,
                    rule_count_ipv6: None,
                    details: None,
                    warnings,
                })
            }
            Err(_) => Err(FirewallError::StatusTimeout {
                backend: "ufw".to_string(),
            }
            .into()),
        }
    }

    async fn get_ufw_detailed_status(
        &self,
        opts: &StatusOptions,
    ) -> (Option<String>, (Option<u64>, Option<u64>), Option<String>) {
        // Get verbose status for default policies
        let default_policy = if let Ok((0, stdout, _)) =
            run_command_with_timeout("ufw", &["status", "verbose"], opts.timeout_ms).await
        {
            stdout
                .lines()
                .find(|line| line.contains("Default:"))
                .map(|line| {
                    let policy_part = line.replace("Default:", "").trim().to_string();
                    policy_part
                })
        } else {
            None
        };

        // Get numbered status for rule counts
        let rule_counts = if let Ok((0, stdout, _)) =
            run_command_with_timeout("ufw", &["status", "numbered"], opts.timeout_ms).await
        {
            let mut ipv4_count = 0u64;
            let mut ipv6_count = 0u64;

            for line in stdout.lines() {
                if line.contains("]")
                    && (line.contains("ALLOW") || line.contains("DENY") || line.contains("REJECT"))
                {
                    if line.contains("(v6)") {
                        ipv6_count += 1;
                    } else {
                        ipv4_count += 1;
                    }
                }
            }

            (Some(ipv4_count), Some(ipv6_count))
        } else {
            (None, None)
        };

        let details = if let (Some(policy), Some(v4), Some(v6)) =
            (&default_policy, rule_counts.0, rule_counts.1)
        {
            Some(format!(
                "UFW active: {}; rules: v4={}, v6={}",
                policy, v4, v6
            ))
        } else {
            Some("UFW active but unable to get detailed metrics".to_string())
        };

        (default_policy, rule_counts, details)
    }

    async fn get_firewalld_status(&self, opts: &StatusOptions) -> Result<FirewallBackendStatus> {
        let mut warnings = Vec::new();

        // Check availability
        let available = is_command_available("firewall-cmd");

        if !available {
            return Ok(FirewallBackendStatus {
                backend: "firewalld".to_string(),
                available: false,
                active: false,
                enabled: false,
                default_policy: None,
                rule_count_ipv4: None,
                rule_count_ipv6: None,
                details: None,
                warnings: vec!["firewall-cmd not available".to_string()],
            });
        }

        // Check if firewalld is running
        match run_command_with_timeout("firewall-cmd", &["--state"], opts.timeout_ms).await {
            Ok((0, stdout, _)) => {
                let active = stdout.trim() == "running";
                let enabled = active; // For runtime, enabled == active

                let (default_policy, rule_counts, details_msg) = if active && opts.include_metrics {
                    self.get_firewalld_detailed_status(opts).await
                } else {
                    (
                        None,
                        (None, None),
                        if active {
                            None
                        } else {
                            Some("firewalld daemon not running".to_string())
                        },
                    )
                };

                Ok(FirewallBackendStatus {
                    backend: "firewalld".to_string(),
                    available,
                    active,
                    enabled,
                    default_policy,
                    rule_count_ipv4: rule_counts.0,
                    rule_count_ipv6: rule_counts.1,
                    details: details_msg,
                    warnings,
                })
            }
            Ok((code, _, stderr)) => {
                if stderr.contains("not running") || code == 252 {
                    Ok(FirewallBackendStatus {
                        backend: "firewalld".to_string(),
                        available,
                        active: false,
                        enabled: false,
                        default_policy: None,
                        rule_count_ipv4: None,
                        rule_count_ipv6: None,
                        details: Some("firewalld daemon not running".to_string()),
                        warnings,
                    })
                } else {
                    warnings.push(format!(
                        "firewall-cmd --state failed with exit code {}: {}",
                        code, stderr
                    ));
                    Ok(FirewallBackendStatus {
                        backend: "firewalld".to_string(),
                        available,
                        active: false,
                        enabled: false,
                        default_policy: None,
                        rule_count_ipv4: None,
                        rule_count_ipv6: None,
                        details: None,
                        warnings,
                    })
                }
            }
            Err(_) => Err(FirewallError::StatusTimeout {
                backend: "firewalld".to_string(),
            }
            .into()),
        }
    }

    async fn get_firewalld_detailed_status(
        &self,
        opts: &StatusOptions,
    ) -> (Option<String>, (Option<u64>, Option<u64>), Option<String>) {
        // Get default zone
        let default_zone = if let Ok((0, stdout, _)) =
            run_command_with_timeout("firewall-cmd", &["--get-default-zone"], opts.timeout_ms).await
        {
            Some(stdout.trim().to_string())
        } else {
            None
        };

        // Get zone count and services/ports
        let (zone_count, port_count, service_count) = if let Ok((0, stdout, _)) =
            run_command_with_timeout("firewall-cmd", &["--list-all-zones"], opts.timeout_ms).await
        {
            let zones = stdout
                .split("\n\n")
                .filter(|s| s.contains("(active)") || s.contains("(default)"))
                .count();
            let ports = stdout.matches("ports:").count();
            let services = stdout.matches("services:").count();
            (zones, ports, services)
        } else {
            (0, 0, 0)
        };

        // For firewalld, we approximate rule counts since they're organized by zones/services
        let total_rules = (port_count + service_count) as u64;
        let rule_counts = (Some(total_rules), Some(total_rules)); // Simplified approach

        let details = if let Some(zone) = &default_zone {
            Some(format!(
                "firewalld running: default zone={}, zones={}, ports={}, services={}",
                zone, zone_count, port_count, service_count
            ))
        } else {
            Some(format!(
                "firewalld running: zones={}, ports={}, services={}",
                zone_count, port_count, service_count
            ))
        };

        (default_zone, rule_counts, details)
    }

    // ===========================================================================
    // Enable Implementation
    // ===========================================================================

    fn handle_enable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.enable_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }
                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(
                        1,
                        response_error_message(response.error.as_ref(), "firewall enable failed"),
                    ))
                }
            }
            Err(e) => {
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::InternalError {
                        message: e.to_string(),
                    }
                };

                let response =
                    EnableResponse::with_error("unknown", firewall_error, OutputFormat::Json);

                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stderr,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stderr, "{}", response.to_text())?;
                    }
                }
                Ok(Status::err(1, "Enable operation failed"))
            }
        }
    }

    async fn enable_async(&self, args: &Args) -> Result<EnableResponse> {
        // Parse options and handle errors gracefully
        let opts = match self.parse_enable_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                // For parsing errors, return an error response instead of propagating error
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::InternalError {
                        message: e.to_string(),
                    }
                };

                let format_output = args
                    .get("format_output")
                    .and_then(|s| OutputFormat::from_str(s).ok())
                    .unwrap_or(OutputFormat::Json);

                return Ok(EnableResponse::with_error(
                    "unknown",
                    firewall_error,
                    format_output,
                ));
            }
        };

        let backend = match &opts.backend {
            FirewallBackend::Auto => match self.detect_available_backend(opts.timeout_ms).await {
                Ok(detected) => detected,
                Err(_) => {
                    return Ok(EnableResponse::with_error(
                        "auto",
                        FirewallError::NoBackendAvailable,
                        opts.format_output.clone(),
                    ));
                }
            },
            other => other.clone(),
        };

        // For dry_run or validate_only, skip backend availability checks
        if opts.dry_run || opts.validate_only {
            return self.handle_dry_run_or_validate(&backend, &opts).await;
        }

        // Check backend availability
        if let Err(_) = self
            .check_backend_availability(&backend, opts.timeout_ms)
            .await
        {
            return Ok(EnableResponse::with_error(
                backend.as_str(),
                FirewallError::BackendUnavailable {
                    backend: backend.as_str().to_string(),
                },
                opts.format_output.clone(),
            ));
        }

        // Get current state
        let previous_state = self.get_current_state(&backend, opts.timeout_ms).await?;

        // Check if already enabled and handle fail_if_already_enabled
        if previous_state.enabled && opts.fail_if_already_enabled {
            return Ok(EnableResponse::with_error(
                backend.as_str(),
                FirewallError::InternalError {
                    message: "Backend already enabled".to_string(),
                },
                opts.format_output.clone(),
            ));
        }

        // If already enabled and not fail_if_already_enabled, return no-op success
        if previous_state.enabled && !opts.fail_if_already_enabled {
            let mut response = EnableResponse::new(backend.as_str(), opts.format_output.clone());
            response.ok = true;
            response.query = self.enable_options_to_json(&opts, &backend);
            response.previous_state = Some(previous_state.clone());
            response.current_state = Some(previous_state);
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: true,
                backup_path: None,
            });
            response
                .warnings
                .push("Firewall backend was already enabled; no changes applied.".to_string());
            return Ok(response);
        }

        // Perform the enable operation
        self.enable_backend(&backend, &opts, &previous_state).await
    }

    async fn handle_dry_run_or_validate(
        &self,
        backend: &FirewallBackend,
        opts: &EnableOptions,
    ) -> Result<EnableResponse> {
        let mut response = EnableResponse::new(backend.as_str(), opts.format_output.clone());
        response.query = self.enable_options_to_json(opts, backend);
        response.ok = true;

        // Create a mock previous state for dry-run/validate
        let previous_state = FirewallStateSnapshot {
            available: true, // Assume available for dry run
            active: false,   // Assume not active
            enabled: false,  // Assume not enabled for dry run
        };

        response.previous_state = Some(previous_state.clone());
        response.current_state = Some(previous_state.clone());

        let mut actions = Vec::new();

        if opts.validate_only {
            actions.push(format!("{} status (validation only)", backend.as_str()));
            response.actions = actions;
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: false,
                backup_path: None,
            });
        } else if opts.dry_run {
            // For iptables, check if path is required
            if matches!(backend, FirewallBackend::Iptables) {
                if opts.path.is_none() {
                    return Ok(EnableResponse::with_error(
                        backend.as_str(),
                        FirewallError::MissingPath,
                        opts.format_output.clone(),
                    ));
                }
                // Add backup action if backup is enabled
                if opts.backup_before_apply {
                    actions.push(format!(
                        "firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                actions.push(format!(
                    "iptables-restore < {}",
                    opts.path.as_ref().unwrap()
                ));
            } else {
                // Add the action that would be performed
                match backend {
                    FirewallBackend::Ufw => {
                        if opts.backup_before_apply {
                            response.warnings.push("backup_before_apply is not supported for ufw; no backup would be taken".to_string());
                        }
                        actions.push("ufw --force enable".to_string());
                    }
                    FirewallBackend::Firewalld => {
                        if opts.backup_before_apply {
                            response.warnings.push("backup_before_apply is not supported for firewalld; no backup would be taken".to_string());
                        }
                        actions.push(
                            "systemctl enable firewalld && systemctl start firewalld".to_string(),
                        );
                    }
                    FirewallBackend::Nftables => {
                        if opts.backup_before_apply {
                            actions.push(format!("firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                                FIREWALL_BACKUP_DIR));
                        }
                        actions.push("nft rules would be applied".to_string());
                    }
                    FirewallBackend::Auto => {
                        actions.push("auto-detected backend would be enabled".to_string())
                    }
                    FirewallBackend::Iptables => {} // Already handled above
                }
            }

            response.actions = actions;
            response.result = Some(EnableResult {
                changed: false, // dry run doesn't change anything
                already_enabled: false,
                backup_path: None,
            });
        }

        Ok(response)
    }

    fn parse_enable_options(&self, args: &Args) -> Result<EnableOptions> {
        let mut opts = EnableOptions::default();

        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        if let Some(path) = args.get("path") {
            opts.path = Some(path.to_string());
        }

        if let Some(source_format_str) = args.get("source_format") {
            opts.source_format = RulesSourceFormat::from_str(source_format_str)?;
        }

        if let Some(dry_run_str) = crate::core::lenient::bool_arg(args, "dry_run")? {
            opts.dry_run = dry_run_str;
        }

        if let Some(validate_only_str) = args.get("validate_only") {
            opts.validate_only = validate_only_str.parse::<bool>().unwrap_or(false);
        }

        if let Some(backup) = crate::core::lenient::bool_arg(args, "backup_before_apply")? {
            opts.backup_before_apply = backup;
        }

        if let Some(fail_str) = args.get("fail_if_already_enabled") {
            opts.fail_if_already_enabled = fail_str.parse::<bool>().unwrap_or(false);
        }

        if let Some(timeout_str) = args.get("timeout_ms") {
            opts.timeout_ms = timeout_str.parse::<u64>().unwrap_or(10000);
        }

        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        Ok(opts)
    }

    fn enable_options_to_json(&self, opts: &EnableOptions, backend: &FirewallBackend) -> Value {
        json!({
            "backend": backend.as_str(),
            "family": opts.family.as_str(),
            "path": opts.path,
            "source_format": opts.source_format.as_str(),
            "dry_run": opts.dry_run,
            "validate_only": opts.validate_only,
            "backup_before_apply": opts.backup_before_apply,
            "fail_if_already_enabled": opts.fail_if_already_enabled,
            "timeout_ms": opts.timeout_ms
        })
    }

    async fn get_current_state(
        &self,
        backend: &FirewallBackend,
        timeout_ms: u64,
    ) -> Result<FirewallStateSnapshot> {
        let status_opts = StatusOptions {
            backend: match backend {
                FirewallBackend::Auto => {
                    return Err(anyhow::anyhow!("Auto backend should be resolved"));
                }
                FirewallBackend::Iptables => StatusBackend::Iptables,
                FirewallBackend::Nftables => StatusBackend::Nftables,
                FirewallBackend::Ufw => StatusBackend::Ufw,
                FirewallBackend::Firewalld => StatusBackend::Firewalld,
            },
            family: StatusFamily::Any,
            include_metrics: false,
            include_rules_summary: false,
            timeout_ms,
            output_format: OutputFormat::Json,
        };

        let backend_status = self.get_backend_status(backend, &status_opts).await?;

        Ok(FirewallStateSnapshot {
            available: backend_status.available,
            active: backend_status.active,
            enabled: backend_status.enabled,
        })
    }

    async fn enable_backend(
        &self,
        backend: &FirewallBackend,
        opts: &EnableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<EnableResponse> {
        match backend {
            FirewallBackend::Ufw => self.enable_ufw(opts, previous_state).await,
            FirewallBackend::Firewalld => self.enable_firewalld(opts, previous_state).await,
            FirewallBackend::Iptables => self.enable_iptables(opts, previous_state).await,
            FirewallBackend::Nftables => self.enable_nftables(opts, previous_state).await,
            FirewallBackend::Auto => Err(anyhow::anyhow!(
                "Auto backend should be resolved before enable"
            )),
        }
    }

    async fn enable_ufw(
        &self,
        opts: &EnableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<EnableResponse> {
        let mut response = EnableResponse::new("ufw", opts.format_output.clone());
        if opts.backup_before_apply {
            response.warnings.push(
                "backup_before_apply is not supported for ufw; no backup was taken".to_string(),
            );
        }
        response.query = self.enable_options_to_json(opts, &FirewallBackend::Ufw);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();
        let backup_path = None;

        if opts.validate_only {
            // For validate_only, just check that ufw is available and return
            actions.push("ufw status (validation only)".to_string());
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        if opts.dry_run {
            actions.push("ufw --force enable".to_string());
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        // Execute enable
        actions.push("ufw --force enable".to_string());

        let (exit_code, stdout, stderr) =
            run_command_with_timeout("ufw", &["--force", "enable"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Ok(EnableResponse::with_error(
                "ufw",
                FirewallError::CommandFailed {
                    command: "ufw --force enable".to_string(),
                    code: exit_code,
                    stderr,
                },
                opts.format_output.clone(),
            ));
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Ufw, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(EnableResult {
            changed: true,
            already_enabled: false,
            backup_path,
        });
        response.ok = true;

        Ok(response)
    }

    async fn enable_firewalld(
        &self,
        opts: &EnableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<EnableResponse> {
        let mut response = EnableResponse::new("firewalld", opts.format_output.clone());
        if opts.backup_before_apply {
            response.warnings.push(
                "backup_before_apply is not supported for firewalld; no backup was taken"
                    .to_string(),
            );
        }
        response.query = self.enable_options_to_json(opts, &FirewallBackend::Firewalld);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();

        if opts.validate_only {
            actions.push("firewall-cmd --state (validation only)".to_string());
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        if opts.dry_run {
            actions.push("systemctl start firewalld".to_string());
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        // Check if firewalld is already running
        let (state_code, state_stdout, _) =
            run_command_with_timeout("firewall-cmd", &["--state"], opts.timeout_ms).await?;

        if state_code == 0 && state_stdout.trim() == "running" {
            // Already running
            let current_state = self
                .get_current_state(&FirewallBackend::Firewalld, opts.timeout_ms)
                .await?;
            response.actions = actions;
            response.current_state = Some(current_state);
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: true,
                backup_path: None,
            });
            response.ok = true;
            response
                .warnings
                .push("firewalld was already running".to_string());
            return Ok(response);
        }

        // Try to start firewalld
        actions.push("systemctl start firewalld".to_string());

        let (exit_code, _stdout, stderr) =
            run_command_with_timeout("systemctl", &["start", "firewalld"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Ok(EnableResponse::with_error(
                "firewalld",
                FirewallError::CommandFailed {
                    command: "systemctl start firewalld".to_string(),
                    code: exit_code,
                    stderr,
                },
                opts.format_output.clone(),
            ));
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Firewalld, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(EnableResult {
            changed: true,
            already_enabled: false,
            backup_path: None,
        });
        response.ok = true;

        Ok(response)
    }

    async fn enable_iptables(
        &self,
        opts: &EnableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<EnableResponse> {
        let mut response = EnableResponse::new("iptables", opts.format_output.clone());
        response.query = self.enable_options_to_json(opts, &FirewallBackend::Iptables);
        response.previous_state = Some(previous_state.clone());

        // Check if we have existing rules
        let has_rules = previous_state.active || previous_state.enabled;

        // If we don't have rules and no path provided, error
        if !has_rules && opts.path.is_none() {
            return Ok(EnableResponse::with_error(
                "iptables",
                FirewallError::InternalError { message: "Enabling backend 'iptables' requires a rules file path when no active rules are present.".to_string() },
                opts.format_output.clone()
            ));
        }

        let mut actions = Vec::new();
        let mut backup_path = None;

        if opts.validate_only {
            if let Some(path) = &opts.path {
                actions.push(format!("iptables-restore --test < {}", path));
            } else {
                actions.push("iptables rules validation (no path provided)".to_string());
            }
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        if opts.dry_run {
            if let Some(path) = &opts.path {
                if opts.backup_before_apply {
                    actions.push(format!(
                        "firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                let command = match opts.family {
                    IpFamily::Ipv4 => format!("iptables-restore < {}", path),
                    IpFamily::Ipv6 => format!("ip6tables-restore < {}", path),
                    IpFamily::Any => format!(
                        "iptables-restore < {} && ip6tables-restore < {}",
                        path, path
                    ),
                };
                actions.push(command);
            }
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        // If rules exist and no path, treat as already enabled
        if has_rules && opts.path.is_none() {
            let current_state = self
                .get_current_state(&FirewallBackend::Iptables, opts.timeout_ms)
                .await?;
            response.actions = actions;
            response.current_state = Some(current_state);
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: true,
                backup_path: None,
            });
            response.ok = true;
            response
                .warnings
                .push("iptables already has active rules; treated as enabled".to_string());
            return Ok(response);
        }

        // Load rules from file
        if let Some(path) = &opts.path {
            // Check if file exists
            if !std::path::Path::new(path).exists() {
                return Ok(EnableResponse::with_error(
                    "iptables",
                    FirewallError::InternalError {
                        message: format!("Rules file not found: {}", path),
                    },
                    opts.format_output.clone(),
                ));
            }

            // Back up every family about to be replaced. A backup that
            // cannot be written stops the operation before any change.
            if opts.backup_before_apply {
                let families: &[&str] = match opts.family {
                    IpFamily::Ipv4 => &["ipv4"],
                    IpFamily::Ipv6 => &["ipv6"],
                    IpFamily::Any => &["ipv4", "ipv6"],
                };
                for family in families {
                    match self.create_iptables_backup(family, opts.timeout_ms).await {
                        Ok(written) => {
                            actions.push(format!("firewall.rules.save(...) -> {}", written));
                            backup_path.get_or_insert(written);
                        }
                        Err(e) => {
                            return Ok(EnableResponse::with_error(
                                "iptables",
                                backup_failure(e),
                                opts.format_output.clone(),
                            ));
                        }
                    }
                }
            }

            // Restore rules. The rules file is passed as an argument (no
            // shell), as disable already does.
            let restore_commands = match opts.family {
                IpFamily::Ipv4 => vec![("iptables-restore", path.clone())],
                IpFamily::Ipv6 => vec![("ip6tables-restore", path.clone())],
                IpFamily::Any => vec![
                    ("iptables-restore", path.clone()),
                    ("ip6tables-restore", path.clone()),
                ],
            };

            for (command, file_path) in restore_commands {
                actions.push(format!("{} < {}", command, file_path));

                let (exit_code, _stdout, stderr) =
                    run_command_with_timeout(command, &[file_path.as_str()], opts.timeout_ms)
                        .await?;

                if exit_code != 0 {
                    return Ok(EnableResponse::with_error(
                        "iptables",
                        FirewallError::CommandFailed {
                            command: format!("{} < {}", command, file_path),
                            code: exit_code,
                            stderr,
                        },
                        opts.format_output.clone(),
                    ));
                }
            }
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Iptables, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(EnableResult {
            changed: true,
            already_enabled: false,
            backup_path,
        });
        response.ok = true;

        Ok(response)
    }

    async fn enable_nftables(
        &self,
        opts: &EnableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<EnableResponse> {
        let mut response = EnableResponse::new("nftables", opts.format_output.clone());
        response.query = self.enable_options_to_json(opts, &FirewallBackend::Nftables);
        response.previous_state = Some(previous_state.clone());

        // Check if we have existing rules
        let has_rules = previous_state.active || previous_state.enabled;

        // If we don't have rules and no path provided, error
        if !has_rules && opts.path.is_none() {
            return Ok(EnableResponse::with_error(
                "nftables",
                FirewallError::InternalError { message: "Enabling backend 'nftables' requires a rules file path when no active rules are present.".to_string() },
                opts.format_output.clone()
            ));
        }

        let mut actions = Vec::new();
        let mut backup_path = None;

        if opts.validate_only {
            if let Some(path) = &opts.path {
                actions.push(format!("nft -c -f {}", path));

                // Actually run the validation if path is provided
                let (exit_code, _stdout, stderr) =
                    run_command_with_timeout("nft", &["-c", "-f", path], opts.timeout_ms).await?;
                if exit_code != 0 {
                    return Ok(EnableResponse::with_error(
                        "nftables",
                        FirewallError::CommandFailed {
                            command: format!("nft -c -f {}", path),
                            code: exit_code,
                            stderr,
                        },
                        opts.format_output.clone(),
                    ));
                }
            } else {
                actions.push("nftables validation (no path provided)".to_string());
            }
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        if opts.dry_run {
            if let Some(path) = &opts.path {
                if opts.backup_before_apply {
                    actions.push(format!(
                        "firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                actions.push(format!("nft -f {}", path));
            }
            response.actions = actions;
            response.current_state = Some(previous_state.clone());
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: previous_state.enabled,
                backup_path: None,
            });
            response.ok = true;
            return Ok(response);
        }

        // If rules exist and no path, treat as already enabled
        if has_rules && opts.path.is_none() {
            let current_state = self
                .get_current_state(&FirewallBackend::Nftables, opts.timeout_ms)
                .await?;
            response.actions = actions;
            response.current_state = Some(current_state);
            response.result = Some(EnableResult {
                changed: false,
                already_enabled: true,
                backup_path: None,
            });
            response.ok = true;
            response
                .warnings
                .push("nftables already has active rules; treated as enabled".to_string());
            return Ok(response);
        }

        // Load rules from file
        if let Some(path) = &opts.path {
            // Check if file exists
            if !std::path::Path::new(path).exists() {
                return Ok(EnableResponse::with_error(
                    "nftables",
                    FirewallError::InternalError {
                        message: format!("Rules file not found: {}", path),
                    },
                    opts.format_output.clone(),
                ));
            }

            // Backup existing rules if requested; no change without it.
            if opts.backup_before_apply {
                match self.create_nftables_backup(opts.timeout_ms).await {
                    Ok(written) => {
                        actions.push(format!("firewall.rules.save(...) -> {}", written));
                        backup_path = Some(written);
                    }
                    Err(e) => {
                        return Ok(EnableResponse::with_error(
                            "nftables",
                            backup_failure(e),
                            opts.format_output.clone(),
                        ));
                    }
                }
            }

            // Load rules
            actions.push(format!("nft -f {}", path));

            let (exit_code, _stdout, stderr) =
                run_command_with_timeout("nft", &["-f", path], opts.timeout_ms).await?;

            if exit_code != 0 {
                return Ok(EnableResponse::with_error(
                    "nftables",
                    FirewallError::CommandFailed {
                        command: format!("nft -f {}", path),
                        code: exit_code,
                        stderr,
                    },
                    opts.format_output.clone(),
                ));
            }
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Nftables, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(EnableResult {
            changed: true,
            already_enabled: false,
            backup_path,
        });
        response.ok = true;

        Ok(response)
    }

    // ===========================================================================
    // Disable Operations
    // ===========================================================================

    fn handle_disable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(async { self.disable_async(args).await });

        match result {
            Ok(response) => {
                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stdout,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stdout, "{}", response.to_text())?;
                    }
                }
                if response.ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(
                        1,
                        response_error_message(response.error.as_ref(), "firewall disable failed"),
                    ))
                }
            }
            Err(e) => {
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::DisableInternalError {
                        message: e.to_string(),
                    }
                };

                let response =
                    DisableResponse::with_error("unknown", firewall_error, OutputFormat::Json);

                match response.format_output {
                    OutputFormat::Json => {
                        writeln!(
                            io.stderr,
                            "{}",
                            serde_json::to_string_pretty(&response.to_json())?
                        )?;
                    }
                    OutputFormat::Text => {
                        writeln!(io.stderr, "{}", response.to_text())?;
                    }
                }
                Ok(Status::err(1, "Disable operation failed"))
            }
        }
    }

    async fn disable_async(&self, args: &Args) -> Result<DisableResponse> {
        // Parse options and handle errors gracefully
        let opts = match self.parse_disable_options(args) {
            Ok(opts) => opts,
            Err(e) => {
                // For parsing errors, return an error response instead of propagating error
                let firewall_error = if let Some(fw_err) = e.downcast_ref::<FirewallError>() {
                    fw_err.clone()
                } else {
                    FirewallError::DisableInternalError {
                        message: e.to_string(),
                    }
                };

                let format_output = args
                    .get("format_output")
                    .and_then(|s| OutputFormat::from_str(s).ok())
                    .unwrap_or(OutputFormat::Json);

                return Ok(DisableResponse::with_error(
                    "unknown",
                    firewall_error,
                    format_output,
                ));
            }
        };

        // Get backend
        let backend = match &opts.backend {
            FirewallBackend::Auto => match self.detect_available_backend(opts.timeout_ms).await {
                Ok(detected) => detected,
                Err(_) => {
                    return Ok(DisableResponse::with_error(
                        "auto",
                        FirewallError::DisableNoBackendAvailable,
                        opts.format_output.clone(),
                    ));
                }
            },
            other => other.clone(),
        };

        // For dry_run or validate_only, skip backend availability checks
        if opts.dry_run || opts.validate_only {
            let previous_state = match self.get_current_state(&backend, opts.timeout_ms).await {
                Ok(state) => state,
                Err(_) => {
                    return Ok(DisableResponse::with_error(
                        backend.as_str(),
                        FirewallError::DisableBackendUnavailable {
                            backend: backend.as_str().to_string(),
                        },
                        opts.format_output.clone(),
                    ));
                }
            };
            return self
                .handle_disable_dry_run_or_validate(&backend, &opts, &previous_state)
                .await;
        }

        // Check backend availability
        if let Err(_) = self
            .check_backend_availability(&backend, opts.timeout_ms)
            .await
        {
            return Ok(DisableResponse::with_error(
                backend.as_str(),
                FirewallError::DisableBackendUnavailable {
                    backend: backend.as_str().to_string(),
                },
                opts.format_output.clone(),
            ));
        }

        // Get previous state
        let previous_state = match self.get_current_state(&backend, opts.timeout_ms).await {
            Ok(state) => state,
            Err(_) => {
                return Ok(DisableResponse::with_error(
                    backend.as_str(),
                    FirewallError::DisableBackendUnavailable {
                        backend: backend.as_str().to_string(),
                    },
                    opts.format_output.clone(),
                ));
            }
        };

        // Create response structure
        let mut response = DisableResponse::new(backend.as_str(), opts.format_output.clone());
        response.query = self.disable_options_to_json(&opts, &backend);
        response.previous_state = Some(previous_state.clone());

        // Check if already disabled
        if !previous_state.active && !previous_state.enabled {
            if opts.fail_if_already_disabled {
                return Ok(DisableResponse::with_error(
                    backend.as_str(),
                    FirewallError::DisableAlreadyDisabled {
                        backend: backend.as_str().to_string(),
                    },
                    opts.format_output.clone(),
                ));
            } else {
                response.current_state = Some(previous_state);
                response.result = Some(DisableResult {
                    changed: false,
                    already_disabled: true,
                    backup_path: None,
                });
                response.warnings.push(format!(
                    "Firewall backend '{}' was already disabled; no changes applied.",
                    backend.as_str()
                ));
                response.ok = true;
                return Ok(response);
            }
        }

        // Perform disable operation
        self.disable_backend(&backend, &opts, &previous_state).await
    }

    async fn handle_disable_dry_run_or_validate(
        &self,
        backend: &FirewallBackend,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        let mut response = DisableResponse::new(backend.as_str(), opts.format_output.clone());
        response.query = self.disable_options_to_json(opts, backend);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();

        // Plan disable actions
        match backend {
            FirewallBackend::Ufw => {
                actions.push("ufw --force disable".to_string());
            }
            FirewallBackend::Firewalld => {
                actions.push("systemctl stop firewalld".to_string());
            }
            FirewallBackend::Iptables => {
                if opts.backup_before_apply {
                    actions.push(format!(
                        "firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                if let Some(path) = &opts.path {
                    match opts.family {
                        IpFamily::Ipv4 | IpFamily::Any => {
                            actions.push(format!("iptables-restore < {}", path))
                        }
                        IpFamily::Ipv6 => actions.push(format!("ip6tables-restore < {}", path)),
                    }
                } else {
                    match opts.family {
                        IpFamily::Ipv4 | IpFamily::Any => {
                            actions.extend_from_slice(&[
                                "iptables -P INPUT ACCEPT".to_string(),
                                "iptables -P OUTPUT ACCEPT".to_string(),
                                "iptables -P FORWARD ACCEPT".to_string(),
                                "iptables -F".to_string(),
                                "iptables -t nat -F".to_string(),
                                "iptables -t mangle -F".to_string(),
                            ]);
                        }
                        IpFamily::Ipv6 => {
                            actions.extend_from_slice(&[
                                "ip6tables -P INPUT ACCEPT".to_string(),
                                "ip6tables -P OUTPUT ACCEPT".to_string(),
                                "ip6tables -P FORWARD ACCEPT".to_string(),
                                "ip6tables -F".to_string(),
                                "ip6tables -t nat -F".to_string(),
                                "ip6tables -t mangle -F".to_string(),
                            ]);
                        }
                    }
                }
            }
            FirewallBackend::Nftables => {
                if opts.backup_before_apply {
                    actions.push(format!(
                        "firewall.rules.save(...) -> new backup in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                if let Some(path) = &opts.path {
                    actions.push(format!("nft -f {}", path));
                } else {
                    actions.push("nft flush ruleset".to_string());
                }
            }
            _ => {
                return Ok(DisableResponse::with_error(
                    backend.as_str(),
                    FirewallError::DisableBackendUnavailable {
                        backend: backend.as_str().to_string(),
                    },
                    opts.format_output.clone(),
                ));
            }
        }

        // For validate_only, check if files exist and are accessible
        if opts.validate_only {
            if let Some(path) = &opts.path {
                if !Path::new(path).exists() {
                    return Ok(DisableResponse::with_error(
                        backend.as_str(),
                        FirewallError::DisablePathNotFound { path: path.clone() },
                        opts.format_output.clone(),
                    ));
                }
            }
        }

        response.actions = actions;
        response.current_state = Some(previous_state.clone());
        response.result = Some(DisableResult {
            changed: false,
            already_disabled: false,
            backup_path: None,
        });
        response.ok = true;

        Ok(response)
    }

    fn parse_disable_options(&self, args: &Args) -> Result<DisableOptions> {
        let mut opts = DisableOptions::default();

        if let Some(backend_str) = args.get("backend") {
            opts.backend = FirewallBackend::from_str(backend_str)?;
        }

        if let Some(family_str) = args.get("family") {
            opts.family = IpFamily::from_str(family_str)?;
        }

        if let Some(path) = args.get("path") {
            opts.path = Some(path.to_string());
        }

        if let Some(source_format_str) = args.get("source_format") {
            opts.source_format = RulesSourceFormat::from_str(source_format_str)?;
        }

        let dry_run = crate::core::lenient::bool_arg(args, "dry_run").map_err(|e| {
            FirewallError::DisableInternalError {
                message: e.to_string(),
            }
        })?;
        if let Some(dry_run) = dry_run {
            opts.dry_run = dry_run;
        }

        if let Some(validate_only_str) = args.get("validate_only") {
            opts.validate_only = validate_only_str.parse::<bool>().map_err(|_| {
                FirewallError::DisableInternalError {
                    message: "Invalid validate_only value".to_string(),
                }
            })?;
        }

        if let Some(backup) =
            crate::core::lenient::bool_arg(args, "backup_before_apply").map_err(|e| {
                FirewallError::DisableInternalError {
                    message: e.to_string(),
                }
            })?
        {
            opts.backup_before_apply = backup;
        }

        if let Some(fail_str) = args.get("fail_if_already_disabled") {
            opts.fail_if_already_disabled =
                fail_str
                    .parse::<bool>()
                    .map_err(|_| FirewallError::DisableInternalError {
                        message: "Invalid fail_if_already_disabled value".to_string(),
                    })?;
        }

        if let Some(timeout_str) = args.get("timeout_ms") {
            opts.timeout_ms =
                timeout_str
                    .parse::<u64>()
                    .map_err(|_| FirewallError::DisableInternalError {
                        message: "Invalid timeout_ms value".to_string(),
                    })?;
        }

        if let Some(format_str) = args.get("format_output") {
            opts.format_output = OutputFormat::from_str(format_str)?;
        }

        Ok(opts)
    }

    fn disable_options_to_json(&self, opts: &DisableOptions, backend: &FirewallBackend) -> Value {
        json!({
            "backend": backend.as_str(),
            "family": opts.family.as_str(),
            "path": opts.path,
            "source_format": opts.source_format.as_str(),
            "dry_run": opts.dry_run,
            "validate_only": opts.validate_only,
            "backup_before_apply": opts.backup_before_apply,
            "fail_if_already_disabled": opts.fail_if_already_disabled,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            }
        })
    }

    async fn disable_backend(
        &self,
        backend: &FirewallBackend,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        match backend {
            FirewallBackend::Ufw => self.disable_ufw(opts, previous_state).await,
            FirewallBackend::Firewalld => self.disable_firewalld(opts, previous_state).await,
            FirewallBackend::Iptables => self.disable_iptables(opts, previous_state).await,
            FirewallBackend::Nftables => self.disable_nftables(opts, previous_state).await,
            _ => Ok(DisableResponse::with_error(
                backend.as_str(),
                FirewallError::DisableBackendUnavailable {
                    backend: backend.as_str().to_string(),
                },
                opts.format_output.clone(),
            )),
        }
    }

    async fn disable_ufw(
        &self,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        let mut response = DisableResponse::new("ufw", opts.format_output.clone());
        if opts.backup_before_apply {
            response.warnings.push(
                "backup_before_apply is not supported for ufw; no backup was taken".to_string(),
            );
        }
        response.query = self.disable_options_to_json(opts, &FirewallBackend::Ufw);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();

        // Execute disable command
        actions.push("ufw --force disable".to_string());

        let (exit_code, _stdout, stderr) =
            run_command_with_timeout("ufw", &["--force", "disable"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Ok(DisableResponse::with_error(
                "ufw",
                FirewallError::DisableCommandFailed {
                    backend: "ufw".to_string(),
                    message: stderr,
                },
                opts.format_output.clone(),
            ));
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Ufw, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(DisableResult {
            changed: true,
            already_disabled: false,
            backup_path: None,
        });
        response.ok = true;

        Ok(response)
    }

    async fn disable_firewalld(
        &self,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        let mut response = DisableResponse::new("firewalld", opts.format_output.clone());
        if opts.backup_before_apply {
            response.warnings.push(
                "backup_before_apply is not supported for firewalld; no backup was taken"
                    .to_string(),
            );
        }
        response.query = self.disable_options_to_json(opts, &FirewallBackend::Firewalld);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();

        // Stop firewalld service
        actions.push("systemctl stop firewalld".to_string());

        let (exit_code, _stdout, stderr) =
            run_command_with_timeout("systemctl", &["stop", "firewalld"], opts.timeout_ms).await?;

        if exit_code != 0 {
            return Ok(DisableResponse::with_error(
                "firewalld",
                FirewallError::DisableFirewalldStopFailed { message: stderr },
                opts.format_output.clone(),
            ));
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Firewalld, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(DisableResult {
            changed: true,
            already_disabled: false,
            backup_path: None,
        });
        response.ok = true;

        Ok(response)
    }

    async fn disable_iptables(
        &self,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        let mut response = DisableResponse::new("iptables", opts.format_output.clone());
        response.query = self.disable_options_to_json(opts, &FirewallBackend::Iptables);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();
        let mut backup_path: Option<String> = None;

        // Take backup if requested, of the family about to be changed
        // (ipv4 for Ipv4/Any, as below). No change without it.
        if opts.backup_before_apply {
            let family = if matches!(opts.family, IpFamily::Ipv6) {
                "ipv6"
            } else {
                "ipv4"
            };
            match self.create_iptables_backup(family, opts.timeout_ms).await {
                Ok(written) => {
                    actions.push(format!("firewall.rules.save(...) -> {}", written));
                    backup_path = Some(written);
                }
                Err(e) => {
                    return Ok(DisableResponse::with_error(
                        "iptables",
                        backup_failure(e),
                        opts.format_output.clone(),
                    ));
                }
            }
        }

        // Apply disable configuration
        if let Some(path) = &opts.path {
            // File-based restore
            match opts.family {
                IpFamily::Ipv4 | IpFamily::Any => {
                    actions.push(format!("iptables-restore < {}", path));
                    let (exit_code, _stdout, stderr) =
                        run_command_with_timeout("iptables-restore", &[path], opts.timeout_ms)
                            .await?;
                    if exit_code != 0 {
                        return Ok(DisableResponse::with_error(
                            "iptables",
                            FirewallError::DisableCommandFailed {
                                backend: "iptables".to_string(),
                                message: stderr,
                            },
                            opts.format_output.clone(),
                        ));
                    }
                }
                IpFamily::Ipv6 => {
                    actions.push(format!("ip6tables-restore < {}", path));
                    let (exit_code, _stdout, stderr) =
                        run_command_with_timeout("ip6tables-restore", &[path], opts.timeout_ms)
                            .await?;
                    if exit_code != 0 {
                        return Ok(DisableResponse::with_error(
                            "iptables",
                            FirewallError::DisableCommandFailed {
                                backend: "iptables".to_string(),
                                message: stderr,
                            },
                            opts.format_output.clone(),
                        ));
                    }
                }
            }
        } else {
            // Flush mode - reset to open/accepting state
            match opts.family {
                IpFamily::Ipv4 | IpFamily::Any => {
                    let commands = [
                        ("iptables", vec!["-P", "INPUT", "ACCEPT"]),
                        ("iptables", vec!["-P", "OUTPUT", "ACCEPT"]),
                        ("iptables", vec!["-P", "FORWARD", "ACCEPT"]),
                        ("iptables", vec!["-F"]),
                        ("iptables", vec!["-t", "nat", "-F"]),
                        ("iptables", vec!["-t", "mangle", "-F"]),
                    ];

                    for (cmd, args) in &commands {
                        actions.push(format!("{} {}", cmd, args.join(" ")));
                        let (exit_code, _stdout, stderr) =
                            run_command_with_timeout(cmd, args, opts.timeout_ms).await?;
                        if exit_code != 0 {
                            return Ok(DisableResponse::with_error(
                                "iptables",
                                FirewallError::DisableCommandFailed {
                                    backend: "iptables".to_string(),
                                    message: stderr,
                                },
                                opts.format_output.clone(),
                            ));
                        }
                    }
                }
                IpFamily::Ipv6 => {
                    let commands = [
                        ("ip6tables", vec!["-P", "INPUT", "ACCEPT"]),
                        ("ip6tables", vec!["-P", "OUTPUT", "ACCEPT"]),
                        ("ip6tables", vec!["-P", "FORWARD", "ACCEPT"]),
                        ("ip6tables", vec!["-F"]),
                        ("ip6tables", vec!["-t", "nat", "-F"]),
                        ("ip6tables", vec!["-t", "mangle", "-F"]),
                    ];

                    for (cmd, args) in &commands {
                        actions.push(format!("{} {}", cmd, args.join(" ")));
                        let (exit_code, _stdout, stderr) =
                            run_command_with_timeout(cmd, args, opts.timeout_ms).await?;
                        if exit_code != 0 {
                            return Ok(DisableResponse::with_error(
                                "iptables",
                                FirewallError::DisableCommandFailed {
                                    backend: "iptables".to_string(),
                                    message: stderr,
                                },
                                opts.format_output.clone(),
                            ));
                        }
                    }
                }
            }
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Iptables, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(DisableResult {
            changed: true,
            already_disabled: false,
            backup_path,
        });
        response.ok = true;

        Ok(response)
    }

    async fn disable_nftables(
        &self,
        opts: &DisableOptions,
        previous_state: &FirewallStateSnapshot,
    ) -> Result<DisableResponse> {
        let mut response = DisableResponse::new("nftables", opts.format_output.clone());
        response.query = self.disable_options_to_json(opts, &FirewallBackend::Nftables);
        response.previous_state = Some(previous_state.clone());

        let mut actions = Vec::new();
        let mut backup_path: Option<String> = None;

        // Take backup if requested; no change without it.
        if opts.backup_before_apply {
            match self.create_nftables_backup(opts.timeout_ms).await {
                Ok(written) => {
                    actions.push(format!("firewall.rules.save(...) -> {}", written));
                    backup_path = Some(written);
                }
                Err(e) => {
                    return Ok(DisableResponse::with_error(
                        "nftables",
                        backup_failure(e),
                        opts.format_output.clone(),
                    ));
                }
            }
        }

        // Apply disable configuration
        if let Some(path) = &opts.path {
            // File-based restore
            actions.push(format!("nft -f {}", path));
            let (exit_code, _stdout, stderr) =
                run_command_with_timeout("nft", &["-f", path], opts.timeout_ms).await?;
            if exit_code != 0 {
                return Ok(DisableResponse::with_error(
                    "nftables",
                    FirewallError::DisableCommandFailed {
                        backend: "nftables".to_string(),
                        message: stderr,
                    },
                    opts.format_output.clone(),
                ));
            }
        } else {
            // Flush mode - clear all rules
            actions.push("nft flush ruleset".to_string());
            let (exit_code, _stdout, stderr) =
                run_command_with_timeout("nft", &["flush", "ruleset"], opts.timeout_ms).await?;
            if exit_code != 0 {
                return Ok(DisableResponse::with_error(
                    "nftables",
                    FirewallError::DisableCommandFailed {
                        backend: "nftables".to_string(),
                        message: stderr,
                    },
                    opts.format_output.clone(),
                ));
            }
        }

        // Get new state
        let current_state = self
            .get_current_state(&FirewallBackend::Nftables, opts.timeout_ms)
            .await?;

        response.actions = actions;
        response.current_state = Some(current_state);
        response.result = Some(DisableResult {
            changed: true,
            already_disabled: false,
            backup_path,
        });
        response.ok = true;

        Ok(response)
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// The human-readable message of a response's `error` value, for the exit
/// status reason.
fn response_error_message(error: Option<&Value>, fallback: &str) -> String {
    // Responses carry either `{message}` or `{error: {message}}`.
    let error = error.map(|e| e.get("error").unwrap_or(e));
    error
        .and_then(|e| {
            e.get("message")
                .and_then(Value::as_str)
                .or_else(|| e.as_str())
        })
        .map(|m| format!("{}: {}", fallback, m))
        .unwrap_or_else(|| fallback.to_string())
}

/// The error reported when a required pre-change backup fails.
fn backup_failure(e: anyhow::Error) -> FirewallError {
    match e.downcast_ref::<FirewallError>() {
        Some(fw) => fw.clone(),
        None => FirewallError::SaveFailed {
            message: format!("Backup failed: {}", e),
        },
    }
}

/// Where enable/disable/reload write the pre-change rule backups.
const FIREWALL_BACKUP_DIR: &str = "/var/backups/firewall";

fn firewall_backup_dir() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(dir) = test_seam::backup_dir() {
        return dir;
    }
    std::path::PathBuf::from(FIREWALL_BACKUP_DIR)
}

/// The program actually executed for `command`. Production code always
/// runs `command` from PATH; tests can redirect every firewall command to
/// mock executables so no test can reach the host firewall.
fn resolve_program(command: &str) -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(dir) = test_seam::bin_dir() {
        return dir.join(command);
    }
    std::path::PathBuf::from(command)
}

/// Writes a rules backup as a new 0600 file inside `dir` (created 0700 if
/// missing) and returns its path. Never overwrites an existing file and
/// never writes through a symlinked directory or file.
fn write_rules_backup(dir: &Path, file_name: &str, contents: &[u8]) -> Result<String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let io_err = |what: &str, e: std::io::Error| FirewallError::IoError {
        message: format!(
            "Failed to write backup ({}): {}: {}",
            what,
            dir.display(),
            e
        ),
    };

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_err("create directory", e))?;
    let meta = fs::symlink_metadata(dir).map_err(|e| io_err("stat directory", e))?;
    if !meta.is_dir() {
        return Err(FirewallError::IoError {
            message: format!(
                "Backup directory {} is not a directory (or is a symlink)",
                dir.display()
            ),
        }
        .into());
    }

    let path = dir.join(file_name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| io_err("create file", e))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(&path);
            io_err("write file", e)
        })?;

    Ok(path.to_string_lossy().into_owned())
}

/// Unique backup file name: `.resh-backup-<backend>[-<family>]-<ms>-<pid>.<ext>`.
fn backup_file_name(backend: &str, family: Option<&str>, ext: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    match family {
        Some(f) => format!(
            ".resh-backup-{}-{}-{}-{}.{}",
            backend,
            f,
            millis,
            std::process::id(),
            ext
        ),
        None => format!(
            ".resh-backup-{}-{}-{}.{}",
            backend,
            millis,
            std::process::id(),
            ext
        ),
    }
}

#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static BIN_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        static BACKUP_DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub fn bin_dir() -> Option<PathBuf> {
        BIN_DIR.with(|d| d.borrow().clone())
    }

    pub fn backup_dir() -> Option<PathBuf> {
        BACKUP_DIR.with(|d| d.borrow().clone())
    }

    /// Redirects firewall commands and backups for the current thread
    /// until the guard is dropped.
    pub struct Guard;

    pub fn install(bin: PathBuf, backups: PathBuf) -> Guard {
        BIN_DIR.with(|d| *d.borrow_mut() = Some(bin));
        BACKUP_DIR.with(|d| *d.borrow_mut() = Some(backups));
        Guard
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            BIN_DIR.with(|d| *d.borrow_mut() = None);
            BACKUP_DIR.with(|d| *d.borrow_mut() = None);
        }
    }
}

/// Run a firewall command, killing it if it is still running after
/// `timeout_ms`. The command is a blocking child process, so the deadline is
/// enforced by polling the child (the backup handle's `wait_with_deadline`),
/// not by an async timeout that a blocking call would never yield to.
#[allow(dead_code)]
async fn run_command_with_timeout(
    command: &str,
    args: &[&str],
    timeout_ms: u64,
) -> Result<(i32, String, String)> {
    use std::process::Stdio;

    let child = Command::new(resolve_program(command))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to execute command: {}", e))?;

    match crate::handles::automation::backuph::wait_with_deadline(
        child,
        Duration::from_millis(timeout_ms),
    )? {
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            Ok((exit_code, stdout, stderr))
        }
        None => Err(anyhow::anyhow!("Command timed out after {}ms", timeout_ms)),
    }
}

// Utility function to check if a binary is available in PATH
#[allow(dead_code)]
fn is_command_available(command: &str) -> bool {
    #[cfg(test)]
    if let Some(dir) = test_seam::bin_dir() {
        return dir.join(command).is_file();
    }
    Command::new("which")
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// ===========================================================================
// Rule and command helpers (pure, unit-tested)
// ===========================================================================

/// Runs a command given as an argument vector (program first).
async fn run_argv(argv: &[String], timeout_ms: u64) -> Result<(i32, String, String)> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("Empty command"))?;
    let args: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
    run_command_with_timeout(program, &args, timeout_ms).await
}

/// Renders an argument vector as a shell-safe command line for display.
fn display_command(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            let safe = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./:,=@%+-".contains(c));
            if safe {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Splits one `iptables-save` rule line into arguments, honoring double
/// quotes and backslash escapes the way iptables-save writes them (for
/// example `--comment "allow ssh"`).
fn tokenize_rule_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut in_quotes = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
                in_token = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                in_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            c => {
                current.push(c);
                in_token = true;
            }
        }
    }
    if in_token {
        tokens.push(current);
    }
    tokens
}

/// The address family ("ipv4" or "ipv6") an address or CIDR belongs to.
fn address_family(addr: &str) -> &'static str {
    if addr.contains(':') { "ipv6" } else { "ipv4" }
}

/// The "any address" CIDR for a family.
fn any_address(family: &str) -> &'static str {
    if family == "ipv6" {
        "::/0"
    } else {
        "0.0.0.0/0"
    }
}

/// Normalizes an address for comparison: unset and "any" addresses
/// (0.0.0.0/0, ::/0, any, Anywhere) compare equal to None.
fn normalize_address(addr: Option<&String>) -> Option<String> {
    let a = addr?;
    match a.to_lowercase().as_str() {
        "" | "0.0.0.0/0" | "::/0" | "any" | "anywhere" => None,
        _ => Some(a.clone()),
    }
}

/// Resolves which IP families `rules.add` must create rules for.
///
/// When saddr or daddr is given, the family follows the address, and an
/// explicitly requested family that disagrees is rejected. Without an
/// address, `any` means both IPv4 and IPv6.
fn resolve_add_families(
    family: &IpFamily,
    family_explicit: bool,
    saddr: Option<&String>,
    daddr: Option<&String>,
) -> Result<Vec<&'static str>, FirewallError> {
    let addrs: Vec<&String> = [saddr, daddr]
        .into_iter()
        .flatten()
        .filter(|a| normalize_address(Some(a)).is_some())
        .collect();
    let mut addr_family: Option<&'static str> = None;
    for addr in &addrs {
        let f = address_family(addr);
        match addr_family {
            Some(prev) if prev != f => {
                return Err(FirewallError::FamilyMismatch {
                    family: prev.to_string(),
                    address: (*addr).clone(),
                });
            }
            _ => addr_family = Some(f),
        }
    }
    if let Some(f) = addr_family {
        let requested = family.as_str();
        if family_explicit && requested != "any" && requested != f {
            let addr = addrs
                .iter()
                .find(|a| address_family(a) == f)
                .map(|a| (*a).clone())
                .unwrap_or_default();
            return Err(FirewallError::FamilyMismatch {
                family: requested.to_string(),
                address: addr,
            });
        }
        return Ok(vec![f]);
    }
    Ok(match family {
        IpFamily::Ipv4 => vec!["ipv4"],
        IpFamily::Ipv6 => vec!["ipv6"],
        IpFamily::Any => vec!["ipv4", "ipv6"],
    })
}

/// True if an iptables-save rule has match conditions that the normalized
/// rule fields do not represent (for example `-m conntrack --ctstate` or
/// `-m limit`). Such a rule never matches `match_mode=exact`. Target
/// options after `-j` are not match conditions and are ignored.
fn iptables_has_unmodeled_match(raw: &str) -> bool {
    let tokens = tokenize_rule_line(raw);
    let mut i = 2; // skip "-A CHAIN"
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-j" | "-g" => return false,
            "-p" | "-s" | "-d" | "-i" | "-o" | "--dport" | "--sport" | "--comment" => i += 2,
            "-m" if i + 1 < tokens.len()
                && matches!(tokens[i + 1].as_str(), "tcp" | "udp" | "comment") =>
            {
                i += 2
            }
            _ => return true,
        }
    }
    false
}

/// The backend's own identifier for a listed rule, as `rules.delete`
/// reports it and accepts in `rule_id=`:
///
/// - iptables: `<CHAIN>:<line>`, the 1-based line within its table and chain
/// - nftables: the rule handle
/// - ufw: the rule number from `ufw status numbered`
/// - firewalld: `<zone>:<kind>:<value>`, kind being service, port, source,
///   or rich-rule
fn rule_id_for(backend: &FirewallBackend, rule: &FirewallRule) -> Option<String> {
    match backend {
        FirewallBackend::Iptables => {
            let chain = rule.chain.as_ref()?;
            let line = rule.priority.filter(|n| *n > 0)?;
            Some(format!("{}:{}", chain, line))
        }
        FirewallBackend::Nftables => {
            let raw = rule.raw.as_ref()?;
            let pos = raw.rfind("# handle ")?;
            let handle: String = raw[pos + 9..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if handle.is_empty() {
                None
            } else {
                Some(handle)
            }
        }
        FirewallBackend::Ufw => rule.priority.filter(|n| *n > 0).map(|n| n.to_string()),
        FirewallBackend::Firewalld => {
            let zone = rule.chain.as_ref()?.strip_prefix("zone:")?;
            let raw = rule.raw.as_ref()?;
            let rest = raw.strip_prefix(&format!("--zone {} --add-", zone))?;
            let (kind, value) = rest.split_once(' ')?;
            let value = value.trim();
            let value = value
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
                .unwrap_or(value);
            Some(format!("{}:{}:{}", zone, kind, value))
        }
        FirewallBackend::Auto => None,
    }
}

/// True if `rule_id` has the form `rule_id_for` produces for `backend`.
fn rule_id_is_valid(backend: &FirewallBackend, rule_id: &str) -> bool {
    let positive = |s: &str| s.parse::<u64>().map(|n| n > 0).unwrap_or(false);
    match backend {
        FirewallBackend::Iptables => match rule_id.rsplit_once(':') {
            Some((chain, line)) => !chain.is_empty() && positive(line),
            None => false,
        },
        FirewallBackend::Nftables | FirewallBackend::Ufw => positive(rule_id),
        FirewallBackend::Firewalld => {
            let mut parts = rule_id.splitn(3, ':');
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(z), Some("service" | "port" | "source" | "rich-rule"), Some(v))
                    if !z.is_empty() && !v.is_empty()
            )
        }
        FirewallBackend::Auto => false,
    }
}

/// `match_mode=exact`: the rule's match fields equal the requested ones
/// (unset and "any" addresses are equal), and an iptables rule has no
/// other match conditions.
fn rule_matches_exactly(rule: &FirewallRule, opts: &RulesDeleteOptions) -> bool {
    let proto = |p: Option<&String>| {
        p.map(|p| p.to_lowercase())
            .filter(|p| !matches!(p.as_str(), "any" | "all"))
    };
    if proto(rule.proto.as_ref()) != proto(opts.proto.as_ref())
        || rule.sport != opts.sport
        || rule.dport != opts.dport
        || normalize_address(rule.saddr.as_ref()) != normalize_address(opts.saddr.as_ref())
        || normalize_address(rule.daddr.as_ref()) != normalize_address(opts.daddr.as_ref())
        || rule.in_iface != opts.in_iface
        || rule.out_iface != opts.out_iface
    {
        return false;
    }
    if rule.backend == "iptables" {
        if let Some(raw) = &rule.raw {
            return !iptables_has_unmodeled_match(raw);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_backend_from_str() {
        assert_eq!(
            FirewallBackend::from_str("auto").unwrap(),
            FirewallBackend::Auto
        );
        assert_eq!(
            FirewallBackend::from_str("iptables").unwrap(),
            FirewallBackend::Iptables
        );
        assert_eq!(
            FirewallBackend::from_str("nftables").unwrap(),
            FirewallBackend::Nftables
        );
        assert_eq!(
            FirewallBackend::from_str("ufw").unwrap(),
            FirewallBackend::Ufw
        );
        assert_eq!(
            FirewallBackend::from_str("firewalld").unwrap(),
            FirewallBackend::Firewalld
        );
        assert!(FirewallBackend::from_str("invalid").is_err());
    }

    #[test]
    fn test_ip_family_from_str() {
        assert_eq!(IpFamily::from_str("any").unwrap(), IpFamily::Any);
        assert_eq!(IpFamily::from_str("ipv4").unwrap(), IpFamily::Ipv4);
        assert_eq!(IpFamily::from_str("ipv6").unwrap(), IpFamily::Ipv6);
        assert!(IpFamily::from_str("invalid").is_err());
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("text").unwrap(), OutputFormat::Text);
        assert!(OutputFormat::from_str("invalid").is_err());
    }

    #[test]
    fn test_firewall_error_codes() {
        let error = FirewallError::InvalidBackend {
            backend: "test".to_string(),
        };
        assert_eq!(error.to_error_code(), "firewall.invalid_backend");

        let error = FirewallError::NoBackendAvailable;
        assert_eq!(error.to_error_code(), "firewall.no_backend_available");

        let error = FirewallError::MaxRulesExceeded {
            count: 15000,
            max: 10000,
        };
        assert_eq!(error.to_error_code(), "firewall.max_rules_exceeded");
    }

    #[test]
    fn test_rules_list_options_default() {
        let opts = RulesListOptions::default();
        assert_eq!(opts.backend, FirewallBackend::Auto);
        assert_eq!(opts.family, IpFamily::Any);
        assert_eq!(opts.max_rules, 10000);
        assert_eq!(opts.timeout_ms, 5000);
        assert!(!opts.include_backend_raw);
        assert!(!opts.include_counters);
    }

    #[test]
    fn test_rules_list_response_creation() {
        let response = RulesListResponse::new();
        assert!(!response.ok);
        assert!(response.error.is_none());
        assert!(response.rules.is_empty());

        let error = FirewallError::NoBackendAvailable;
        let error_response = RulesListResponse::with_error(error);
        assert!(!error_response.ok);
        assert!(error_response.error.is_some());
    }

    // -----------------------------------------------------------------------
    // Fixtures and helpers for rule selection and command construction.
    // None of these tests run a firewall command.
    // -----------------------------------------------------------------------

    fn handle() -> FirewallHandle {
        FirewallHandle::from_url(&Url::parse("firewall://").unwrap()).unwrap()
    }

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const IPTABLES_V4: &str = "\
# Generated by iptables-save v1.8.9
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -m tcp --dport 8080 -j REDIRECT --to-ports 80
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
-A FORWARD -p tcp -m tcp --dport 22 -j DROP
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 22 -m comment --comment \"allow ssh out\" -j ACCEPT
-A OUTPUT ! -s 10.0.0.0/8 -p tcp -m tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable
COMMIT
";

    const IPTABLES_V6: &str = "\
*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
";

    fn raw_list_opts() -> RulesListOptions {
        RulesListOptions {
            include_backend_raw: true,
            ..RulesListOptions::default()
        }
    }

    fn iptables_rules() -> Vec<FirewallRule> {
        let h = handle();
        let mut rules = h.parse_iptables_save_output(IPTABLES_V4, "ipv4", &raw_list_opts());
        rules.extend(h.parse_iptables_save_output(IPTABLES_V6, "ipv6", &raw_list_opts()));
        rules
    }

    fn delete_opts(pairs: &[(&str, &str)]) -> RulesDeleteOptions {
        handle().parse_rules_delete_options(&args(pairs)).unwrap()
    }

    fn select(
        backend: &FirewallBackend,
        rules: Vec<FirewallRule>,
        pairs: &[(&str, &str)],
    ) -> Result<Vec<MatchedFirewallRule>> {
        handle().select_rules_for_delete(backend, rules, &delete_opts(pairs))
    }

    fn lines(cmds: &[Vec<String>]) -> Vec<String> {
        cmds.iter().map(|c| display_command(c)).collect()
    }

    fn fw_err(e: anyhow::Error) -> FirewallError {
        e.downcast::<FirewallError>().expect("FirewallError")
    }

    // -----------------------------------------------------------------------
    // C2: iptables line numbers and rule ids are per table and chain
    // -----------------------------------------------------------------------

    #[test]
    fn iptables_line_numbers_are_per_chain() {
        let rules = iptables_rules();
        let ids: Vec<(String, String, Option<String>)> = rules
            .iter()
            .map(|r| {
                (
                    r.family.clone(),
                    r.table.clone().unwrap(),
                    rule_id_for(&FirewallBackend::Iptables, r),
                )
            })
            .collect();
        let expect =
            |f: &str, t: &str, id: &str| (f.to_string(), t.to_string(), Some(id.to_string()));
        assert_eq!(
            ids,
            vec![
                expect("ipv4", "nat", "PREROUTING:1"),
                expect("ipv4", "filter", "INPUT:1"),
                expect("ipv4", "filter", "INPUT:2"),
                expect("ipv4", "filter", "INPUT:3"),
                expect("ipv4", "filter", "FORWARD:1"),
                expect("ipv4", "filter", "OUTPUT:1"),
                expect("ipv4", "filter", "OUTPUT:2"),
                expect("ipv4", "filter", "OUTPUT:3"),
                expect("ipv6", "filter", "INPUT:1"),
                expect("ipv6", "filter", "OUTPUT:1"),
                expect("ipv6", "filter", "OUTPUT:2"),
            ]
        );
    }

    #[test]
    fn iptables_parse_quoted_comment_and_negation() {
        let rules = iptables_rules();
        let ssh_out = &rules[6];
        assert_eq!(ssh_out.comment.as_deref(), Some("allow ssh out"));
        assert_eq!(ssh_out.action.as_deref(), Some("accept"));
        let smtp = &rules[7];
        assert_eq!(smtp.saddr.as_deref(), Some("!10.0.0.0/8"));
        assert_eq!(smtp.dport.as_deref(), Some("25"));
    }

    #[test]
    fn iptables_delete_in_later_chain_targets_that_rule_by_spec() {
        // The FORWARD rule is the 4th rule in the filter table but line 1
        // of its chain; the delete must name that exact rule.
        let matched = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("chain", "FORWARD"), ("proto", "tcp"), ("dport", "22")],
        )
        .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].rule_id.as_deref(), Some("FORWARD:1"));
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Iptables, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec!["iptables -t filter -D FORWARD -p tcp -m tcp --dport 22 -j DROP"]
        );
    }

    #[test]
    fn iptables_delete_keeps_quoted_comment_as_one_argument() {
        let matched = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("family", "ipv4"), ("rule_id", "OUTPUT:2")],
        )
        .unwrap();
        assert_eq!(matched.len(), 1);
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Iptables, &matched)
            .unwrap();
        assert_eq!(
            cmds[0],
            [
                "iptables",
                "-t",
                "filter",
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                "22",
                "-m",
                "comment",
                "--comment",
                "allow ssh out",
                "-j",
                "ACCEPT"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        );
        assert_eq!(
            display_command(&cmds[0]),
            "iptables -t filter -D OUTPUT -p tcp -m tcp --dport 22 -m comment --comment 'allow ssh out' -j ACCEPT"
        );
    }

    #[test]
    fn iptables_delete_by_line_number_goes_highest_first() {
        // Without the listed spec, delete by line number in each chain,
        // highest first so earlier deletions do not renumber later ones.
        let mut matched = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[
                ("family", "ipv4"),
                ("table", "filter"),
                ("chain", "INPUT"),
                ("match_mode", "subset"),
            ],
        )
        .unwrap();
        assert_eq!(matched.len(), 3);
        for m in &mut matched {
            m.raw = None;
        }
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Iptables, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec![
                "iptables -t filter -D INPUT 3",
                "iptables -t filter -D INPUT 2",
                "iptables -t filter -D INPUT 1",
            ]
        );
    }

    #[test]
    fn iptables_delete_spans_families_with_right_binary() {
        let matched = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("chain", "OUTPUT"), ("proto", "udp"), ("dport", "53")],
        )
        .unwrap();
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Iptables, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec![
                "iptables -t filter -D OUTPUT -p udp -m udp --dport 53 -j ACCEPT",
                "ip6tables -t filter -D OUTPUT -p udp -m udp --dport 53 -j ACCEPT",
            ]
        );
    }

    #[test]
    fn rule_id_selects_one_rule_and_rejects_ambiguity() {
        // INPUT:1 exists in IPv4 and IPv6.
        let err = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("rule_id", "INPUT:1")],
        )
        .unwrap_err();
        assert!(matches!(
            fw_err(err),
            FirewallError::AmbiguousRuleId { count: 2, .. }
        ));

        let one = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("rule_id", "INPUT:1"), ("family", "ipv6")],
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].family, "ipv6");

        // Extra filters must also hold for the selected rule.
        let none = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("rule_id", "INPUT:3"), ("family", "ipv4"), ("dport", "80")],
        )
        .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn rule_id_format_is_validated_per_backend() {
        assert!(rule_id_is_valid(&FirewallBackend::Iptables, "INPUT:3"));
        assert!(!rule_id_is_valid(&FirewallBackend::Iptables, "INPUT"));
        assert!(!rule_id_is_valid(&FirewallBackend::Iptables, "INPUT:0"));
        assert!(rule_id_is_valid(&FirewallBackend::Nftables, "12"));
        assert!(!rule_id_is_valid(&FirewallBackend::Ufw, "x"));
        assert!(rule_id_is_valid(
            &FirewallBackend::Firewalld,
            "public:port:80/tcp"
        ));
        assert!(!rule_id_is_valid(
            &FirewallBackend::Firewalld,
            "public:bogus:80/tcp"
        ));

        let h = handle();
        let opts = delete_opts(&[("rule_id", "INPUT")]);
        let err = h
            .validate_delete_options_for_backend(&FirewallBackend::Iptables, &opts)
            .unwrap_err();
        assert!(matches!(fw_err(err), FirewallError::InvalidRuleId { .. }));
    }

    #[test]
    fn match_mode_exact_and_subset_differ() {
        // exact: dport=22 alone does not match the rule that also has saddr,
        // nor rules with other match conditions.
        let exact = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[
                ("family", "ipv4"),
                ("chain", "INPUT"),
                ("proto", "tcp"),
                ("dport", "22"),
            ],
        )
        .unwrap();
        assert!(exact.is_empty());

        let subset = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[
                ("family", "ipv4"),
                ("chain", "INPUT"),
                ("dport", "22"),
                ("match_mode", "subset"),
            ],
        )
        .unwrap();
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].rule_id.as_deref(), Some("INPUT:3"));

        // A rule with an unmodeled match (conntrack) only matches subset.
        let exact_lo = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[
                ("family", "ipv4"),
                ("table", "filter"),
                ("chain", "INPUT"),
                ("action", "accept"),
            ],
        )
        .unwrap();
        assert!(
            exact_lo.is_empty(),
            "INPUT:1 has -i lo, INPUT:2 has conntrack"
        );
        assert!(iptables_has_unmodeled_match(
            "-A INPUT -m conntrack --ctstate NEW -j ACCEPT"
        ));
        assert!(!iptables_has_unmodeled_match(
            "-A INPUT -p tcp -m tcp --dport 22 -j REJECT --reject-with tcp-reset"
        ));

        // Negated address does not match a plain saddr filter.
        let negated = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("saddr", "10.0.0.0/8"), ("match_mode", "subset")],
        )
        .unwrap();
        assert!(negated.is_empty());
    }

    #[test]
    fn delete_requires_rule_id_or_criteria() {
        let err = handle()
            .parse_rules_delete_options(&args(&[("dry_run", "true")]))
            .unwrap_err();
        assert!(matches!(fw_err(err), FirewallError::MissingDeleteCriteria));
    }

    #[test]
    fn zone_is_rejected_outside_firewalld() {
        let h = handle();
        let opts = delete_opts(&[("zone", "public")]);
        let err = h
            .validate_delete_options_for_backend(&FirewallBackend::Iptables, &opts)
            .unwrap_err();
        assert!(matches!(
            fw_err(err),
            FirewallError::UnsupportedOption { .. }
        ));
        assert!(
            h.validate_delete_options_for_backend(&FirewallBackend::Firewalld, &opts)
                .is_ok()
        );
    }

    fn firewalld_rule(zone: &str, raw: &str, dport: Option<&str>) -> FirewallRule {
        FirewallRule {
            backend: "firewalld".to_string(),
            family: "any".to_string(),
            table: None,
            chain: Some(format!("zone:{}", zone)),
            direction: Some("input".to_string()),
            priority: Some(1),
            action: Some("accept".to_string()),
            proto: dport.map(|_| "tcp".to_string()),
            sport: None,
            dport: dport.map(|d| d.to_string()),
            saddr: None,
            daddr: None,
            in_iface: None,
            out_iface: None,
            comment: None,
            packets: None,
            bytes: None,
            raw: Some(raw.to_string()),
        }
    }

    #[test]
    fn firewalld_zone_selects_and_delete_uses_rule_zone() {
        let rules = vec![
            firewalld_rule("public", "--zone public --add-port 80/tcp", Some("80")),
            firewalld_rule("internal", "--zone internal --add-port 80/tcp", Some("80")),
            firewalld_rule(
                "internal",
                "--zone internal --add-rich-rule 'rule family=\"ipv4\" source address=\"10.0.0.0/8\" accept'",
                None,
            ),
        ];
        let matched = select(
            &FirewallBackend::Firewalld,
            rules.clone(),
            &[("zone", "internal"), ("proto", "tcp"), ("dport", "80")],
        )
        .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].rule_id.as_deref(), Some("internal:port:80/tcp"));
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Firewalld, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec!["firewall-cmd --zone=internal --remove-port=80/tcp"]
        );

        let rich = select(
            &FirewallBackend::Firewalld,
            rules,
            &[(
                "rule_id",
                "internal:rich-rule:rule family=\"ipv4\" source address=\"10.0.0.0/8\" accept",
            )],
        )
        .unwrap();
        assert_eq!(rich.len(), 1);
        let cmds = handle()
            .generate_delete_commands(&FirewallBackend::Firewalld, &rich)
            .unwrap();
        assert_eq!(
            cmds[0][2],
            "--remove-rich-rule=rule family=\"ipv4\" source address=\"10.0.0.0/8\" accept"
        );
    }

    #[test]
    fn nftables_delete_uses_listed_handle() {
        let h = handle();
        let rule = h
            .parse_nftables_rule(
                "tcp dport 22 accept # handle 7",
                &Some(("inet".to_string(), "filter".to_string())),
                &Some(("input".to_string(), "input".to_string())),
                1,
                &raw_list_opts(),
            )
            .unwrap();
        assert_eq!(
            rule_id_for(&FirewallBackend::Nftables, &rule).as_deref(),
            Some("7")
        );
        let matched = select(&FirewallBackend::Nftables, vec![rule], &[("rule_id", "7")]).unwrap();
        let cmds = h
            .generate_delete_commands(&FirewallBackend::Nftables, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec!["nft delete rule inet filter input handle 7"]
        );
    }

    #[test]
    fn ufw_delete_uses_rule_numbers_highest_first() {
        let h = handle();
        let opts = raw_list_opts();
        let rules: Vec<FirewallRule> = [
            "[ 1] 22/tcp                     ALLOW IN    Anywhere",
            "[ 2] 80/tcp                     ALLOW IN    Anywhere",
            "[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)",
        ]
        .iter()
        .filter_map(|l| h.parse_ufw_rule(l, 99, &opts))
        .collect();
        assert_eq!(
            rules.iter().map(|r| r.priority).collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );
        let matched = select(
            &FirewallBackend::Ufw,
            rules,
            &[("dport", "22"), ("match_mode", "subset")],
        )
        .unwrap();
        let cmds = h
            .generate_delete_commands(&FirewallBackend::Ufw, &matched)
            .unwrap();
        assert_eq!(
            lines(&cmds),
            vec!["ufw --force delete 3", "ufw --force delete 1"]
        );
    }

    #[test]
    fn delete_fails_when_a_rule_cannot_be_addressed() {
        let mut matched = select(
            &FirewallBackend::Iptables,
            iptables_rules(),
            &[("family", "ipv4"), ("rule_id", "FORWARD:1")],
        )
        .unwrap();
        matched[0].raw = None;
        matched[0].line_number = None;
        let err = handle()
            .generate_delete_commands(&FirewallBackend::Iptables, &matched)
            .unwrap_err();
        assert!(matches!(
            fw_err(err),
            FirewallError::RuleIdUnavailable { .. }
        ));
    }

    #[test]
    fn tokenizer_and_display_round_trip() {
        assert_eq!(
            tokenize_rule_line(r#"-A INPUT -m comment --comment "say \"hi\" now" -j ACCEPT"#),
            vec![
                "-A",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "say \"hi\" now",
                "-j",
                "ACCEPT"
            ]
        );
        assert_eq!(
            display_command(&["a".to_string(), "it's here".to_string(), "".to_string()]),
            "a 'it'\\''s here' ''"
        );
    }

    // -----------------------------------------------------------------------
    // C3: rules.add family handling
    // -----------------------------------------------------------------------

    fn add_plan(
        backend: FirewallBackend,
        pairs: &[(&str, &str)],
    ) -> Result<(Vec<FirewallRuleSpec>, Vec<String>)> {
        let h = handle();
        let opts = h.parse_rules_add_options(&args(pairs))?;
        let specs = h.normalize_rule_specs(&opts, &backend)?;
        let mut cmds = Vec::new();
        for spec in &specs {
            cmds.extend(h.generate_add_commands(spec, &opts)?);
        }
        Ok((specs, lines(&cmds)))
    }

    #[test]
    fn add_family_any_creates_ipv4_and_ipv6_rules() {
        let (specs, cmds) = add_plan(
            FirewallBackend::Iptables,
            &[("family", "any"), ("proto", "tcp"), ("dport", "22")],
        )
        .unwrap();
        assert_eq!(
            cmds,
            vec![
                "iptables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT",
                "ip6tables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT",
            ]
        );
        assert_eq!(specs.len(), 2);
        assert_eq!(
            (specs[0].family.as_str(), specs[0].saddr.as_deref()),
            ("ipv4", Some("0.0.0.0/0"))
        );
        assert_eq!(
            (specs[1].family.as_str(), specs[1].saddr.as_deref()),
            ("ipv6", Some("::/0"))
        );
        assert_eq!(specs[1].daddr.as_deref(), Some("::/0"));

        let (_, nft) = add_plan(
            FirewallBackend::Nftables,
            &[("family", "any"), ("proto", "tcp"), ("dport", "22")],
        )
        .unwrap();
        assert_eq!(
            nft,
            vec![
                "nft add rule ip filter input tcp dport 22 accept",
                "nft add rule ip6 filter input tcp dport 22 accept",
            ]
        );
    }

    #[test]
    fn add_family_follows_address() {
        let (specs, cmds) = add_plan(
            FirewallBackend::Iptables,
            &[
                ("family", "any"),
                ("saddr", "2001:db8::/32"),
                ("proto", "tcp"),
                ("dport", "443"),
            ],
        )
        .unwrap();
        assert_eq!(
            cmds,
            vec!["ip6tables -t filter -A INPUT -p tcp -s 2001:db8::/32 --dport 443 -j ACCEPT"]
        );
        assert_eq!(specs[0].family, "ipv6");
        assert_eq!(specs[0].daddr.as_deref(), Some("::/0"));

        // Without family=, an IPv6 address also selects IPv6.
        let (_, cmds) = add_plan(FirewallBackend::Iptables, &[("saddr", "2001:db8::1")]).unwrap();
        assert_eq!(
            cmds,
            vec!["ip6tables -t filter -A INPUT -s 2001:db8::1 -j ACCEPT"]
        );

        // An IPv4 address with family=any goes to iptables, never ip6tables.
        let (_, cmds) = add_plan(
            FirewallBackend::Iptables,
            &[("family", "any"), ("saddr", "198.51.100.7")],
        )
        .unwrap();
        assert_eq!(
            cmds,
            vec!["iptables -t filter -A INPUT -s 198.51.100.7 -j ACCEPT"]
        );
    }

    #[test]
    fn add_rejects_family_address_mismatch() {
        let err = add_plan(
            FirewallBackend::Iptables,
            &[("family", "ipv4"), ("saddr", "2001:db8::/32")],
        )
        .unwrap_err();
        assert!(matches!(fw_err(err), FirewallError::FamilyMismatch { .. }));
        let err = add_plan(
            FirewallBackend::Iptables,
            &[("saddr", "10.0.0.0/8"), ("daddr", "2001:db8::1")],
        )
        .unwrap_err();
        assert!(matches!(fw_err(err), FirewallError::FamilyMismatch { .. }));
    }

    #[test]
    fn add_single_rule_backends_cover_both_families() {
        let (specs, cmds) = add_plan(
            FirewallBackend::Ufw,
            &[("family", "any"), ("proto", "tcp"), ("dport", "22")],
        )
        .unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].family, "any");
        assert_eq!(specs[0].saddr, None);
        assert_eq!(cmds, vec!["ufw allow proto tcp from any to any port 22"]);

        let (_, cmds) =
            add_plan(FirewallBackend::Ufw, &[("proto", "tcp"), ("dport", "22")]).unwrap();
        assert_eq!(
            cmds,
            vec!["ufw allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 22"]
        );

        let (_, cmds) = add_plan(
            FirewallBackend::Firewalld,
            &[
                ("family", "any"),
                ("zone", "public"),
                ("proto", "tcp"),
                ("dport", "22"),
            ],
        )
        .unwrap();
        assert_eq!(
            cmds,
            vec![
                "firewall-cmd --zone=public '--add-rich-rule=rule port protocol=\"tcp\" port=\"22\" accept'"
            ]
        );
    }

    #[test]
    fn add_rejects_port_without_protocol_and_zone_outside_firewalld() {
        let err = add_plan(FirewallBackend::Iptables, &[("dport", "22")]).unwrap_err();
        assert!(matches!(
            fw_err(err),
            FirewallError::UnsupportedOption { .. }
        ));
        let err = add_plan(
            FirewallBackend::Iptables,
            &[("zone", "public"), ("proto", "tcp")],
        )
        .unwrap_err();
        assert!(matches!(
            fw_err(err),
            FirewallError::UnsupportedOption { .. }
        ));
    }

    #[test]
    fn add_comment_is_one_argument() {
        let (_, cmds) = add_plan(
            FirewallBackend::Iptables,
            &[("proto", "tcp"), ("dport", "22"), ("comment", "allow ssh")],
        )
        .unwrap();
        assert_eq!(
            cmds,
            vec![
                "iptables -t filter -A INPUT -p tcp --dport 22 -m comment --comment 'allow ssh' -j ACCEPT"
            ]
        );
    }

    #[test]
    fn idempotency_match_ignores_any_address() {
        let h = handle();
        let opts = h
            .parse_rules_add_options(&args(&[
                ("proto", "udp"),
                ("dport", "53"),
                ("direction", "output"),
            ]))
            .unwrap();
        let spec = h
            .normalize_rule_specs(&opts, &FirewallBackend::Iptables)
            .unwrap()
            .remove(0);
        let rules = iptables_rules();
        assert!(
            h.rules_match(&spec, &rules[5]),
            "OUTPUT udp 53 ACCEPT exists"
        );
        assert!(
            !h.rules_match(&spec, &rules[9]),
            "the IPv6 rule is a different family"
        );
    }

    // -----------------------------------------------------------------------
    // L1 / H2: in-URL help
    // -----------------------------------------------------------------------

    fn run_call(verb: &str, pairs: &[(&str, &str)]) -> (Status, String) {
        let h = handle();
        let mut i: &[u8] = &[];
        let mut o: Vec<u8> = Vec::new();
        let mut e: Vec<u8> = Vec::new();
        let status = {
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            h.call(verb, &args(pairs), &mut io).unwrap()
        };
        (status, String::from_utf8(o).unwrap())
    }

    #[test]
    fn in_url_help_renders_approved_help() {
        for verb in ["--help", "-h", "help"] {
            let (status, out) = run_call(verb, &[]);
            assert!(status.ok);
            assert!(out.starts_with("Handle: firewall"), "{}", out);
        }
        let (_, out) = run_call("help", &[("verb", "rules.delete")]);
        assert!(out.contains("Verb: rules.delete"), "{}", out);
        let (_, out) = run_call("--help=rules.add", &[]);
        assert!(out.contains("Verb: rules.add"), "{}", out);
    }

    #[test]
    fn non_help_verbs_are_not_help() {
        let (status, out) = run_call("my-help", &[]);
        assert!(!status.ok);
        assert!(out.is_empty());
    }
}

// SEC-05: every mutating firewall verb reads dry_run the same way, and a
// malformed value is an error instead of a real rule change.
#[cfg(test)]
mod dry_run_tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Args {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn with(base: &[(&str, &str)], dry_run: Option<&str>) -> Args {
        let mut a = args(base);
        if let Some(v) = dry_run {
            a.insert("dry_run".into(), v.into());
        }
        a
    }

    type DryRunParser = Box<dyn Fn(&Args) -> Result<bool>>;

    /// (verb, minimal valid args, parser returning the parsed dry_run)
    fn parsers() -> Vec<(
        &'static str,
        Vec<(&'static str, &'static str)>,
        DryRunParser,
    )> {
        let h = || FirewallHandle::from_url(&Url::parse("firewall://").unwrap()).unwrap();
        vec![
            (
                "rules.save",
                vec![],
                Box::new(move |a: &Args| Ok(h().parse_rules_save_options(a)?.dry_run)),
            ),
            (
                "rules.add",
                vec![("proto", "tcp"), ("dport", "22")],
                Box::new(move |a: &Args| Ok(h().parse_rules_add_options(a)?.dry_run)),
            ),
            (
                "rules.delete",
                vec![("rule_id", "INPUT")],
                Box::new(move |a: &Args| Ok(h().parse_rules_delete_options(a)?.dry_run)),
            ),
            (
                "rules.reload",
                vec![],
                Box::new(move |a: &Args| Ok(h().parse_rules_reload_options(a)?.dry_run)),
            ),
            (
                "enable",
                vec![],
                Box::new(move |a: &Args| Ok(h().parse_enable_options(a)?.dry_run)),
            ),
            (
                "disable",
                vec![],
                Box::new(move |a: &Args| Ok(h().parse_disable_options(a)?.dry_run)),
            ),
        ]
    }

    #[test]
    fn dry_run_spellings_are_consistent() {
        for (verb, base, parse) in parsers() {
            for v in ["true", "1", "yes", "on", "TRUE"] {
                assert!(parse(&with(&base, Some(v))).unwrap(), "{verb} dry_run={v}");
            }
            for v in ["false", "0", "no", "off"] {
                assert!(!parse(&with(&base, Some(v))).unwrap(), "{verb} dry_run={v}");
            }
            for v in ["maybe", "", "2", "tru"] {
                assert!(
                    parse(&with(&base, Some(v))).is_err(),
                    "{verb} accepted dry_run={v:?}"
                );
            }
            // Missing: the parser's own default, which is not a dry run.
            assert!(parse(&with(&base, None)).is_ok(), "{verb}");
        }
    }
}

// FUNC-03: enable/disable take a real backup before changing rules, report
// its true path, and change nothing when a required backup fails. Every
// firewall command is redirected to mock scripts for the test thread.
#[cfg(test)]
mod backup_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const NFT_RULES: &str = "table ip filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n";
    const IPT_RULES_EMPTY: &str =
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
    const IPT_RULES: &str = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n";

    struct Fixture {
        dir: TempDir,
        backups: std::path::PathBuf,
    }

    impl Fixture {
        /// Mock nft/iptables tools. `rules` is what the save/list commands
        /// print; `apply_exit` is the exit code of the rule-changing calls.
        fn new(nft_rules: &str, ipt_rules: &str, apply_exit: i32) -> Self {
            let dir = TempDir::new().unwrap();
            let bin = dir.path().join("bin");
            fs::create_dir(&bin).unwrap();
            fs::write(dir.path().join("nft.rules"), nft_rules).unwrap();
            fs::write(dir.path().join("ipt.rules"), ipt_rules).unwrap();
            let log = dir.path().join("calls.log");
            let script = format!(
                "#!/bin/sh\nname=$(basename \"$0\")\necho \"$name $*\" >> '{log}'\n\
                 case \"$name $1\" in\n\
                 \"nft list\") cat '{d}/nft.rules' ;;\n\
                 \"iptables-save \"*|\"ip6tables-save \"*) cat '{d}/ipt.rules' ;;\n\
                 \"nft -f\"|\"iptables-restore \"*|\"ip6tables-restore \"*|\"nft flush\"|\"iptables -F\"|\"iptables -P\") exit {apply_exit} ;;\n\
                 esac\nexit 0\n",
                log = log.display(),
                d = dir.path().display(),
            );
            for tool in [
                "nft",
                "iptables",
                "ip6tables",
                "iptables-save",
                "ip6tables-save",
                "iptables-restore",
                "ip6tables-restore",
            ] {
                let p = bin.join(tool);
                fs::write(&p, &script).unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let backups = dir.path().join("backups");
            Fixture { dir, backups }
        }

        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn backup_files(&self) -> Vec<std::path::PathBuf> {
            match fs::read_dir(&self.backups) {
                Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
                Err(_) => Vec::new(),
            }
        }

        fn rules_file(&self) -> String {
            let p = self.dir.path().join("new.rules");
            fs::write(&p, "# new rules\n").unwrap();
            p.to_string_lossy().into_owned()
        }

        /// Runs a verb with commands and backups redirected into the fixture.
        fn run(&self, verb: &str, pairs: &[(&str, &str)]) -> (Status, Value) {
            let _seam = test_seam::install(self.dir.path().join("bin"), self.backups.clone());
            let h = FirewallHandle::from_url(&Url::parse("firewall://").unwrap()).unwrap();
            let args: Args = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut i: &[u8] = &[];
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let status = {
                let mut io = IoStreams {
                    stdin: &mut i,
                    stdout: &mut o,
                    stderr: &mut e,
                };
                h.call(verb, &args, &mut io).unwrap()
            };
            let text = if o.is_empty() { e } else { o };
            (status, serde_json::from_slice(&text).unwrap_or(Value::Null))
        }
    }

    fn position(calls: &[String], prefix: &str) -> Option<usize> {
        calls.iter().position(|c| c.starts_with(prefix))
    }

    #[test]
    fn nft_disable_writes_backup_before_flushing() {
        let fx = Fixture::new(NFT_RULES, IPT_RULES_EMPTY, 0);
        let (status, json) = fx.run("disable", &[("backend", "nftables")]);
        assert!(status.ok, "{json}");
        assert_eq!(json["ok"], true);

        let reported = json["result"]["backup_path"]
            .as_str()
            .unwrap_or_else(|| panic!("no backup_path: {json} {:?}", fx.calls()));
        let files = fx.backup_files();
        assert_eq!(
            files,
            vec![std::path::PathBuf::from(reported)],
            "reported path is the file on disk"
        );
        assert_eq!(fs::read_to_string(reported).unwrap(), NFT_RULES);
        assert_eq!(
            fs::metadata(reported).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let calls = fx.calls();
        let flush = position(&calls, "nft flush ruleset").expect("flush ran");
        // The last ruleset listing before the flush is the backup capture.
        assert!(
            calls[..flush].iter().any(|c| c == "nft list ruleset"),
            "{calls:?}"
        );
    }

    #[test]
    fn iptables_enable_backs_up_then_restores_without_a_shell() {
        let fx = Fixture::new("", IPT_RULES_EMPTY, 0);
        let rules = fx.rules_file();
        let (status, json) = fx.run(
            "enable",
            &[
                ("backend", "iptables"),
                ("family", "ipv4"),
                ("path", &rules),
            ],
        );
        assert!(status.ok, "{json}");

        let reported = json["result"]["backup_path"]
            .as_str()
            .unwrap_or_else(|| panic!("no backup_path: {json} {:?}", fx.calls()));
        assert_eq!(fs::read_to_string(reported).unwrap(), IPT_RULES_EMPTY);
        assert!(reported.starts_with(fx.backups.to_str().unwrap()));

        let calls = fx.calls();
        let restore = position(&calls, "iptables-restore").expect("restore ran");
        assert_eq!(
            calls[restore],
            format!("iptables-restore {}", rules),
            "rules file is one argument"
        );
        assert!(position(&calls, "iptables-save").unwrap() < restore);
        assert!(!calls.iter().any(|c| c.starts_with("sh ")));
    }

    #[test]
    fn backup_write_failure_prevents_any_change() {
        for (backend, rules_nft, rules_ipt, change) in [
            ("nftables", NFT_RULES, IPT_RULES_EMPTY, "nft flush"),
            ("iptables", "", IPT_RULES, "iptables -"),
        ] {
            let fx = Fixture::new(rules_nft, rules_ipt, 0);
            // The backup directory path is an existing regular file.
            fs::write(&fx.backups, "not a directory").unwrap();
            let (status, json) = fx.run("disable", &[("backend", backend)]);
            assert!(!status.ok, "{backend}: {json}");
            assert_ne!(status.code, Some(0));
            assert!(
                status.reason.as_deref().unwrap_or("").contains("backup"),
                "{:?}",
                status.reason
            );
            assert_eq!(json["ok"], false);
            let calls = fx.calls();
            assert!(
                !calls.iter().any(|c| c.starts_with(change)),
                "{backend} changed rules: {calls:?}"
            );
        }
    }

    #[test]
    fn backup_directory_permission_failure_prevents_change() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root bypasses directory permissions
        }
        let fx = Fixture::new(NFT_RULES, IPT_RULES_EMPTY, 0);
        let locked = fx.dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        let fx = Fixture {
            backups: locked.join("backups"),
            ..fx
        };

        let (status, json) = fx.run("disable", &[("backend", "nftables")]);
        assert!(!status.ok, "{json}");
        assert!(
            json["error"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Permission denied"),
            "{json}"
        );
        assert!(!fx.calls().iter().any(|c| c.starts_with("nft flush")));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn symlinked_backup_directory_is_refused() {
        let fx = Fixture::new(NFT_RULES, IPT_RULES_EMPTY, 0);
        let elsewhere = fx.dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &fx.backups).unwrap();

        let (status, _) = fx.run("disable", &[("backend", "nftables")]);
        assert!(!status.ok);
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert!(!fx.calls().iter().any(|c| c.starts_with("nft flush")));
    }

    #[test]
    fn mutation_failure_after_backup_is_a_failure() {
        let fx = Fixture::new("", IPT_RULES_EMPTY, 3);
        let rules = fx.rules_file();
        let (status, json) = fx.run("enable", &[("backend", "nftables"), ("path", &rules)]);
        assert!(!status.ok, "{json}");
        assert_ne!(status.code, Some(0));
        assert_eq!(json["ok"], false);
        assert_eq!(
            json["error"]["error"]["code"], "firewall.command_failed",
            "{json}"
        );
        assert!(
            status.reason.as_deref().unwrap().contains("exit code 3"),
            "{:?}",
            status.reason
        );
        // The backup taken before the failed change is still there.
        assert_eq!(fx.backup_files().len(), 1);
    }

    #[test]
    fn no_backup_requested_means_none_reported() {
        let fx = Fixture::new(NFT_RULES, IPT_RULES_EMPTY, 0);
        let (status, json) = fx.run(
            "disable",
            &[("backend", "nftables"), ("backup_before_apply", "no")],
        );
        assert!(status.ok, "{json}");
        assert!(json["result"]["backup_path"].is_null());
        assert!(fx.backup_files().is_empty());
        assert!(
            !fx.run(
                "disable",
                &[("backend", "nftables"), ("backup_before_apply", "maybe")]
            )
            .0
            .ok
        );
    }

    #[test]
    fn dry_run_writes_no_backup_and_changes_nothing() {
        let fx = Fixture::new(NFT_RULES, IPT_RULES, 0);
        let rules = fx.rules_file();
        for (verb, backend) in [
            ("disable", "nftables"),
            ("disable", "iptables"),
            ("enable", "nftables"),
            ("enable", "iptables"),
        ] {
            for dry in ["true", "1", "yes"] {
                let (status, json) = fx.run(
                    verb,
                    &[("backend", backend), ("path", &rules), ("dry_run", dry)],
                );
                assert!(status.ok, "{verb} {backend}: {json}");
                assert!(json["result"]["backup_path"].is_null());
            }
        }
        assert!(fx.backup_files().is_empty());
        let calls = fx.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("nft -f")
                || c.starts_with("nft flush")
                || c.starts_with("iptables-restore")
                || c.starts_with("iptables -")),
            "dry run changed rules: {calls:?}"
        );
    }

    #[test]
    fn write_rules_backup_never_overwrites() {
        let dir = TempDir::new().unwrap();
        let first = write_rules_backup(dir.path(), "b.rules", b"one").unwrap();
        assert_eq!(fs::read(&first).unwrap(), b"one");
        assert!(write_rules_backup(dir.path(), "b.rules", b"two").is_err());
        assert_eq!(fs::read(&first).unwrap(), b"one");
        // A planted symlink at the file name is not followed.
        let target = dir.path().join("target");
        std::os::unix::fs::symlink(&target, dir.path().join("c.rules")).unwrap();
        assert!(write_rules_backup(dir.path(), "c.rules", b"x").is_err());
        assert!(!target.exists());
    }
}

/// Stage 3 (SEC-08): firewall `timeout_ms` is enforced. Commands resolve to
/// per-test mock executables; the host firewall tools are never run.
#[cfg(test)]
mod timeout_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;
    use tempfile::TempDir;

    fn mock_tool(bin: &std::path::Path, name: &str, body: &str) {
        let p = bin.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        (dir, bin)
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn hung_command_is_killed_and_reaped_at_the_deadline() {
        let (dir, bin) = fixture();
        let pidfile = dir.path().join("pid");
        mock_tool(
            &bin,
            "nft",
            &format!("echo $$ > '{}'\nexec sleep 30", pidfile.display()),
        );
        let _seam = test_seam::install(bin, dir.path().join("backups"));

        let start = Instant::now();
        let err = rt()
            .block_on(run_command_with_timeout("nft", &["list", "ruleset"], 300))
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("timed out after 300ms"), "{err}");
        assert!(
            elapsed >= Duration::from_millis(300),
            "returned before the deadline: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout did not fire: {elapsed:?}"
        );

        let pid: libc::pid_t = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The child was killed and reaped: the pid no longer exists.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "timed-out command {pid} is still running"
        );
    }

    #[test]
    fn completed_command_keeps_exit_code_and_output() {
        let (dir, bin) = fixture();
        mock_tool(&bin, "nft", "echo out; echo err >&2; exit 3");
        let _seam = test_seam::install(bin, dir.path().join("backups"));
        let (code, out, err) = rt()
            .block_on(run_command_with_timeout("nft", &["list", "ruleset"], 5000))
            .unwrap();
        assert_eq!((code, out.as_str(), err.as_str()), (3, "out\n", "err\n"));
    }

    #[test]
    fn large_output_does_not_deadlock_before_the_deadline() {
        let (dir, bin) = fixture();
        mock_tool(&bin, "nft", "head -c 400000 /dev/zero | tr '\\0' 'x'");
        let _seam = test_seam::install(bin, dir.path().join("backups"));
        let (code, out, _) = rt()
            .block_on(run_command_with_timeout("nft", &[], 5000))
            .unwrap();
        assert_eq!(code, 0);
        assert_eq!(out.len(), 400000);
    }

    #[test]
    fn missing_command_is_an_error() {
        let (dir, bin) = fixture();
        let _seam = test_seam::install(bin, dir.path().join("backups"));
        assert!(
            rt().block_on(run_command_with_timeout("nft", &[], 1000))
                .is_err()
        );
    }
}
