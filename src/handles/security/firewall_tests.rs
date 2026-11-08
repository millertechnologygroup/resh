//! Dispatch tests for every firewall verb: each runs through
//! `Handle::call` with every firewall tool redirected to a mock script in a
//! temporary directory (see `test_seam`), so no test reaches the host
//! firewall. The mock logs each call, prints canned listings from files in
//! its directory, and fails or hangs when told to.

use super::*;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

const ALL_TOOLS: &[&str] = &[
    "nft",
    "iptables",
    "ip6tables",
    "iptables-save",
    "ip6tables-save",
    "iptables-restore",
    "ip6tables-restore",
    "ufw",
    "firewall-cmd",
    "systemctl",
];

const IPT_TOOLS: &[&str] = &[
    "iptables",
    "ip6tables",
    "iptables-save",
    "ip6tables-save",
    "iptables-restore",
    "ip6tables-restore",
];

const NFT_RULESET: &str = "table inet filter { # handle 1
\tchain input { # handle 1
\t\ttype filter hook input priority filter; policy drop;
\t\ttcp dport 22 accept comment \"ssh\" # handle 4
\t\tmeta nfproto ipv4 udp dport 53 accept # handle 5
\t\tip6 saddr 2001:db8::/32 drop # handle 6
\t}
}
";

const V4_SAVE: &str = "*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
COMMIT
";

const V6_SAVE: &str = "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
";

const UFW_NUMBERED: &str = "Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    10.0.0.0/8                 # web
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
";

const UFW_VERBOSE: &str = "Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
";

const MOCK: &str = r#"#!/bin/sh
D='@DIR@'
name=${0##*/}
key="$name${*:+ $*}"
echo "$key" >> "$D/calls.log"
if [ -f "$D/sleepon" ]; then
  case "$key" in $(cat "$D/sleepon")) sleep 30 ;; esac
fi
if [ -f "$D/failon" ]; then
  case "$key" in $(cat "$D/failon"))
    # failskip: let that many matching calls succeed first.
    n=$(grep -cxF -- "$key" "$D/calls.log")
    if [ "$n" -gt "$(cat "$D/failskip" 2>/dev/null || echo 0)" ]; then
      cat "$D/failmsg" >&2 2>/dev/null; exit 4
    fi ;;
  esac
fi
case "$key" in
  "nft list ruleset"|"nft -a list ruleset") cat "$D/nft.ruleset" 2>/dev/null ;;
  "iptables-save") cat "$D/v4.save" 2>/dev/null ;;
  "ip6tables-save") cat "$D/v6.save" 2>/dev/null ;;
  "ufw status verbose") cat "$D/ufw.verbose" 2>/dev/null ;;
  "ufw status numbered") cat "$D/ufw.numbered" 2>/dev/null ;;
  "ufw status") cat "$D/ufw.status" 2>/dev/null || echo "Status: inactive" ;;
  "ufw allow"*|"ufw deny"*|"ufw reject"*)
    if [ -f "$D/ufw.skip" ]; then echo "Skipping adding existing rule"; fi ;;
  "firewall-cmd --state")
    s=$(cat "$D/fwd.state" 2>/dev/null || echo running); echo "$s"
    [ "$s" = running ] || exit 252 ;;
  "firewall-cmd --get-default-zone") echo public ;;
  "firewall-cmd --zone=public --list-all") printf 'public (default, active)\n  target: default\n' ;;
  "firewall-cmd --list-all-zones") printf 'public (default, active)\n  target: default\n' ;;
  "firewall-cmd --zone public --list-services") echo ssh ;;
  "firewall-cmd --zone public --list-rich-rules") cat "$D/fwd.rich" 2>/dev/null ;;
esac
exit 0
"#;

struct Out {
    status: Status,
    json: Value,
    stdout: String,
    stderr: String,
}

impl Out {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert!(self.status.ok, "{} {}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], true, "{}", self.json);
        assert_eq!(self.stderr, "", "a success prints nothing on stderr");
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Value {
        assert!(!self.status.ok, "{}", self.stdout);
        assert_eq!(
            self.status.exit_code(),
            exit,
            "{} {}",
            self.stdout,
            self.stderr
        );
        assert_eq!(self.json["ok"], false, "{}", self.json);
        assert_eq!(self.json["error"]["code"], code, "{}", self.json);
        if code != "firewall.timeout" {
            assert!(
                self.stderr.starts_with(&format!("Error: [{code}] ")),
                "{}",
                self.stderr
            );
        }
        &self.json
    }
}

struct Mock {
    dir: TempDir,
}

impl Mock {
    /// Mock tools named `tools`; every other firewall tool is missing.
    fn new(tools: &[&str]) -> Self {
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let script = MOCK.replace("@DIR@", &dir.path().display().to_string());
        for tool in tools {
            crate::core::test_support::write_executable(&bin.join(tool), &script);
        }
        Mock { dir }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    fn put(&self, name: &str, content: &str) -> &Self {
        fs::write(self.path(name), content).unwrap();
        self
    }

    /// Calls of the mock tools, one `tool args...` line each.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Calls other than the read-only listings.
    fn changes(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| {
                !(c.starts_with("nft list")
                    || c.starts_with("nft -a list")
                    || c.contains("-save")
                    || c.starts_with("ufw status")
                    || c.starts_with("firewall-cmd --state")
                    || c.starts_with("firewall-cmd --get")
                    || c.contains("--list"))
            })
            .collect()
    }

    fn backups(&self) -> Vec<std::path::PathBuf> {
        match fs::read_dir(self.path("backups")) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn run(&self, verb: &str, pairs: &[(&str, &str)]) -> Out {
        let _seam = test_seam::install(self.path("bin"), self.path("backups"));
        let h = FirewallHandle::from_url(&Url::parse("firewall://").unwrap()).unwrap();
        let args: Args = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut stdin: &[u8] = &[];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let status = {
            let mut io = IoStreams {
                stdin: &mut stdin,
                stdout: &mut o,
                stderr: &mut e,
            };
            h.call(verb, &args, &mut io).unwrap()
        };
        let stdout = String::from_utf8(o).unwrap();
        Out {
            status,
            json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8(e).unwrap(),
        }
    }
}

fn nft_host() -> Mock {
    let m = Mock::new(&["nft"]);
    m.put("nft.ruleset", NFT_RULESET);
    m
}

fn ipt_host() -> Mock {
    let m = Mock::new(IPT_TOOLS);
    m.put("v4.save", V4_SAVE).put("v6.save", V6_SAVE);
    m
}

fn ufw_host() -> Mock {
    let m = Mock::new(&["ufw"]);
    m.put("ufw.status", "Status: active\n")
        .put("ufw.verbose", UFW_VERBOSE)
        .put("ufw.numbered", UFW_NUMBERED);
    m
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// One value of every `FirewallError` variant.
fn every_error() -> Vec<FirewallError> {
    let s = || "x".to_string();
    vec![
        FirewallError::InvalidArgument { message: s() },
        FirewallError::InvalidPort { port: s() },
        FirewallError::InvalidCidr { cidr: s() },
        FirewallError::InvalidProto { proto: s() },
        FirewallError::InvalidField {
            field: s(),
            value: s(),
        },
        FirewallError::ZoneRequired,
        FirewallError::InvalidRuleId { rule_id: s() },
        FirewallError::MissingDeleteCriteria,
        FirewallError::UnsupportedOption {
            option: s(),
            backend: s(),
            message: s(),
        },
        FirewallError::FamilyMismatch {
            family: s(),
            address: s(),
        },
        FirewallError::PathRequired { message: s() },
        FirewallError::NoBackendAvailable { reason: s() },
        FirewallError::BackendUnavailable { backend: s() },
        FirewallError::ToolNotFound { tool: s() },
        FirewallError::CommandFailed {
            command: s(),
            code: 1,
            stderr: s(),
        },
        FirewallError::CommandFailed {
            command: s(),
            code: 1,
            stderr: "Operation not permitted".into(),
        },
        FirewallError::Timeout { tool: s() },
        FirewallError::MaxRulesExceeded { count: 2, max: 1 },
        FirewallError::IdempotencyCheckFailed { message: s() },
        FirewallError::NoRulesMatched,
        FirewallError::ListFailedForDelete { message: s() },
        FirewallError::AmbiguousRuleId {
            rule_id: s(),
            count: 2,
        },
        FirewallError::RuleIdUnavailable { message: s() },
        FirewallError::PathExists { path: s() },
        FirewallError::MissingDirectory { path: s() },
        FirewallError::PathNotFound { path: s() },
        FirewallError::SaveFailed { message: s() },
        FirewallError::IoError { message: s() },
        FirewallError::InvalidSnapshot { message: s() },
        FirewallError::SnapshotNativeMissing {
            backend: s(),
            family: s(),
        },
        FirewallError::ChainNotFound { message: s() },
        FirewallError::AlreadyEnabled { backend: s() },
        FirewallError::AlreadyDisabled { backend: s() },
        FirewallError::InternalError { message: s() },
    ]
}

#[test]
fn every_code_is_valid_listed_and_documented() {
    let doc = include_str!("../../../docs/Security_Secrets/firewall.md");
    for (code, exit) in ERROR_CODES {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!([1, 2, 124].contains(exit), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
    let listed: Vec<&str> = ERROR_CODES.iter().map(|(c, _)| *c).collect();
    let mut emitted: Vec<&str> = every_error().iter().map(|e| e.to_error_code()).collect();
    emitted.push("firewall.unknown_verb");
    for code in &emitted {
        assert!(listed.contains(code), "{code} is emitted but not listed");
    }
    for code in &listed {
        assert!(emitted.contains(code), "{code} is listed but never emitted");
    }
    // Invalid input is exit 2, a timeout 124, anything else 1.
    for e in every_error() {
        let exit = match e {
            FirewallError::Timeout { .. } => 124,
            FirewallError::InvalidArgument { .. }
            | FirewallError::InvalidPort { .. }
            | FirewallError::InvalidCidr { .. }
            | FirewallError::InvalidProto { .. }
            | FirewallError::InvalidField { .. }
            | FirewallError::ZoneRequired
            | FirewallError::InvalidRuleId { .. }
            | FirewallError::MissingDeleteCriteria
            | FirewallError::UnsupportedOption { .. }
            | FirewallError::FamilyMismatch { .. }
            | FirewallError::PathRequired { .. } => 2,
            _ => 1,
        };
        assert_eq!(e.exit_code(), exit, "{e:?}");
        let j = e.to_json();
        assert_eq!(j["error"]["code"], e.to_error_code());
        assert_eq!(j["error"]["message"], e.to_string());
    }
    // An unexpected error is reported as an internal error.
    let internal = as_firewall_error(&anyhow::anyhow!("boom"));
    assert_eq!(internal.to_error_code(), "firewall.internal_error");
}

// ---------------------------------------------------------------------------
// Strict arguments
// ---------------------------------------------------------------------------

#[test]
fn invalid_arguments_exit_2_and_run_nothing() {
    let m = Mock::new(ALL_TOOLS);
    for (verb, pairs) in [
        ("status", vec![("backnd", "nftables")]),
        ("status", vec![("include_metrics", "sure")]),
        ("status", vec![("timeout_ms", "soon")]),
        ("status", vec![("dry_run", "true")]),
        ("rules.list", vec![("max_rules", "0")]),
        ("rules.list", vec![("backend", "all")]),
        ("rules.add", vec![("position", "before")]),
        ("rules.add", vec![("before_rule_id", "INPUT:1")]),
        ("rules.add", vec![("log_prefix", "x"), ("action", "accept")]),
        (
            "rules.delete",
            vec![("rule_id", "1"), ("match_mode", "subset")],
        ),
        ("rules.delete", vec![("limit", "-1")]),
        ("rules.save", vec![("compress", "zstd")]),
        (
            "rules.save",
            vec![("include_all_backends", "true"), ("backend", "ufw")],
        ),
        (
            "rules.reload",
            vec![("dry_run", "true"), ("validate_only", "true")],
        ),
        ("enable", vec![("fail_if_already_disabled", "true")]),
        ("disable", vec![("family", "inet")]),
        ("disable", vec![("source_format", "auto")]),
    ] {
        let out = m.run(verb, &pairs);
        out.fails(2, "firewall.invalid_argument");
        assert!(m.calls().is_empty(), "{verb} {pairs:?} ran {:?}", m.calls());
    }
    let out = m.run("status", &[("backnd", "nftables")]);
    assert!(
        out.stderr.contains("did you mean `backend`"),
        "{}",
        out.stderr
    );
    let out = m.run("rules.lst", &[]);
    out.fails(2, "firewall.unknown_verb");
    assert!(
        out.stderr.contains("did you mean `rules.list`"),
        "{}",
        out.stderr
    );
    // dry_run=false on a read-only verb is accepted.
    m.put("nft.ruleset", NFT_RULESET);
    m.run("status", &[("backend", "nftables"), ("dry_run", "false")])
        .ok();
}

#[test]
fn booleans_take_every_cli_spelling() {
    let m = nft_host();
    let out = m.run(
        "status",
        &[("include_metrics", "OFF"), ("include_rules_summary", "yes")],
    );
    let b = &out.ok()["backends"][0];
    assert!(b["details"].is_null(), "{b}");
    assert_eq!(b["rules_summary"]["total"], 3, "{b}");
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[test]
fn status_counts_inet_rules_per_family() {
    let m = nft_host();
    let out = m.run("status", &[]);
    let b = &out.ok()["backends"][0];
    assert_eq!(b["backend"], "nftables");
    assert_eq!(b["active"], true);
    assert_eq!(b["default_policy"], "DROP");
    // ssh (both), udp 53 (nfproto ipv4), ip6 saddr drop (ipv6).
    assert_eq!(b["rule_count_ipv4"], 2, "{b}");
    assert_eq!(b["rule_count_ipv6"], 2, "{b}");
    assert!(
        b["details"].as_str().unwrap().contains("inet filter"),
        "{b}"
    );
    assert!(b.get("rules_summary").is_none(), "{b}");

    let out = m.run(
        "status",
        &[("family", "ipv6"), ("include_rules_summary", "true")],
    );
    let b = &out.ok()["backends"][0];
    assert!(b["rule_count_ipv4"].is_null());
    assert_eq!(b["rule_count_ipv6"], 2);
    assert_eq!(b["rules_summary"]["by_action"]["drop"], 1, "{b}");
    assert_eq!(b["rules_summary"]["by_direction"]["input"], 2, "{b}");
}

#[test]
fn status_iptables_ufw_firewalld_and_all() {
    let m = ipt_host();
    let b = m.run("status", &[]).ok()["backends"][0].clone();
    assert_eq!(b["backend"], "iptables");
    assert_eq!(b["default_policy"], "IPv4: DROP, IPv6: ACCEPT");
    assert_eq!(
        (b["rule_count_ipv4"].clone(), b["rule_count_ipv6"].clone()),
        (json!(3), json!(1))
    );
    assert!(
        b["details"]
            .as_str()
            .unwrap()
            .starts_with("iptables active"),
        "{b}"
    );

    let m = ufw_host();
    let b = m.run("status", &[("format_output", "json")]).ok()["backends"][0].clone();
    assert_eq!(b["backend"], "ufw");
    assert_eq!(
        b["default_policy"],
        "deny (incoming), allow (outgoing), disabled (routed)"
    );
    assert_eq!(b["rule_count_ipv4"], 2);
    assert_eq!(b["rule_count_ipv6"], 1);

    let m = Mock::new(&["firewall-cmd", "nft"]);
    m.put("nft.ruleset", "");
    let b = m.run("status", &[]).ok()["backends"][0].clone();
    assert_eq!(b["backend"], "firewalld");
    assert_eq!(b["default_policy"], "default");
    assert_eq!(b["rule_count_ipv4"], 1, "the ssh service: {b}");
    m.put("fwd.state", "not running");
    let b = m.run("status", &[("backend", "firewalld")]).ok()["backends"][0].clone();
    assert_eq!(
        (b["available"].clone(), b["active"].clone()),
        (json!(true), json!(false))
    );

    let out = m.run("status", &[("backend", "all")]);
    let all = out.ok()["backends"].as_array().unwrap().clone();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0]["available"], false, "iptables is not installed");
    assert!(
        all[0]["warnings"][0]
            .as_str()
            .unwrap()
            .contains("not installed")
    );
    assert_eq!(all[1]["backend"], "nftables");

    let out = m.run("status", &[("format_output", "text")]);
    assert!(out.status.ok);
    assert!(out.stdout.starts_with("Firewall Status"), "{}", out.stdout);
}

#[test]
fn status_failures() {
    let m = Mock::new(&[]);
    let out = m.run("status", &[]);
    out.fails(1, "firewall.no_backend_available");
    let out = m.run("status", &[("backend", "nftables")]);
    assert_eq!(out.ok()["backends"][0]["available"], false);

    let m = nft_host();
    m.put("failon", "nft*")
        .put("failmsg", "Error: Operation not permitted\n");
    m.run("status", &[("backend", "nftables")])
        .fails(1, "firewall.permission_denied");
    let out = m.run("status", &[]);
    let e = out.fails(1, "firewall.no_backend_available");
    assert!(
        e["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Operation not permitted"),
        "{e}"
    );
    m.put("failmsg", "boom\n");
    m.run("status", &[("backend", "nftables")])
        .fails(1, "firewall.command_failed");
}

#[test]
fn a_tool_past_its_deadline_is_a_timeout() {
    let m = nft_host();
    m.put("sleepon", "nft*");
    let start = std::time::Instant::now();
    let out = m.run("status", &[("backend", "nftables"), ("timeout_ms", "300")]);
    out.fails(124, "firewall.timeout");
    assert!(start.elapsed() < Duration::from_secs(10));
    crate::core::process::take_lost();
}

// ---------------------------------------------------------------------------
// rules.list
// ---------------------------------------------------------------------------

#[test]
fn rules_list_filters_and_limits() {
    let m = ipt_host();
    let out = m.run("rules.list", &[("dport", "443")]);
    let j = out.ok();
    assert_eq!(j["summary"]["total_rules"], 4);
    assert_eq!(j["summary"]["filtered_rules"], 1);
    assert_eq!(j["rules"][0]["saddr"], "203.0.113.0/24");
    assert!(j["rules"][0]["raw"].is_null());

    let j = m
        .run(
            "rules.list",
            &[("family", "ipv6"), ("include_backend_raw", "1")],
        )
        .ok()
        .clone();
    assert_eq!(j["rules"].as_array().unwrap().len(), 1);
    assert!(
        j["rules"][0]["raw"]
            .as_str()
            .unwrap()
            .contains("--dport 22")
    );

    m.run("rules.list", &[("max_rules", "2")])
        .fails(1, "firewall.max_rules_exceeded");
    m.run("rules.list", &[("dport", "022")])
        .fails(2, "firewall.invalid_port");
    m.run("rules.list", &[("proto", "tcp;drop")])
        .fails(2, "firewall.rules_add_invalid_proto");
    m.run("rules.list", &[("backend", "ufw")])
        .fails(1, "firewall.backend_unavailable");

    // An nft inet rule restricted to IPv4 is not an IPv6 rule.
    let m = nft_host();
    let j = m.run("rules.list", &[("family", "ipv6")]).ok().clone();
    let ports: Vec<&Value> = j["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| &r["dport"])
        .collect();
    assert_eq!(ports, vec![&json!("22"), &Value::Null], "{j}");

    let out = m.run("rules.list", &[("format_output", "text")]);
    assert!(out.status.ok, "{}", out.stderr);
    assert!(!out.stdout.trim_start().starts_with('{'));
    assert!(m.changes().is_empty());
}

#[test]
fn rules_list_reports_a_failed_listing() {
    let m = ipt_host();
    m.put("failon", "iptables-save*").put(
        "failmsg",
        "iptables-save: Permission denied (you must be root)\n",
    );
    m.run("rules.list", &[])
        .fails(1, "firewall.permission_denied");
}

// ---------------------------------------------------------------------------
// rules.add
// ---------------------------------------------------------------------------

#[test]
fn rules_add_on_iptables() {
    let m = ipt_host();
    let out = m.run(
        "rules.add",
        &[("proto", "tcp"), ("dport", "8080"), ("dry_run", "true")],
    );
    let j = out.ok();
    assert_eq!(
        j["backend_commands"],
        json!(["iptables -t filter -A INPUT -p tcp --dport 8080 -j ACCEPT"])
    );
    assert!(m.changes().is_empty(), "{:?}", m.changes());

    let j = m
        .run(
            "rules.add",
            &[
                ("family", "any"),
                ("proto", "udp"),
                ("dport", "53"),
                ("position", "insert"),
                ("comment", "dns"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(
        m.changes(),
        vec![
            "iptables -t filter -I INPUT 1 -p udp --dport 53 -m comment --comment dns -j ACCEPT",
            "ip6tables -t filter -I INPUT 1 -p udp --dport 53 -m comment --comment dns -j ACCEPT",
        ]
    );

    // Already there (exactly): nothing runs.
    let j = m
        .run("rules.add", &[("proto", "tcp"), ("dport", "22")])
        .ok()
        .clone();
    assert_eq!(j["result"]["already_exists"], true);
    // A narrower existing rule (conntrack) does not count (R5-01).
    let j = m
        .run(
            "rules.add",
            &[("proto", "tcp"), ("dport", "80"), ("dry_run", "yes")],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["already_exists"], false);

    let j = m
        .run(
            "rules.add",
            &[
                ("proto", "tcp"),
                ("dport", "25"),
                ("action", "log"),
                ("log_prefix", "smtp:"),
                ("rate_limit", "5/m"),
                ("dry_run", "on"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(
        j["backend_commands"][0],
        "iptables -t filter -A INPUT -p tcp --dport 25 -m limit --limit 5/minute -j LOG \
         --log-prefix smtp:"
    );
}

#[test]
fn rules_add_refusals() {
    let m = ipt_host();
    for (pairs, exit, code) in [
        (vec![("dport", "22")], 2, "firewall.unsupported_option"),
        (
            vec![("proto", "tcp"), ("dport", "0x16")],
            2,
            "firewall.invalid_port",
        ),
        (
            vec![("proto", "6;flush")],
            2,
            "firewall.rules_add_invalid_proto",
        ),
        (
            vec![("saddr", "10.0.0.0/010")],
            2,
            "firewall.rules_add_invalid_cidr",
        ),
        (vec![("comment", "a\"b")], 2, "firewall.invalid_field"),
        (
            vec![("action", "log"), ("log_prefix", "a\"b")],
            2,
            "firewall.invalid_field",
        ),
        (vec![("action", "dnat")], 2, "firewall.unsupported_option"),
        (vec![("zone", "public")], 2, "firewall.unsupported_option"),
        (
            vec![("family", "ipv6"), ("saddr", "10.0.0.1")],
            2,
            "firewall.rules_add_family_mismatch",
        ),
    ] {
        m.run("rules.add", &pairs).fails(exit, code);
    }
    assert!(m.changes().is_empty(), "{:?}", m.changes());

    let m = Mock::new(&["firewall-cmd"]);
    m.run("rules.add", &[("proto", "tcp"), ("dport", "22")])
        .fails(2, "firewall.rules_add_zone_required");
    m.run("rules.add", &[("zone", "public"), ("in_iface", "eth0")])
        .fails(2, "firewall.unsupported_option");
    assert!(m.changes().is_empty(), "{:?}", m.changes());
}

#[test]
fn rules_add_reports_failures_and_partial_changes() {
    let m = ipt_host();
    m.put("failon", "ip6tables -t*")
        .put("failmsg", "ip6tables: Bad rule\n");
    let out = m.run(
        "rules.add",
        &[("family", "any"), ("proto", "tcp"), ("dport", "993")],
    );
    let j = out.fails(1, "firewall.command_failed");
    assert_eq!(
        j["backend_commands"],
        json!(["iptables -t filter -A INPUT -p tcp --dport 993 -j ACCEPT"])
    );
    assert!(j["warnings"][0].as_str().unwrap().contains("1 of 2"), "{j}");

    let m = ipt_host();
    m.put("failon", "iptables-save*").put("failmsg", "no\n");
    m.run("rules.add", &[("proto", "tcp"), ("dport", "993")])
        .fails(1, "firewall.rules_add_idempotency_check_failed");
    assert!(m.changes().is_empty());
}

#[test]
fn rules_add_on_nftables_uses_the_live_chain() {
    let m = nft_host();
    let j = m
        .run(
            "rules.add",
            &[("proto", "tcp"), ("dport", "443"), ("family", "any")],
        )
        .ok()
        .clone();
    assert_eq!(
        m.changes(),
        vec!["nft add rule inet filter input tcp dport 443 accept"],
        "{j}"
    );
    m.run("rules.add", &[("proto", "tcp"), ("dport", "443")])
        .ok();
    assert_eq!(
        m.changes()[1],
        "nft add rule inet filter input meta nfproto ipv4 tcp dport 443 accept"
    );
    // The listed `meta nfproto ipv4 udp dport 53` rule is the same rule.
    let j = m
        .run("rules.add", &[("proto", "udp"), ("dport", "53")])
        .ok()
        .clone();
    assert_eq!(j["result"]["already_exists"], true, "{j}");
    m.run(
        "rules.add",
        &[("proto", "tcp"), ("dport", "1"), ("direction", "forward")],
    )
    .fails(1, "firewall.chain_not_found");
    m.run(
        "rules.add",
        &[
            ("proto", "tcp"),
            ("dport", "1"),
            ("table", "filter"),
            ("chain", "nosuch"),
        ],
    )
    .fails(1, "firewall.chain_not_found");
}

#[test]
fn rules_add_on_ufw_and_firewalld() {
    let m = ufw_host();
    let j = m
        .run(
            "rules.add",
            &[("proto", "tcp"), ("dport", "22"), ("family", "any")],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["already_exists"], true);
    m.put("ufw.skip", "");
    let j = m
        .run("rules.add", &[("proto", "tcp"), ("dport", "25")])
        .ok()
        .clone();
    assert_eq!(j["result"]["already_exists"], true, "ufw skipped it: {j}");
    assert_eq!(
        m.changes(),
        vec!["ufw allow proto tcp from 0.0.0.0/0 to 0.0.0.0/0 port 25"]
    );

    let m = Mock::new(&["firewall-cmd"]);
    m.run(
        "rules.add",
        &[
            ("zone", "public"),
            ("proto", "tcp"),
            ("dport", "8443"),
            ("family", "any"),
        ],
    )
    .ok();
    assert_eq!(
        m.changes(),
        vec![
            "firewall-cmd --zone=public --add-rich-rule=rule port protocol=\"tcp\" port=\"8443\" accept"
        ]
    );
}

// ---------------------------------------------------------------------------
// rules.delete
// ---------------------------------------------------------------------------

#[test]
fn rules_delete_selects_and_deletes() {
    let m = ipt_host();
    let j = m.run(
        "rules.delete",
        &[("proto", "tcp"), ("dport", "80"), ("dry_run", "true")],
    );
    // exact: the conntrack rule has another match condition.
    j.fails(1, "firewall.rules_delete_no_match");
    let j = m
        .run(
            "rules.delete",
            &[
                ("proto", "tcp"),
                ("dport", "80"),
                ("match_mode", "subset"),
                ("dry_run", "true"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(j["matched_rules"][0]["rule_id"], "INPUT:3");
    assert!(m.changes().is_empty());

    let j = m
        .run(
            "rules.delete",
            &[("rule_id", "INPUT:2"), ("family", "ipv4")],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["deleted_count"], 1);
    assert_eq!(
        m.changes(),
        vec!["iptables -t filter -D INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 443 -j ACCEPT"]
    );

    let j = m
        .run(
            "rules.delete",
            &[
                ("dport", "22"),
                ("proto", "tcp"),
                ("limit", "1"),
                ("dry_run", "1"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(j["matched_rules"].as_array().unwrap().len(), 1);
    let j = m
        .run(
            "rules.delete",
            &[("dport", "9"), ("proto", "tcp"), ("require_match", "no")],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["deleted_count"], 0);
}

#[test]
fn rules_delete_refusals_and_failures() {
    let m = ipt_host();
    m.run("rules.delete", &[])
        .fails(2, "firewall.rules_delete_missing_criteria");
    m.run("rules.delete", &[("rule_id", "INPUT")])
        .fails(2, "firewall.rules_delete_invalid_rule_id");
    m.run("rules.delete", &[("rule_id", "INPUT:1")])
        .fails(1, "firewall.rules_delete_ambiguous_rule_id");
    m.run("rules.delete", &[("zone", "public")])
        .fails(2, "firewall.unsupported_option");
    m.run("rules.delete", &[("dport", "99999")])
        .fails(2, "firewall.invalid_port");
    assert!(m.changes().is_empty());

    m.put("failon", "iptables -t*")
        .put("failmsg", "iptables: Bad rule\n");
    let j = m.run(
        "rules.delete",
        &[("rule_id", "INPUT:2"), ("family", "ipv4")],
    );
    let j = j.fails(1, "firewall.command_failed");
    assert_eq!(j["result"]["deleted_count"], 0);

    m.put("failon", "ip*tables-save*");
    m.run("rules.delete", &[("dport", "22"), ("proto", "tcp")])
        .fails(1, "firewall.rules_delete_list_failed");
}

// ---------------------------------------------------------------------------
// rules.save
// ---------------------------------------------------------------------------

#[test]
fn rules_save_writes_an_owner_only_snapshot() {
    let m = ipt_host();
    let path = m.path("out/snap.json");
    let p = path.to_str().unwrap();
    let j = m
        .run("rules.save", &[("path", p), ("format", "both")])
        .ok()
        .clone();
    let entries = &j["summary"]["backends"];
    assert_eq!(entries[0]["family"], "ipv4", "{j}");
    assert_eq!(entries[1]["family"], "ipv6", "{j}");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(m.path("out")).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let snap: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(snap["backends"][1]["native"]["data"], V6_SAVE);
    assert_eq!(snap["backends"][0]["rules"].as_array().unwrap().len(), 3);

    m.run("rules.save", &[("path", p)])
        .fails(1, "firewall.rules_save_path_exists");
    // A planted symlink is replaced, never written through.
    let target = m.path("target");
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    m.run(
        "rules.save",
        &[("path", p), ("overwrite", "true"), ("compress", "gzip")],
    )
    .ok();
    assert!(!target.exists());
    assert!(
        !fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(&fs::read(&path).unwrap()[..2], &[0x1f, 0x8b]);

    let j = m.run("rules.save", &[("dry_run", "true")]).ok().clone();
    assert_eq!(j["summary"]["bytes_written"], 0);
}

#[test]
fn rules_save_refusals() {
    let m = ipt_host();
    m.run("rules.save", &[]).fails(2, "firewall.path_required");
    let missing = m.path("no/such/dir/x.json");
    m.run(
        "rules.save",
        &[
            ("path", missing.to_str().unwrap()),
            ("create_dirs", "false"),
        ],
    )
    .fails(1, "firewall.rules_save_missing_directory");
    m.put("afile", "");
    let under_file = m.path("afile/x.json");
    m.run("rules.save", &[("path", under_file.to_str().unwrap())])
        .fails(1, "firewall.io_error");
    assert!(m.calls().iter().all(|c| !c.contains("restore")));
}

// ---------------------------------------------------------------------------
// rules.reload
// ---------------------------------------------------------------------------

#[test]
fn rules_reload_backend_reload() {
    let m = ufw_host();
    let j = m.run("rules.reload", &[("dry_run", "true")]).ok().clone();
    assert_eq!(j["actions"], json!(["ufw reload"]));
    assert!(m.changes().is_empty());
    m.run("rules.reload", &[]).ok();
    assert_eq!(m.changes(), vec!["ufw reload"]);
    m.run("rules.reload", &[("validate_only", "true")])
        .fails(2, "firewall.unsupported_option");
    m.run("rules.reload", &[("path", "/x")])
        .fails(2, "firewall.unsupported_option");

    let m = Mock::new(&["firewall-cmd"]);
    m.run("rules.reload", &[("validate_only", "true")]).ok();
    m.run("rules.reload", &[]).ok();
    assert_eq!(
        m.changes(),
        vec!["firewall-cmd --check-config", "firewall-cmd --reload"]
    );
}

#[test]
fn rules_reload_from_files_and_snapshots() {
    let m = ipt_host();
    m.run("rules.reload", &[])
        .fails(2, "firewall.path_required");
    let native = m.path("rules.v4");
    fs::write(&native, V4_SAVE).unwrap();
    let n = native.to_str().unwrap();
    m.run("rules.reload", &[("path", n)])
        .fails(2, "firewall.invalid_argument");
    m.run(
        "rules.reload",
        &[("path", n), ("family", "ipv4"), ("validate_only", "true")],
    )
    .ok();
    let j = m
        .run("rules.reload", &[("path", n), ("family", "ipv4")])
        .ok()
        .clone();
    let backup = j["result"]["backup_path"].as_str().unwrap().to_string();
    assert_eq!(fs::read_to_string(&backup).unwrap(), V4_SAVE);
    assert_eq!(
        m.changes(),
        vec![
            format!("iptables-restore --test {n}"),
            format!("iptables-restore {n}")
        ]
    );
    m.run("rules.reload", &[("path", "/no/such"), ("family", "ipv4")])
        .fails(1, "firewall.path_not_found");
    m.run(
        "rules.reload",
        &[
            ("path", n),
            ("family", "ipv4"),
            ("source_format", "normalized_json"),
        ],
    )
    .fails(1, "firewall.invalid_snapshot");

    // A gzip snapshot with both families restores both; temporary files
    // are removed again.
    let snap = m.path("snap.json.gz");
    m.run(
        "rules.save",
        &[
            ("path", snap.to_str().unwrap()),
            ("format", "both"),
            ("compress", "gzip"),
        ],
    )
    .ok();
    let before = m.changes().len();
    let j = m
        .run("rules.reload", &[("path", snap.to_str().unwrap())])
        .ok()
        .clone();
    assert_eq!(j["source"]["source_format"], "normalized_json");
    let applied: Vec<String> = m.changes()[before..].to_vec();
    assert_eq!(applied.len(), 2, "{applied:?}");
    assert!(
        applied[0].starts_with("iptables-restore ") && applied[1].starts_with("ip6tables-restore ")
    );
    let left: Vec<_> = m
        .backups()
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("apply"))
        .collect();
    assert!(left.is_empty(), "{left:?}");

    // A snapshot without native data cannot be applied.
    let plain = m.path("plain.json");
    m.run("rules.save", &[("path", plain.to_str().unwrap())])
        .ok();
    m.run("rules.reload", &[("path", plain.to_str().unwrap())])
        .fails(1, "firewall.snapshot_native_missing");

    // A missing restore tool.
    fs::remove_file(m.path("bin/ip6tables-restore")).unwrap();
    m.run(
        "rules.reload",
        &[
            ("path", n),
            ("family", "ipv6"),
            ("backup_before_apply", "false"),
        ],
    )
    .fails(1, "firewall.tool_not_found");
}

#[test]
fn nft_snapshot_reload_replaces_the_ruleset() {
    let m = nft_host();
    let snap = m.path("snap.json");
    m.run(
        "rules.save",
        &[
            ("path", snap.to_str().unwrap()),
            ("format", "backend_native"),
        ],
    )
    .ok();
    m.run(
        "rules.reload",
        &[("path", snap.to_str().unwrap()), ("family", "ipv4")],
    )
    .fails(2, "firewall.unsupported_option");
    // The data is applied from a temporary file that starts with a flush.
    m.put("sleepon", "nft -f*");
    let out = m.run(
        "rules.reload",
        &[("path", snap.to_str().unwrap()), ("timeout_ms", "300")],
    );
    out.fails(124, "firewall.timeout");
    crate::core::process::take_lost();
    let applied = m
        .calls()
        .into_iter()
        .find(|c| c.starts_with("nft -f"))
        .unwrap();
    assert!(applied.contains("apply-nftables"), "{applied}");
    assert!(
        m.backups()
            .iter()
            .all(|p| !p.to_string_lossy().contains("apply"))
    );
}

// ---------------------------------------------------------------------------
// enable / disable
// ---------------------------------------------------------------------------

#[test]
fn enable_and_disable_ufw() {
    let m = ufw_host();
    let j = m.run("enable", &[]).ok().clone();
    assert_eq!(j["result"]["already_enabled"], true);
    m.run("enable", &[("fail_if_already_enabled", "true")])
        .fails(1, "firewall.already_enabled");
    let j = m.run("disable", &[("dry_run", "true")]).ok().clone();
    assert_eq!(j["previous_state"]["active"], true, "queried, not assumed");
    assert_eq!(j["actions"], json!(["ufw --force disable"]));
    assert!(m.changes().is_empty());
    m.run("disable", &[]).ok();
    assert_eq!(m.changes(), vec!["ufw --force disable"]);
    m.run("disable", &[("path", "/x")])
        .fails(2, "firewall.unsupported_option");
    m.run("disable", &[("validate_only", "true")])
        .fails(2, "firewall.unsupported_option");
    m.run("enable", &[("family", "ipv4")])
        .fails(2, "firewall.unsupported_option");

    m.put("ufw.status", "Status: inactive\n")
        .put("ufw.verbose", "Status: inactive\n");
    m.run("disable", &[("fail_if_already_disabled", "1")])
        .fails(1, "firewall.already_disabled");
    let j = m.run("enable", &[]).ok().clone();
    assert_eq!(j["result"]["changed"], true);
}

#[test]
fn enable_and_disable_firewalld_use_systemctl() {
    let m = Mock::new(&["firewall-cmd", "systemctl"]);
    m.put("fwd.state", "not running");
    m.run("enable", &[("backend", "firewalld")]).ok();
    m.put("fwd.state", "running");
    m.run("disable", &[]).ok();
    assert_eq!(
        m.changes(),
        vec![
            "systemctl enable firewalld",
            "systemctl start firewalld",
            "systemctl stop firewalld"
        ]
    );
}

#[test]
fn disable_iptables_flushes_both_families_after_a_backup() {
    let m = ipt_host();
    let j = m.run("disable", &[]).ok().clone();
    assert_eq!(m.backups().len(), 2, "{j}");
    let changes = m.changes();
    assert_eq!(changes.len(), 12, "{changes:?}");
    assert!(changes[0].starts_with("iptables -P INPUT ACCEPT"));
    assert!(changes[6].starts_with("ip6tables -P INPUT ACCEPT"));
    let j = m
        .run(
            "disable",
            &[
                ("family", "ipv6"),
                ("dry_run", "true"),
                ("backup_before_apply", "no"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(j["actions"].as_array().unwrap().len(), 6, "{j}");
}

#[test]
fn enable_iptables_needs_a_file_when_nothing_is_active() {
    let m = ipt_host();
    let empty =
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
    m.put("v4.save", empty).put("v6.save", empty);
    m.run("enable", &[]).fails(2, "firewall.path_required");
    m.run("enable", &[("validate_only", "true")])
        .fails(2, "firewall.path_required");
    let rules = m.path("rules.v6");
    fs::write(&rules, V6_SAVE).unwrap();
    let r = rules.to_str().unwrap();
    m.run(
        "enable",
        &[("path", r), ("family", "ipv6"), ("validate_only", "true")],
    )
    .ok();
    let j = m
        .run(
            "enable",
            &[
                ("path", r),
                ("family", "ipv6"),
                ("source_format", "backend_native"),
            ],
        )
        .ok()
        .clone();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(
        m.changes(),
        vec![
            format!("ip6tables-restore --test {r}"),
            format!("ip6tables-restore {r}")
        ]
    );

    // A failure after the backup still reports the backup.
    m.put("failon", "ip6tables-restore*")
        .put("failmsg", "line 3 failed\n");
    let j = m.run("enable", &[("path", r), ("family", "ipv6")]);
    let j = j.fails(1, "firewall.command_failed");
    assert!(j["result"]["backup_path"].is_string(), "{j}");

    // A backup that cannot be captured stops before any change (the
    // state is read twice first).
    m.put("v6.save", V6_SAVE);
    let seen = m.calls().iter().filter(|c| *c == "ip6tables-save").count();
    m.put("failon", "ip6tables-save*")
        .put("failskip", &(seen + 2).to_string());
    let before = m.changes().len();
    m.run("disable", &[("family", "ipv6")])
        .fails(1, "firewall.rules_save_failed");
    assert_eq!(m.changes().len(), before);
}

#[test]
fn backend_unavailable_and_none_available() {
    let m = Mock::new(&["ufw"]);
    m.run("enable", &[("backend", "nftables")])
        .fails(1, "firewall.backend_unavailable");
    let m = Mock::new(&[]);
    for verb in ["rules.list", "rules.reload", "enable", "disable"] {
        m.run(verb, &[]).fails(1, "firewall.no_backend_available");
    }
}
