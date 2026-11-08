//! Integration tests for `firewall://` through the built `resh` binary: help
//! output (golden files) in every form and its accuracy, strict arguments
//! (exit 2, nothing run), the help examples, every verb on mock backends,
//! the error format and exit codes, and timeouts. Debug builds take every
//! firewall tool from the directory in `RESH_TEST_FIREWALL_BIN` (never from
//! PATH then) and write backups to `RESH_TEST_FIREWALL_BACKUP_DIR`, so no
//! test reaches the host firewall. Real backends run in
//! firewall_e2e_docker.rs.

mod common;

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const VERBS: &[&str] = &[
    "status",
    "rules.list",
    "rules.add",
    "rules.delete",
    "rules.save",
    "rules.reload",
    "enable",
    "disable",
];

/// The options each verb accepts (src/handles/security/firewall_args.rs).
fn accepted(verb: &str) -> Vec<&'static str> {
    let filters = [
        "table",
        "chain",
        "direction",
        "action",
        "proto",
        "sport",
        "dport",
        "saddr",
        "daddr",
        "in_iface",
        "out_iface",
    ];
    let mut v: Vec<&'static str> = match verb {
        "status" => vec![
            "backend",
            "family",
            "include_metrics",
            "include_rules_summary",
        ],
        "rules.list" => [
            &[
                "backend",
                "family",
                "comment_contains",
                "include_backend_raw",
            ][..],
            &["include_counters", "max_rules"],
            &filters,
        ]
        .concat(),
        "rules.add" => [
            &[
                "backend",
                "family",
                "zone",
                "log_prefix",
                "rate_limit",
                "comment",
            ][..],
            &["position", "dry_run", "idempotent"],
            &filters,
        ]
        .concat(),
        "rules.delete" => [
            &["backend", "family", "rule_id", "match_mode", "zone"][..],
            &["comment_contains", "limit", "dry_run", "require_match"],
            &filters,
        ]
        .concat(),
        "rules.save" => vec![
            "path",
            "backend",
            "family",
            "include_all_backends",
            "format",
            "compress",
            "include_metadata",
            "dry_run",
            "overwrite",
            "create_dirs",
        ],
        "rules.reload" => vec![
            "path",
            "backend",
            "family",
            "source_format",
            "dry_run",
            "validate_only",
            "backup_before_apply",
        ],
        "enable" | "disable" => vec![
            "path",
            "backend",
            "family",
            "source_format",
            "dry_run",
            "validate_only",
            "backup_before_apply",
            if verb == "enable" {
                "fail_if_already_enabled"
            } else {
                "fail_if_already_disabled"
            },
        ],
        other => panic!("no verb {other}"),
    };
    v.extend(["timeout_ms", "format_output"]);
    v.sort_unstable();
    v
}

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/firewall_help.txt"),
        Some("status") => include_str!("golden/firewall_status_help.txt"),
        Some("rules.list") => include_str!("golden/firewall_rules.list_help.txt"),
        Some("rules.add") => include_str!("golden/firewall_rules.add_help.txt"),
        Some("rules.delete") => include_str!("golden/firewall_rules.delete_help.txt"),
        Some("rules.save") => include_str!("golden/firewall_rules.save_help.txt"),
        Some("rules.reload") => include_str!("golden/firewall_rules.reload_help.txt"),
        Some("enable") => include_str!("golden/firewall_enable_help.txt"),
        Some("disable") => include_str!("golden/firewall_disable_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

const NFT_RULESET: &str = "table inet filter { # handle 1
\tchain input { # handle 1
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept # handle 2
\t\tiif \"lo\" accept # handle 3
\t\ttcp dport 22 accept # handle 4
\t\tmeta nfproto ipv4 udp dport 53 accept # handle 5
\t}
}
";

const V4_SAVE: &str = "*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
";

const V6_SAVE: &str = "*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
";

/// One mock for every tool: logs its call, prints the canned listing from
/// a file in `$D`, and fails (`$D/failon`) or hangs (`$D/sleepon`) for
/// calls matching the shell pattern in those files.
const MOCK: &str = r#"#!/bin/sh
name=${0##*/}
key="$name${*:+ $*}"
echo "$key" >> "$D/calls.log"
if [ -f "$D/sleepon" ]; then
  case "$key" in $(cat "$D/sleepon")) sleep 30 ;; esac
fi
if [ -f "$D/failon" ]; then
  case "$key" in $(cat "$D/failon")) cat "$D/failmsg" >&2; exit 4 ;; esac
fi
case "$key" in
  "nft list ruleset"|"nft -a list ruleset") cat "$D/nft.ruleset" 2>/dev/null ;;
  "iptables-save") cat "$D/v4.save" 2>/dev/null ;;
  "ip6tables-save") cat "$D/v6.save" 2>/dev/null ;;
  "ufw status"|"ufw status verbose") cat "$D/ufw.status" 2>/dev/null ;;
  "ufw status numbered") cat "$D/ufw.status" 2>/dev/null ;;
  "firewall-cmd --state") echo running ;;
esac
exit 0
"#;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.out)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{}", self.out, self.err))
    }

    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{}\n{}", self.out, self.err);
        assert_eq!(self.err, "", "a success prints nothing on stderr");
        self
    }

    #[track_caller]
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(self.code, exit, "{}\n{}", self.out, self.err);
        let j = self.json();
        assert_eq!(j["ok"], false, "{j}");
        assert_eq!(j["error"]["code"], code, "{j}");
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        assert_eq!(self.err.lines().count(), 1, "one error line: {}", self.err);
        self
    }
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    /// Mock tools named `tools`; every other firewall tool is missing.
    fn new(tools: &[&str]) -> Self {
        let env = Env {
            dir: tempfile::TempDir::new().unwrap(),
        };
        std::fs::create_dir(env.dir().join("bin")).unwrap();
        for tool in tools {
            common::write_executable(&env.dir().join("bin").join(tool), MOCK);
        }
        env
    }

    fn nft() -> Self {
        let env = Env::new(&["nft"]);
        env.put("nft.ruleset", NFT_RULESET);
        env
    }

    fn iptables() -> Self {
        let env = Env::new(&[
            "iptables",
            "ip6tables",
            "iptables-save",
            "ip6tables-save",
            "iptables-restore",
            "ip6tables-restore",
        ]);
        env.put("v4.save", V4_SAVE).put("v6.save", V6_SAVE);
        env
    }

    fn ufw(active: bool) -> Self {
        let env = Env::new(&["ufw"]);
        env.put(
            "ufw.status",
            if active {
                "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
            } else {
                "Status: inactive\n"
            },
        );
        env
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn put(&self, name: &str, content: &str) -> &Self {
        std::fs::write(self.dir().join(name), content).unwrap();
        self
    }

    fn run(&self, args: &[&str]) -> Run {
        let out = Command::new(env!("CARGO_BIN_EXE_resh"))
            .args(args)
            .env("RESH_TEST_FIREWALL_BIN", self.dir().join("bin"))
            .env("RESH_TEST_FIREWALL_BACKUP_DIR", self.dir().join("backups"))
            .env("D", self.dir())
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Calls other than read-only listings.
    fn changes(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| {
                !(c.contains("list")
                    || c.contains("-save")
                    || c.starts_with("ufw status")
                    || c == "firewall-cmd --state")
            })
            .collect()
    }

    fn backups(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(self.dir().join("backups")) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

// --- help ---------------------------------------------------------------------------

#[test]
fn handle_help_matches_golden_in_every_form() {
    let env = Env::new(&[]);
    for form in [
        vec!["firewall", "--help"],
        vec!["firewall", "-h"],
        vec!["firewall", "help"],
        vec!["help", "firewall"],
        vec!["firewall://--help"],
        vec!["firewall://-h"],
        vec!["firewall://.help"],
    ] {
        let r = env.run(&form).ok();
        assert_eq!(r.out, golden(None), "{form:?}");
    }
    let out = golden(None);
    assert_plain_text(out);
    let listed: Vec<&str> = out
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, VERBS);
    assert!(env.calls().is_empty());
}

#[test]
fn verb_help_matches_golden_and_lists_exactly_the_accepted_options() {
    let env = Env::new(&[]);
    for verb in VERBS {
        let in_url = format!("firewall://--help={verb}");
        let stage = format!("firewall://.{verb}");
        for form in [
            vec!["firewall", verb, "--help"],
            vec!["firewall", verb, "-h"],
            vec!["help", "firewall", verb],
            vec![in_url.as_str()],
            vec![stage.as_str(), "--help"],
        ] {
            let r = env.run(&form).ok();
            assert_eq!(r.out, golden(Some(verb)), "{form:?}");
        }
        let out = golden(Some(verb));
        assert_plain_text(out);
        for section in ["Usage:\n", "Example:\n", "Example Output:\n"] {
            assert!(out.contains(section), "{verb} {section}");
        }
        let usage = out
            .split("Usage:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        let mut listed: Vec<&str> = usage
            .split(['[', ' ', '\n'])
            .filter_map(|w| w.split_once('='))
            .map(|(k, _)| k)
            .collect();
        listed.sort_unstable();
        listed.dedup();
        assert_eq!(listed, accepted(verb), "{verb}: {usage}");
        // The defaults the help states are the ones in force.
        if ["rules.reload", "enable", "disable"].contains(verb) {
            assert!(out.contains("\"timeout_ms\": 10000"), "{verb}");
        } else {
            assert!(out.contains("\"timeout_ms\": 5000"), "{verb}");
        }
    }
    assert!(env.calls().is_empty());
}

/// The example of each verb's help runs and gives output of the documented
/// shape. rules.save writes into a temporary directory instead of
/// /var/backups (the example itself runs as root in firewall_e2e_docker.rs).
#[test]
fn help_examples_run() {
    for verb in VERBS {
        let text = golden(Some(verb));
        let example = text
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim();
        let env = match *verb {
            "status" => Env::nft(),
            v if v.starts_with("rules.") && v != "rules.reload" => Env::iptables(),
            "enable" | "rules.reload" => Env::ufw(false),
            _ => Env::ufw(true),
        };
        let save_path = env.dir().join("out/firewall.json");
        let words: Vec<String> = example
            .split_whitespace()
            .skip(1)
            .map(|w| match w.strip_prefix("path=") {
                Some(_) => format!("path={}", save_path.display()),
                None => w.to_string(),
            })
            .collect();
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let r = env.run(&words).ok();
        let got = r.json();
        let shown: Value = serde_json::from_str(
            text.split("Example Output:\n")
                .nth(1)
                .unwrap()
                .split("\n\n")
                .next()
                .unwrap(),
        )
        .unwrap();
        let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
        assert_eq!(keys(&got), keys(&shown), "{verb}");
        assert_eq!(keys(&got["query"]), keys(&shown["query"]), "{verb}");
        if *verb == "rules.save" {
            assert!(save_path.exists());
        }
    }
}

// --- strict arguments and errors -----------------------------------------------------

#[test]
fn invalid_arguments_exit_2_and_run_nothing() {
    let env = Env::new(&["nft", "ufw", "iptables", "iptables-save", "ip6tables-save"]);
    for args in [
        &["firewall://.status", "backnd=nftables"][..],
        &["firewall://.status", "timeout_ms=soon"],
        &["firewall://.status", "include_metrics=maybe"],
        &["firewall://.rules.list", "backend=all"],
        &["firewall://.rules.add", "position=after"],
        &[
            "firewall://.rules.delete",
            "rule_id=INPUT:1",
            "match_mode=subset",
        ],
        &["firewall://.rules.save", "format=yaml"],
        &["firewall://.rules.reload", "dry_run=1", "validate_only=1"],
        &["firewall://.enable", "fail_if_already_disabled=true"],
        &["firewall://.disable", "source_format=auto"],
    ] {
        let r = env.run(args).fails(2, "firewall.invalid_argument");
        if args[1] == "backnd=nftables" {
            assert!(r.err.contains("did you mean `backend`"), "{}", r.err);
        }
    }
    // The dispatcher refuses a dry run of a verb that has none.
    let r = env.run(&["firewall://.status", "dry_run=true"]);
    assert_eq!(r.code, 2, "{} {}", r.out, r.err);
    assert!(
        r.err.starts_with("Error: [firewall.invalid_argument] "),
        "{}",
        r.err
    );
    let r = env.run(&["firewall://.rules.lst"]);
    assert_eq!(r.code, 2, "{} {}", r.out, r.err);
    assert!(r.err.contains("rules.list"), "{}", r.err);
    assert!(env.calls().is_empty(), "{:?}", env.calls());

    // Rule fields are refused before anything runs, also in a dry run.
    for (arg, code) in [
        ("dport=022", "firewall.invalid_port"),
        ("saddr=10.0.0.0/010", "firewall.rules_add_invalid_cidr"),
        ("proto=tcp;", "firewall.rules_add_invalid_proto"),
        ("comment=a\"b", "firewall.invalid_field"),
    ] {
        env.run(&["firewall://.rules.add", "proto=tcp", arg, "dry_run=true"])
            .fails(2, code);
    }
    assert!(env.calls().is_empty(), "{:?}", env.calls());
}

#[test]
fn no_backend_and_missing_tools() {
    let env = Env::new(&[]);
    env.run(&["firewall://.status"])
        .fails(1, "firewall.no_backend_available");
    env.run(&["firewall://.rules.list", "backend=iptables"])
        .fails(1, "firewall.backend_unavailable");
    let r = env.run(&["firewall://.status", "backend=all"]).ok();
    assert_eq!(r.json()["backends"].as_array().unwrap().len(), 4);
}

#[test]
fn permission_errors_and_timeouts() {
    let env = Env::nft();
    env.put("failon", "nft*")
        .put("failmsg", "Error: Operation not permitted\n");
    env.run(&["firewall://.rules.list", "backend=nftables"])
        .fails(1, "firewall.permission_denied");

    let env = Env::nft();
    env.put("sleepon", "nft*");
    let start = Instant::now();
    let r = env.run(&["firewall://.status", "backend=nftables", "timeout_ms=300"]);
    assert_eq!(r.code, 124, "{} {}", r.out, r.err);
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(r.json()["error"]["code"], "firewall.timeout");
    assert!(
        r.err
            .starts_with("Error: [firewall.timeout] outcome unknown: "),
        "{}",
        r.err
    );
}

// --- every verb on mock backends -----------------------------------------------------

#[test]
fn status_and_list() {
    let env = Env::nft();
    let j = env
        .run(&["firewall://.status", "include_rules_summary=true"])
        .ok()
        .json();
    let b = &j["backends"][0];
    assert_eq!(b["default_policy"], "DROP");
    assert_eq!(
        (b["rule_count_ipv4"].clone(), b["rule_count_ipv6"].clone()),
        (json!(4), json!(3))
    );
    assert_eq!(b["rules_summary"]["total"], 4);
    let j = env
        .run(&[
            "firewall://.rules.list",
            "dport=22",
            "include_backend_raw=yes",
        ])
        .ok()
        .json();
    assert_eq!(j["rules"][0]["raw"], "tcp dport 22 accept # handle 4");
    let r = env
        .run(&["firewall://.rules.list", "format_output=text"])
        .ok();
    assert!(r.out.contains("nftables"), "{}", r.out);
    assert!(env.changes().is_empty());
}

#[test]
fn add_and_delete_on_iptables() {
    let env = Env::iptables();
    let j = env
        .run(&[
            "firewall://.rules.add",
            "family=any",
            "proto=tcp",
            "dport=8080",
        ])
        .ok()
        .json();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(
        env.changes(),
        vec![
            "iptables -t filter -A INPUT -p tcp --dport 8080 -j ACCEPT",
            "ip6tables -t filter -A INPUT -p tcp --dport 8080 -j ACCEPT"
        ]
    );
    let j = env
        .run(&["firewall://.rules.add", "proto=tcp", "dport=443"])
        .ok()
        .json();
    assert_eq!(j["result"]["already_exists"], true);

    let j = env
        .run(&[
            "firewall://.rules.delete",
            "rule_id=INPUT:3",
            "dry_run=true",
        ])
        .ok()
        .json();
    assert_eq!(j["matched_rules"][0]["saddr"], "203.0.113.0/24");
    assert_eq!(env.changes().len(), 2);
    env.run(&["firewall://.rules.delete", "rule_id=INPUT:3"])
        .ok();
    assert_eq!(
        env.changes()[2],
        "iptables -t filter -D INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 22 -j ACCEPT"
    );
    env.run(&["firewall://.rules.delete", "dport=9", "proto=tcp"])
        .fails(1, "firewall.rules_delete_no_match");
    env.run(&["firewall://.rules.delete"])
        .fails(2, "firewall.rules_delete_missing_criteria");
}

#[test]
fn save_and_reload_round_trip() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::iptables();
    let snap = env.dir().join("snap.json");
    let s = format!("path={}", snap.display());
    env.run(&["firewall://.rules.save", &s, "format=both"]).ok();
    assert_eq!(
        std::fs::metadata(&snap).unwrap().permissions().mode() & 0o777,
        0o600
    );
    env.run(&["firewall://.rules.save", &s])
        .fails(1, "firewall.rules_save_path_exists");
    let j = env
        .run(&["firewall://.rules.reload", &s, "validate_only=true"])
        .ok()
        .json();
    assert_eq!(j["source"]["source_format"], "normalized_json");
    assert!(env.backups().is_empty());
    let j = env.run(&["firewall://.rules.reload", &s]).ok().json();
    assert_eq!(j["result"]["changed"], true);
    assert_eq!(env.backups().len(), 2 + 0, "one backup per family: {j}");
    let restores: Vec<String> = env
        .changes()
        .into_iter()
        .filter(|c| c.contains("restore") && !c.contains("--test"))
        .collect();
    assert_eq!(restores.len(), 2, "{restores:?}");
    env.run(&["firewall://.rules.reload"])
        .fails(2, "firewall.path_required");
    env.run(&[
        "firewall://.rules.reload",
        "path=/no/such/file",
        "family=ipv4",
    ])
    .fails(1, "firewall.path_not_found");
}

#[test]
fn enable_and_disable() {
    let env = Env::ufw(false);
    let j = env.run(&["firewall://.enable", "dry_run=true"]).ok().json();
    assert_eq!(j["previous_state"]["active"], false);
    assert!(env.changes().is_empty());
    env.run(&["firewall://.enable"]).ok();
    assert_eq!(env.changes(), vec!["ufw --force enable"]);
    env.run(&["firewall://.disable", "fail_if_already_disabled=true"])
        .fails(1, "firewall.already_disabled");
    env.run(&["firewall://.disable", "path=/etc/x"])
        .fails(2, "firewall.unsupported_option");

    let env = Env::iptables();
    let j = env.run(&["firewall://.disable", "family=ipv4"]).ok().json();
    assert!(j["result"]["backup_path"].as_str().is_some(), "{j}");
    assert_eq!(env.changes().len(), 6, "{:?}", env.changes());
    env.put("failon", "iptables -F*")
        .put("failmsg", "iptables: busy\n");
    let r = env.run(&["firewall://.disable", "family=ipv4"]);
    let j = r.fails(1, "firewall.command_failed").json();
    assert!(j["result"]["backup_path"].is_string(), "{j}");
    assert!(
        j["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "iptables -F")
    );
}
