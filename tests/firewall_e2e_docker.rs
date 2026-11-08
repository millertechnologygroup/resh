//! End-to-end tests for `firewall://` against real backends inside
//! throwaway containers. Each container has its own network namespace
//! (`--network=none`), so every rule change stays inside it; the host
//! firewall is never touched. The host-built `resh` binary is mounted
//! read-only, and each result is checked with the backend's own listing
//! (`nft list ruleset`, `iptables-save`, `ufw status`, `firewall-cmd`).
//!
//! Images (built on first use):
//! - `resh-fw-nft:1`: Debian 13 with nftables;
//! - `resh-fw-ipt:1`: Debian 13 with iptables (nf_tables, and legacy where
//!   the host kernel provides the legacy tables);
//! - `resh-fw-ufw:1`: Debian 13 with ufw;
//! - `resh-fw-firewalld:1`: Debian 13 with firewalld, its daemon started
//!   directly on D-Bus;
//! - `resh-fw-firewalld-systemd:1`: the same under systemd as PID 1
//!   (privileged container) for `enable`/`disable` through systemctl.
//!
//! Run with `cargo test --features e2e-docker --test firewall_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const NFT: &str = "resh-fw-nft:1";
const IPT: &str = "resh-fw-ipt:1";
const UFW: &str = "resh-fw-ufw:1";
const FWD: &str = "resh-fw-firewalld:1";
const FWD_SD: &str = "resh-fw-firewalld-systemd:1";

fn build(image: &str, packages: &str) {
    let have = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if have.success() {
        return;
    }
    let dockerfile = format!(
        "FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
         apt-get install -y --no-install-recommends {packages} && rm -rf /var/lib/apt/lists/*\n"
    );
    let mut child = Command::new("docker")
        .args(["build", "-q", "-t", image, "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(dockerfile.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "cannot build {image}");
}

fn ensure_images() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        build(NFT, "nftables");
        build(IPT, "iptables");
        build(UFW, "ufw");
        build(FWD, "firewalld dbus");
        build(FWD_SD, "systemd systemd-sysv dbus firewalld");
    });
}

/// `r <tag> <command...>` prints `<tag>\t<exit>\t<stdout on one line>\t<stderr>`;
/// `check <name> <command...>` prints the command's output as base64.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(printf '%s' "$out" | tr '\n' ' ')" "$(tr '\n' ' ' < /tmp/err)"
}
check() {
  name=$1; shift
  printf 'check\t%s\t%s\n' "$name" "$("$@" 2>&1 | base64 -w0)"
}
"#;

struct Res {
    code: i32,
    json: Value,
    err: String,
}

struct Ctr {
    results: HashMap<String, Res>,
    checks: HashMap<String, String>,
    raw: String,
}

impl Ctr {
    fn parse(raw: String) -> Self {
        let mut results = HashMap::new();
        let mut checks = HashMap::new();
        for line in raw.lines() {
            let f: Vec<&str> = line.splitn(4, '\t').collect();
            if f[0] == "check" && f.len() >= 3 {
                let bytes = base64_decode(f[2]);
                checks.insert(
                    f[1].to_string(),
                    String::from_utf8_lossy(&bytes).into_owned(),
                );
            } else if f.len() == 4 {
                results.insert(
                    f[0].to_string(),
                    Res {
                        code: f[1].parse().unwrap_or(-1),
                        json: serde_json::from_str(f[2]).unwrap_or(Value::Null),
                        err: f[3].to_string(),
                    },
                );
            }
        }
        Ctr {
            results,
            checks,
            raw,
        }
    }

    fn get(&self, tag: &str) -> &Res {
        self.results
            .get(tag)
            .unwrap_or_else(|| panic!("no result {tag}:\n{}", self.raw))
    }

    #[track_caller]
    fn ok(&self, tag: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, 0, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["ok"], true, "{tag}: {}", r.json);
        &r.json
    }

    #[track_caller]
    fn fails(&self, tag: &str, exit: i32, code: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, exit, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["error"]["code"], code, "{tag}: {}", r.json);
        assert!(
            r.err.starts_with(&format!("Error: [{code}] ")),
            "{tag}: {}",
            r.err
        );
        &r.json
    }

    #[track_caller]
    fn check(&self, name: &str) -> &str {
        self.checks
            .get(name)
            .unwrap_or_else(|| panic!("no check {name}:\n{}", self.raw))
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let Some(v) = T.iter().position(|t| *t == c) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

fn mount() -> String {
    format!("{}:/usr/local/bin/resh:ro", env!("CARGO_BIN_EXE_resh"))
}

/// Runs `script` (after PRELUDE) in a fresh container of `image`, with its
/// own network namespace and only the capability to manage it.
fn container(image: &str, script: &str) -> Ctr {
    ensure_images();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "--cap-add=NET_ADMIN",
            "-v",
            &mount(),
            image,
            "sh",
            "-c",
        ])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container failed: {raw}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ctr::parse(raw)
}

// ===========================================================================
// nftables
// ===========================================================================

#[test]
fn nftables_rules_lifecycle() {
    let c = container(
        NFT,
        r#"
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input tcp dport 22 accept comment '"ssh"'
r example resh --json-pretty firewall://.status backend=nftables include_metrics=false
r status resh firewall://.status include_rules_summary=true
r add resh firewall://.rules.add proto=tcp dport=443 comment=web
r add2 resh firewall://.rules.add proto=tcp dport=443 comment=web
r addany resh firewall://.rules.add proto=udp dport=53 family=any
r addlog resh firewall://.rules.add proto=tcp dport=8080 action=log log_prefix=p8080 rate_limit=10/m
r addsrc resh firewall://.rules.add saddr=2001:db8::/32 action=drop
r nochain resh firewall://.rules.add proto=tcp dport=1 direction=forward
check after_add nft list ruleset
r list resh firewall://.rules.list family=ipv6
r deldry resh firewall://.rules.delete proto=tcp dport=443 dry_run=true
r del resh firewall://.rules.delete proto=tcp dport=443
check after_del nft list ruleset
r save resh firewall://.rules.save path=/root/snap.json format=both
r disable resh firewall://.disable
check after_disable nft list ruleset
r reload resh firewall://.rules.reload path=/root/snap.json
r reload2 resh firewall://.rules.reload path=/root/snap.json
check after_reload nft list ruleset
r validate resh firewall://.rules.reload path=/root/snap.json validate_only=true
printf 'table inet filter {\n chain input {\n bogus\n }\n}\n' > /root/bad.nft
r invalid resh firewall://.rules.reload path=/root/bad.nft validate_only=true
r enable_active resh firewall://.enable
check backup_head sh -c 'for f in /var/backups/firewall/.resh-backup-nftables-*.rules; do head -1 "$f"; break; done'
check backup_mode sh -c 'stat -c %a /var/backups/firewall /var/backups/firewall/.resh-backup-nftables-*.rules | sort -u'
"#,
    );
    let b = &c.ok("example")["backends"][0];
    assert_eq!(b["default_policy"], "DROP");
    assert!(b["details"].is_null());
    let b = &c.ok("status")["backends"][0];
    assert_eq!(b["rule_count_ipv4"], 2, "{b}");
    assert_eq!(b["rules_summary"]["total"], 2, "{b}");

    assert_eq!(
        c.ok("add")["backend_commands"][0],
        "nft add rule inet filter input meta nfproto ipv4 tcp dport 443 accept comment '\"web\"'"
    );
    assert_eq!(c.ok("add2")["result"]["already_exists"], true);
    c.ok("addany");
    c.ok("addlog");
    c.ok("addsrc");
    c.fails("nochain", 1, "firewall.chain_not_found");
    let rules = c.check("after_add");
    for want in [
        "meta nfproto ipv4 tcp dport 443 accept comment \"web\"",
        "udp dport 53 accept",
        "tcp dport 8080 limit rate 10/minute burst 5 packets log prefix \"p8080\"",
        "ip6 saddr 2001:db8::/32 drop",
    ] {
        assert!(rules.contains(want), "{want}:\n{rules}");
    }
    assert_eq!(rules.matches("tcp dport 443").count(), 1, "{rules}");

    let ports: Vec<Value> = c.ok("list")["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["dport"].clone())
        .collect();
    assert!(
        !ports.contains(&Value::from("443")),
        "IPv4-only rule listed: {ports:?}"
    );
    assert!(ports.contains(&Value::from("53")));

    assert_eq!(c.ok("deldry")["result"]["deleted_count"], 0);
    assert_eq!(c.ok("del")["result"]["deleted_count"], 1);
    assert!(!c.check("after_del").contains("dport 443"));

    c.ok("save");
    assert!(c.ok("disable")["result"]["backup_path"].is_string());
    assert_eq!(c.check("after_disable").trim(), "");
    c.ok("reload");
    c.ok("reload2");
    let after = c.check("after_reload");
    assert_eq!(
        after.matches("tcp dport 22 accept").count(),
        1,
        "replaced, not appended:\n{after}"
    );
    assert!(after.contains("policy drop"));
    c.ok("validate");
    c.fails("invalid", 1, "firewall.command_failed");
    assert_eq!(c.ok("enable_active")["result"]["already_enabled"], true);
    assert_eq!(c.check("backup_head").trim(), "flush ruleset");
    assert_eq!(
        c.check("backup_mode")
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["600", "700"]
    );
}

// ===========================================================================
// iptables
// ===========================================================================

const IPT_FLOW: &str = r#"
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -s 203.0.113.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
mkdir -p /var/backups
r ex_list resh --json-pretty firewall://.rules.list family=ipv4 dport=22
r ex_add resh --json-pretty firewall://.rules.add proto=tcp dport=22 dry_run=true
r ex_delete resh --json-pretty firewall://.rules.delete rule_id=INPUT:3 dry_run=true
r ex_save resh --json-pretty firewall://.rules.save path=/var/backups/firewall.json
r add resh firewall://.rules.add proto=tcp dport=443 family=any comment=web
r add2 resh firewall://.rules.add proto=tcp dport=443 family=any comment=web
r add80 resh firewall://.rules.add proto=tcp dport=80
r addlog resh firewall://.rules.add proto=tcp dport=25 action=log log_prefix=smtp rate_limit=5/s
check v4 iptables-save
check v6 ip6tables-save
r subset resh firewall://.rules.delete proto=tcp dport=80 match_mode=subset
check v4_del iptables-save
r status resh firewall://.status family=ipv4
r save resh firewall://.rules.save path=/root/snap.json format=both
r disable resh firewall://.disable
check v4_off iptables-save
check v6_off ip6tables-save
r enable resh firewall://.enable path=/root/snap.json
check v4_on iptables-save
check v6_on ip6tables-save
r again resh firewall://.enable path=/root/snap.json fail_if_already_enabled=true
r native resh firewall://.rules.reload path=/var/backups/firewall/.resh-backup-iptables-ipv4-placeholder
# The first IPv4 backup is the one taken by disable, before the flush.
for f in /var/backups/firewall/.resh-backup-iptables-ipv4-*; do first=$f; break; done
r nofamily resh firewall://.rules.reload path=$first
r testonly resh firewall://.rules.reload path=$first family=ipv4 validate_only=true
r restore resh firewall://.rules.reload path=$first family=ipv4
check v4_restored iptables-save
"#;

fn assert_ipt_flow(c: &Ctr) {
    let j = c.ok("ex_list");
    assert_eq!(j["rules"][0]["saddr"], "203.0.113.0/24");
    assert_eq!(
        c.ok("ex_add")["backend_commands"][0],
        "iptables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT"
    );
    assert_eq!(c.ok("ex_delete")["matched_rules"][0]["rule_id"], "INPUT:3");
    assert_eq!(c.ok("ex_save")["summary"]["backends"][0]["family"], "ipv4");

    c.ok("add");
    assert_eq!(c.ok("add2")["result"]["already_exists"], true);
    assert_eq!(c.ok("add80")["result"]["already_exists"], false, "R5-01");
    c.ok("addlog");
    let v4 = c.check("v4");
    assert_eq!(v4.matches("--dport 443").count(), 1, "{v4}");
    assert!(
        v4.contains("-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"),
        "{v4}"
    );
    assert!(
        v4.contains("--limit 5/sec") && v4.contains("--log-prefix smtp"),
        "{v4}"
    );
    assert!(c.check("v6").contains("--dport 443"));
    assert_eq!(c.ok("subset")["result"]["deleted_count"], 2);
    assert!(!c.check("v4_del").contains("--dport 80"));
    let b = &c.ok("status")["backends"][0];
    assert!(b["rule_count_ipv6"].is_null());
    assert!(b["rule_count_ipv4"].as_u64().unwrap() >= 5, "{b}");

    c.ok("save");
    let d = c.ok("disable");
    assert_eq!(d["actions"].as_array().unwrap().len(), 14, "{d}");
    assert!(!c.check("v4_off").contains("-A "));
    assert!(!c.check("v6_off").contains("-A "));
    let e = c.ok("enable");
    assert_eq!(e["result"]["changed"], true, "{e}");
    assert!(c.check("v4_on").contains("--dport 443"));
    assert!(c.check("v6_on").contains("--dport 443"));
    c.fails("again", 1, "firewall.already_enabled");
    c.fails("native", 1, "firewall.path_not_found");
    c.fails("nofamily", 2, "firewall.invalid_argument");
    c.ok("testonly");
    c.ok("restore");
    assert!(c.check("v4_restored").contains("--dport 443"));
}

#[test]
fn iptables_nft_rules_lifecycle() {
    let c = container(IPT, IPT_FLOW);
    assert_ipt_flow(&c);
}

#[test]
fn iptables_legacy_rules_lifecycle() {
    let c = container(
        IPT,
        &format!(
            "update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null\n\
             update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy >/dev/null\n\
             if ! iptables -L >/dev/null 2>&1; then echo 'legacy\tunsupported'; exit 0; fi\n\
             {IPT_FLOW}"
        ),
    );
    if c.raw.contains("legacy\tunsupported") {
        eprintln!("skipped: the host kernel has no legacy iptables tables");
        return;
    }
    assert_ipt_flow(&c);
}

// ===========================================================================
// ufw
// ===========================================================================

#[test]
fn ufw_lifecycle() {
    let c = container(
        UFW,
        r#"
r ex_enable resh --json-pretty firewall://.enable backend=ufw dry_run=true
r ex_reload resh --json-pretty firewall://.rules.reload backend=ufw dry_run=true
r add_inactive resh firewall://.rules.add backend=ufw proto=tcp dport=22 family=any
r add_inactive2 resh firewall://.rules.add backend=ufw proto=tcp dport=22 family=any
r enable resh firewall://.enable backend=ufw
r ex_disable resh --json-pretty firewall://.disable backend=ufw dry_run=true
r status resh firewall://.status
r add resh firewall://.rules.add proto=tcp dport=443 saddr=10.0.0.0/8 comment=web
r add2 resh firewall://.rules.add proto=tcp dport=443 saddr=10.0.0.0/8 comment=web
r out resh firewall://.rules.add proto=udp dport=53 action=drop direction=output family=any
r refused resh firewall://.rules.add proto=tcp dport=1 rate_limit=1/s
check numbered ufw status numbered
r del resh firewall://.rules.delete proto=tcp dport=22
check numbered_del ufw status numbered
r reload resh firewall://.rules.reload
r noval resh firewall://.rules.reload validate_only=true
r disable resh firewall://.disable
r disable2 resh firewall://.disable fail_if_already_disabled=true
check final ufw status
"#,
    );
    assert_eq!(c.ok("ex_enable")["actions"][0], "ufw --force enable");
    assert_eq!(c.ok("ex_reload")["actions"][0], "ufw reload");
    c.ok("add_inactive");
    assert_eq!(c.ok("add_inactive2")["result"]["already_exists"], true);
    assert_eq!(c.ok("enable")["result"]["changed"], true);
    assert_eq!(c.ok("ex_disable")["previous_state"]["active"], true);
    let b = &c.ok("status")["backends"][0];
    assert_eq!(b["backend"], "ufw");
    assert_eq!(b["rule_count_ipv4"], 1, "{b}");
    c.ok("add");
    assert_eq!(c.ok("add2")["result"]["already_exists"], true);
    c.ok("out");
    c.fails("refused", 2, "firewall.unsupported_option");
    let n = c.check("numbered");
    assert!(
        n.contains("443/tcp") && n.contains("10.0.0.0/8") && n.contains("# web"),
        "{n}"
    );
    assert!(n.contains("DENY OUT"), "{n}");
    assert_eq!(c.ok("del")["result"]["deleted_count"], 2);
    assert!(!c.check("numbered_del").contains("22/tcp"));
    c.ok("reload");
    c.fails("noval", 2, "firewall.unsupported_option");
    c.ok("disable");
    c.fails("disable2", 1, "firewall.already_disabled");
    assert!(c.check("final").contains("inactive"));
}

// ===========================================================================
// firewalld
// ===========================================================================

#[test]
fn firewalld_rules_lifecycle() {
    let c = container(
        FWD,
        r#"
mkdir -p /run/dbus
dbus-daemon --system --fork
firewalld --nofork --nopid > /tmp/fwd.log 2>&1 &
i=0; while [ $i -lt 150 ]; do firewall-cmd --state >/dev/null 2>&1 && break; sleep 0.2; i=$((i+1)); done
r status resh firewall://.status
r add resh firewall://.rules.add backend=firewalld zone=public proto=tcp dport=8443 family=any
r add2 resh firewall://.rules.add zone=public proto=tcp dport=8443 family=any
r add3 resh firewall://.rules.add zone=public proto=tcp dport=9000 saddr=10.0.0.0/8 action=reject
r nozone resh firewall://.rules.add proto=tcp dport=9001
r iface resh firewall://.rules.add zone=public in_iface=eth0
check rich firewall-cmd --zone=public --list-rich-rules
r list resh firewall://.rules.list dport=8443
r deldry resh firewall://.rules.delete zone=public proto=tcp dport=8443 dry_run=true
r del resh firewall://.rules.delete zone=public proto=tcp dport=8443
check rich_del firewall-cmd --zone=public --list-rich-rules
r save resh firewall://.rules.save path=/root/f.json format=both
r checkcfg resh firewall://.rules.reload validate_only=true
r reload resh firewall://.rules.reload
check rich_reload firewall-cmd --zone=public --list-rich-rules
"#,
    );
    let b = &c.ok("status")["backends"][0];
    assert_eq!(b["backend"], "firewalld");
    assert_eq!(b["active"], true);
    c.ok("add");
    assert_eq!(c.ok("add2")["result"]["already_exists"], true);
    c.ok("add3");
    c.fails("nozone", 2, "firewall.rules_add_zone_required");
    c.fails("iface", 2, "firewall.unsupported_option");
    let rich = c.check("rich");
    assert_eq!(rich.matches("8443").count(), 1, "{rich}");
    assert!(
        rich.contains("source address=\"10.0.0.0/8\"") && rich.contains("reject"),
        "{rich}"
    );
    assert_eq!(c.ok("list")["rules"].as_array().unwrap().len(), 1);
    assert_eq!(c.ok("deldry")["result"]["deleted_count"], 0);
    assert_eq!(c.ok("del")["result"]["deleted_count"], 1);
    assert!(!c.check("rich_del").contains("8443"));
    c.ok("save");
    assert_eq!(
        c.ok("checkcfg")["actions"][0],
        "firewall-cmd --check-config"
    );
    c.ok("reload");
    // Runtime rules are discarded by a reload.
    assert!(!c.check("rich_reload").contains("9000"));
}

// ===========================================================================
// NAT
// ===========================================================================

#[test]
fn nftables_nat() {
    let c = container(
        NFT,
        r#"
r dnat resh firewall://.rules.add action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r dnat2 resh firewall://.rules.add action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r dnat6 resh firewall://.rules.add action=dnat proto=tcp dport=443 to=[2001:db8::5]:8443
r masq resh firewall://.rules.add action=masquerade out_iface=eth0
r snat resh firewall://.rules.add action=snat saddr=10.1.0.0/16 to=192.0.2.1
r snat2 resh firewall://.rules.add action=snat saddr=10.1.0.0/16 to=192.0.2.1
check rules nft list ruleset
r list resh firewall://.rules.list action=dnat
r del resh firewall://.rules.delete action=dnat proto=tcp dport=80 to=10.0.0.5:8080
check after_del nft list table inet resh
"#,
    );
    let j = c.ok("dnat");
    assert_eq!(j["backend_commands"][0], "nft add table inet resh", "{j}");
    assert_eq!(c.ok("dnat2")["result"]["already_exists"], true);
    c.ok("dnat6");
    c.ok("masq");
    c.ok("snat");
    assert_eq!(c.ok("snat2")["result"]["already_exists"], true);
    let rules = c.check("rules");
    for want in [
        "table inet resh",
        "type nat hook prerouting priority dstnat",
        "type nat hook postrouting priority srcnat",
        "tcp dport 80 dnat ip to 10.0.0.5:8080",
        "tcp dport 443 dnat ip6 to [2001:db8::5]:8443",
        "oifname \"eth0\" masquerade",
        "ip saddr 10.1.0.0/16 snat ip to 192.0.2.1",
    ] {
        assert!(rules.contains(want), "{want}:\n{rules}");
    }
    assert_eq!(rules.matches("10.0.0.5:8080").count(), 1, "{rules}");
    let listed = c.ok("list")["rules"].as_array().unwrap().clone();
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert_eq!(c.ok("del")["result"]["deleted_count"], 1);
    assert!(!c.check("after_del").contains("10.0.0.5:8080"));
}

#[test]
fn iptables_nat() {
    let c = container(
        IPT,
        r#"
r dnat resh firewall://.rules.add action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r dnat2 resh firewall://.rules.add action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r dnat6 resh firewall://.rules.add action=dnat proto=tcp dport=443 to=[2001:db8::5]:8443
r snat resh firewall://.rules.add action=snat saddr=10.1.0.0/16 out_iface=eth0 to=192.0.2.1
r masq resh firewall://.rules.add action=masquerade out_iface=eth1
r masq2 resh firewall://.rules.add action=masquerade out_iface=eth1
check v4 iptables-save -t nat
check v6 ip6tables-save -t nat
r del resh firewall://.rules.delete action=snat to=192.0.2.1 family=ipv4 match_mode=subset
check v4_del iptables-save -t nat
"#,
    );
    c.ok("dnat");
    assert_eq!(c.ok("dnat2")["result"]["already_exists"], true);
    c.ok("dnat6");
    c.ok("snat");
    c.ok("masq");
    assert_eq!(c.ok("masq2")["result"]["already_exists"], true);
    let v4 = c.check("v4");
    for want in [
        "-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.0.5:8080",
        "-A POSTROUTING -s 10.1.0.0/16 -o eth0 -j SNAT --to-source 192.0.2.1",
        "-A POSTROUTING -o eth1 -j MASQUERADE",
    ] {
        assert!(v4.contains(want), "{want}:\n{v4}");
    }
    assert_eq!(v4.matches("--to-destination").count(), 1, "{v4}");
    assert_eq!(v4.matches("MASQUERADE").count(), 1, "{v4}");
    assert!(
        c.check("v6")
            .contains("-j DNAT --to-destination [2001:db8::5]:8443"),
        "{}",
        c.check("v6")
    );
    assert_eq!(c.ok("del")["result"]["deleted_count"], 1);
    assert!(!c.check("v4_del").contains("SNAT"));
}

#[test]
fn firewalld_and_ufw_nat() {
    let c = container(
        FWD,
        r#"
mkdir -p /run/dbus
dbus-daemon --system --fork
firewalld --nofork --nopid > /tmp/fwd.log 2>&1 &
i=0; while [ $i -lt 150 ]; do firewall-cmd --state >/dev/null 2>&1 && break; sleep 0.2; i=$((i+1)); done
r dnat resh firewall://.rules.add zone=public action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r dnat2 resh firewall://.rules.add zone=public action=dnat proto=tcp dport=80 to=10.0.0.5:8080
r masq resh firewall://.rules.add zone=public action=masquerade saddr=10.0.0.0/8
r masq2 resh firewall://.rules.add zone=public action=masquerade saddr=10.0.0.0/8
r snat resh firewall://.rules.add zone=public action=snat to=192.0.2.1
check rich firewall-cmd --zone=public --list-rich-rules
r list resh firewall://.rules.list action=dnat
r del resh firewall://.rules.delete zone=public action=dnat proto=tcp dport=80 to=10.0.0.5:8080
check rich_del firewall-cmd --zone=public --list-rich-rules
"#,
    );
    c.ok("dnat");
    assert_eq!(c.ok("dnat2")["result"]["already_exists"], true);
    c.ok("masq");
    assert_eq!(c.ok("masq2")["result"]["already_exists"], true);
    c.fails("snat", 2, "firewall.unsupported_option");
    let rich = c.check("rich");
    assert!(
        rich.contains(
            "forward-port port=\"80\" protocol=\"tcp\" to-port=\"8080\" to-addr=\"10.0.0.5\""
        ),
        "{rich}"
    );
    assert!(
        rich.contains("source address=\"10.0.0.0/8\" masquerade"),
        "{rich}"
    );
    assert_eq!(rich.matches("forward-port").count(), 1, "{rich}");
    assert_eq!(c.ok("list")["rules"][0]["to"], "10.0.0.5:8080");
    assert_eq!(c.ok("del")["result"]["deleted_count"], 1);
    assert!(!c.check("rich_del").contains("forward-port"));

    let c = container(
        UFW,
        r#"
r dnat resh firewall://.rules.add backend=ufw action=dnat proto=tcp dport=80 to=10.0.0.5
"#,
    );
    c.fails("dnat", 2, "firewall.unsupported_option");
}

/// A container running systemd as PID 1 (privileged, its own network
/// namespace); removed on drop.
struct SystemdBox(String);

impl SystemdBox {
    fn start() -> Self {
        ensure_images();
        let name = format!("resh-fw-e2e-{}", std::process::id());
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--privileged",
                "--cgroupns=private",
                "--network=none",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "--name",
                &name,
                "-v",
                &mount(),
                FWD_SD,
                "/lib/systemd/systemd",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let b = SystemdBox(name);
        for _ in 0..150 {
            if b.exec("firewall-cmd --state 2>/dev/null")
                .contains("running")
            {
                return b;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("firewalld did not start");
    }

    fn exec(&self, script: &str) -> String {
        let out = Command::new("docker")
            .args(["exec", &self.0, "sh", "-c"])
            .arg(format!("{PRELUDE}\n{script}"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for SystemdBox {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn firewalld_enable_and_disable_through_systemd() {
    let b = SystemdBox::start();
    let c = Ctr::parse(b.exec(
        r#"
r already resh firewall://.enable fail_if_already_enabled=true
r drydis resh firewall://.disable dry_run=true
r disable resh firewall://.disable
check state_off systemctl is-active firewalld
r disable2 resh firewall://.disable backend=firewalld
r enable resh firewall://.enable backend=firewalld
check state_on systemctl is-active firewalld
check enabled systemctl is-enabled firewalld
r status resh firewall://.status backend=firewalld
"#,
    ));
    c.fails("already", 1, "firewall.already_enabled");
    assert_eq!(c.ok("drydis")["actions"][0], "systemctl stop firewalld");
    assert_eq!(c.ok("disable")["current_state"]["active"], false);
    assert_eq!(c.check("state_off").trim(), "inactive");
    assert_eq!(c.ok("disable2")["result"]["already_disabled"], true);
    let e = c.ok("enable");
    assert_eq!(
        e["actions"],
        serde_json::json!(["systemctl enable firewalld", "systemctl start firewalld"])
    );
    assert_eq!(c.check("state_on").trim(), "active");
    assert_eq!(c.check("enabled").trim(), "enabled");
    assert_eq!(c.ok("status")["backends"][0]["active"], true);
}
