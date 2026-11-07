//! End-to-end tests for `net://` inside throwaway containers with a known
//! network setup (`--network=none`, and a custom bridge with a fixed
//! subnet, address and MAC), so `list` and `route.list` output can be
//! asserted exactly, and `ping` can be shown to fail for an unreachable host
//! without any packet leaving the test network. The host-built `resh`
//! binary is mounted read-only; nothing on the host is changed.
//!
//! Images: `debian:13-slim` (no `ip`, no `ping`: the /proc and TCP
//! fallbacks) and `resh-net-e2e:1` (ubuntu:24.04 with iproute2 and
//! iputils-ping), built on first use.
//!
//! Run with `cargo test --features e2e-docker --test net_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const SLIM: &str = "debian:13-slim";
const TOOLS: &str = "resh-net-e2e:1";
const SUBNET: &str = "10.231.7.0/24";
const IP: &str = "10.231.7.10";
const MAC: &str = "02:42:0a:e7:07:0a";

fn ensure_tools_image() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let have = Command::new("docker")
            .args(["image", "inspect", TOOLS])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if have.success() {
            return;
        }
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", TOOLS, "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"FROM ubuntu:24.04\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
                  apt-get install -y --no-install-recommends iproute2 iputils-ping \
                  && rm -rf /var/lib/apt/lists/*\n",
            )
            .unwrap();
        assert!(child.wait().unwrap().success(), "cannot build {TOOLS}");
    });
}

/// A docker network with a fixed subnet, removed on drop.
struct Bridge(
    String,
    #[allow(dead_code)] std::sync::MutexGuard<'static, ()>,
);

/// Tests on the bridge share its fixed subnet, so they run one at a time.
static BRIDGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Bridge {
    fn new() -> Self {
        let guard = BRIDGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let name = format!("resh-net-e2e-{}", std::process::id());
        let ok = Command::new("docker")
            .args(["network", "create", "--internal", "--subnet", SUBNET, &name])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(ok.success(), "cannot create network {name}");
        Bridge(name, guard)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        Command::new("docker")
            .args(["network", "rm", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

/// Runs `resh <args>` in a fresh container; returns (exit, stdout JSON,
/// stderr).
fn run(image: &str, net: &[&str], args: &[&str]) -> (i32, Value, String) {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let mut argv = vec!["run", "--rm", "-v", &mount];
    argv.extend_from_slice(net);
    argv.extend_from_slice(&[image, "resh"]);
    argv.extend_from_slice(args);
    let out = Command::new("docker").args(&argv).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (
        out.status.code().unwrap_or(-1),
        serde_json::from_str(&stdout).unwrap_or_else(|_| json!(stdout)),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn lo(with_v6: bool) -> Value {
    let mut addrs = vec![json!({"addr": "127.0.0.1", "family": "ipv4", "scope": "host"})];
    if with_v6 {
        addrs.push(json!({"addr": "::1", "family": "ipv6", "scope": "host"}));
    }
    json!({"name": "lo", "index": 1, "mac": "00:00:00:00:00:00",
           "flags": ["up", "loopback", "running", "lower_up"], "mtu": 65536,
           "addresses": addrs})
}

#[test]
fn list_without_network_is_exactly_loopback() {
    let (code, out, err) = run(SLIM, &["--network=none"], &["net://if.list", "family=ipv4"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, json!({"interfaces": [lo(false)]}));
    let (code, out, _) = run(SLIM, &["--network=none"], &["net://if.list", "up=false"]);
    assert_eq!(code, 0);
    assert_eq!(out, json!({"interfaces": []}));
}

#[test]
fn list_on_a_custom_bridge() {
    let bridge = Bridge::new();
    let net = format!("--network={}", bridge.0);
    let args = [net.as_str(), "--ip", IP, "--mac-address", MAC];
    let (code, out, err) = run(SLIM, &args, &["net://if.list", "family=ipv4"]);
    assert_eq!(code, 0, "{err}");
    let ifaces = out["interfaces"].as_array().unwrap();
    assert_eq!(ifaces.len(), 2, "{out}");
    let eth0 = &ifaces[0];
    assert_eq!(eth0["name"], "eth0");
    assert_eq!(eth0["mac"], MAC);
    assert_eq!(eth0["mtu"], 1500);
    assert_eq!(
        eth0["addresses"],
        json!([{"addr": IP, "family": "ipv4", "scope": "global"}])
    );
    assert_eq!(
        eth0["flags"],
        json!(["up", "broadcast", "running", "multicast", "lower_up"])
    );
    assert_eq!(ifaces[1], lo(false));
}

#[test]
fn route_list_on_a_custom_bridge_with_ip_and_with_proc() {
    ensure_tools_image();
    let bridge = Bridge::new();
    let net = format!("--network={}", bridge.0);
    let args = [net.as_str(), "--ip", IP];
    let want_ip = json!([{"dst": SUBNET, "family": "ipv4", "flags": ["link"],
        "gateway": null, "iface": "eth0", "metric": 0, "protocol": "kernel",
        "scope": "link", "table": "main"}]);
    let (code, out, err) = run(TOOLS, &args, &["net://localhost.route.list"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, want_ip);
    // Without ip: /proc/net/route, same route.
    let (code, out, err) = run(SLIM, &args, &["net://localhost.route.list"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        json!([{"dst": SUBNET, "family": "ipv4", "flags": ["up"], "gateway": null,
            "iface": "eth0", "metric": 0, "protocol": null, "scope": null, "table": "main"}])
    );
    // The local table needs ip.
    let (code, out, _) = run(TOOLS, &args, &["net://localhost.route.list", "table=local"]);
    assert_eq!(code, 0);
    assert!(
        out.as_array()
            .unwrap()
            .iter()
            .any(|r| r["dst"] == IP && r["table"] == "local"),
        "{out}"
    );
    let (code, out, _) = run(SLIM, &args, &["net://localhost.route.list", "table=local"]);
    assert_eq!(code, 1);
    assert_eq!(out["error"]["code"], "net.route_read_failed");
}

#[test]
fn route_list_without_network_is_empty() {
    ensure_tools_image();
    for image in [SLIM, TOOLS] {
        let (code, out, err) = run(image, &["--network=none"], &["net://localhost.route.list"]);
        assert_eq!(code, 0, "{image}: {err}");
        assert_eq!(out, json!([]), "{image}");
    }
}

#[test]
fn ping_reports_unreachable_hosts_with_exit_1() {
    ensure_tools_image();
    let bridge = Bridge::new();
    let net = format!("--network={}", bridge.0);
    let args = [net.as_str(), "--ip", IP];
    // Loopback answers.
    let (code, out, err) = run(TOOLS, &args, &["net://127.0.0.1.ping", "count=1"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out["backend"], "system_ping");
    // An unused address on the bridge: ARP fails, ping prints ICMP
    // "Destination Host Unreachable" lines, which are not replies.
    let (code, out, err) = run(
        TOOLS,
        &args,
        &["net://10.231.7.200.ping", "count=2", "timeout_ms=3000"],
    );
    assert_eq!(code, 1, "{out}\n{err}");
    assert_eq!(out["reachable"], false);
    assert_eq!(out["received"], 0);
    assert_eq!(out["error"]["code"], "net.unreachable");
    assert!(err.starts_with("Error: [net.unreachable] "), "{err}");
    // No route at all, no ping installed: the TCP fallback fails too.
    let (code, out, _) = run(
        SLIM,
        &["--network=none"],
        &["net://192.0.2.1.ping", "count=1", "timeout_ms=500"],
    );
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["backend"], "tcp_fallback");
    assert_eq!(out["error"]["code"], "net.unreachable");
}

#[test]
fn names_that_do_not_resolve() {
    ensure_tools_image();
    let none = ["--network=none"];
    let (code, out, _) = run(TOOLS, &none, &["net://nohost.test.ping", "count=1"]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["error"]["code"], "net.resolve_failed");
    let (code, out, _) = run(SLIM, &none, &["net://nohost.test:80.tcp_check"]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["error"]["code"], "net.resolve_failed");
    let (code, out, _) = run(SLIM, &none, &["net://nohost.test.scan", "ports=80"]);
    assert_eq!(code, 1, "{out}");
    assert_eq!(out["error"]["code"], "net.scan_failed");
    assert_eq!(out["ports"][0]["state"], "error");
}
