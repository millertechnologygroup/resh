//! End-to-end tests for `system://` inside throwaway containers started with
//! `--memory`, `--memory-swap`, `--cpus` and `--shm-size` limits: the cgroup
//! figures must be the container's own limits and usage, not the host's.
//! The host-built `resh` binary is mounted read-only; nothing on the host is
//! changed. cgroup v1 layouts are covered by the fixture unit tests (this
//! host's Docker uses whichever cgroup version the host runs).
//!
//! Image: `debian:13-slim` (util-linux `setpriv` runs commands as nobody).
//!
//! Run with `cargo test --features e2e-docker --test system_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;

const IMAGE: &str = "debian:13-slim";

/// `r <tag> <resh args...>` prints `<tag>\t<exit>\t<stdout>\t<stderr>` on
/// one line. `NOBODY` runs a command as uid 65534.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(echo $out)" "$(cat /tmp/err)"
}
NOBODY="setpriv --reuid=65534 --regid=65534 --clear-groups"
"#;

struct Res {
    code: i32,
    json: Value,
    err: String,
}

struct Ctr {
    results: HashMap<String, Res>,
    raw: String,
}

impl Ctr {
    fn get(&self, tag: &str) -> &Res {
        self.results
            .get(tag)
            .unwrap_or_else(|| panic!("no result {tag}:\n{}", self.raw))
    }
    fn ok(&self, tag: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, 0, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["ok"], true, "{tag}: {}", r.json);
        &r.json
    }
    fn fails(&self, tag: &str, exit: i32, code: &str) {
        let r = self.get(tag);
        assert_eq!(r.code, exit, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["error"]["code"], code, "{tag}: {}", r.json);
        assert!(
            r.err.starts_with(&format!("Error: [{code}] ")),
            "{tag}: {}",
            r.err
        );
    }
}

/// Runs `script` (after PRELUDE) in a fresh container with `flags`.
fn container(flags: &[&str], script: &str) -> Ctr {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let out = Command::new("docker")
        .args(["run", "--rm", "--network=none", "-v", &mount])
        .args(flags)
        .args([IMAGE, "sh", "-c"])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container failed: {raw}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut results = HashMap::new();
    for line in raw.lines() {
        let f: Vec<&str> = line.splitn(4, '\t').collect();
        if f.len() == 4 {
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
    Ctr { results, raw }
}

fn host_cgroup_v2() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

const MIB: u64 = 1024 * 1024;

#[test]
fn limited_container_reports_its_own_limits_and_usage() {
    let c = container(
        &[
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1.5",
            "--shm-size=128m",
        ],
        r#"
r mem0 resh system://.memory
dd if=/dev/zero of=/dev/shm/fill bs=1M count=64 2>/dev/null
r mem1 resh system://.memory
timeout 1 sh -c 'while :; do :; done'
r cpu resh system://.cpu sample_duration_ms=100
r info resh system://.info scopes=cgroup,virtualization,memory
r disk resh system://.disk mount_points=/
r load resh system://.load
r up resh system://.uptime
r env resh system://.env.list names=HOSTNAME,HOME
r envpid resh system://.env.list pid=1 names=PATH
r denied $NOBODY resh system://.env.list pid=1
r nosuch resh system://.env.list pid=999999
r text resh system://.memory format=text
"#,
    );
    let m0 = c.ok("mem0");
    let cg = &m0["cgroup"];
    assert_eq!(cg["available"], true, "{m0}");
    assert_eq!(cg["memory_limit_bytes"], 256 * MIB, "{m0}");
    if host_cgroup_v2() {
        assert_eq!(cg["unified"], true);
        // --memory-swap equal to --memory: no swap.
        assert_eq!(cg["swap_limit_bytes"], 0, "{m0}");
    }
    let before = cg["memory_usage_bytes"].as_u64().unwrap();
    assert!(before < 256 * MIB);
    // 64 MiB in tmpfs is charged to the container.
    let m1 = c.ok("mem1");
    let after = m1["cgroup"]["memory_usage_bytes"].as_u64().unwrap();
    assert!(after >= before + 60 * MIB, "{before} -> {after}");
    let pct = m1["cgroup"]["memory_used_pct"].as_f64().unwrap();
    assert!((pct - 100.0 * after as f64 / (256 * MIB) as f64).abs() < 1e-6);
    // The system section is the host's (not namespaced).
    assert!(m1["system"]["mem_total_bytes"].as_u64().unwrap() > 256 * MIB);
    assert!(
        m1["human"]["cgroup_summary"]
            .as_str()
            .unwrap()
            .contains("limit")
    );

    let cpu = c.ok("cpu");
    let cc = &cpu["cgroup"];
    assert_eq!(cc["available"], true, "{cpu}");
    assert!(
        (cc["cpu_quota_cores"].as_f64().unwrap() - 1.5).abs() < 1e-9,
        "{cpu}"
    );
    assert_eq!(cc["cpu_quota_us"], 150_000);
    assert_eq!(cc["cpu_period_us"], 100_000);
    // The busy loop ran for about a second inside this cgroup.
    assert!(cc["usage_seconds"].as_f64().unwrap() >= 0.5, "{cpu}");

    let info = c.ok("info");
    assert!((info["cgroup"]["limits"]["cpu_quota_pct"].as_f64().unwrap() - 150.0).abs() < 1e-6);
    assert_eq!(info["cgroup"]["limits"]["memory_limit_bytes"], 256 * MIB);
    assert_eq!(info["virtualization"]["is_container"], true);
    assert_eq!(info["virtualization"]["container_type"], "docker");

    // The container's root is overlay, which is real storage.
    let disk = c.ok("disk");
    assert_eq!(disk["mounts"][0]["mount_point"], "/");
    assert!(disk["mounts"][0]["total_bytes"].as_u64().unwrap() > 0);

    c.ok("load");
    c.ok("up");
    let env = c.ok("env");
    assert_eq!(env["variables"][0]["name"], "HOME");
    let p1 = c.ok("envpid");
    assert_eq!(p1["source"], "proc");
    assert_eq!(p1["variables"][0]["name"], "PATH");
    c.fails("denied", 1, "system.env_list_permission_denied");
    c.fails("nosuch", 1, "system.env_list_pid_not_found");
    assert_eq!(c.get("text").code, 0);
}

#[test]
fn unlimited_container_has_no_cgroup_limits() {
    let c = container(
        &[],
        r#"
r mem resh system://.memory
r cpu resh system://.cpu sample_duration_ms=50 per_cpu=false
r info resh system://.info scopes=cgroup
"#,
    );
    let m = c.ok("mem");
    assert_eq!(m["cgroup"]["available"], true, "{m}");
    assert!(m["cgroup"].get("memory_limit_bytes").is_none(), "{m}");
    assert!(m["cgroup"]["memory_usage_bytes"].as_u64().unwrap() > 0);
    let cpu = c.ok("cpu");
    assert!(cpu["cgroup"].get("cpu_quota_cores").is_none(), "{cpu}");
    let info = c.ok("info");
    assert_eq!(info["cgroup"]["limits"], serde_json::json!({}));
}
