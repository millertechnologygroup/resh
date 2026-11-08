//! Integration tests for `system://` through the built `resh` binary. The
//! handle only reads, so every verb runs on this host; the figures are
//! checked against the kernel's own files. Failure paths run against
//! fixture trees through `RESH_TEST_SYSTEM_ROOT` (honored by debug builds
//! only). Container and cgroup-limit checks are in
//! tests/system_e2e_docker.rs.

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};

const VERBS: &[&str] = &[
    "info", "uptime", "load", "memory", "cpu", "disk", "env.list",
];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.json["ok"], true, "{}", self.stdout);
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.stderr);
        assert!(
            self.stderr.starts_with(&format!("Error: [{code}] ")),
            "{code}: {}",
            self.stderr
        );
        if !self.stdout.is_empty() {
            assert_eq!(self.json["ok"], false, "{}", self.stdout);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
    }
}

fn resh_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("resh"));
    cmd.env_remove("SSH_AUTH_SOCK")
        .env_remove("RESH_TEST_SYSTEM_ROOT")
        .args(args)
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn resh(args: &[&str]) -> Run {
    resh_env(args, &[])
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A `/proc/meminfo` field in bytes.
fn meminfo(key: &str) -> u64 {
    read("/proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}:")))
        .map(|v| v.split_whitespace().next().unwrap().parse::<u64>().unwrap() * 1024)
        .unwrap()
}

fn online_cpus() -> u64 {
    read("/proc/stat")
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count() as u64
}

// ---------------------------------------------------------------------------
// Every verb on this host, checked against the kernel's files
// ---------------------------------------------------------------------------

#[test]
fn uptime_matches_proc() {
    let v = resh(&["system://.uptime"]).ok().clone();
    let up: f64 = read("/proc/uptime")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (v["uptime_seconds"].as_f64().unwrap() - up).abs() < 5.0,
        "{v}"
    );
    let btime: i64 = read("/proc/stat")
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(v["boot_time_unix"], btime);
    let r = resh(&["system://.uptime", "format=text"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.starts_with("System Uptime"), "{}", r.stdout);
}

#[test]
fn load_matches_proc() {
    let v = resh(&["system://.load", "include_raw=true"]).ok().clone();
    assert_eq!(v["cpu_count_logical"], online_cpus());
    // The raw line is what the figures were parsed from.
    let line = v["raw"]["proc_loadavg_line"].as_str().unwrap().to_string();
    let f: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(v["load_1m"].as_f64().unwrap(), f[0].parse::<f64>().unwrap());
    assert_eq!(
        v["load_15m"].as_f64().unwrap(),
        f[2].parse::<f64>().unwrap()
    );
    let total: u64 = f[3].split('/').nth(1).unwrap().parse().unwrap();
    assert_eq!(v["total_processes"], total);
    let per = v["load_1m_per_cpu"].as_f64().unwrap();
    assert!((per - f[0].parse::<f64>().unwrap() / online_cpus() as f64).abs() < 1e-9);
}

#[test]
fn memory_matches_proc_and_own_cgroup() {
    let v = resh(&["system://.memory"]).ok().clone();
    assert_eq!(v["system"]["mem_total_bytes"], meminfo("MemTotal"));
    assert_eq!(v["system"]["swap_total_bytes"], meminfo("SwapTotal"));
    // The cgroup figures are this process's own group.
    let cg = read("/proc/self/cgroup");
    if let Some(path) = cg.lines().find_map(|l| l.strip_prefix("0::")) {
        let dir = format!("/sys/fs/cgroup{}", path.trim_end_matches('/'));
        if Path::new(&format!("{dir}/memory.current")).exists() {
            assert_eq!(v["cgroup"]["available"], true, "{v}");
            assert_eq!(v["cgroup"]["unified"], true);
            assert!(v["cgroup"]["memory_usage_bytes"].as_u64().unwrap() > 0);
        }
    }
    let v = resh(&["system://.memory", "include_swap=false"])
        .ok()
        .clone();
    assert!(v["system"].get("swap_total_bytes").is_none());
}

#[test]
fn cpu_samples_this_host() {
    let v = resh(&["system://.cpu", "sample_duration_ms=100"])
        .ok()
        .clone();
    assert_eq!(v["sample_duration_ms"], 100);
    assert_eq!(v["system"]["logical_count"], online_cpus());
    let s = &v["system"];
    if let Some(u) = s["utilization_pct"].as_f64() {
        assert!((0.0..=100.0).contains(&u));
        let sum: f64 = [
            "user_pct",
            "nice_pct",
            "system_pct",
            "idle_pct",
            "iowait_pct",
            "irq_pct",
            "softirq_pct",
            "steal_pct",
        ]
        .iter()
        .map(|k| s[*k].as_f64().unwrap())
        .sum();
        assert!((sum - 100.0).abs() < 0.01, "{sum}: {s}");
    }
    assert_eq!(v["per_cpu"].as_array().unwrap().len() as u64, online_cpus());
}

#[test]
fn disk_root_matches_statvfs() {
    let v = resh(&["system://.disk", "mount_points=/", "include_virtual=true"])
        .ok()
        .clone();
    let m = &v["mounts"][0];
    assert_eq!(m["mount_point"], "/");
    let st = nix::sys::statvfs::statvfs("/").unwrap();
    let unit = st.fragment_size() as u64;
    assert_eq!(m["total_bytes"], st.blocks() as u64 * unit);
    assert_eq!(m["inodes_total"], st.files() as u64);
    // used_pct is df's Use% (the filesystem is live: allow one point).
    let out = Command::new("df")
        .args(["--output=pcent", "/"])
        .output()
        .unwrap();
    let df: f64 = String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)
        .unwrap()
        .trim()
        .trim_end_matches('%')
        .parse()
        .unwrap();
    let used = m["used_pct"].as_f64().unwrap();
    assert!((used - df).abs() <= 1.0, "resh {used} df {df}");
    let of_total = 100.0 * m["used_bytes"].as_f64().unwrap() / m["total_bytes"].as_f64().unwrap();
    assert!((m["used_of_total_pct"].as_f64().unwrap() - of_total).abs() < 0.01);
    resh(&["system://.disk", "mount_points=/no/such/mount"])
        .fails(1, "system.disk_mount_not_found");
    let r = resh(&["system://.disk", "format=text"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
}

#[test]
fn env_list_reads_and_masks() {
    let r = resh_env(
        &["system://.env.list", "prefix_filters=RESH_IT_"],
        &[("RESH_IT_PLAIN", "hello"), ("RESH_IT_PASSWORD", "hunter2")],
    );
    let v = r.ok();
    assert_eq!(v["env_count_returned"], 2);
    assert_eq!(v["variables"][0]["name"], "RESH_IT_PASSWORD");
    assert_eq!(v["variables"][0]["value"], "***MASKED***");
    assert_eq!(v["variables"][1]["value"], "hello");
    assert!(!r.stdout.contains("hunter2"));
    // Another process: a child we started, with its own environment.
    let mut child = Command::new("sleep")
        .arg("30")
        .env("RESH_IT_CHILD", "x")
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let v = resh(&[
        "system://.env.list",
        &format!("pid={pid}"),
        "names=RESH_IT_CHILD",
    ])
    .ok()
    .clone();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(v["source"], "proc");
    assert_eq!(v["variables"][0]["value"], "x");
    resh(&["system://.env.list", "pid=999999999"]).fails(1, "system.env_list_pid_not_found");
    // PID 1 belongs to root (permission denied unless we are root).
    if !nix::unistd::geteuid().is_root() && Path::new("/proc/1/environ").exists() {
        resh(&["system://.env.list", "pid=1"]).fails(1, "system.env_list_permission_denied");
    }
    resh(&["system://.env.list", "regex_filters=("]).fails(2, "system.invalid_argument");
}

#[test]
fn info_scopes_on_this_host() {
    let v = resh(&[
        "system://.info",
        "scopes=os,kernel,cpu,memory,load,disk,process,pressure,cgroup,virtualization",
        "sample_duration_ms=50",
    ])
    .ok()
    .clone();
    assert_eq!(
        v["kernel"]["release"].as_str().unwrap(),
        read("/proc/sys/kernel/osrelease").trim()
    );
    assert_eq!(
        v["os"]["hostname"].as_str().unwrap(),
        read("/proc/sys/kernel/hostname").trim()
    );
    assert_eq!(v["kernel"]["machine"], v["os"]["architecture"]);
    assert_eq!(v["memory"]["mem_total_bytes"], meminfo("MemTotal"));
    assert!(v["process"]["total_processes"].as_u64().unwrap() > 0);
    assert_eq!(v["cpu"]["online_logical"], online_cpus());
    let v = resh(&[
        "system://.info",
        "scopes=kernel",
        "fields=kernel.release",
        "format=text",
    ]);
    assert_eq!(v.code, 0);
    assert!(v.stdout.contains("release"), "{}", v.stdout);
}

// ---------------------------------------------------------------------------
// Refusals and failures
// ---------------------------------------------------------------------------

#[test]
fn strict_arguments() {
    for verb in VERBS {
        let r = resh(&[&format!("system://.{verb}"), "bogus=1"]);
        r.fails(2, "system.invalid_argument");
        assert!(r.stderr.contains("bogus"), "{}", r.stderr);
    }
    let r = resh(&["system://.memory", "include_swpa=false"]);
    r.fails(2, "system.invalid_argument");
    assert!(
        r.stderr.contains("did you mean `include_swap`?"),
        "{}",
        r.stderr
    );
    resh(&["system://.load", "timeout_ms=10"]).fails(2, "system.invalid_argument");
    resh(&["system://.uptime", "format=xml"]).fails(2, "system.invalid_argument");
    resh(&["system://.uptime", "include_idle=maybe"]).fails(2, "system.invalid_argument");
    resh(&["system://.info", "scopes=kernal"]).fails(2, "system.invalid_argument");
    // A dry run is refused before the handle runs (no dry-run mode).
    let r = resh(&["system://.uptime", "dry_run=true"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    let r = resh(&["system://.uptime", "format=text", "bogus=1"]);
    r.fails(2, "system.invalid_argument");
    assert!(r.stdout.is_empty());
}

#[test]
fn targets_and_unknown_verbs_are_refused() {
    resh(&["system://localhost.info"]).fails(2, "system.invalid_target");
    let r = resh(&["system://.uptim"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("uptime"), "{}", r.stderr);
}

/// A fixture root with the files `files` (host path, content).
fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for (p, c) in files {
        let p = d.path().join(p.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, c).unwrap();
    }
    d
}

fn in_root(root: &Path, args: &[&str]) -> Run {
    resh_env(args, &[("RESH_TEST_SYSTEM_ROOT", root.to_str().unwrap())])
}

#[test]
fn failures_against_fixture_roots() {
    let empty = fixture(&[]);
    let r = empty.path();
    in_root(r, &["system://.uptime"]).fails(1, "system.uptime_unavailable");
    in_root(r, &["system://.load"]).fails(1, "system.load_unavailable");
    in_root(r, &["system://.memory"]).fails(1, "system.memory_meminfo_unavailable");
    in_root(r, &["system://.cpu"]).fails(1, "system.cpu_stat_unavailable");
    in_root(r, &["system://.disk"]).fails(1, "system.disk_mounts_unavailable");
    in_root(r, &["system://.env.list", "pid=1"]).fails(1, "system.env_list_pid_not_found");
    // info reports unreadable scopes instead of failing.
    let v = in_root(r, &["system://.info"]).ok().clone();
    assert_eq!(v["kernel"]["available"], false);

    let bad = fixture(&[
        ("/proc/uptime", "x\n"),
        ("/proc/loadavg", "1 2\n"),
        ("/proc/meminfo", "MemFree: 1 kB\n"),
        ("/proc/stat", "intr 1\n"),
        ("/proc/self/mounts", "garbage\n"),
    ]);
    let r = bad.path();
    in_root(r, &["system://.uptime"]).fails(1, "system.uptime_parse_error");
    in_root(r, &["system://.load"]).fails(1, "system.load_parse_error");
    in_root(r, &["system://.memory"]).fails(1, "system.memory_meminfo_parse_error");
    in_root(r, &["system://.cpu"]).fails(1, "system.cpu_stat_parse_error");
    in_root(r, &["system://.disk"]).fails(1, "system.disk_mounts_parse_error");
    let r = in_root(r, &["system://.uptime", "format=text"]);
    r.fails(1, "system.uptime_parse_error");
    assert!(r.stdout.is_empty());
}

#[test]
fn cgroup_v1_fixture_through_the_binary() {
    let d = fixture(&[
        ("/proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 500 kB\n"),
        ("/proc/self/cgroup", "5:memory:/\n"),
        (
            "/proc/self/mountinfo",
            "40 1 0:30 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
        ),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "1048576\n"),
        ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "524288\n"),
    ]);
    let v = in_root(d.path(), &["system://.memory"]).ok().clone();
    assert_eq!(v["cgroup"]["unified"], false);
    assert_eq!(v["cgroup"]["memory_limit_bytes"], 1_048_576);
    assert_eq!(v["cgroup"]["memory_used_pct"], 50.0);
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn golden(verb: &str) -> &'static str {
    match verb {
        "info" => include_str!("golden/system_info_help.txt"),
        "uptime" => include_str!("golden/system_uptime_help.txt"),
        "load" => include_str!("golden/system_load_help.txt"),
        "memory" => include_str!("golden/system_memory_help.txt"),
        "cpu" => include_str!("golden/system_cpu_help.txt"),
        "disk" => include_str!("golden/system_disk_help.txt"),
        "env.list" => include_str!("golden/system_env.list_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let want = include_str!("golden/system_help.txt");
    for args in [
        &["system", "--help"][..],
        &["system", "-h"][..],
        &["system", "help"][..],
        &["help", "system"][..],
        &["system://--help"][..],
        &["system://help"][..],
    ] {
        let r = resh(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden() {
    for verb in VERBS {
        let stage = format!("system://.{verb}");
        for args in [
            vec!["system", verb, "--help"],
            vec!["system", verb, "-h"],
            vec!["help", "system", verb],
            vec![stage.as_str(), "--help"],
        ] {
            let r = resh(&args);
            assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(golden(verb).lines().all(|l| l.len() <= 80), "{verb}");
    }
    let r = resh(&["system", "memroy", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("memory"), "{}", r.stderr);
}

fn example(verb: &str) -> (Vec<String>, Value) {
    let text = golden(verb);
    let line = text
        .lines()
        .skip_while(|l| *l != "Example:")
        .nth(1)
        .unwrap()
        .trim();
    let words: Vec<String> = line.split_whitespace().map(String::from).collect();
    assert_eq!(words[0], "resh");
    let start = text.find("Example Output:").unwrap();
    let body: String = text[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with("Shown"))
        .collect::<Vec<_>>()
        .join("\n");
    (words[1..].to_vec(), serde_json::from_str(&body).unwrap())
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// Every example runs on this host and prints the same top-level keys as
/// its sample output.
#[test]
fn help_examples_run() {
    for verb in VERBS {
        let (args, sample) = example(verb);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = resh(&args);
        assert_eq!(r.code, 0, "{verb}: {}", r.stderr);
        let got: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(keys(&got), keys(&sample), "{verb}");
    }
}
