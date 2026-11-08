//! Unit tests for the system handle. Every verb runs against fixture trees
//! laid out like a root filesystem (see [`Host::at`]), so cgroup v1/v2,
//! missing files and odd formats are covered without touching the machine.

use super::*;
use crate::core::status::is_valid_error_code;
use std::path::Path;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn empty() -> Fx {
        Fx {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// A host with the common /proc and /sys files and a cgroup v2 group
    /// `/app/svc` limited to 512 MiB and 1.5 CPUs (its parent `/app` to 1 GiB
    /// and 2 CPUs).
    fn new() -> Fx {
        let f = Fx::empty();
        f.put("/proc/uptime", "1000.50 3000.25\n");
        f.put("/proc/loadavg", "0.80 0.40 0.20 3/412 9999\n");
        f.put("/proc/stat", STAT_A);
        f.put("/proc/meminfo", MEMINFO);
        f.put("/proc/sys/kernel/ostype", "Linux\n");
        f.put("/proc/sys/kernel/osrelease", "6.1.0-test\n");
        f.put("/proc/sys/kernel/version", "#1 SMP PREEMPT_DYNAMIC Test\n");
        f.put("/proc/sys/kernel/hostname", "fixture-host\n");
        f.put("/proc/sys/kernel/arch", "x86_64\n");
        f.put(
            "/etc/os-release",
            "NAME=\"Debian GNU/Linux\"\nVERSION_ID='13'\nID=debian\n",
        );
        f.cgroup_v2();
        f
    }

    fn put(&self, abs: &str, content: &str) {
        let p = self.path(abs);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn mkdir(&self, abs: &str) {
        std::fs::create_dir_all(self.path(abs)).unwrap();
    }

    fn rm(&self, abs: &str) {
        let p = self.path(abs);
        if p.is_dir() {
            std::fs::remove_dir_all(p).unwrap();
        } else {
            std::fs::remove_file(p).unwrap();
        }
    }

    fn path(&self, abs: &str) -> std::path::PathBuf {
        self.dir.path().join(abs.trim_start_matches('/'))
    }

    fn host(&self) -> Host {
        Host::at(self.dir.path())
    }

    fn cgroup_v2(&self) {
        self.put("/proc/self/cgroup", "0::/app/svc\n");
        self.put(
            "/proc/self/mountinfo",
            "22 1 0:21 / / rw - ext4 /dev/sda1 rw\n\
             30 22 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw,nsdelegate\n",
        );
        let g = "/sys/fs/cgroup";
        self.put(&format!("{g}/cgroup.controllers"), "cpu memory\n");
        self.put(&format!("{g}/app/memory.max"), "1073741824\n");
        self.put(&format!("{g}/app/cpu.max"), "200000 100000\n");
        self.put(&format!("{g}/app/svc/memory.max"), "536870912\n");
        self.put(&format!("{g}/app/svc/memory.current"), "134217728\n");
        self.put(&format!("{g}/app/svc/memory.swap.max"), "max\n");
        self.put(&format!("{g}/app/svc/memory.swap.current"), "1048576\n");
        self.put(&format!("{g}/app/svc/cpu.max"), "150000 100000\n");
        self.put(
            &format!("{g}/app/svc/cpu.stat"),
            "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n",
        );
    }

    /// cgroup v1 with memory and cpu,cpuacct hierarchies (as in a v1
    /// Docker container: the mount root is the container's group).
    fn cgroup_v1(&self) {
        self.rm("/sys/fs/cgroup");
        self.put(
            "/proc/self/cgroup",
            "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n1:name=systemd:/docker/abc\n",
        );
        self.put(
            "/proc/self/mountinfo",
            "22 1 0:21 / / rw - overlay overlay rw\n\
             40 22 0:30 /docker/abc /sys/fs/cgroup/memory ro - cgroup cgroup rw,memory\n\
             41 22 0:31 /docker/abc /sys/fs/cgroup/cpu,cpuacct ro - cgroup cgroup rw,cpu,cpuacct\n",
        );
        let m = "/sys/fs/cgroup/memory";
        self.put(&format!("{m}/memory.limit_in_bytes"), "268435456\n");
        self.put(&format!("{m}/memory.usage_in_bytes"), "67108864\n");
        self.put(&format!("{m}/memory.memsw.limit_in_bytes"), "536870912\n");
        self.put(&format!("{m}/memory.memsw.usage_in_bytes"), "75497472\n");
        let c = "/sys/fs/cgroup/cpu,cpuacct";
        self.put(&format!("{c}/cpu.cfs_quota_us"), "50000\n");
        self.put(&format!("{c}/cpu.cfs_period_us"), "100000\n");
        self.put(&format!("{c}/cpuacct.usage"), "3000000000\n");
        self.put(&format!("{c}/cpuacct.stat"), "user 200\nsystem 100\n");
    }
}

const STAT_A: &str = "cpu  1000 100 500 8000 200 10 20 5 50 10\n\
cpu0 500 50 250 4000 100 5 10 3 25 5\n\
cpu2 500 50 250 4000 100 5 10 2 25 5\n\
intr 12345\nctxt 999\nbtime 1700000000\nprocesses 5000\n\
procs_running 2\nprocs_blocked 1\n";

/// STAT_A plus 1000 ticks on each line: user +300 (of which guest +100),
/// system +100, idle +500, iowait +100.
const STAT_B: &str = "cpu  1300 100 600 8500 300 10 20 5 150 10\n\
cpu0 650 50 300 4250 150 5 10 3 75 5\n\
cpu2 650 50 300 4250 150 5 10 2 75 5\n\
intr 12345\nctxt 999\nbtime 1700000000\nprocesses 5000\n\
procs_running 2\nprocs_blocked 1\n";

const MEMINFO: &str = "MemTotal:       16000000 kB\n\
MemFree:         4000000 kB\n\
MemAvailable:   12000000 kB\n\
Buffers:          500000 kB\n\
Cached:          6000000 kB\n\
Shmem:            100000 kB\n\
SReclaimable:     300000 kB\n\
SwapTotal:       2000000 kB\n\
SwapFree:        1500000 kB\n\
HugePages_Total:       4\n\
HugePages_Free:        2\n\
HugePages_Rsvd:        1\n\
HugePages_Surp:        0\n\
Hugepagesize:       2048 kB\n";

fn a(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

struct Out {
    status: Status,
    stdout: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.stdout))
    }

    #[track_caller]
    fn ok(&self) -> Value {
        assert!(
            self.status.is_success(),
            "{:?}\n{}",
            self.status,
            self.stdout
        );
        let v = self.json();
        assert_eq!(v["ok"], true);
        v
    }

    #[track_caller]
    fn fails(&self, exit_code: i32, code: &str) {
        assert_eq!(
            self.status.exit_code(),
            exit_code,
            "{:?}\n{}",
            self.status,
            self.stdout
        );
        let reason = self.status.reason.clone().unwrap_or_default();
        assert!(
            reason.starts_with(&format!("[{code}] ")),
            "{code}: {reason}"
        );
        if !self.stdout.is_empty() {
            let v = self.json();
            assert_eq!(v["ok"], false, "{}", self.stdout);
            assert_eq!(v["error"]["code"], code, "{}", self.stdout);
        }
    }

    fn reason(&self) -> String {
        self.status.reason.clone().unwrap_or_default()
    }
}

fn call(host: &Host, verb: &str, args: &[(&str, &str)]) -> Out {
    let mut stdin = std::io::empty();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
    let status = run(host, verb, &a(args), &mut io).unwrap();
    Out {
        status,
        stdout: String::from_utf8(out).unwrap(),
    }
}

fn close(a: &Value, b: f64) -> bool {
    a.as_f64().is_some_and(|a| (a - b).abs() < 1e-6)
}

const VERBS: &[&str] = &[
    "info", "uptime", "load", "memory", "cpu", "disk", "env.list",
];

// ---------------------------------------------------------------------------
// Arguments, help and error codes
// ---------------------------------------------------------------------------

/// The option names a verb's help usage lists as `[name=...]`.
fn usage_options(verb: &str) -> Vec<String> {
    let v = SYSTEM_HELP.verbs.iter().find(|v| v.name == verb).unwrap();
    let usage = v.detail.as_ref().unwrap().usage;
    let mut out: Vec<String> = usage
        .split('[')
        .skip(1)
        .filter_map(|s| s.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| k.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
        .collect();
    out.sort();
    out
}

#[test]
fn accepted_options_match_help_usage_exactly() {
    for verb in VERBS {
        let mut want: Vec<String> = args::accepted(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.push("input".into());
        want.sort();
        assert_eq!(usage_options(verb), want, "{verb}");
    }
    assert!(args::accepted("nope").is_none());
}

#[test]
fn help_lines_fit_80_columns_and_examples_parse() {
    for v in SYSTEM_HELP.verbs {
        let text = crate::core::help::render_verb("system", v).unwrap();
        for l in text.lines() {
            assert!(l.len() <= 80, "{}: {l:?}", v.name);
        }
        let ex = v.detail.as_ref().unwrap().example;
        assert!(ex.starts_with("resh --json-pretty system://."), "{ex}");
        let out = v.detail.as_ref().unwrap().example_output.unwrap();
        let body = out.split("\n\nShown").next().unwrap();
        let _: Value = serde_json::from_str(body).unwrap();
    }
    let h = crate::core::help::render_handle("system", &SYSTEM_HELP, SYSTEM_VERBS);
    assert!(h.lines().all(|l| l.len() <= 80));
}

#[test]
fn unknown_arguments_are_refused_with_a_suggestion() {
    let fx = Fx::new();
    let h = fx.host();
    for verb in VERBS {
        let o = call(&h, verb, &[("bogus_option", "1")]);
        o.fails(2, "system.invalid_argument");
        assert!(o.reason().contains("bogus_option"), "{}", o.reason());
    }
    let o = call(&h, "memory", &[("include_swpa", "false")]);
    o.fails(2, "system.invalid_argument");
    assert!(
        o.reason().contains("did you mean `include_swap`?"),
        "{}",
        o.reason()
    );
    // Inside input too.
    let o = call(&h, "load", &[("input", r#"{"normalise_per_cpu":true}"#)]);
    o.fails(2, "system.invalid_argument");
    assert!(o.reason().contains("normalize_per_cpu"), "{}", o.reason());
}

#[test]
fn timeout_ms_and_dry_run_are_refused_where_not_supported() {
    let fx = Fx::new();
    let h = fx.host();
    for verb in ["uptime", "load", "memory", "cpu", "env.list"] {
        let o = call(&h, verb, &[("timeout_ms", "100")]);
        o.fails(2, "system.invalid_argument");
        assert!(
            o.reason().contains("does not take timeout_ms"),
            "{}",
            o.reason()
        );
    }
    for verb in VERBS {
        let o = call(&h, verb, &[("dry_run", "false")]);
        o.fails(2, "system.invalid_argument");
        assert!(o.reason().contains("dry_run"), "{}", o.reason());
    }
    for verb in ["info", "disk"] {
        call(&h, verb, &[("timeout_ms", "0")]).fails(2, "system.invalid_argument");
        call(&h, verb, &[("timeout_ms", "soon")]).fails(2, "system.invalid_argument");
    }
}

#[test]
fn bad_values_are_refused_naming_the_argument() {
    let fx = Fx::new();
    let h = fx.host();
    let cases: &[(&str, &[(&str, &str)], &str)] = &[
        ("memory", &[("include_swap", "maybe")], "include_swap"),
        ("uptime", &[("format", "xml")], "format"),
        ("load", &[("min_cpu_count", "0")], "min_cpu_count"),
        ("load", &[("min_cpu_count", "-1")], "min_cpu_count"),
        (
            "cpu",
            &[("sample_duration_ms", "70000")],
            "sample_duration_ms",
        ),
        ("cpu", &[("sample_duration_ms", "10")], "sample_duration_ms"),
        ("cpu", &[("sample_min_ms", "0")], "sample_min_ms"),
        ("disk", &[("max_mounts", "0")], "max_mounts"),
        ("disk", &[("mount_points", "relative/dir")], "mount_points"),
        ("disk", &[("fs_types", "ext4,")], "fs_types"),
        ("env.list", &[("pid", "0")], "pid"),
        ("env.list", &[("pid", "abc")], "pid"),
        ("env.list", &[("sort_by", "size")], "sort_by"),
        ("env.list", &[("sort_order", "up")], "sort_order"),
        ("env.list", &[("regex_filters", "(")], "regex_filters"),
        ("env.list", &[("max_vars", "0")], "max_vars"),
        ("info", &[("scopes", "kernal")], "kernal"),
        ("info", &[("scopes", "")], "scopes"),
        ("info", &[("per_cpu", "true")], "per_cpu"),
        ("info", &[("fields", "load.load_2m")], "load_2m"),
        ("info", &[("fields", "disk")], "disk"),
        ("info", &[("fields", "bogus.x")], "bogus"),
        (
            "info",
            &[("sample_duration_ms", "500"), ("timeout_ms", "500")],
            "timeout_ms",
        ),
    ];
    for (verb, args, needle) in cases {
        let o = call(&h, verb, args);
        o.fails(2, "system.invalid_argument");
        assert!(
            o.reason().contains(needle),
            "{verb} {args:?}: {}",
            o.reason()
        );
    }
    let o = call(&h, "info", &[("scopes", "kernal")]);
    assert!(
        o.reason().contains("did you mean `kernel`?"),
        "{}",
        o.reason()
    );
}

#[test]
fn input_must_be_a_json_object_and_words_override_it() {
    let fx = Fx::new();
    let h = fx.host();
    call(&h, "uptime", &[("input", "[1]")]).fails(2, "system.invalid_argument");
    call(&h, "uptime", &[("input", "{nope")]).fails(2, "system.invalid_argument");
    // Partial input uses defaults for the rest (no option is required).
    let v = call(&h, "memory", &[("input", r#"{"include_hugepages":false}"#)]).ok();
    assert!(v.get("hugepages").is_none());
    assert!(v["cgroup"].is_object());
    // A word overrides the same key in input.
    let o = call(
        &h,
        "uptime",
        &[("input", r#"{"format":"json"}"#), ("format", "text")],
    );
    assert!(o.stdout.starts_with("System Uptime"), "{}", o.stdout);
    // Typed JSON values work as well as strings.
    let v = call(&h, "load", &[("input", r#"{"min_cpu_count":8}"#)]).ok();
    assert!(close(&v["load_1m_per_cpu"], 0.1));
}

#[test]
fn a_text_failure_prints_nothing_on_stdout() {
    let fx = Fx::new();
    fx.rm("/proc/uptime");
    let o = call(&fx.host(), "uptime", &[("format", "text")]);
    o.fails(1, "system.uptime_unavailable");
    assert!(o.stdout.is_empty());
    let o = call(
        &fx.host(),
        "uptime",
        &[("input", r#"{"format":"text","x":1}"#)],
    );
    o.fails(2, "system.invalid_argument");
    assert!(o.stdout.is_empty());
}

#[test]
fn unknown_verb_is_a_usage_error() {
    let fx = Fx::new();
    let o = call(&fx.host(), "uptim", &[]);
    o.fails(2, "system.unknown_verb");
    assert!(
        o.reason().contains("did you mean `uptime`?"),
        "{}",
        o.reason()
    );
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../../docs/SystemInformation/system.md");
    for (code, exit_code) in error::ERROR_CODES {
        assert!(is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} not in system.md"
        );
        assert!([1, 2, 124].contains(exit_code));
    }
    assert!(doc.contains("`system.invalid_target`"));
}

#[test]
fn url_with_a_target_is_refused() {
    for ok in [
        "system://",
        "system:///",
        "system://--help",
        "system://help",
    ] {
        assert!(
            SystemHandle::from_url(&Url::parse(ok).unwrap()).is_ok(),
            "{ok}"
        );
    }
    for bad in ["system://localhost", "system:///etc"] {
        assert!(
            SystemHandle::from_url(&Url::parse(bad).unwrap()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn help_requests_are_exact() {
    assert_eq!(help_request(&a(&[("help", "")])), Some(None));
    assert_eq!(
        help_request(&a(&[("--help", "memory")])),
        Some(Some("memory".to_string()))
    );
    assert_eq!(help_request(&a(&[("input", "--help")])), Some(None));
    assert_eq!(
        help_request(&a(&[("input", "--help=cpu")])),
        Some(Some("cpu".to_string()))
    );
    assert_eq!(
        help_request(&a(&[("input", r#"{"names":["my-host"]}"#)])),
        None
    );
    assert_eq!(help_request(&a(&[("format", "text")])), None);
    // Through the handle: the verb's own help.
    let mut stdin = std::io::empty();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
    SystemHandle
        .call("load", &a(&[("--help", "true")]), &mut io)
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Verb: load"), "{text}");
}

// ---------------------------------------------------------------------------
// uptime
// ---------------------------------------------------------------------------

#[test]
fn uptime_reads_proc_uptime_and_btime() {
    let fx = Fx::new();
    let v = call(&fx.host(), "uptime", &[]).ok();
    assert!(close(&v["uptime_seconds"], 1000.5));
    assert!(close(&v["idle_seconds"], 3000.25));
    // Two CPUs in /proc/stat.
    assert!(close(&v["idle_seconds_per_cpu"], 1500.125));
    assert_eq!(v["boot_time_unix"], 1_700_000_000);
    assert_eq!(v["uptime_human"], "16m 40s");
    assert!(v.get("raw").is_none() && v.get("paths").is_none());
    assert_eq!(v["warnings"], json!([]));

    let v = call(
        &fx.host(),
        "uptime",
        &[
            ("include_idle", "false"),
            ("include_boot_time", "no"),
            ("include_human", "0"),
            ("include_raw", "yes"),
            ("include_paths", "on"),
        ],
    )
    .ok();
    for k in [
        "idle_seconds",
        "idle_seconds_per_cpu",
        "boot_time_unix",
        "uptime_human",
    ] {
        assert!(v.get(k).is_none(), "{k}");
    }
    assert_eq!(v["raw"]["proc_uptime_line"], "1000.50 3000.25");
    assert_eq!(v["raw"]["proc_stat_btime_line"], "btime 1700000000");
    assert_eq!(v["paths"]["uptime"], "/proc/uptime");
}

#[test]
fn uptime_failures_and_fallbacks() {
    let fx = Fx::new();
    fx.put("/proc/uptime", "not-a-number 1\n");
    call(&fx.host(), "uptime", &[]).fails(1, "system.uptime_parse_error");
    fx.put("/proc/uptime", "");
    call(&fx.host(), "uptime", &[]).fails(1, "system.uptime_parse_error");
    fx.rm("/proc/uptime");
    call(&fx.host(), "uptime", &[]).fails(1, "system.uptime_unavailable");
    // No idle field, no btime: warnings and a computed boot time.
    fx.put("/proc/uptime", "100.0\n");
    fx.put("/proc/stat", "cpu 1 2 3 4\ncpu0 1 2 3 4\n");
    let v = call(&fx.host(), "uptime", &[]).ok();
    assert!(v.get("idle_seconds").is_none());
    let now = chrono::Utc::now().timestamp();
    assert!((v["boot_time_unix"].as_i64().unwrap() - (now - 100)).abs() <= 2);
    assert_eq!(v["warnings"].as_array().unwrap().len(), 2, "{v}");
    assert_eq!(metrics::human_duration(90061.0), "1d 1h 1m 01s");
}

#[test]
fn uptime_text() {
    let fx = Fx::new();
    let o = call(&fx.host(), "uptime", &[("format", "text")]);
    assert!(o.status.is_success());
    assert!(o.stdout.contains("Uptime    : 16m 40s"), "{}", o.stdout);
    assert!(o.stdout.contains("Boot Time : 2023-11-14T22:13:20Z"));
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn load_reads_loadavg_and_normalizes_per_online_cpu() {
    let fx = Fx::new();
    let v = call(&fx.host(), "load", &[]).ok();
    assert!(close(&v["load_1m"], 0.8));
    assert!(close(&v["load_5m"], 0.4));
    assert!(close(&v["load_15m"], 0.2));
    assert_eq!(v["cpu_count_logical"], 2);
    assert!(close(&v["load_1m_per_cpu"], 0.4));
    assert!(close(&v["load_15m_per_cpu"], 0.1));
    assert_eq!(v["runnable_processes"], 3);
    assert_eq!(v["total_processes"], 412);
    assert_eq!(v["human"]["status"], "normal");

    let v = call(&fx.host(), "load", &[("min_cpu_count", "8")]).ok();
    assert!(close(&v["load_1m_per_cpu"], 0.1));
    assert_eq!(v["human"]["status"], "normal");

    let v = call(
        &fx.host(),
        "load",
        &[
            ("normalize_per_cpu", "false"),
            ("include_queue", "false"),
            ("include_human", "false"),
            ("include_raw", "true"),
            ("include_paths", "true"),
        ],
    )
    .ok();
    for k in [
        "load_1m_per_cpu",
        "cpu_count_logical",
        "runnable_processes",
        "human",
    ] {
        assert!(v.get(k).is_none(), "{k}");
    }
    assert_eq!(v["raw"]["proc_loadavg_line"], "0.80 0.40 0.20 3/412 9999");
    assert_eq!(v["paths"]["load"], "/proc/loadavg");
}

#[test]
fn load_failures_and_odd_formats() {
    let fx = Fx::new();
    fx.put("/proc/loadavg", "0.10 0.20\n");
    call(&fx.host(), "load", &[]).fails(1, "system.load_parse_error");
    fx.put("/proc/loadavg", "x y z 1/2 3\n");
    call(&fx.host(), "load", &[]).fails(1, "system.load_parse_error");
    fx.put("/proc/loadavg", "2.00 1.00 0.50\n");
    let v = call(&fx.host(), "load", &[]).ok();
    assert!(v.get("runnable_processes").is_none());
    assert_eq!(v["human"]["status"], "busy");
    assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
    fx.put("/proc/loadavg", "9.00 1.00 0.50 1/2 3\n");
    assert_eq!(
        call(&fx.host(), "load", &[]).ok()["human"]["status"],
        "overloaded"
    );
    fx.put("/proc/loadavg", "0.01 0.0 0.0 1/2 3\n");
    assert_eq!(
        call(&fx.host(), "load", &[]).ok()["human"]["status"],
        "idle"
    );
    // No CPU count: no per-CPU values, a warning.
    fx.rm("/proc/stat");
    let v = call(&fx.host(), "load", &[]).ok();
    assert!(v.get("load_1m_per_cpu").is_none());
    assert!(!v["warnings"].as_array().unwrap().is_empty());
    fx.rm("/proc/loadavg");
    call(&fx.host(), "load", &[]).fails(1, "system.load_unavailable");
}

#[test]
fn load_text() {
    let fx = Fx::new();
    let o = call(&fx.host(), "load", &[("format", "text")]);
    assert!(o.stdout.contains("1m  : 0.80"), "{}", o.stdout);
    assert!(o.stdout.contains("Logical CPUs : 2"));
}

// ---------------------------------------------------------------------------
// memory and cgroups
// ---------------------------------------------------------------------------

#[test]
fn memory_reports_meminfo_in_bytes() {
    let fx = Fx::new();
    let v = call(&fx.host(), "memory", &[]).ok();
    let s = &v["system"];
    assert_eq!(s["mem_total_bytes"], 16_000_000u64 * 1024);
    assert_eq!(s["mem_available_bytes"], 12_000_000u64 * 1024);
    assert_eq!(s["mem_used_bytes"], 4_000_000u64 * 1024);
    assert!(close(&s["mem_used_pct"], 25.0));
    assert_eq!(s["swap_used_bytes"], 500_000u64 * 1024);
    assert!(close(&s["swap_used_pct"], 25.0));
    assert_eq!(s["sreclaimable_bytes"], 300_000u64 * 1024);
    let hp = &v["hugepages"];
    assert_eq!(hp["total"], 4);
    assert_eq!(hp["reserved"], 1);
    assert_eq!(hp["page_bytes"], 2 * 1024 * 1024);
    assert!(
        v["human"]["system_summary"]
            .as_str()
            .unwrap()
            .starts_with("15.3 GiB total, 3.8 GiB used (25.0%)")
    );
}

#[test]
fn memory_include_swap_false_omits_swap() {
    let fx = Fx::new();
    let v = call(&fx.host(), "memory", &[("include_swap", "false")]).ok();
    for k in [
        "swap_total_bytes",
        "swap_free_bytes",
        "swap_used_bytes",
        "swap_used_pct",
    ] {
        assert!(v["system"].get(k).is_none(), "{k}");
    }
    assert!(v["cgroup"].get("swap_usage_bytes").is_none());
    assert!(
        !v["human"]["system_summary"]
            .as_str()
            .unwrap()
            .contains("swap")
    );
    let o = call(
        &fx.host(),
        "memory",
        &[("include_swap", "false"), ("format", "text")],
    );
    assert!(!o.stdout.contains("Swap:"), "{}", o.stdout);
}

#[test]
fn memory_cgroup_v2_uses_the_smallest_limit_up_the_tree() {
    let fx = Fx::new();
    let v = call(
        &fx.host(),
        "memory",
        &[("include_paths", "true"), ("include_raw", "true")],
    )
    .ok();
    let c = &v["cgroup"];
    assert_eq!(c["available"], true);
    assert_eq!(c["unified"], true);
    assert_eq!(c["memory_limit_bytes"], 536_870_912u64);
    assert_eq!(c["memory_usage_bytes"], 134_217_728u64);
    assert!(close(&c["memory_used_pct"], 25.0));
    assert!(c.get("swap_limit_bytes").is_none(), "swap max is unlimited");
    assert_eq!(c["swap_usage_bytes"], 1_048_576);
    let paths: Vec<&str> = v["paths"]["cgroup_memory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/sys/fs/cgroup/app/svc/memory.max"));
    assert!(paths.contains(&"/sys/fs/cgroup/app/memory.max"));
    assert_eq!(
        v["raw"]["cgroup"]["/sys/fs/cgroup/app/svc/memory.current"],
        "134217728"
    );
    assert!(
        v["human"]["cgroup_summary"]
            .as_str()
            .unwrap()
            .starts_with("0.5 GiB limit")
    );
    // A lower limit on the parent wins.
    fx.put("/sys/fs/cgroup/app/memory.max", "268435456\n");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["cgroup"]["memory_limit_bytes"], 268_435_456u64);
    // "max" everywhere: no limit.
    fx.put("/sys/fs/cgroup/app/memory.max", "max\n");
    fx.put("/sys/fs/cgroup/app/svc/memory.max", "max\n");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert!(v["cgroup"].get("memory_limit_bytes").is_none());
    assert_eq!(v["cgroup"]["available"], true);
    assert!(
        v["human"]["cgroup_summary"]
            .as_str()
            .unwrap()
            .starts_with("no limit")
    );
}

#[test]
fn memory_cgroup_v2_in_a_container_namespace() {
    // Docker with a private cgroup namespace: "0::/" and the group mounted
    // at /sys/fs/cgroup.
    let fx = Fx::new();
    fx.rm("/sys/fs/cgroup");
    fx.put("/proc/self/cgroup", "0::/\n");
    fx.put("/sys/fs/cgroup/memory.max", "268435456\n");
    fx.put("/sys/fs/cgroup/memory.current", "1000\n");
    fx.put("/sys/fs/cgroup/memory.swap.max", "0\n");
    fx.put("/sys/fs/cgroup/memory.swap.current", "0\n");
    fx.put("/sys/fs/cgroup/cpu.max", "max 100000\n");
    fx.put("/sys/fs/cgroup/cpu.stat", "usage_usec 10\n");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["cgroup"]["memory_limit_bytes"], 268_435_456u64);
    assert_eq!(v["cgroup"]["swap_limit_bytes"], 0);
    let c = call(
        &fx.host(),
        "cpu",
        &[("sample_duration_ms", "1"), ("sample_min_ms", "1")],
    )
    .ok();
    assert!(c["cgroup"].get("cpu_quota_cores").is_none());
    assert_eq!(c["cgroup"]["cpu_period_us"], 100_000);
}

#[test]
fn memory_cgroup_v1_reads_limit_usage_and_memsw() {
    let fx = Fx::new();
    fx.cgroup_v1();
    let v = call(&fx.host(), "memory", &[]).ok();
    let c = &v["cgroup"];
    assert_eq!(c["unified"], false);
    assert_eq!(c["memory_limit_bytes"], 268_435_456u64);
    assert_eq!(c["memory_usage_bytes"], 67_108_864u64);
    // memsw is memory + swap.
    assert_eq!(c["swap_limit_bytes"], 268_435_456u64);
    assert_eq!(c["swap_usage_bytes"], 8_388_608u64);
    // The v1 "unlimited" counter is no limit.
    fx.put(
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "9223372036854771712\n",
    );
    let v = call(&fx.host(), "memory", &[]).ok();
    assert!(v["cgroup"].get("memory_limit_bytes").is_none());
    assert!(v["cgroup"].get("swap_limit_bytes").is_none());
}

#[test]
fn memory_cgroup_hybrid_prefers_the_v1_memory_controller() {
    let fx = Fx::new();
    fx.cgroup_v1();
    fx.put(
        "/proc/self/cgroup",
        "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc\n",
    );
    let mut mi = std::fs::read_to_string(fx.path("/proc/self/mountinfo")).unwrap();
    mi.push_str("50 22 0:40 /docker/abc /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n");
    fx.put("/proc/self/mountinfo", &mi);
    fx.mkdir("/sys/fs/cgroup/unified");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["cgroup"]["unified"], false);
    assert_eq!(v["cgroup"]["memory_limit_bytes"], 268_435_456u64);
}

#[test]
fn memory_without_cgroup_information() {
    let fx = Fx::new();
    fx.rm("/proc/self/mountinfo");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["cgroup"]["available"], false);
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("cgroup memory not available"))
    );
    // A group without the memory controller.
    let fx = Fx::new();
    fx.rm("/sys/fs/cgroup/app/svc/memory.current");
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["cgroup"]["available"], false);
    let v = call(&fx.host(), "memory", &[("include_cgroup", "false")]).ok();
    assert!(v.get("cgroup").is_none());
    assert_eq!(v["warnings"], json!([]));
}

#[test]
fn memory_failures_and_fallbacks() {
    let fx = Fx::new();
    fx.put("/proc/meminfo", "MemFree: 10 kB\n");
    call(&fx.host(), "memory", &[]).fails(1, "system.memory_meminfo_parse_error");
    fx.put("/proc/meminfo", "garbage\n\n");
    call(&fx.host(), "memory", &[]).fails(1, "system.memory_meminfo_parse_error");
    // No MemAvailable (old kernels): used = total - free - buffers - cached.
    fx.put(
        "/proc/meminfo",
        "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 300 kB\n",
    );
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["system"]["mem_used_bytes"], 500 * 1024);
    assert_eq!(v["hugepages"]["available"], false);
    // Odd values never underflow.
    fx.put(
        "/proc/meminfo",
        "MemTotal: 100 kB\nMemAvailable: 200 kB\nSwapTotal: 10 kB\nSwapFree: 20 kB\n",
    );
    let v = call(&fx.host(), "memory", &[]).ok();
    assert_eq!(v["system"]["mem_used_bytes"], 0);
    assert_eq!(v["system"]["swap_used_bytes"], 0);
    fx.rm("/proc/meminfo");
    call(&fx.host(), "memory", &[]).fails(1, "system.memory_meminfo_unavailable");
}

#[test]
fn memory_text() {
    let fx = Fx::new();
    let o = call(&fx.host(), "memory", &[("format", "text")]);
    assert!(o.stdout.contains("Limit       : 0.5 GiB"), "{}", o.stdout);
    assert!(o.stdout.contains("Page Size   : 2.0 MiB"), "{}", o.stdout);
}

// ---------------------------------------------------------------------------
// cpu
// ---------------------------------------------------------------------------

/// A host whose /proc/stat changes from STAT_A to STAT_B between samples.
fn two_samples(fx: &Fx) -> (Host, Arc<Mutex<Vec<u64>>>) {
    let p = fx.path("/proc/stat");
    let pauses = Arc::new(Mutex::new(Vec::new()));
    let seen = pauses.clone();
    let host = fx.host().with_pause(move |ms| {
        seen.lock().unwrap().push(ms);
        std::fs::write(&p, STAT_B).unwrap();
    });
    (host, pauses)
}

#[test]
fn cpu_utilization_is_the_delta_between_two_samples() {
    let fx = Fx::new();
    let (host, pauses) = two_samples(&fx);
    let v = call(&host, "cpu", &[("include_cgroup", "false")]).ok();
    assert_eq!(*pauses.lock().unwrap(), vec![250]);
    assert_eq!(v["sample_duration_ms"], 250);
    let s = &v["system"];
    // 1000 ticks: user 300 (guest 100 within it), system 100, idle 500,
    // iowait 100. iowait counts as idle; guest is not counted twice.
    assert!(close(&s["user_pct"], 30.0), "{s}");
    assert!(close(&s["system_pct"], 10.0));
    assert!(close(&s["idle_pct"], 50.0));
    assert!(close(&s["iowait_pct"], 10.0));
    assert!(close(&s["guest_pct"], 10.0));
    assert!(close(&s["utilization_pct"], 40.0));
    assert_eq!(s["logical_count"], 2);
    // Per-CPU ids come from the line names (cpu1 is offline).
    let ids: Vec<u64> = v["per_cpu"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![0, 2]);
    assert!(close(&v["per_cpu"][1]["utilization_pct"], 40.0));
    assert_eq!(v["human"]["status"], "normal");
}

#[test]
fn cpu_zero_delta_omits_percentages() {
    let fx = Fx::new();
    let host = fx.host().with_pause(|_| {});
    let v = call(&host, "cpu", &[("sample_duration_ms", "0")]).ok();
    // 0 uses sample_min_ms.
    assert_eq!(v["sample_duration_ms"], 50);
    assert!(v["system"].get("utilization_pct").is_none());
    assert_eq!(v["human"]["status"], "unknown");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("no CPU time passed"))
    );
}

#[test]
fn cpu_topology_and_frequency() {
    let fx = Fx::new();
    // Two sockets, each with core_id 0: two physical cores.
    for (cpu, core, pkg, cur, max) in [
        (0, 0, 0, 1_000_000, 3_000_000),
        (2, 0, 1, 2_000_000, 4_000_000),
    ] {
        let d = format!("/sys/devices/system/cpu/cpu{cpu}");
        fx.put(&format!("{d}/topology/core_id"), &format!("{core}\n"));
        fx.put(
            &format!("{d}/topology/physical_package_id"),
            &format!("{pkg}\n"),
        );
        fx.put(
            &format!("{d}/cpufreq/scaling_cur_freq"),
            &format!("{cur}\n"),
        );
        fx.put(
            &format!("{d}/cpufreq/cpuinfo_max_freq"),
            &format!("{max}\n"),
        );
    }
    let (host, _) = two_samples(&fx);
    let v = call(
        &host,
        "cpu",
        &[("include_raw", "true"), ("include_paths", "true")],
    )
    .ok();
    let s = &v["system"];
    assert_eq!(s["physical_count"], 2);
    assert_eq!(s["socket_count"], 2);
    assert_eq!(s["frequency_current_hz"], 1_500_000_000u64);
    assert_eq!(s["frequency_max_hz"], 4_000_000_000u64);
    assert_eq!(v["per_cpu"][1]["socket_id"], 1);
    assert_eq!(v["per_cpu"][1]["frequency_current_hz"], 2_000_000_000u64);
    assert_eq!(
        v["raw"]["frequency"]["cpu2_cpuinfo_max_freq_khz"],
        4_000_000
    );
    assert_eq!(v["raw"]["proc_stat_end"], STAT_B);
    assert_eq!(v["paths"]["stat"], "/proc/stat");
    // Without /sys: warnings, no figures.
    let fx = Fx::new();
    let (host, _) = two_samples(&fx);
    let v = call(&host, "cpu", &[]).ok();
    assert!(v["system"].get("physical_count").is_none());
    assert!(v["system"].get("frequency_current_hz").is_none());
    assert!(v["warnings"].as_array().unwrap().len() >= 2);
    fx.put("/proc/stat", STAT_A);
    let v = call(
        &host,
        "cpu",
        &[
            ("include_topology", "false"),
            ("include_frequency", "false"),
            ("include_cgroup", "false"),
            ("per_cpu", "false"),
            ("include_human", "false"),
        ],
    )
    .ok();
    for k in ["per_cpu", "cgroup", "human"] {
        assert!(v.get(k).is_none(), "{k}");
    }
    assert_eq!(v["warnings"], json!([]));
}

#[test]
fn cpu_cgroup_v2_quota_is_the_smallest_up_the_tree() {
    let fx = Fx::new();
    let (host, _) = two_samples(&fx);
    let v = call(&host, "cpu", &[]).ok();
    let c = &v["cgroup"];
    assert_eq!(c["available"], true);
    assert_eq!(c["unified"], true);
    assert!(close(&c["cpu_quota_cores"], 1.5));
    assert_eq!(c["cpu_quota_us"], 150_000);
    assert_eq!(c["cpu_period_us"], 100_000);
    assert!(close(&c["usage_seconds"], 2.5));
    assert!(close(&c["usage_user_seconds"], 2.0));
    assert!(close(&c["usage_system_seconds"], 0.5));
    fx.put("/sys/fs/cgroup/app/cpu.max", "50000 100000\n");
    let v = call(&host, "cpu", &[]).ok();
    assert!(close(&v["cgroup"]["cpu_quota_cores"], 0.5));
}

#[test]
fn cpu_cgroup_v1_quota_and_cpuacct() {
    let fx = Fx::new();
    fx.cgroup_v1();
    let (host, _) = two_samples(&fx);
    let v = call(&host, "cpu", &[]).ok();
    let c = &v["cgroup"];
    assert_eq!(c["unified"], false);
    assert!(close(&c["cpu_quota_cores"], 0.5));
    assert!(close(&c["usage_seconds"], 3.0));
    let hz = fx.host().clock_ticks() as f64;
    assert!(close(&c["usage_user_seconds"], 200.0 / hz));
    // -1 is no quota.
    fx.put("/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us", "-1\n");
    let v = call(&host, "cpu", &[]).ok();
    assert!(v["cgroup"].get("cpu_quota_cores").is_none());
    assert_eq!(v["cgroup"]["cpu_period_us"], 100_000);
}

#[test]
fn cpu_failures() {
    let fx = Fx::new();
    fx.put("/proc/stat", "cpu0 1 2 3 4\n");
    call(
        &fx.host(),
        "cpu",
        &[("sample_duration_ms", "1"), ("sample_min_ms", "1")],
    )
    .fails(1, "system.cpu_stat_parse_error");
    fx.put("/proc/stat", "cpu 1 2 x 4\n");
    call(
        &fx.host(),
        "cpu",
        &[("sample_duration_ms", "1"), ("sample_min_ms", "1")],
    )
    .fails(1, "system.cpu_stat_parse_error");
    fx.put("/proc/stat", "cpu 1 2\n");
    call(
        &fx.host(),
        "cpu",
        &[("sample_duration_ms", "1"), ("sample_min_ms", "1")],
    )
    .fails(1, "system.cpu_stat_parse_error");
    fx.rm("/proc/stat");
    call(
        &fx.host(),
        "cpu",
        &[("sample_duration_ms", "1"), ("sample_min_ms", "1")],
    )
    .fails(1, "system.cpu_stat_unavailable");
    // The file disappears between the samples.
    let fx = Fx::new();
    let p = fx.path("/proc/stat");
    let host = fx
        .host()
        .with_pause(move |_| std::fs::remove_file(&p).unwrap());
    let o = call(&host, "cpu", &[]);
    o.fails(1, "system.cpu_stat_unavailable");
    assert!(o.reason().contains("second sample"), "{}", o.reason());
}

#[test]
fn cpu_text() {
    let fx = Fx::new();
    let (host, _) = two_samples(&fx);
    let o = call(&host, "cpu", &[("format", "text")]);
    assert!(o.stdout.contains("Utilization  : 40.0%"), "{}", o.stdout);
    assert!(
        o.stdout.contains("Quota        : 1.50 CPUs"),
        "{}",
        o.stdout
    );
}

// ---------------------------------------------------------------------------
// disk
// ---------------------------------------------------------------------------

/// Mounts: the fixture root as `/`, `/data`, `/mnt/my disk` (escaped),
/// and pseudo filesystems.
fn disk_fx() -> Fx {
    let fx = Fx::new();
    fx.mkdir("/data");
    fx.mkdir("/mnt/my disk");
    fx.put(
        "/proc/self/mounts",
        "/dev/sda2 / ext4 rw 0 0\n\
         proc /proc proc rw 0 0\n\
         tmpfs /run tmpfs rw 0 0\n\
         /dev/nvme0n1p1 /data xfs rw 0 0\n\
         /dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n\
         overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n",
    );
    fx.mkdir("/var/lib/docker/overlay2/x/merged");
    fx.put(
        "/proc/diskstats",
        "   8       0 sda 100 0 2000 50 200 0 4000 60 0 70 110 0 0 0 0\n\
         \x20  8       2 sda2 90 0 1800 40 190 0 3800 55 0 60 95 0 0 0 0\n\
         259       0 nvme0n1 10 0 80 5 20 0 160 6 1 7 11 0 0 0 0\n",
    );
    fx
}

#[test]
fn disk_reports_real_filesystems() {
    let fx = disk_fx();
    let v = call(&fx.host(), "disk", &[]).ok();
    let mps: Vec<&str> = v["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["mount_point"].as_str().unwrap())
        .collect();
    // proc and tmpfs are skipped; overlay is real storage.
    assert_eq!(
        mps,
        vec![
            "/",
            "/data",
            "/mnt/my disk",
            "/var/lib/docker/overlay2/x/merged"
        ]
    );
    let root = &v["mounts"][0];
    let st = host::statvfs_at(fx.dir.path()).unwrap();
    assert_eq!(root["total_bytes"], st.total_bytes);
    assert_eq!(root["inodes_total"], st.inodes_total);
    assert_eq!(root["tags"], json!(["rootfs"]));
    assert_eq!(root["fs_type"], "ext4");
    assert_eq!(root["io_device"], "sda");
    assert_eq!(v["mounts"][1]["io_device"], "nvme0n1");
    assert_eq!(v["mounts"][2]["tags"], json!(["data"]));
    let names: Vec<&str> = v["io"]["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["sda", "nvme0n1"]);
    let sda = &v["io"]["devices"][0];
    assert_eq!(sda["read_bytes"], 2000 * 512);
    assert_eq!(sda["writes_completed"], 200);
    assert_eq!(sda["time_in_io_ms"], 70);
    assert_eq!(v["human"]["summaries"].as_array().unwrap().len(), 4, "{v}");
    assert_eq!(v["mounts_truncated"], false);
}

#[test]
fn disk_filters_and_limits() {
    let fx = disk_fx();
    let h = fx.host();
    let v = call(&h, "disk", &[("include_virtual", "true")]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 6);
    assert_eq!(v["mounts"][1]["virtual_fs"], true);
    let v = call(&h, "disk", &[("fs_types", "ext4")]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 2);
    let v = call(&h, "disk", &[("devices", "/dev/nvme0n1p1")]).ok();
    assert_eq!(v["mounts"][0]["mount_point"], "/data");
    let v = call(
        &h,
        "disk",
        &[("input", r#"{"mount_points":["/mnt/my disk/"]}"#)],
    )
    .ok();
    assert_eq!(v["mounts"][0]["device"], "/dev/sdb1");
    let v = call(&h, "disk", &[("max_mounts", "2")]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 2);
    assert_eq!(v["mounts_truncated"], true);
    let v = call(
        &h,
        "disk",
        &[
            ("mount_points", "/"),
            ("include_io", "false"),
            ("include_fs_types", "false"),
            ("include_human", "false"),
            ("include_raw", "true"),
            ("include_paths", "true"),
        ],
    )
    .ok();
    let m = &v["mounts"][0];
    assert!(m.get("fs_type").is_none() && m.get("io_device").is_none());
    assert!(v.get("io").is_none() && v.get("human").is_none());
    assert!(v["raw"]["mounts"].as_str().unwrap().contains("/dev/sda2"));
    assert_eq!(v["paths"]["mounts"], "/proc/self/mounts");
    // A requested mount point or device that is not mounted.
    let o = call(&h, "disk", &[("mount_points", "/nope")]);
    o.fails(1, "system.disk_mount_not_found");
    assert!(o.reason().contains("/nope"));
    call(&h, "disk", &[("devices", "/dev/zzz")]).fails(1, "system.disk_mount_not_found");
}

#[test]
fn disk_odd_mounts_tables() {
    let fx = disk_fx();
    // A mount whose directory is gone: a warning, no figures.
    fx.put(
        "/proc/self/mounts",
        "/dev/sda2 / ext4 rw 0 0\nbroken\n/dev/sdc1 /gone ext4 rw 0 0\n",
    );
    let v = call(&fx.host(), "disk", &[]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 2);
    assert!(v["mounts"][1].get("total_bytes").is_none());
    assert_eq!(v["mounts"][1]["human_summary"], "/gone: stats unavailable");
    let w = v["warnings"].to_string();
    assert!(
        w.contains("malformed") && w.contains("statvfs /gone failed"),
        "{w}"
    );
    fx.put("/proc/self/mounts", "junk\nmore junk\n");
    call(&fx.host(), "disk", &[]).fails(1, "system.disk_mounts_parse_error");
    // /proc/mounts is the fallback.
    fx.rm("/proc/self/mounts");
    fx.put("/proc/mounts", "/dev/sda2 / ext4 rw 0 0\n");
    let v = call(&fx.host(), "disk", &[]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 1);
    assert!(v["warnings"].to_string().contains("/proc/mounts"));
    fx.rm("/proc/mounts");
    call(&fx.host(), "disk", &[]).fails(1, "system.disk_mounts_unavailable");
    // No diskstats: io unavailable with a warning.
    let fx = disk_fx();
    fx.rm("/proc/diskstats");
    let v = call(&fx.host(), "disk", &[]).ok();
    assert_eq!(v["io"]["available"], false);
}

#[test]
fn disk_stops_at_the_deadline_with_partial_results() {
    let fx = disk_fx();
    let host = fx.host().with_stat_hook(|mp| {
        if mp == "/data" {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });
    let started = std::time::Instant::now();
    let o = call(&host, "disk", &[("timeout_ms", "300")]);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    o.fails(124, "system.timeout");
    let v = o.json();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 1, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("/data"));
}

#[test]
fn device_names_map_to_whole_disks() {
    for (dev, want) in [
        ("sda1", "sda"),
        ("sda", "sda"),
        ("sdaa12", "sdaa"),
        ("xvdb3", "xvdb"),
        ("vda", "vda"),
        ("nvme0n1p2", "nvme0n1"),
        ("nvme0n1", "nvme0n1"),
        ("mmcblk0p1", "mmcblk0"),
        ("loop7", "loop7"),
        ("dm-0", "dm-0"),
        ("sdé1", "sdé1"),
        ("hd\u{1F600}", "hd\u{1F600}"),
    ] {
        assert_eq!(disk::base_device_name(dev).as_deref(), Some(want), "{dev}");
    }
    assert_eq!(disk::base_device_name("mapper/vg-lv"), None);
    assert_eq!(host::unescape_octal(r"a\040b\011c\134d\012"), "a b\tc\\d\n");
    assert_eq!(host::unescape_octal(r"x\0"), r"x\0");
    assert_eq!(host::unescape_octal(r"x\999"), r"x\999");
}

#[test]
fn disk_text() {
    let fx = disk_fx();
    let o = call(
        &fx.host(),
        "disk",
        &[("format", "text"), ("mount_points", "/")],
    );
    assert!(o.stdout.contains("/ (ext4 on /dev/sda2)"), "{}", o.stdout);
}

// ---------------------------------------------------------------------------
// env.list
// ---------------------------------------------------------------------------

fn env_host(fx: &Fx) -> Host {
    fx.host().with_env(&[
        ("HOME", "/home/alice"),
        ("PWD", "/srv/app"),
        ("DB_PASSWORD", "hunter2"),
        ("API_TOKEN", "t0k"),
        ("DATABASE", "postgres://bob:pw@db/x"),
        ("XDG_A", "1"),
        ("XDG_BBB", "22"),
        ("LONG", "ééééé"),
    ])
}

fn names(v: &Value) -> Vec<String> {
    v["variables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn env_list_masks_sensitive_values() {
    let fx = Fx::new();
    let h = env_host(&fx);
    let v = call(&h, "env.list", &[]).ok();
    assert_eq!(v["env_count_total"], 8);
    assert_eq!(v["source"], "process");
    assert_eq!(v["pid"], std::process::id());
    let get = |n: &str| {
        v["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == n)
            .unwrap()
            .clone()
    };
    for n in ["DB_PASSWORD", "API_TOKEN", "DATABASE"] {
        assert_eq!(get(n)["value"], env::MASK, "{n}");
        assert_eq!(get(n)["masked"], true);
    }
    assert_eq!(get("PWD")["value"], "/srv/app");
    assert_eq!(v["env_count_masked"], 3);
    assert_eq!(names(&v)[0], "API_TOKEN", "sorted by name");
    let v = call(&h, "env.list", &[("include_sensitive", "true")]).ok();
    assert_eq!(v["env_count_masked"], 0);
    // The raw view is masked the same way.
    let v = call(
        &h,
        "env.list",
        &[("include_raw", "true"), ("names", "DB_PASSWORD,HOME")],
    )
    .ok();
    let raw = v["raw"]["environ"].to_string();
    assert!(
        raw.contains("DB_PASSWORD=***MASKED***") && !raw.contains("hunter2"),
        "{raw}"
    );
    assert_eq!(v["paths"], Value::Null);
}

#[test]
fn env_list_filters_sorts_and_limits() {
    let fx = Fx::new();
    let h = env_host(&fx);
    let v = call(&h, "env.list", &[("prefix_filters", "XDG_")]).ok();
    assert_eq!(names(&v), vec!["XDG_A", "XDG_BBB"]);
    let v = call(&h, "env.list", &[("regex_filters", "^X.*B$,^HOME$")]).ok();
    assert_eq!(names(&v), vec!["HOME", "XDG_BBB"]);
    let v = call(
        &h,
        "env.list",
        &[("prefix_filters", "XDG_"), ("sort_order", "desc")],
    )
    .ok();
    assert_eq!(names(&v), vec!["XDG_BBB", "XDG_A"]);
    let v = call(
        &h,
        "env.list",
        &[("names", "HOME,XDG_A,LONG"), ("sort_by", "length")],
    )
    .ok();
    assert_eq!(names(&v), vec!["XDG_A", "LONG", "HOME"]);
    let v = call(&h, "env.list", &[("max_vars", "2")]).ok();
    assert_eq!(v["env_count_returned"], 2);
    assert_eq!(v["truncated_vars"], true);
    // Truncation counts characters, not bytes.
    let v = call(
        &h,
        "env.list",
        &[("names", "LONG"), ("truncate_length", "3")],
    )
    .ok();
    assert_eq!(v["variables"][0]["value"], "ééé");
    assert_eq!(v["variables"][0]["value_length"], 5);
    assert_eq!(v["env_count_truncated"], 1);
    let v = call(
        &h,
        "env.list",
        &[("names", "LONG"), ("truncate_length", "0")],
    )
    .ok();
    assert_eq!(v["variables"][0]["value"], "ééééé");
    let v = call(&h, "env.list", &[("include_values", "false")]).ok();
    assert!(v["variables"][0].get("value").is_none());
    assert_eq!(v["env_count_truncated"], 0);
    let o = call(&h, "env.list", &[("names", "HOME"), ("format", "text")]);
    assert!(
        o.stdout.contains("HOME                 = /home/alice"),
        "{}",
        o.stdout
    );
}

#[test]
fn env_list_reads_another_process() {
    let fx = Fx::new();
    std::fs::create_dir_all(fx.path("/proc/4242")).unwrap();
    std::fs::write(
        fx.path("/proc/4242/environ"),
        b"A=1\0SECRET_KEY=x\0NOEQUALS\0B=two=2\0",
    )
    .unwrap();
    let v = call(
        &fx.host(),
        "env.list",
        &[("pid", "4242"), ("include_paths", "true")],
    )
    .ok();
    assert_eq!(v["pid"], 4242);
    assert_eq!(v["source"], "proc");
    assert_eq!(names(&v), vec!["A", "B", "SECRET_KEY"]);
    assert_eq!(v["variables"][1]["value"], "two=2");
    assert_eq!(v["variables"][2]["masked"], true);
    assert_eq!(v["paths"]["environ"], "/proc/4242/environ");
    call(&fx.host(), "env.list", &[("pid", "999999")]).fails(1, "system.env_list_pid_not_found");
    // An unreadable environ (not checkable as root).
    if !nix::unistd::geteuid().is_root() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            fx.path("/proc/4242/environ"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        call(&fx.host(), "env.list", &[("pid", "4242")])
            .fails(1, "system.env_list_permission_denied");
    }
    // A directory where the file should be: another read error.
    std::fs::create_dir_all(fx.path("/proc/77/environ")).unwrap();
    call(&fx.host(), "env.list", &[("pid", "77")]).fails(1, "system.env_list_unavailable");
}

#[test]
fn sensitive_names() {
    for n in [
        "PASSWORD",
        "my_passwd",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "aws_access_key_id",
        "AUTH_KEY",
        "SESSION_ID",
        "PGPASS",
    ] {
        assert!(env::is_sensitive_name(n), "{n}");
    }
    for n in ["PWD", "OLDPWD", "HOME", "PATH", "AUTHOR"] {
        assert!(!env::is_sensitive_name(n), "{n}");
    }
    assert!(env::value_has_credentials("https://u:p@host/x"));
    assert!(!env::value_has_credentials("https://host/x?a=b@c"));
    assert!(!env::value_has_credentials("user@example.com"));
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

#[test]
fn info_default_scopes() {
    let fx = Fx::new();
    let v = call(&fx.host(), "info", &[]).ok();
    assert_eq!(
        v["scopes"],
        json!(["os", "kernel", "cpu", "memory", "load"])
    );
    assert_eq!(v["os"]["name"], "Linux");
    assert_eq!(v["os"]["distribution"], "Debian GNU/Linux");
    assert_eq!(v["os"]["distribution_version"], "13");
    assert_eq!(v["os"]["hostname"], "fixture-host");
    assert_eq!(v["os"]["architecture"], "x86_64");
    assert_eq!(v["kernel"]["release"], "6.1.0-test");
    assert_eq!(v["kernel"]["version"], "#1 SMP PREEMPT_DYNAMIC Test");
    assert_eq!(v["kernel"]["machine"], "x86_64");
    assert_eq!(v["kernel"]["boot_time_unix"], 1_700_000_000);
    assert!(close(&v["kernel"]["uptime_seconds"], 1000.5));
    assert_eq!(v["cpu"]["count_logical"], 2);
    assert_eq!(v["cpu"]["utilization_pct"], Value::Null);
    assert_eq!(v["memory"]["mem_total_bytes"], 16_000_000u64 * 1024);
    assert!(close(&v["memory"]["usage_pct"], 25.0));
    assert!(close(&v["load"]["load_1m"], 0.8));
    assert_eq!(v["load"]["total_processes"], 412);
    assert!(v.get("raw").is_none() && v.get("paths").is_none());
    assert_eq!(v["warnings"], json!([]));
}

#[test]
fn info_cpu_sampling_and_cpu_lists() {
    let fx = Fx::new();
    fx.put("/sys/devices/system/cpu/present", "0-3\n");
    fx.put("/sys/devices/system/cpu/online", "0,2\n");
    let (host, pauses) = two_samples(&fx);
    let v = call(
        &host,
        "info",
        &[
            ("scopes", "cpu"),
            ("sample_duration_ms", "100"),
            ("per_cpu", "true"),
        ],
    )
    .ok();
    assert_eq!(*pauses.lock().unwrap(), vec![100]);
    assert_eq!(v["cpu"]["count_logical"], 4);
    assert_eq!(v["cpu"]["online_logical"], 2);
    assert!(close(&v["cpu"]["utilization_pct"], 40.0));
    assert_eq!(v["cpu"]["per_cpu"][1]["id"], 2);
    assert_eq!(info::count_cpu_list("0-3,8,10-11"), Some(7));
    assert_eq!(info::count_cpu_list("x"), None);
}

#[test]
fn info_fields_filter_the_report() {
    let fx = Fx::new();
    let v = call(
        &fx.host(),
        "info",
        &[
            ("scopes", "kernel,load,os"),
            ("fields", "kernel.release,load"),
        ],
    )
    .ok();
    assert_eq!(v["kernel"], json!({ "release": "6.1.0-test" }));
    assert!(v["load"].get("load_5m").is_some());
    assert!(v.get("os").is_none());
    assert_eq!(v["scopes"], json!(["kernel", "load", "os"]));
}

#[test]
fn info_disk_process_pressure_cgroup_virtualization() {
    let fx = disk_fx();
    fx.put("/proc/1/stat", "1 (systemd) S 0 1 1\n");
    fx.put("/proc/20/stat", "20 (bash) R 1 20 20\n");
    fx.put("/proc/21/stat", "21 (bash) S 1 21 21\n");
    fx.put("/proc/22/stat", "22 (we ird) proc) Z 1 22 22\n");
    fx.put("/proc/23/stat", "23 (kworker/0:1) I 2 0 0\n");
    fx.put("/proc/24/stat", "24 (sleep) T 1 24 24\n");
    fx.put("/proc/25/stat", "25 (dd) D 1 25 25\n");
    fx.put(
        "/proc/pressure/cpu",
        "some avg10=1.50 avg60=0.75 avg300=0.10 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    );
    fx.put(
        "/proc/pressure/memory",
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    );
    fx.put("/.dockerenv", "");
    fx.put("/sys/class/dmi/id/product_name", "KVM\n");
    let v = call(
        &fx.host(),
        "info",
        &[
            ("scopes", "disk,process,pressure,cgroup,virtualization"),
            ("max_process_classes", "2"),
            ("include_raw", "true"),
            ("include_paths", "true"),
        ],
    )
    .ok();
    let mounts = v["disk"]["mounts"].as_array().unwrap();
    assert_eq!(mounts[0]["mount_point"], "/");
    assert!(mounts.iter().all(|m| m["fs_type"] != "proc"));
    let p = &v["process"];
    assert_eq!(p["total_processes"], 7);
    assert_eq!(p["running"], 1);
    assert_eq!(p["sleeping"], 3);
    assert_eq!(p["zombie"], 1);
    assert_eq!(p["stopped"], 1);
    assert_eq!(p["blocked"], 1);
    assert_eq!(p["classes"][0], json!({ "name": "bash", "count": 2 }));
    assert_eq!(p["classes"].as_array().unwrap().len(), 2);
    let ps = &v["pressure"];
    assert_eq!(ps["available"], true);
    assert!(close(&ps["cpu"]["some_avg10"], 1.5));
    assert!(close(&ps["cpu"]["full_avg300"], 0.0));
    assert_eq!(ps["io"], Value::Null);
    assert!(ps["memory"].get("full_avg10").is_none());
    let cg = &v["cgroup"];
    assert_eq!(cg["available"], true);
    assert_eq!(cg["unified"], true);
    assert_eq!(cg["paths"]["base"], "/sys/fs/cgroup/app/svc");
    assert_eq!(cg["paths"]["memory"], "/sys/fs/cgroup/app/svc/memory.max");
    assert!(close(&cg["limits"]["cpu_quota_pct"], 150.0));
    assert_eq!(cg["limits"]["memory_limit_bytes"], 536_870_912u64);
    let vt = &v["virtualization"];
    assert_eq!(vt["is_container"], true);
    assert_eq!(vt["container_type"], "docker");
    assert_eq!(vt["hypervisor_type"], "kvm");
    assert!(v["raw"]["pressure"]["/proc/pressure/cpu"].is_string());
    assert!(v["paths"]["disk"].is_array());
}

#[test]
fn info_unreadable_scopes_are_marked_unavailable() {
    let fx = Fx::empty();
    let v = call(
        &fx.host(),
        "info",
        &[("scopes", "os,kernel,cpu,memory,load,pressure,cgroup,disk")],
    )
    .ok();
    for s in [
        "os", "kernel", "cpu", "memory", "load", "pressure", "cgroup", "disk",
    ] {
        assert_eq!(v[s]["available"], false, "{s}: {v}");
    }
    assert!(v["warnings"].as_array().unwrap().len() >= 8);
    // v1 cgroups in the cgroup scope.
    let fx = Fx::new();
    fx.cgroup_v1();
    let v = call(&fx.host(), "info", &[("scopes", "cgroup")]).ok();
    assert_eq!(v["cgroup"]["unified"], false);
    assert!(close(&v["cgroup"]["limits"]["cpu_quota_pct"], 50.0));
    assert_eq!(
        v["cgroup"]["paths"]["cpu"],
        "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us"
    );
}

#[test]
fn info_disk_scope_timeout() {
    let fx = disk_fx();
    let host = fx.host().with_stat_hook(|mp| {
        if mp == "/data" {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });
    let o = call(
        &host,
        "info",
        &[("scopes", "disk,load"), ("timeout_ms", "300")],
    );
    o.fails(124, "system.timeout");
    let v = o.json();
    assert_eq!(v["disk"]["mounts"].as_array().unwrap().len(), 1);
}

#[test]
fn info_text() {
    let fx = Fx::new();
    let o = call(&fx.host(), "info", &[("format", "text")]);
    assert!(o.status.is_success());
    assert!(o.stdout.starts_with("System Info"), "{}", o.stdout);
    assert!(o.stdout.contains("hostname"), "{}", o.stdout);
}

// ---------------------------------------------------------------------------
// cgroup-relative CPU utilization and df-style disk percentages
// ---------------------------------------------------------------------------

/// Like `two_samples`; the cgroup usage file `usage` gets `after` too.
fn two_samples_with_usage(fx: &Fx, usage: &str, after: &'static str) -> Host {
    let stat = fx.path("/proc/stat");
    let usage = fx.path(usage);
    fx.host().with_pause(move |_| {
        std::fs::write(&stat, STAT_B).unwrap();
        std::fs::write(&usage, after).unwrap();
    })
}

#[test]
fn cpu_cgroup_utilization_v2() {
    let fx = Fx::new();
    // 0.1875 s used in 250 ms with a 1.5-CPU quota: 50%.
    let host = two_samples_with_usage(
        &fx,
        "/sys/fs/cgroup/app/svc/cpu.stat",
        "usage_usec 2687500\nuser_usec 2100000\nsystem_usec 587500\n",
    );
    let v = call(&host, "cpu", &[("include_cgroup", "false")]).ok();
    assert!(close(&v["system"]["cgroup_utilization_pct"], 50.0), "{v}");
    // The usage file no longer changes: 0% of the quota.
    let o = call(&host, "cpu", &[("format", "text")]);
    assert!(
        o.stdout.contains("Utilization  : 0.0% of quota"),
        "{}",
        o.stdout
    );
    // No quota anywhere: null.
    fx.put("/sys/fs/cgroup/app/svc/cpu.max", "max 100000\n");
    fx.put("/sys/fs/cgroup/app/cpu.max", "max 100000\n");
    let v = call(&host, "cpu", &[]).ok();
    assert_eq!(v["system"]["cgroup_utilization_pct"], Value::Null, "{v}");
    // No cgroup information: null.
    fx.rm("/proc/self/cgroup");
    let v = call(&host, "cpu", &[]).ok();
    assert_eq!(v["system"]["cgroup_utilization_pct"], Value::Null);
}

#[test]
fn cpu_cgroup_utilization_v1() {
    let fx = Fx::new();
    fx.cgroup_v1();
    // 0.0625 s used in 250 ms with a 0.5-CPU quota: 50%.
    let host = two_samples_with_usage(
        &fx,
        "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage",
        "3062500000\n",
    );
    let v = call(&host, "cpu", &[]).ok();
    assert!(close(&v["system"]["cgroup_utilization_pct"], 50.0), "{v}");
    assert!(close(&v["cgroup"]["usage_seconds"], 3.0625));
}

#[test]
fn disk_used_pct_matches_df() {
    assert_eq!(disk::df_pct(1, 2), Some(34.0));
    assert_eq!(disk::df_pct(50, 50), Some(50.0));
    assert_eq!(disk::df_pct(0, 10), Some(0.0));
    assert_eq!(disk::df_pct(10, 0), Some(100.0));
    assert_eq!(disk::df_pct(0, 0), None);
    assert_eq!(disk::df_pct(u64::MAX, u64::MAX), Some(50.0));
    let fx = disk_fx();
    let v = call(&fx.host(), "disk", &[("mount_points", "/")]).ok();
    let m = &v["mounts"][0];
    let st = host::statvfs_at(fx.dir.path()).unwrap();
    // The filesystem is live; allow one percent of drift between the reads.
    let df = disk::df_pct(st.used_bytes, st.avail_bytes).unwrap();
    assert!((m["used_pct"].as_f64().unwrap() - df).abs() <= 1.0, "{m}");
    assert_eq!(m["used_pct"].as_f64().unwrap().fract(), 0.0);
    let total = 100.0 * st.used_bytes as f64 / st.total_bytes as f64;
    assert!((m["used_of_total_pct"].as_f64().unwrap() - total).abs() < 1.0);
}

// ---------------------------------------------------------------------------
// The real host (read-only)
// ---------------------------------------------------------------------------

#[test]
fn every_verb_runs_on_this_host() {
    if !Path::new("/proc/self/stat").exists() {
        return;
    }
    let h = Host::real();
    for verb in VERBS {
        let args: &[(&str, &str)] = match *verb {
            "cpu" => &[("sample_duration_ms", "50")],
            _ => &[],
        };
        let v = call(&h, verb, args).ok();
        assert!(v["timestamp_unix_ms"].as_i64().unwrap() > 0, "{verb}");
        let t = call(&h, verb, &[args, &[("format", "text")]].concat());
        assert!(t.status.is_success(), "{verb}: {:?}", t.status);
    }
}
