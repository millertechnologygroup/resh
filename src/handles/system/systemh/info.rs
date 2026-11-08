//! `info`: one report over selected scopes. A scope that cannot be read is
//! reported with `"available": false` and a warning instead of failing the
//! verb; only the deadline (`timeout_ms`, which `statvfs` in the `disk`
//! scope can reach on a hung mount) fails it.

use super::args::{INFO_SCOPES, InfoOptions};
use super::cgroup::{self, Version};
use super::disk;
use super::error::SysError;
use super::host::Host;
use super::metrics;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The keys each scope reports (what `fields` may name).
pub fn scope_keys(scope: &str) -> &'static [&'static str] {
    match scope {
        "os" => &[
            "available",
            "name",
            "distribution",
            "distribution_version",
            "hostname",
            "architecture",
        ],
        "kernel" => &[
            "available",
            "release",
            "version",
            "machine",
            "boot_time_unix",
            "uptime_seconds",
        ],
        "cpu" => &[
            "available",
            "count_logical",
            "count_physical",
            "online_logical",
            "utilization_pct",
            "per_cpu",
        ],
        "memory" => &[
            "available",
            "mem_total_bytes",
            "mem_free_bytes",
            "mem_available_bytes",
            "buffers_bytes",
            "cached_bytes",
            "swap_total_bytes",
            "swap_free_bytes",
            "usage_pct",
        ],
        "load" => &[
            "available",
            "load_1m",
            "load_5m",
            "load_15m",
            "runnable_processes",
            "total_processes",
        ],
        "disk" => &["available", "mounts_truncated", "mounts"],
        "process" => &[
            "available",
            "total_processes",
            "running",
            "sleeping",
            "zombie",
            "stopped",
            "blocked",
            "classes",
        ],
        "pressure" => &["available", "cpu", "io", "memory"],
        "cgroup" => &["available", "unified", "paths", "limits"],
        "virtualization" => &[
            "available",
            "is_container",
            "container_type",
            "is_virtual_machine",
            "hypervisor_type",
        ],
        _ => &[],
    }
}

/// Each `fields` entry is `<scope>` or `<scope>.<key>`, for a requested
/// scope and a key that scope reports.
pub fn validate_fields(fields: &[String], scopes: &[String]) -> Result<(), SysError> {
    if fields.is_empty() {
        return Err(SysError::invalid(
            "fields is empty (expected entries such as kernel.release or load)",
        ));
    }
    for f in fields {
        let (scope, key) = match f.split_once('.') {
            Some((s, k)) => (s, Some(k)),
            None => (f.as_str(), None),
        };
        if !INFO_SCOPES.contains(&scope) {
            return Err(SysError::invalid(format!(
                "invalid fields entry {f:?}: {scope:?} is not a scope{}",
                super::args::did_you_mean(scope, INFO_SCOPES)
            )));
        }
        if !scopes.iter().any(|s| s == scope) {
            return Err(SysError::invalid(format!(
                "invalid fields entry {f:?}: scope {scope} is not in scopes ({})",
                scopes.join(",")
            )));
        }
        if let Some(k) = key {
            let keys = scope_keys(scope);
            if !keys.contains(&k) {
                return Err(SysError::invalid(format!(
                    "invalid fields entry {f:?}: {scope} has no key {k:?}{} (keys: {})",
                    super::args::did_you_mean(k, keys),
                    keys.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// What one scope read: its object, raw text by source, and the files.
struct Part {
    value: Value,
    raw: Map<String, Value>,
    paths: Vec<String>,
}

impl Part {
    fn new(value: Value) -> Part {
        Part {
            value,
            raw: Map::new(),
            paths: Vec::new(),
        }
    }
}

/// `0-3,5,7-8` (a /sys CPU list) -> number of CPUs.
pub fn count_cpu_list(s: &str) -> Option<u32> {
    let mut n = 0u32;
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (u32, u32) = (a.parse().ok()?, b.parse().ok()?);
                n += b.checked_sub(a)? + 1;
            }
            None => {
                part.parse::<u32>().ok()?;
                n += 1;
            }
        }
    }
    (n > 0).then_some(n)
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

fn os_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let ostype = host.read_trim("/proc/sys/kernel/ostype");
    if ostype.is_none() {
        w.push("os: /proc/sys/kernel/ostype not readable".into());
    }
    let hostname = host.read_trim("/proc/sys/kernel/hostname");
    let mut p = Part::new(Value::Null);
    let mut distro = None;
    let mut version = None;
    let release = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .find_map(|f| host.read(f).ok().map(|t| (*f, t)));
    match &release {
        Some((path, text)) => {
            p.paths.push(path.to_string());
            p.raw.insert(path.to_string(), json!(text));
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    match k.trim() {
                        "NAME" => distro = Some(unquote(v)),
                        "VERSION_ID" => version = Some(unquote(v)),
                        _ => {}
                    }
                }
            }
        }
        None => w.push("os: /etc/os-release not readable".into()),
    }
    p.paths
        .extend(["/proc/sys/kernel/ostype", "/proc/sys/kernel/hostname"].map(String::from));
    p.value = json!({
        "available": ostype.is_some(),
        "name": ostype,
        "distribution": distro,
        "distribution_version": version,
        "hostname": hostname,
        "architecture": host.machine(),
    });
    p
}

fn kernel_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let release = host.read_trim("/proc/sys/kernel/osrelease");
    let version = host.read_trim("/proc/sys/kernel/version");
    if release.is_none() {
        w.push("kernel: /proc/sys/kernel/osrelease not readable".into());
    }
    let boot = host
        .read("/proc/stat")
        .ok()
        .and_then(|s| metrics::parse_btime(&s));
    let uptime = host
        .read("/proc/uptime")
        .ok()
        .and_then(|t| metrics::parse_uptime(&t).ok())
        .map(|(u, _)| u);
    if uptime.is_none() {
        w.push("kernel: /proc/uptime not readable".into());
    }
    let mut p = Part::new(json!({
        "available": release.is_some(),
        "release": release,
        "version": version,
        "machine": host.machine(),
        "boot_time_unix": boot,
        "uptime_seconds": uptime,
    }));
    p.paths = [
        "/proc/sys/kernel/osrelease",
        "/proc/sys/kernel/version",
        "/proc/stat",
        "/proc/uptime",
    ]
    .map(String::from)
    .to_vec();
    if let Some(r) = &release {
        p.raw.insert("osrelease".into(), json!(r));
    }
    if let Some(v) = &version {
        p.raw.insert("version".into(), json!(v));
    }
    p
}

fn cpu_scope(host: &Host, o: &InfoOptions, w: &mut Vec<String>) -> Part {
    let stat = host.read("/proc/stat");
    let parsed = stat
        .as_ref()
        .map_err(|e| e.to_string())
        .and_then(|t| metrics::parse_proc_stat(t));
    let stat_ids: Vec<u32> = match &parsed {
        Ok(p) => p.iter().filter_map(|c| c.id).collect(),
        Err(e) => {
            w.push(format!("cpu: {e}"));
            Vec::new()
        }
    };
    let present = host
        .read_trim("/sys/devices/system/cpu/present")
        .and_then(|s| count_cpu_list(&s));
    let online = host
        .read_trim("/sys/devices/system/cpu/online")
        .and_then(|s| count_cpu_list(&s));
    let stat_n = (!stat_ids.is_empty()).then_some(stat_ids.len() as u32);
    let (physical, _) = metrics::topology(host, &stat_ids);
    let mut p = Part::new(Value::Null);
    p.paths = vec![
        "/proc/stat".into(),
        "/sys/devices/system/cpu/present".into(),
        "/sys/devices/system/cpu/online".into(),
    ];
    let mut util = None;
    let mut per_cpu = Vec::new();
    if o.sample_duration_ms > 0 && parsed.is_ok() {
        match metrics::sample_cpu(host, o.sample_duration_ms) {
            Ok(s) => {
                let get = |l: &[metrics::CpuTimes], id| l.iter().find(|c| c.id == id).cloned();
                if let (Some(a), Some(b)) = (get(&s.first, None), get(&s.second, None)) {
                    util = metrics::cpu_pct(&a, &b).map(|p| round3(p.utilization));
                    if util.is_none() {
                        w.push("cpu: no CPU time passed between the samples".into());
                    }
                }
                if o.per_cpu {
                    for a in s.first.iter().filter(|c| c.id.is_some()) {
                        if let Some(b) = get(&s.second, a.id) {
                            per_cpu.push(json!({
                                "id": a.id,
                                "utilization_pct": metrics::cpu_pct(a, &b).map(|p| round3(p.utilization)),
                            }));
                        }
                    }
                }
                p.raw.insert("proc_stat_start".into(), json!(s.first_text));
                p.raw.insert("proc_stat_end".into(), json!(s.second_text));
            }
            Err(e) => w.push(format!("cpu: {}", e.message)),
        }
    } else if let Ok(t) = &stat {
        p.raw.insert("proc_stat".into(), json!(t));
    }
    let mut v = json!({
        "available": parsed.is_ok(),
        "count_logical": present.or(stat_n),
        "count_physical": physical,
        "online_logical": online.or(stat_n),
        "utilization_pct": util,
    });
    if o.per_cpu {
        v["per_cpu"] = json!(per_cpu);
    }
    p.value = v;
    p
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn memory_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let mut p = Part::new(Value::Null);
    p.paths.push("/proc/meminfo".into());
    let (m, ok) = match host.read("/proc/meminfo") {
        Ok(t) => {
            p.raw.insert("meminfo".into(), json!(t));
            let (m, _) = metrics::parse_meminfo(&t);
            let ok = m.contains_key("MemTotal");
            if !ok {
                w.push("memory: /proc/meminfo has no MemTotal line".into());
            }
            (m, ok)
        }
        Err(e) => {
            w.push(format!("memory: {e}"));
            (BTreeMap::new(), false)
        }
    };
    let g = |k: &str| m.get(k).copied();
    let usage = match (g("MemTotal"), g("MemAvailable")) {
        (Some(t), Some(a)) if t > 0 => Some(round3(100.0 * t.saturating_sub(a) as f64 / t as f64)),
        _ => None,
    };
    p.value = json!({
        "available": ok,
        "mem_total_bytes": g("MemTotal"),
        "mem_free_bytes": g("MemFree"),
        "mem_available_bytes": g("MemAvailable"),
        "buffers_bytes": g("Buffers"),
        "cached_bytes": g("Cached"),
        "swap_total_bytes": g("SwapTotal"),
        "swap_free_bytes": g("SwapFree"),
        "usage_pct": usage,
    });
    p
}

fn load_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let mut p = Part::new(Value::Null);
    p.paths.push("/proc/loadavg".into());
    let la = match host.read("/proc/loadavg") {
        Ok(t) => {
            p.raw.insert("proc_loadavg_line".into(), json!(t.trim()));
            metrics::parse_loadavg(&t)
                .map_err(|e| w.push(format!("load: {e}")))
                .ok()
        }
        Err(e) => {
            w.push(format!("load: {e}"));
            None
        }
    };
    p.value = json!({
        "available": la.is_some(),
        "load_1m": la.as_ref().map(|l| l.one),
        "load_5m": la.as_ref().map(|l| l.five),
        "load_15m": la.as_ref().map(|l| l.fifteen),
        "runnable_processes": la.as_ref().and_then(|l| l.queue).map(|q| q.0),
        "total_processes": la.as_ref().and_then(|l| l.queue).map(|q| q.1),
    });
    p
}

/// Mount points listed first by the `disk` scope.
const PRIORITY_MOUNTS: &[&str] = &["/", "/home", "/var", "/data", "/boot", "/tmp"];

/// Returns the scope and, on timeout, the mount point still being read.
fn disk_scope(
    host: &Host,
    o: &InfoOptions,
    deadline: Instant,
    w: &mut Vec<String>,
) -> (Part, Option<String>) {
    let mut p = Part::new(Value::Null);
    let lines = match disk::read_mounts(host, w) {
        Ok((path, text)) => {
            p.paths.push(path.clone());
            p.raw.insert(path, json!(text));
            disk::parse_mounts(&text, w)
                .map_err(|e| w.push(format!("disk: {e}")))
                .ok()
        }
        Err(e) => {
            w.push(format!("disk: {}", e.message));
            None
        }
    };
    let Some(lines) = lines else {
        p.value = json!({ "available": false, "mounts_truncated": false, "mounts": [] });
        return (p, None);
    };
    let mut real: Vec<disk::MountLine> = lines
        .into_iter()
        .filter(|l| !disk::is_virtual(&l.fs_type))
        .collect();
    // Priority mounts first (in PRIORITY_MOUNTS order), then table order.
    real.sort_by_key(|l| {
        PRIORITY_MOUNTS
            .iter()
            .position(|m| *m == l.mount_point)
            .unwrap_or(PRIORITY_MOUNTS.len())
    });
    let truncated = real.len() > o.max_mounts as usize;
    if truncated {
        w.push(format!(
            "disk: {} mounts, only the first max_mounts={} reported",
            real.len(),
            o.max_mounts
        ));
        real.truncate(o.max_mounts as usize);
    }
    let mps: Vec<String> = real.iter().map(|l| l.mount_point.clone()).collect();
    let (stats, stuck) = disk::stat_all(host, &mps, deadline);
    let mut mounts = Vec::new();
    for (l, st) in real.iter().zip(stats) {
        match st {
            None => {}
            Some(Err(e)) => w.push(format!("disk: statvfs {} failed: {e}", l.mount_point)),
            Some(Ok(st)) => mounts.push(json!({
                "mount_point": l.mount_point,
                "fs_type": l.fs_type,
                "device": l.device,
                "total_bytes": st.total_bytes,
                "used_bytes": st.used_bytes,
                "free_bytes": st.free_bytes,
                "usage_pct": (st.total_bytes > 0)
                    .then(|| round3(100.0 * st.used_bytes as f64 / st.total_bytes as f64)),
            })),
        }
    }
    p.value = json!({ "available": true, "mounts_truncated": truncated, "mounts": mounts });
    (p, stuck)
}

fn process_scope(host: &Host, o: &InfoOptions, w: &mut Vec<String>) -> Part {
    let mut p = Part::new(Value::Null);
    p.paths = vec!["/proc".into(), "/proc/<pid>/stat".into()];
    let pids = match host.list_dir("/proc") {
        Ok(names) => names
            .into_iter()
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .collect::<Vec<_>>(),
        Err(e) => {
            w.push(format!("process: {e}"));
            p.value = json!({
                "available": false, "total_processes": null, "running": null,
                "sleeping": null, "zombie": null, "stopped": null, "blocked": null,
                "classes": [],
            });
            return p;
        }
    };
    let mut states: BTreeMap<char, u32> = BTreeMap::new();
    let mut names: BTreeMap<String, u32> = BTreeMap::new();
    let mut total = 0u32;
    for pid in pids {
        // A process can exit between the listing and the read.
        let Ok(stat) = host.read(&format!("/proc/{pid}/stat")) else {
            continue;
        };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        if close < open {
            continue;
        }
        let Some(state) = stat[close + 1..].trim_start().chars().next() else {
            continue;
        };
        total += 1;
        *states.entry(state).or_default() += 1;
        *names.entry(stat[open + 1..close].to_string()).or_default() += 1;
    }
    let s = |c: char| states.get(&c).copied().unwrap_or(0);
    let mut classes: Vec<(String, u32)> = names.into_iter().collect();
    classes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    classes.truncate(o.max_process_classes as usize);
    p.value = json!({
        "available": true,
        "total_processes": total,
        "running": s('R'),
        "sleeping": s('S') + s('I'),
        "zombie": s('Z'),
        "stopped": s('T') + s('t'),
        "blocked": s('D'),
        "classes": classes
            .into_iter()
            .map(|(name, count)| json!({ "name": name, "count": count }))
            .collect::<Vec<_>>(),
    });
    p
}

/// One `/proc/pressure/<resource>` file: `some` (and `full`) averages.
pub fn parse_pressure(text: &str) -> Value {
    let mut out = Map::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(kind @ ("some" | "full")) = it.next() else {
            continue;
        };
        for kv in it {
            if let Some((k, v)) = kv.split_once('=')
                && let ("avg10" | "avg60" | "avg300", Ok(v)) = (k, v.parse::<f64>())
            {
                out.insert(format!("{kind}_{k}"), json!(v));
            }
        }
    }
    Value::Object(out)
}

fn pressure_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let mut p = Part::new(Value::Null);
    let mut v = json!({ "available": false, "cpu": null, "io": null, "memory": null });
    for r in ["cpu", "io", "memory"] {
        let path = format!("/proc/pressure/{r}");
        p.paths.push(path.clone());
        if let Ok(t) = host.read(&path) {
            v["available"] = json!(true);
            v[r] = parse_pressure(&t);
            p.raw.insert(path, json!(t));
        }
    }
    if v["available"] == false {
        w.push("pressure: PSI not available (/proc/pressure)".into());
    }
    p.value = v;
    p
}

fn cgroup_scope(host: &Host, w: &mut Vec<String>) -> Part {
    let mut p = Part::new(Value::Null);
    p.paths = vec!["/proc/self/cgroup".into(), "/proc/self/mountinfo".into()];
    let cg = match cgroup::resolve(host) {
        Ok(c) => c,
        Err(e) => {
            w.push(format!("cgroup: {e}"));
            p.value = json!({ "available": false, "unified": false, "paths": {}, "limits": {} });
            return p;
        }
    };
    if let Ok(t) = host.read("/proc/self/cgroup") {
        p.raw.insert("/proc/self/cgroup".into(), json!(t));
    }
    let mem = cgroup::memory(host, &cg);
    let cpu = cgroup::cpu(host, &cg);
    let mut paths = Map::new();
    if let Some(base) = cg.unified.as_ref().or(cg.memory.as_ref()) {
        paths.insert("base".into(), json!(base.dir));
    }
    if let Some(c) = &cg.cpu {
        let f = match c.version {
            Version::V2 => "cpu.max",
            Version::V1 => "cpu.cfs_quota_us",
        };
        paths.insert("cpu".into(), json!(c.file(f)));
    }
    if let Some(m) = &cg.memory {
        let f = match m.version {
            Version::V2 => "memory.max",
            Version::V1 => "memory.limit_in_bytes",
        };
        paths.insert("memory".into(), json!(m.file(f)));
    }
    let mut limits = Map::new();
    if let Some(c) = cpu.as_ref().and_then(|c| c.quota_cores) {
        limits.insert("cpu_quota_pct".into(), json!(round3(c * 100.0)));
    }
    if let Some(l) = mem.as_ref().and_then(|m| m.limit) {
        limits.insert("memory_limit_bytes".into(), json!(l));
    }
    for f in mem
        .iter()
        .flat_map(|m| m.raw.iter())
        .chain(cpu.iter().flat_map(|c| c.raw.iter()))
    {
        p.raw.insert(f.0.clone(), json!(f.1));
        p.paths.push(f.0.clone());
    }
    let unified = cg
        .memory
        .as_ref()
        .or(cg.cpu.as_ref())
        .or(cg.unified.as_ref())
        .is_some_and(|c| c.version == Version::V2);
    p.value = json!({
        "available": cg.memory.is_some() || cg.cpu.is_some() || cg.unified.is_some(),
        "unified": unified,
        "paths": paths,
        "limits": limits,
    });
    p
}

fn virtualization_scope(host: &Host) -> Part {
    let mut p = Part::new(Value::Null);
    let mut available = false;
    let mut container: Option<&str> = None;
    let mut vm: Option<String> = None;
    if host.exists("/.dockerenv") {
        available = true;
        container = Some("docker");
    } else if host.exists("/run/.containerenv") {
        available = true;
        container = Some("podman");
    }
    p.paths = vec![
        "/.dockerenv".into(),
        "/run/.containerenv".into(),
        "/proc/1/cgroup".into(),
        "/sys/class/dmi/id/product_name".into(),
        "/proc/cpuinfo".into(),
    ];
    if let Ok(t) = host.read("/proc/1/cgroup") {
        available = true;
        p.raw.insert("/proc/1/cgroup".into(), json!(t));
        if container.is_none() {
            container = if t.contains("kubepods") {
                Some("kubernetes")
            } else if t.contains("docker") {
                Some("docker")
            } else if t.contains("lxc") {
                Some("lxc")
            } else {
                None
            };
        }
    }
    if let Some(product) = host.read_trim("/sys/class/dmi/id/product_name") {
        available = true;
        p.raw
            .insert("/sys/class/dmi/id/product_name".into(), json!(product));
        let l = product.to_lowercase();
        vm = ["virtualbox", "vmware", "kvm", "qemu"]
            .into_iter()
            .find(|k| l.contains(k))
            .map(String::from);
    }
    if vm.is_none()
        && let Ok(t) = host.read("/proc/cpuinfo")
    {
        available = true;
        let flagged = t
            .lines()
            .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"));
        if flagged {
            vm = Some("unknown".into());
        }
    }
    p.value = json!({
        "available": available,
        "is_container": container.is_some(),
        "container_type": container,
        "is_virtual_machine": vm.is_some(),
        "hypervisor_type": vm,
    });
    p
}

/// Keeps only the requested fields of each scope object; scopes no entry
/// names are left out.
fn apply_fields(out: &mut Map<String, Value>, fields: &[String], scopes: &[String]) {
    for scope in scopes {
        let whole = fields.iter().any(|f| f == scope);
        if whole {
            continue;
        }
        let keys: Vec<&str> = fields
            .iter()
            .filter_map(|f| f.split_once('.'))
            .filter(|(s, _)| s == scope)
            .map(|(_, k)| k)
            .collect();
        if keys.is_empty() {
            out.remove(scope);
        } else if let Some(Value::Object(obj)) = out.get_mut(scope) {
            obj.retain(|k, _| keys.contains(&k.as_str()));
        }
    }
}

pub fn info(host: &Host, o: &InfoOptions) -> Result<Value, SysError> {
    let deadline = Instant::now() + Duration::from_millis(o.timeout_ms);
    let mut warnings = Vec::new();
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("timestamp_unix_ms".into(), json!(host.now_unix_ms()));
    // Each scope once, in the order given.
    let mut scopes: Vec<String> = Vec::new();
    for s in &o.scopes {
        if !scopes.contains(s) {
            scopes.push(s.clone());
        }
    }
    out.insert("scopes".into(), json!(scopes));
    let mut raw = Map::new();
    let mut paths = Map::new();
    let mut stuck = None;
    for scope in &scopes {
        let part = match scope.as_str() {
            "os" => os_scope(host, &mut warnings),
            "kernel" => kernel_scope(host, &mut warnings),
            "cpu" => cpu_scope(host, o, &mut warnings),
            "memory" => memory_scope(host, &mut warnings),
            "load" => load_scope(host, &mut warnings),
            "disk" => {
                let (p, s) = disk_scope(host, o, deadline, &mut warnings);
                stuck = s;
                p
            }
            "process" => process_scope(host, o, &mut warnings),
            "pressure" => pressure_scope(host, &mut warnings),
            "cgroup" => cgroup_scope(host, &mut warnings),
            "virtualization" => virtualization_scope(host),
            // validate_info refuses other names.
            _ => continue,
        };
        out.insert(scope.clone(), part.value);
        raw.insert(scope.clone(), Value::Object(part.raw));
        paths.insert(scope.clone(), json!(part.paths));
        if stuck.is_some() {
            break;
        }
    }
    if let Some(fields) = &o.fields {
        apply_fields(&mut out, fields, &scopes);
    }
    if o.include_raw {
        out.insert("raw".into(), Value::Object(raw));
    }
    if o.include_paths {
        out.insert("paths".into(), Value::Object(paths));
    }
    if let Some(mp) = stuck {
        out.insert("ok".into(), json!(false));
        out.insert(
            "error".into(),
            SysError::new(
                "system.timeout",
                format!(
                    "timed out after {} ms waiting for statvfs on {mp} (disk scope)",
                    o.timeout_ms
                ),
            )
            .to_json(),
        );
    }
    out.insert("warnings".into(), json!(warnings));
    Ok(Value::Object(out))
}
