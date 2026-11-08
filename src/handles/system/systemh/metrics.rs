//! `uptime`, `load`, `memory` and `cpu`: parsing `/proc` and `/sys` and
//! building the responses. The parsers are shared with `info`.

use super::args::{CpuOptions, LoadOptions, MemoryOptions, UptimeOptions};
use super::cgroup::{self, Version};
use super::error::SysError;
use super::host::Host;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Shared parsers
// ---------------------------------------------------------------------------

/// `/proc/uptime`: seconds since boot and the summed idle time of all CPUs.
pub fn parse_uptime(text: &str) -> Result<(f64, Option<f64>), String> {
    let mut it = text.split_whitespace();
    let up = it
        .next()
        .ok_or_else(|| "/proc/uptime is empty".to_string())?;
    let up: f64 = up
        .parse()
        .ok()
        .filter(|v: &f64| v.is_finite() && *v >= 0.0)
        .ok_or_else(|| format!("/proc/uptime: {up:?} is not a number of seconds"))?;
    let idle = it
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0);
    Ok((up, idle))
}

/// `btime` (boot time, Unix seconds) from `/proc/stat`.
pub fn parse_btime(stat: &str) -> Option<i64> {
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// `/proc/loadavg`: the three averages and the runnable/total field.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    /// `None` when the queue field is missing or malformed.
    pub queue: Option<(u32, u32)>,
}

pub fn parse_loadavg(text: &str) -> Result<LoadAvg, String> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let num = |i: usize| -> Result<f64, String> {
        let s = parts
            .get(i)
            .ok_or_else(|| format!("/proc/loadavg has {} fields, expected 5", parts.len()))?;
        s.parse::<f64>()
            .ok()
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or_else(|| format!("/proc/loadavg: {s:?} is not a load average"))
    };
    let queue = parts.get(3).and_then(|q| {
        let (r, t) = q.split_once('/')?;
        Some((r.parse().ok()?, t.parse().ok()?))
    });
    Ok(LoadAvg {
        one: num(0)?,
        five: num(1)?,
        fifteen: num(2)?,
        queue,
    })
}

/// `/proc/meminfo` as name -> value in bytes (`kB` values are multiplied by
/// 1024; unitless counts such as `HugePages_Total` are kept as they are).
/// Also returns the raw numbers as written.
pub fn parse_meminfo(text: &str) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let mut bytes = BTreeMap::new();
    let mut raw = BTreeMap::new();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let Some(Ok(v)) = it.next().map(str::parse::<u64>) else {
            continue;
        };
        let scaled = match it.next() {
            Some("kB") => v.saturating_mul(1024),
            _ => v,
        };
        raw.insert(key.trim().to_string(), v);
        bytes.insert(key.trim().to_string(), scaled);
    }
    (bytes, raw)
}

/// One `cpu` line of `/proc/stat`, in clock ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTimes {
    pub name: String,
    /// `None` for the aggregate `cpu` line, else the N of `cpuN`.
    pub id: Option<u32>,
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

/// The `cpu` lines of `/proc/stat`. The aggregate line must be present and
/// every `cpu` line must have at least four numeric fields.
pub fn parse_proc_stat(text: &str) -> Result<Vec<CpuTimes>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        let Some(suffix) = name.strip_prefix("cpu") else {
            continue;
        };
        let id = if suffix.is_empty() {
            None
        } else {
            match suffix.parse::<u32>() {
                Ok(n) => Some(n),
                Err(_) => continue,
            }
        };
        let vals: Vec<u64> = it
            .map(|s| s.parse::<u64>())
            .collect::<Result<_, _>>()
            .map_err(|_| format!("/proc/stat: line {name:?} has a non-numeric field"))?;
        if vals.len() < 4 {
            return Err(format!(
                "/proc/stat: line {name:?} has {} fields, expected at least 4",
                vals.len()
            ));
        }
        let v = |i: usize| vals.get(i).copied().unwrap_or(0);
        out.push(CpuTimes {
            name: name.to_string(),
            id,
            user: v(0),
            nice: v(1),
            system: v(2),
            idle: v(3),
            iowait: v(4),
            irq: v(5),
            softirq: v(6),
            steal: v(7),
            guest: v(8),
            guest_nice: v(9),
        });
    }
    if !out.iter().any(|c| c.id.is_none()) {
        return Err("/proc/stat has no aggregate \"cpu\" line".to_string());
    }
    Ok(out)
}

/// The number of online logical CPUs (`cpuN` lines of `/proc/stat`).
pub fn cpu_count(host: &Host) -> Result<u32, String> {
    let text = host.read("/proc/stat").map_err(|e| e.to_string())?;
    let n = parse_proc_stat(&text)?
        .iter()
        .filter(|c| c.id.is_some())
        .count() as u32;
    if n == 0 {
        Err("/proc/stat lists no CPUs".to_string())
    } else {
        Ok(n)
    }
}

/// Percentages of the time between two samples. `user` and `nice` include
/// guest time (the kernel counts it in both), so the parts other than
/// `guest`/`guest_nice` add up to 100.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CpuPct {
    pub utilization: f64,
    pub user: f64,
    pub nice: f64,
    pub system: f64,
    pub idle: f64,
    pub iowait: f64,
    pub irq: f64,
    pub softirq: f64,
    pub steal: f64,
    pub guest: f64,
    pub guest_nice: f64,
}

/// `None` when no time passed for this CPU between the samples.
pub fn cpu_pct(a: &CpuTimes, b: &CpuTimes) -> Option<CpuPct> {
    let d = |x: u64, y: u64| y.saturating_sub(x);
    let user = d(a.user, b.user);
    let nice = d(a.nice, b.nice);
    let system = d(a.system, b.system);
    let idle = d(a.idle, b.idle);
    let iowait = d(a.iowait, b.iowait);
    let irq = d(a.irq, b.irq);
    let softirq = d(a.softirq, b.softirq);
    let steal = d(a.steal, b.steal);
    let total = user + nice + system + idle + iowait + irq + softirq + steal;
    if total == 0 {
        return None;
    }
    let p = |x: u64| 100.0 * x as f64 / total as f64;
    Some(CpuPct {
        // Time waiting for I/O is idle time for the CPU.
        utilization: p(total - idle - iowait),
        user: p(user),
        nice: p(nice),
        system: p(system),
        idle: p(idle),
        iowait: p(iowait),
        irq: p(irq),
        softirq: p(softirq),
        steal: p(steal),
        guest: p(d(a.guest, b.guest).min(user)),
        guest_nice: p(d(a.guest_nice, b.guest_nice).min(nice)),
    })
}

/// Two samples of `/proc/stat` `interval_ms` apart.
pub struct Samples {
    pub first_text: String,
    pub second_text: String,
    pub first: Vec<CpuTimes>,
    pub second: Vec<CpuTimes>,
}

pub fn sample_cpu(host: &Host, interval_ms: u64) -> Result<Samples, SysError> {
    let read = |which: &str| -> Result<(String, Vec<CpuTimes>), SysError> {
        let text = host.read("/proc/stat").map_err(|e| {
            SysError::new(
                "system.cpu_stat_unavailable",
                format!("{e} ({which} sample)"),
            )
        })?;
        let parsed =
            parse_proc_stat(&text).map_err(|e| SysError::new("system.cpu_stat_parse_error", e))?;
        Ok((text, parsed))
    };
    let (first_text, first) = read("first")?;
    host.pause(interval_ms);
    let (second_text, second) = read("second")?;
    Ok(Samples {
        first_text,
        second_text,
        first,
        second,
    })
}

/// Unique physical cores and sockets of the given CPUs, from
/// `/sys/devices/system/cpu/cpuN/topology`.
pub fn topology(host: &Host, ids: &[u32]) -> (Option<u32>, Option<u32>) {
    let mut cores = BTreeSet::new();
    let mut sockets = BTreeSet::new();
    for id in ids {
        let (core, socket) = cpu_topology(host, *id);
        if let Some(s) = socket {
            sockets.insert(s);
        }
        if let Some(c) = core {
            // core_id repeats on every socket.
            cores.insert((socket.unwrap_or(0), c));
        }
    }
    (
        (!cores.is_empty()).then_some(cores.len() as u32),
        (!sockets.is_empty()).then_some(sockets.len() as u32),
    )
}

fn cpu_topology(host: &Host, id: u32) -> (Option<u32>, Option<u32>) {
    let read = |f: &str| {
        host.read_trim(&format!("/sys/devices/system/cpu/cpu{id}/topology/{f}"))
            .and_then(|s| s.parse().ok())
    };
    (read("core_id"), read("physical_package_id"))
}

/// Current and maximum frequency of one CPU in Hz (cpufreq reports kHz).
fn cpu_freq(host: &Host, id: u32) -> Freq {
    let read = |f: &str| {
        host.read_trim(&format!("/sys/devices/system/cpu/cpu{id}/cpufreq/{f}"))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|khz| khz.saturating_mul(1000))
    };
    (read("scaling_cur_freq"), read("cpuinfo_max_freq"))
}

fn round(v: f64, places: i32) -> f64 {
    let m = 10f64.powi(places);
    (v * m).round() / m
}

// ---------------------------------------------------------------------------
// uptime
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct UptimeResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub uptime_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_time_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_seconds_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    pub warnings: Vec<String>,
}

/// "3d 4h 5m 06s": days, hours and minutes once non-zero, seconds always.
pub fn human_duration(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let (d, h, m, s) = (
        total / 86400,
        total % 86400 / 3600,
        total % 3600 / 60,
        total % 60,
    );
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if d > 0 || h > 0 {
        parts.push(format!("{h}h"));
    }
    if d > 0 || h > 0 || m > 0 {
        parts.push(format!("{m}m"));
    }
    parts.push(format!("{s:02}s"));
    parts.join(" ")
}

pub fn uptime(host: &Host, o: &UptimeOptions) -> Result<UptimeResponse, SysError> {
    let now = host.now_unix_ms();
    let text = host
        .read("/proc/uptime")
        .map_err(|e| SysError::new("system.uptime_unavailable", e.to_string()))?;
    let (up, idle) =
        parse_uptime(&text).map_err(|e| SysError::new("system.uptime_parse_error", e))?;
    let mut warnings = Vec::new();
    let mut idle_seconds = None;
    let mut idle_per_cpu = None;
    if o.include_idle {
        match idle {
            Some(i) => {
                idle_seconds = Some(i);
                match cpu_count(host) {
                    Ok(n) => idle_per_cpu = Some(i / n as f64),
                    Err(e) => warnings.push(format!("idle_seconds_per_cpu not available: {e}")),
                }
            }
            None => warnings.push("idle time not available: /proc/uptime has no idle field".into()),
        }
    }
    let stat = host.read("/proc/stat");
    let mut boot = None;
    if o.include_boot_time {
        boot = stat.as_ref().ok().and_then(|s| parse_btime(s));
        if boot.is_none() {
            boot = Some(now / 1000 - up as i64);
            warnings.push(
                "boot_time_unix computed as now - uptime: btime not found in /proc/stat".into(),
            );
        }
    }
    let raw = o.include_raw.then(|| {
        let mut r = json!({ "proc_uptime_line": text.trim() });
        if let Some(line) = stat
            .as_ref()
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("btime ")))
        {
            r["proc_stat_btime_line"] = json!(line);
        }
        r
    });
    Ok(UptimeResponse {
        ok: true,
        timestamp_unix_ms: now,
        uptime_seconds: up,
        uptime_human: o.include_human.then(|| human_duration(up)),
        boot_time_unix: boot,
        idle_seconds,
        idle_seconds_per_cpu: idle_per_cpu,
        raw,
        paths: o
            .include_paths
            .then(|| json!({ "uptime": "/proc/uptime", "btime": "/proc/stat" })),
        warnings,
    })
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct LoadHuman {
    pub status: String,
    pub status_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_vs_cpu_ratio: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct LoadResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_1m_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_5m_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_15m_per_cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count_logical: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runnable_processes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_processes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<LoadHuman>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    pub warnings: Vec<String>,
}

/// The status of a 1-minute load per CPU: idle < 0.1 <= normal < 0.7 <=
/// busy <= 1.5 < overloaded.
fn classify(per_cpu: f64) -> (&'static str, &'static str) {
    if per_cpu < 0.1 {
        ("idle", "is very low (< 0.1)")
    } else if per_cpu < 0.7 {
        ("normal", "is within normal range (0.1-0.7)")
    } else if per_cpu <= 1.5 {
        ("busy", "is busy but manageable (0.7-1.5)")
    } else {
        ("overloaded", "exceeds safe threshold (> 1.5)")
    }
}

pub fn load(host: &Host, o: &LoadOptions) -> Result<LoadResponse, SysError> {
    let now = host.now_unix_ms();
    let text = host
        .read("/proc/loadavg")
        .map_err(|e| SysError::new("system.load_unavailable", e.to_string()))?;
    let la = parse_loadavg(&text).map_err(|e| SysError::new("system.load_parse_error", e))?;
    let mut warnings = Vec::new();
    let (runnable, total) = if o.include_queue {
        match la.queue {
            Some((r, t)) => (Some(r), Some(t)),
            None => {
                warnings.push(
                    "queue counts not available: /proc/loadavg has no runnable/total field".into(),
                );
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    let mut cpus = None;
    if o.normalize_per_cpu {
        match cpu_count(host) {
            Ok(n) => cpus = Some(n),
            Err(e) => warnings.push(format!("per-CPU load not available: {e}")),
        }
    }
    // The divisor: the CPU count, at least min_cpu_count.
    let divisor = cpus.unwrap_or(0).max(o.min_cpu_count) as f64;
    let per = |v: f64| cpus.map(|_| v / divisor);
    let human = o.include_human.then(|| {
        let ratio = la.one / divisor;
        let (status, why) = classify(ratio);
        let label = if cpus.is_some() {
            "1m load per CPU".to_string()
        } else {
            format!("1m load divided by min_cpu_count={}", o.min_cpu_count)
        };
        LoadHuman {
            status: status.to_string(),
            status_reason: format!("{label} {why}"),
            load_vs_cpu_ratio: Some(ratio),
        }
    });
    Ok(LoadResponse {
        ok: true,
        timestamp_unix_ms: now,
        load_1m: la.one,
        load_5m: la.five,
        load_15m: la.fifteen,
        load_1m_per_cpu: per(la.one),
        load_5m_per_cpu: per(la.five),
        load_15m_per_cpu: per(la.fifteen),
        cpu_count_logical: cpus,
        runnable_processes: runnable,
        total_processes: total,
        human,
        raw: o
            .include_raw
            .then(|| json!({ "proc_loadavg_line": text.trim() })),
        paths: o.include_paths.then(|| {
            let mut p = json!({ "load": "/proc/loadavg" });
            if o.normalize_per_cpu {
                p["cpu_count"] = json!("/proc/stat");
            }
            p
        }),
        warnings,
    })
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Default)]
pub struct MemorySystem {
    pub available: bool,
    pub mem_total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_available_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffers_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shmem_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sreclaimable_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Hugepages {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surplus: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_bytes: Option<u64>,
}

#[derive(Debug, Serialize, Default)]
pub struct MemoryCgroup {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_usage_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_usage_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_used_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MemoryHuman {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_summary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MemoryResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub system: MemorySystem,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugepages: Option<Hugepages>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<MemoryCgroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<MemoryHuman>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    pub warnings: Vec<String>,
}

fn pct(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| 100.0 * part as f64 / whole as f64)
}

/// The `system` section from parsed meminfo. `MemTotal` is required.
pub fn memory_system(
    m: &BTreeMap<String, u64>,
    include_swap: bool,
    warnings: &mut Vec<String>,
) -> Result<MemorySystem, String> {
    let total = *m
        .get("MemTotal")
        .ok_or_else(|| "/proc/meminfo has no MemTotal line".to_string())?;
    let g = |k: &str| m.get(k).copied();
    let used = match (g("MemAvailable"), g("MemFree"), g("Buffers"), g("Cached")) {
        (Some(avail), ..) => Some(total.saturating_sub(avail)),
        (None, Some(free), Some(buf), Some(cached)) => {
            warnings.push(
                "MemAvailable not in /proc/meminfo: used = MemTotal - MemFree - Buffers - Cached"
                    .into(),
            );
            Some(total.saturating_sub(free + buf + cached))
        }
        _ => {
            warnings.push("memory used not available: /proc/meminfo lacks MemAvailable".into());
            None
        }
    };
    let mut s = MemorySystem {
        available: true,
        mem_total_bytes: total,
        mem_free_bytes: g("MemFree"),
        mem_available_bytes: g("MemAvailable"),
        buffers_bytes: g("Buffers"),
        cached_bytes: g("Cached"),
        shmem_bytes: g("Shmem"),
        sreclaimable_bytes: g("SReclaimable"),
        mem_used_bytes: used,
        mem_used_pct: used.and_then(|u| pct(u, total)),
        ..Default::default()
    };
    if include_swap {
        s.swap_total_bytes = g("SwapTotal");
        s.swap_free_bytes = g("SwapFree");
        if let (Some(t), Some(f)) = (s.swap_total_bytes, s.swap_free_bytes) {
            let used = t.saturating_sub(f);
            s.swap_used_bytes = Some(used);
            s.swap_used_pct = Some(pct(used, t).unwrap_or(0.0));
        }
    }
    Ok(s)
}

fn gib(b: u64) -> f64 {
    b as f64 / 1_073_741_824.0
}

pub fn memory(host: &Host, o: &MemoryOptions) -> Result<MemoryResponse, SysError> {
    let now = host.now_unix_ms();
    let text = host
        .read("/proc/meminfo")
        .map_err(|e| SysError::new("system.memory_meminfo_unavailable", e.to_string()))?;
    let (m, raw_map) = parse_meminfo(&text);
    let mut warnings = Vec::new();
    let system = memory_system(&m, o.include_swap, &mut warnings)
        .map_err(|e| SysError::new("system.memory_meminfo_parse_error", e))?;

    let hugepages = o.include_hugepages.then(|| {
        let g = |k: &str| m.get(k).copied();
        let available = g("HugePages_Total").is_some();
        if !available {
            warnings.push("hugepage counts not in /proc/meminfo".into());
        }
        Hugepages {
            available,
            total: g("HugePages_Total"),
            free: g("HugePages_Free"),
            reserved: g("HugePages_Rsvd"),
            surplus: g("HugePages_Surp"),
            page_bytes: g("Hugepagesize"),
        }
    });

    let mut cg_paths = Vec::new();
    let mut cg_raw = Map::new();
    let cgroup = o.include_cgroup.then(|| {
        let figures = match cgroup::resolve(host) {
            Ok(cg) => cgroup::memory(host, &cg),
            Err(e) => {
                warnings.push(format!("cgroup memory not available: {e}"));
                None
            }
        };
        match figures {
            None => {
                if !warnings.iter().any(|w| w.starts_with("cgroup memory")) {
                    warnings.push(
                        "cgroup memory not available: no memory controller for this process".into(),
                    );
                }
                MemoryCgroup::default()
            }
            Some(f) => {
                cg_paths = f.paths.clone();
                for (p, v) in &f.raw {
                    cg_raw.insert(p.clone(), json!(v));
                }
                let swap = o.include_swap;
                MemoryCgroup {
                    available: true,
                    unified: f.version.map(|v| v == Version::V2),
                    memory_limit_bytes: f.limit,
                    memory_usage_bytes: f.usage,
                    memory_used_pct: match (f.usage, f.limit) {
                        (Some(u), Some(l)) => pct(u, l),
                        _ => None,
                    },
                    swap_limit_bytes: f.swap_limit.filter(|_| swap),
                    swap_usage_bytes: f.swap_usage.filter(|_| swap),
                    swap_used_pct: match (f.swap_usage, f.swap_limit) {
                        (Some(u), Some(l)) if swap => pct(u, l),
                        _ => None,
                    },
                }
            }
        }
    });

    let human = o.include_human.then(|| {
        let system_summary = system.mem_used_bytes.map(|used| {
            let swap = match (system.swap_total_bytes, system.swap_used_bytes) {
                (Some(t), Some(u)) if t > 0 => format!(
                    ", {:.1} GiB swap used ({:.1}%)",
                    gib(u),
                    system.swap_used_pct.unwrap_or(0.0)
                ),
                (Some(_), Some(_)) => ", no swap".to_string(),
                _ => String::new(),
            };
            format!(
                "{:.1} GiB total, {:.1} GiB used ({:.1}%){}",
                gib(system.mem_total_bytes),
                gib(used),
                system.mem_used_pct.unwrap_or(0.0),
                swap
            )
        });
        let cgroup_summary = cgroup.as_ref().and_then(|c| {
            let usage = c.memory_usage_bytes?;
            Some(match c.memory_limit_bytes {
                Some(l) => format!(
                    "{:.1} GiB limit, {:.1} GiB used ({:.1}%)",
                    gib(l),
                    gib(usage),
                    c.memory_used_pct.unwrap_or(0.0)
                ),
                None => format!("no limit, {:.1} GiB used", gib(usage)),
            })
        });
        MemoryHuman {
            system_summary,
            cgroup_summary,
        }
    });

    let raw = o.include_raw.then(|| {
        let mut r = json!({ "meminfo": raw_map });
        if !cg_raw.is_empty() {
            r["cgroup"] = Value::Object(cg_raw);
        }
        r
    });
    let paths = o.include_paths.then(|| {
        let mut p = json!({ "meminfo": "/proc/meminfo" });
        if o.include_cgroup {
            p["cgroup_memory"] = json!(cg_paths);
        }
        p
    });
    Ok(MemoryResponse {
        ok: true,
        timestamp_unix_ms: now,
        system,
        hugepages,
        cgroup,
        human,
        raw,
        paths,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// cpu
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Default)]
pub struct CpuSystem {
    pub available: bool,
    pub logical_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_count: Option<u32>,
    #[serde(flatten)]
    pub pct: PctFields,
    /// The resh process's cgroup CPU usage over the sample as a share of its
    /// quota (quota cores x sample time); `null` without a quota or usage.
    pub cgroup_utilization_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_current_hz: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_max_hz: Option<u64>,
}

/// Current and maximum frequency of a CPU, in Hz.
type Freq = (Option<u64>, Option<u64>);

/// The percentage fields of a CPU entry; absent when no time passed.
#[derive(Debug, Serialize, Default)]
pub struct PctFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utilization_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iowait_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub irq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub softirq_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steal_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_nice_pct: Option<f64>,
}

impl From<Option<CpuPct>> for PctFields {
    fn from(p: Option<CpuPct>) -> Self {
        let Some(p) = p else {
            return PctFields::default();
        };
        let r = |v: f64| Some(round(v, 3));
        PctFields {
            utilization_pct: r(p.utilization),
            user_pct: r(p.user),
            nice_pct: r(p.nice),
            system_pct: r(p.system),
            idle_pct: r(p.idle),
            iowait_pct: r(p.iowait),
            irq_pct: r(p.irq),
            softirq_pct: r(p.softirq),
            steal_pct: r(p.steal),
            guest_pct: r(p.guest),
            guest_nice_pct: r(p.guest_nice),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CpuCore {
    pub id: u32,
    #[serde(flatten)]
    pub pct: PctFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_current_hz: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_max_hz: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub core_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_id: Option<u32>,
}

#[derive(Debug, Serialize, Default)]
pub struct CpuCgroup {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota_cores: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota_us: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_user_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_system_seconds: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct CpuHuman {
    pub status: String,
    pub status_reason: String,
    pub per_cpu_hotspots: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CpuResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub sample_duration_ms: u64,
    pub system: CpuSystem,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_cpu: Option<Vec<CpuCore>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<CpuCgroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<CpuHuman>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    pub warnings: Vec<String>,
}

fn cpu_status(util: Option<f64>) -> (String, String) {
    let Some(u) = util else {
        return (
            "unknown".into(),
            "No CPU time passed between the samples.".into(),
        );
    };
    let (s, why) = if u < 5.0 {
        ("idle", "system is idle")
    } else if u < 60.0 {
        ("normal", "well within normal range")
    } else if u < 85.0 {
        ("busy", "system is busy but manageable")
    } else {
        ("overloaded", "system is overloaded")
    };
    (
        s.into(),
        format!("Overall CPU utilization is {u:.1}%, {why}."),
    )
}

pub fn cpu(host: &Host, o: &CpuOptions) -> Result<CpuResponse, SysError> {
    let now = host.now_unix_ms();
    let interval = o.interval_ms();
    // The cgroup's CPU usage is read around the two /proc/stat samples.
    let cg = cgroup::resolve(host).ok();
    let cg_usage = || cg.as_ref().and_then(|c| cgroup::usage_seconds(host, c));
    let usage_before = cg_usage();
    let started = std::time::Instant::now();
    let s = sample_cpu(host, interval)?;
    let usage_after = cg_usage();
    // The pause is at least `interval`; use the time that really passed.
    let elapsed_s = started
        .elapsed()
        .as_secs_f64()
        .max(interval as f64 / 1000.0);
    let quota = cg
        .as_ref()
        .and_then(|c| cgroup::cpu(host, c))
        .and_then(|f| f.quota_cores);
    let cgroup_utilization_pct = match (usage_before, usage_after, quota) {
        (Some(a), Some(b), Some(q)) if q > 0.0 && elapsed_s > 0.0 => {
            Some(round((b - a).max(0.0) / (q * elapsed_s) * 100.0, 3))
        }
        _ => None,
    };
    let mut warnings = Vec::new();
    let find = |list: &[CpuTimes], id: Option<u32>| list.iter().find(|c| c.id == id).cloned();
    let (Some(a), Some(b)) = (find(&s.first, None), find(&s.second, None)) else {
        // parse_proc_stat guarantees the aggregate line.
        return Err(SysError::new(
            "system.cpu_stat_parse_error",
            "/proc/stat has no aggregate \"cpu\" line",
        ));
    };
    let total = cpu_pct(&a, &b);
    if total.is_none() {
        warnings.push(format!(
            "no CPU time passed in {interval} ms between the samples; percentages omitted"
        ));
    }
    let ids: Vec<u32> = s.first.iter().filter_map(|c| c.id).collect();
    let (physical, sockets) = if o.include_topology {
        let t = topology(host, &ids);
        if t.0.is_none() {
            warnings.push("CPU topology not available under /sys/devices/system/cpu".into());
        }
        t
    } else {
        (None, None)
    };
    let freqs: Vec<(u32, Freq)> = if o.include_frequency {
        ids.iter().map(|id| (*id, cpu_freq(host, *id))).collect()
    } else {
        Vec::new()
    };
    let cur: Vec<u64> = freqs.iter().filter_map(|(_, f)| f.0).collect();
    let max = freqs.iter().filter_map(|(_, f)| f.1).max();
    if o.include_frequency && cur.is_empty() {
        warnings.push("CPU frequency not available (no cpufreq under /sys)".into());
    }
    let system = CpuSystem {
        available: true,
        logical_count: ids.len() as u32,
        physical_count: physical,
        socket_count: sockets,
        pct: total.into(),
        cgroup_utilization_pct,
        frequency_current_hz: (!cur.is_empty()).then(|| cur.iter().sum::<u64>() / cur.len() as u64),
        frequency_max_hz: max,
    };

    let per_cpu = o.per_cpu.then(|| {
        let mut out = Vec::new();
        for c in s.first.iter().filter(|c| c.id.is_some()) {
            let id = c.id.unwrap_or_default();
            let Some(end) = find(&s.second, c.id) else {
                warnings.push(format!("{} went offline between the samples", c.name));
                continue;
            };
            let (fc, fm) = if o.include_frequency {
                cpu_freq(host, id)
            } else {
                (None, None)
            };
            let (core, socket) = if o.include_topology {
                cpu_topology(host, id)
            } else {
                (None, None)
            };
            out.push(CpuCore {
                id,
                pct: cpu_pct(c, &end).into(),
                frequency_current_hz: fc,
                frequency_max_hz: fm,
                core_id: core,
                socket_id: socket,
            });
        }
        out
    });

    let mut cg_paths = Vec::new();
    let mut cg_raw = Map::new();
    let cgroup = o.include_cgroup.then(|| {
        let figures = match cgroup::resolve(host) {
            Ok(cg) => cgroup::cpu(host, &cg),
            Err(e) => {
                warnings.push(format!("cgroup CPU figures not available: {e}"));
                None
            }
        };
        match figures {
            None => {
                if !warnings.iter().any(|w| w.starts_with("cgroup CPU")) {
                    warnings.push(
                        "cgroup CPU figures not available: no cpu controller for this process"
                            .into(),
                    );
                }
                CpuCgroup::default()
            }
            Some(f) => {
                cg_paths = f.paths.clone();
                for (p, v) in &f.raw {
                    cg_raw.insert(p.clone(), json!(v));
                }
                CpuCgroup {
                    available: true,
                    unified: f.version.map(|v| v == Version::V2),
                    cpu_quota_cores: f.quota_cores,
                    cpu_period_us: f.period_us,
                    cpu_quota_us: f.quota_us,
                    usage_seconds: f.usage_seconds,
                    usage_user_seconds: f.user_seconds,
                    usage_system_seconds: f.system_seconds,
                }
            }
        }
    });

    let human = o.include_human.then(|| {
        let (status, status_reason) = cpu_status(system.pct.utilization_pct);
        let per_cpu_hotspots = per_cpu
            .iter()
            .flatten()
            .filter_map(|c| {
                let u = c.pct.utilization_pct?;
                (u > 80.0).then(|| format!("cpu{} at {:.1}%", c.id, u))
            })
            .collect();
        CpuHuman {
            status,
            status_reason,
            per_cpu_hotspots,
        }
    });

    let raw = o.include_raw.then(|| {
        let mut r = json!({
            "proc_stat_start": s.first_text,
            "proc_stat_end": s.second_text,
            "sample_duration_ms": interval,
        });
        if o.include_frequency {
            let mut f = Map::new();
            for (id, (c, m)) in &freqs {
                if let Some(c) = c {
                    f.insert(format!("cpu{id}_scaling_cur_freq_khz"), json!(c / 1000));
                }
                if let Some(m) = m {
                    f.insert(format!("cpu{id}_cpuinfo_max_freq_khz"), json!(m / 1000));
                }
            }
            if !f.is_empty() {
                r["frequency"] = Value::Object(f);
            }
        }
        if !cg_raw.is_empty() {
            r["cgroup"] = Value::Object(cg_raw);
        }
        r
    });
    let paths = o.include_paths.then(|| {
        let mut p = json!({ "stat": "/proc/stat" });
        if o.include_frequency {
            p["cpufreq_scaling_cur_freq"] =
                json!("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq");
            p["cpufreq_cpuinfo_max_freq"] =
                json!("/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq");
        }
        if o.include_topology {
            p["topology_core_id"] = json!("/sys/devices/system/cpu/cpu*/topology/core_id");
            p["topology_physical_package_id"] =
                json!("/sys/devices/system/cpu/cpu*/topology/physical_package_id");
        }
        if o.include_cgroup {
            p["cgroup_cpu"] = json!(cg_paths);
        }
        p
    });

    Ok(CpuResponse {
        ok: true,
        timestamp_unix_ms: now,
        sample_duration_ms: interval,
        system,
        per_cpu,
        cgroup,
        human,
        raw,
        paths,
        warnings,
    })
}
