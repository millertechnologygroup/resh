//! `format=text` renderings of the system responses.

use super::disk::{DiskResponse, human_bytes};
use super::env::EnvListResponse;
use super::metrics::{CpuResponse, LoadResponse, MemoryResponse, UptimeResponse};
use serde_json::Value;
use std::fmt::Write as _;

fn timestamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| ms.to_string())
}

fn header(out: &mut String, title: &str, ms: i64) {
    let _ = writeln!(out, "{title}\n{}\n", "=".repeat(title.len()));
    let _ = writeln!(out, "Timestamp : {}\n", timestamp(ms));
}

fn warnings(out: &mut String, w: &[String]) {
    out.push_str("Warnings:\n");
    if w.is_empty() {
        out.push_str("  (none)\n");
    }
    for x in w {
        let _ = writeln!(out, "  - {x}");
    }
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / 1_073_741_824.0)
}

pub fn uptime(r: &UptimeResponse) -> String {
    let mut o = String::new();
    header(&mut o, "System Uptime", r.timestamp_unix_ms);
    let _ = writeln!(
        o,
        "Uptime    : {}",
        r.uptime_human.as_deref().unwrap_or("(not requested)")
    );
    let _ = writeln!(o, "Seconds   : {:.2}", r.uptime_seconds);
    match r.boot_time_unix {
        Some(b) => {
            let _ = writeln!(o, "Boot Time : {}", timestamp(b * 1000));
        }
        None => o.push_str("Boot Time : (not requested)\n"),
    }
    match (r.idle_seconds, r.idle_seconds_per_cpu) {
        (Some(i), Some(p)) => {
            let _ = writeln!(o, "Idle      : {i:.2} s (per CPU: {p:.2} s)");
        }
        (Some(i), None) => {
            let _ = writeln!(o, "Idle      : {i:.2} s");
        }
        _ => o.push_str("Idle      : (not available)\n"),
    }
    o.push('\n');
    warnings(&mut o, &r.warnings);
    o
}

pub fn load(r: &LoadResponse) -> String {
    let mut o = String::new();
    header(&mut o, "System Load", r.timestamp_unix_ms);
    let _ = writeln!(
        o,
        "Load Averages:\n  1m  : {:.2}\n  5m  : {:.2}\n  15m : {:.2}\n",
        r.load_1m, r.load_5m, r.load_15m
    );
    if let Some(n) = r.cpu_count_logical {
        let _ = writeln!(o, "CPU:\n  Logical CPUs : {n}");
        if let Some(p) = r.load_1m_per_cpu {
            let _ = writeln!(o, "  1m per CPU   : {p:.3}");
        }
        o.push('\n');
    }
    if let (Some(run), Some(total)) = (r.runnable_processes, r.total_processes) {
        let _ = writeln!(
            o,
            "Queue:\n  Runnable     : {run}\n  Total        : {total}\n"
        );
    }
    if let Some(h) = &r.human {
        let _ = writeln!(o, "Status:\n  {} - {}\n", h.status, h.status_reason);
    }
    warnings(&mut o, &r.warnings);
    o
}

pub fn memory(r: &MemoryResponse) -> String {
    let mut o = String::new();
    header(&mut o, "System Memory", r.timestamp_unix_ms);
    let s = &r.system;
    let opt = |v: Option<u64>| v.map(gib).unwrap_or_else(|| "(unknown)".into());
    let _ = writeln!(o, "System:\n  Total       : {}", gib(s.mem_total_bytes));
    match (s.mem_used_bytes, s.mem_used_pct) {
        (Some(u), Some(p)) => {
            let _ = writeln!(o, "  Used        : {} ({p:.1}%)", gib(u));
        }
        _ => o.push_str("  Used        : (unknown)\n"),
    }
    let _ = writeln!(o, "  Free        : {}", opt(s.mem_free_bytes));
    let _ = writeln!(o, "  Available   : {}", opt(s.mem_available_bytes));
    let _ = writeln!(o, "  Buffers     : {}", opt(s.buffers_bytes));
    let _ = writeln!(o, "  Cached      : {}\n", opt(s.cached_bytes));
    if let Some(t) = s.swap_total_bytes {
        let _ = writeln!(o, "Swap:\n  Total       : {}", gib(t));
        if let (Some(u), Some(p)) = (s.swap_used_bytes, s.swap_used_pct) {
            let _ = writeln!(o, "  Used        : {} ({p:.1}%)", gib(u));
        }
        let _ = writeln!(o, "  Free        : {}\n", opt(s.swap_free_bytes));
    }
    if let Some(c) = &r.cgroup {
        o.push_str("Cgroup:\n");
        if c.available {
            let v = match c.unified {
                Some(true) => "v2",
                Some(false) => "v1",
                None => "?",
            };
            let _ = writeln!(o, "  Available   : yes ({v})");
            let _ = writeln!(
                o,
                "  Limit       : {}",
                c.memory_limit_bytes
                    .map(gib)
                    .unwrap_or_else(|| "unlimited".into())
            );
            match (c.memory_usage_bytes, c.memory_used_pct) {
                (Some(u), Some(p)) => {
                    let _ = writeln!(o, "  Used        : {} ({p:.1}%)\n", gib(u));
                }
                (Some(u), None) => {
                    let _ = writeln!(o, "  Used        : {}\n", gib(u));
                }
                _ => o.push_str("  Used        : (unknown)\n\n"),
            }
        } else {
            o.push_str("  Available   : no\n\n");
        }
    }
    if let Some(h) = &r.hugepages {
        o.push_str("Hugepages:\n");
        if h.available {
            let _ = writeln!(o, "  Total       : {}", h.total.unwrap_or(0));
            let _ = writeln!(o, "  Free        : {}", h.free.unwrap_or(0));
            if let Some(pb) = h.page_bytes {
                let _ = writeln!(o, "  Page Size   : {}", human_bytes(pb));
            }
            o.push('\n');
        } else {
            o.push_str("  Available   : no\n\n");
        }
    }
    warnings(&mut o, &r.warnings);
    o
}

pub fn cpu(r: &CpuResponse) -> String {
    let mut o = String::new();
    header(&mut o, "CPU Metrics", r.timestamp_unix_ms);
    let s = &r.system;
    let _ = writeln!(
        o,
        "System:\n  Sample       : {} ms\n  Logical CPUs : {}",
        r.sample_duration_ms, s.logical_count
    );
    if let Some(n) = s.physical_count {
        let _ = writeln!(o, "  Physical     : {n}");
    }
    if let Some(n) = s.socket_count {
        let _ = writeln!(o, "  Sockets      : {n}");
    }
    o.push('\n');
    let p = &s.pct;
    for (label, v) in [
        ("Utilization", p.utilization_pct),
        ("User", p.user_pct),
        ("System", p.system_pct),
        ("Idle", p.idle_pct),
        ("IOwait", p.iowait_pct),
    ] {
        if let Some(v) = v {
            let _ = writeln!(o, "  {label:<12} : {v:.1}%");
        }
    }
    if let (Some(c), Some(m)) = (s.frequency_current_hz, s.frequency_max_hz) {
        let _ = writeln!(
            o,
            "  Freq (avg)   : {:.2} GHz (max {:.2} GHz)",
            c as f64 / 1e9,
            m as f64 / 1e9
        );
    }
    o.push('\n');
    if let Some(per) = &r.per_cpu {
        o.push_str("Per-CPU:\n");
        for c in per.iter().take(16) {
            let u = c
                .pct
                .utilization_pct
                .map_or("n/a".to_string(), |u| format!("{u:.1}%"));
            let f = c
                .frequency_current_hz
                .map_or(String::new(), |f| format!("  ({:.2} GHz)", f as f64 / 1e9));
            let _ = writeln!(o, "  cpu{}: {u}{f}", c.id);
        }
        if per.len() > 16 {
            let _ = writeln!(o, "  ... and {} more CPUs", per.len() - 16);
        }
        o.push('\n');
    }
    if let Some(c) = &r.cgroup {
        if c.available {
            o.push_str("Cgroup:\n");
            match c.cpu_quota_cores {
                Some(q) => {
                    let _ = writeln!(o, "  Quota        : {q:.2} CPUs");
                }
                None => o.push_str("  Quota        : unlimited\n"),
            }
            if let Some(u) = c.usage_seconds {
                let _ = writeln!(o, "  Usage        : {u:.1} s");
            }
            o.push('\n');
        }
    }
    if let Some(h) = &r.human {
        let _ = writeln!(o, "Status:\n  {} - {}", h.status, h.status_reason);
        if !h.per_cpu_hotspots.is_empty() {
            o.push_str("\nHotspots:\n");
            for x in &h.per_cpu_hotspots {
                let _ = writeln!(o, "  {x}");
            }
        }
        o.push('\n');
    }
    warnings(&mut o, &r.warnings);
    o
}

pub fn disk(r: &DiskResponse) -> String {
    let mut o = String::new();
    header(&mut o, "Disk Usage", r.timestamp_unix_ms);
    o.push_str("Mounts:\n");
    if r.mounts.is_empty() {
        o.push_str("  (none)\n\n");
    }
    for m in &r.mounts {
        match &m.fs_type {
            Some(t) => {
                let _ = writeln!(o, "  {} ({t} on {})", m.mount_point, m.device);
            }
            None => {
                let _ = writeln!(o, "  {} ({})", m.mount_point, m.device);
            }
        }
        match (m.total_bytes, m.used_bytes, m.avail_bytes, m.used_pct) {
            (Some(t), Some(u), Some(a), Some(p)) => {
                let _ = writeln!(
                    o,
                    "    Total   : {}\n    Used    : {} ({p:.1}%)\n    Avail   : {}",
                    human_bytes(t),
                    human_bytes(u),
                    human_bytes(a)
                );
            }
            _ => o.push_str("    Stats   : unavailable\n"),
        }
        o.push('\n');
    }
    if r.mounts_truncated {
        let _ = writeln!(o, "  (list truncated at max_mounts)\n");
    }
    if let Some(io) = &r.io {
        o.push_str("I/O:\n");
        if !io.available {
            o.push_str("  (not available)\n");
        }
        for d in &io.devices {
            let _ = writeln!(
                o,
                "  {} ({})\n    Reads   : {} ({})\n    Writes  : {} ({})",
                d.name,
                d.maj_min,
                d.reads_completed,
                human_bytes(d.read_bytes),
                d.writes_completed,
                human_bytes(d.write_bytes)
            );
        }
        o.push('\n');
    }
    warnings(&mut o, &r.warnings);
    o
}

pub fn env_list(r: &EnvListResponse) -> String {
    let mut o = String::new();
    header(&mut o, "Environment Variables", r.timestamp_unix_ms);
    let _ = writeln!(
        o,
        "PID       : {}\nSource    : {}\nReturned  : {} of {} ({} masked, {} truncated)\n",
        r.pid,
        r.source,
        r.env_count_returned,
        r.env_count_total,
        r.env_count_masked,
        r.env_count_truncated
    );
    if r.variables.is_empty() {
        o.push_str("No environment variables match.\n");
    }
    for v in &r.variables {
        match &v.value {
            Some(val) => {
                let _ = writeln!(o, "{:20} = {val}", v.name);
            }
            None => {
                let _ = writeln!(o, "{}", v.name);
            }
        }
    }
    o.push('\n');
    if r.truncated_vars {
        o.push_str("Note: list truncated at max_vars.\n");
    }
    warnings(&mut o, &r.warnings);
    o
}

fn s(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

pub fn info(r: &Value) -> String {
    let mut o = String::new();
    header(
        &mut o,
        "System Info",
        r["timestamp_unix_ms"].as_i64().unwrap_or(0),
    );
    let scopes: Vec<String> = r["scopes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for scope in &scopes {
        let Some(v) = r.get(scope).filter(|v| v.is_object()) else {
            continue;
        };
        let mut title = scope.clone();
        if let Some(c) = title.get_mut(0..1) {
            c.make_ascii_uppercase();
        }
        let _ = writeln!(o, "{title}:");
        if scope == "disk" {
            for m in v["mounts"].as_array().into_iter().flatten() {
                let _ = writeln!(
                    o,
                    "  {:<20} {} total, {}% used",
                    s(m, "mount_point").unwrap_or_default(),
                    m["total_bytes"]
                        .as_u64()
                        .map(human_bytes)
                        .unwrap_or_default(),
                    s(m, "usage_pct").unwrap_or_else(|| "?".into())
                );
            }
        } else if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                let shown = match val {
                    Value::Null => "(unknown)".to_string(),
                    Value::String(s) => s.clone(),
                    Value::Array(a) if a.is_empty() => "(none)".to_string(),
                    other => other.to_string(),
                };
                let _ = writeln!(o, "  {k:<22}: {shown}");
            }
        }
        o.push('\n');
    }
    let w: Vec<String> = r["warnings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    warnings(&mut o, &w);
    o
}
