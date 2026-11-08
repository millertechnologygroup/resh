//! cgroup (v1 and v2) memory and CPU figures for the resh process.
//!
//! The process's own cgroup comes from `/proc/self/cgroup`, and where each
//! hierarchy is mounted from `/proc/self/mountinfo` (its mount root makes
//! the path right inside containers and cgroup namespaces). Limits are
//! hierarchical: the effective limit is the smallest one set on the
//! process's cgroup or any ancestor up to the mount point, so every level
//! is read. On a hybrid host a controller attached to a v1 hierarchy is read
//! there; otherwise the unified (v2) hierarchy is used.

use super::host::{Host, unescape_octal};

/// v1 counters at or above this value mean "no limit" (the kernel's
/// `PAGE_COUNTER_MAX` in bytes, rounded down to a page).
const V1_UNLIMITED: u64 = 0x7FFF_FFFF_FFFF_F000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

/// Where one controller of the resh process's cgroup lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controller {
    pub version: Version,
    /// The process's cgroup directory (a host path).
    pub dir: String,
    /// The hierarchy's mount point (the walk for limits stops here).
    pub mount: String,
}

impl Controller {
    /// The process's directory and each ancestor up to the mount point,
    /// nearest first.
    fn levels(&self) -> Vec<String> {
        let mut out = vec![self.dir.clone()];
        let mut cur = self.dir.clone();
        while cur != self.mount && cur.starts_with(&self.mount) {
            match cur.rfind('/') {
                Some(0) | None => break,
                Some(i) => {
                    cur.truncate(i);
                    if cur.len() < self.mount.len() {
                        break;
                    }
                    out.push(cur.clone());
                }
            }
        }
        out
    }

    pub fn file(&self, name: &str) -> String {
        format!("{}/{}", self.dir, name)
    }
}

/// The resh process's cgroup controllers that matter here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cgroups {
    pub memory: Option<Controller>,
    pub cpu: Option<Controller>,
    pub cpuacct: Option<Controller>,
    /// The unified (v2) group, when the process is in one.
    pub unified: Option<Controller>,
}

struct Mount {
    root: String,
    point: String,
    fstype: String,
    super_opts: Vec<String>,
}

fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre: Vec<&str> = pre.split_whitespace().collect();
        let post: Vec<&str> = post.split_whitespace().collect();
        if pre.len() < 5 || post.len() < 3 {
            continue;
        }
        out.push(Mount {
            root: unescape_octal(pre[3]),
            point: unescape_octal(pre[4]),
            fstype: post[0].to_string(),
            super_opts: post[2].split(',').map(str::to_string).collect(),
        });
    }
    out
}

/// The cgroup directory for `path` inside a hierarchy mounted with
/// `mount` (whose root may be a sub-tree, as in a container).
fn join(mount: &Mount, path: &str) -> String {
    let rel = if mount.root == "/" {
        path
    } else if path == mount.root {
        "/"
    } else if let Some(rest) = path.strip_prefix(&format!("{}/", mount.root)) {
        // Keep the leading slash.
        &path[path.len() - rest.len() - 1..]
    } else {
        // Outside the mount root (a cgroup namespace shows "/" or "/.."
        // paths): the mount point itself is the process's cgroup.
        "/"
    };
    let rel = if rel.starts_with("/..") { "/" } else { rel };
    let point = mount.point.trim_end_matches('/');
    if rel == "/" {
        if point.is_empty() {
            "/".to_string()
        } else {
            point.to_string()
        }
    } else {
        format!("{point}{rel}")
    }
}

/// Finds the process's controllers from `/proc/self/cgroup` and
/// `/proc/self/mountinfo`. `Err` carries a warning when neither file can be
/// read.
pub fn resolve(host: &Host) -> Result<Cgroups, String> {
    let cg = host.read("/proc/self/cgroup").map_err(|e| e.to_string())?;
    let mi = host
        .read("/proc/self/mountinfo")
        .map_err(|e| e.to_string())?;
    let mounts = parse_mountinfo(&mi);
    let mut out = Cgroups::default();

    let mut unified_path = None;
    let mut v1_paths: Vec<(Vec<String>, String)> = Vec::new();
    for line in cg.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(ctrls), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if id == "0" && ctrls.is_empty() {
            unified_path = Some(path.to_string());
        } else {
            v1_paths.push((
                ctrls.split(',').map(str::to_string).collect(),
                path.to_string(),
            ));
        }
    }

    let v1 = |name: &str| -> Option<Controller> {
        let (_, path) = v1_paths.iter().find(|(c, _)| c.iter().any(|c| c == name))?;
        let m = mounts
            .iter()
            .find(|m| m.fstype == "cgroup" && m.super_opts.iter().any(|o| o == name))?;
        Some(Controller {
            version: Version::V1,
            dir: join(m, path),
            mount: m.point.trim_end_matches('/').to_string(),
        })
    };
    if let Some(path) = &unified_path
        && let Some(m) = mounts.iter().find(|m| m.fstype == "cgroup2")
    {
        out.unified = Some(Controller {
            version: Version::V2,
            dir: join(m, path),
            mount: m.point.trim_end_matches('/').to_string(),
        });
    }
    let v2 = |file: &str| -> Option<Controller> {
        let u = out.unified.clone()?;
        // A v2 controller is usable when its interface files exist in the
        // process's group (the parent enabled it).
        host.exists(&u.file(file)).then_some(u)
    };
    out.memory = v1("memory").or_else(|| v2("memory.current"));
    out.cpu = v1("cpu").or_else(|| v2("cpu.stat"));
    out.cpuacct = v1("cpuacct").or_else(|| v2("cpu.stat"));
    Ok(out)
}

fn read_u64(host: &Host, path: &str) -> Option<u64> {
    host.read_trim(path)?.parse().ok()
}

/// A limit file's value: `None` for "max" or a v1 "unlimited" counter.
fn limit_value(host: &Host, path: &str) -> Option<Option<u64>> {
    let s = host.read_trim(path)?;
    if s == "max" {
        return Some(None);
    }
    let v: u64 = s.parse().ok()?;
    Some((v < V1_UNLIMITED).then_some(v))
}

/// The smallest limit in `file` over the levels of `c`, and the files read.
fn min_limit(host: &Host, c: &Controller, file: &str) -> (Option<u64>, Vec<String>) {
    let mut best: Option<u64> = None;
    let mut read = Vec::new();
    for dir in c.levels() {
        let p = format!("{dir}/{file}");
        if let Some(v) = limit_value(host, &p) {
            read.push(p);
            if let Some(v) = v {
                best = Some(best.map_or(v, |b| b.min(v)));
            }
        }
    }
    (best, read)
}

/// cgroup memory figures (bytes).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryFigures {
    pub version: Option<Version>,
    pub limit: Option<u64>,
    pub usage: Option<u64>,
    pub swap_limit: Option<u64>,
    pub swap_usage: Option<u64>,
    /// Files read, for `include_paths`.
    pub paths: Vec<String>,
    /// Raw contents by file, for `include_raw`.
    pub raw: Vec<(String, String)>,
}

pub fn memory(host: &Host, cg: &Cgroups) -> Option<MemoryFigures> {
    let c = cg.memory.as_ref()?;
    let mut f = MemoryFigures {
        version: Some(c.version),
        ..Default::default()
    };
    let (usage_file, limit_file) = match c.version {
        Version::V2 => ("memory.current", "memory.max"),
        Version::V1 => ("memory.usage_in_bytes", "memory.limit_in_bytes"),
    };
    f.usage = read_u64(host, &c.file(usage_file));
    if f.usage.is_some() {
        f.paths.push(c.file(usage_file));
    }
    let (limit, read) = min_limit(host, c, limit_file);
    f.limit = limit;
    f.paths.extend(read);
    match c.version {
        Version::V2 => {
            let (swap_limit, read) = min_limit(host, c, "memory.swap.max");
            f.swap_limit = swap_limit;
            f.paths.extend(read);
            f.swap_usage = read_u64(host, &c.file("memory.swap.current"));
            if f.swap_usage.is_some() {
                f.paths.push(c.file("memory.swap.current"));
            }
        }
        Version::V1 => {
            // memsw counts memory plus swap; swap alone is the difference.
            let (memsw_limit, read) = min_limit(host, c, "memory.memsw.limit_in_bytes");
            f.paths.extend(read);
            f.swap_limit = match (memsw_limit, f.limit) {
                (Some(ms), Some(m)) => Some(ms.saturating_sub(m)),
                _ => None,
            };
            let memsw = read_u64(host, &c.file("memory.memsw.usage_in_bytes"));
            if memsw.is_some() {
                f.paths.push(c.file("memory.memsw.usage_in_bytes"));
            }
            f.swap_usage = match (memsw, f.usage) {
                (Some(ms), Some(m)) => Some(ms.saturating_sub(m)),
                _ => None,
            };
        }
    }
    for p in &f.paths {
        if let Some(s) = host.read_trim(p) {
            f.raw.push((p.clone(), s));
        }
    }
    (f.usage.is_some() || f.limit.is_some()).then_some(f)
}

/// cgroup CPU figures.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuFigures {
    pub version: Option<Version>,
    /// The binding limit as quota and period (microseconds).
    pub quota_us: Option<i64>,
    pub period_us: Option<u64>,
    /// quota / period, in CPUs.
    pub quota_cores: Option<f64>,
    pub usage_seconds: Option<f64>,
    pub user_seconds: Option<f64>,
    pub system_seconds: Option<f64>,
    pub paths: Vec<String>,
    pub raw: Vec<(String, String)>,
}

/// Parses a v2 `cpu.max` ("max 100000" or "150000 100000").
fn parse_cpu_max(s: &str) -> Option<(Option<i64>, u64)> {
    let mut it = s.split_whitespace();
    let q = it.next()?;
    let p: u64 = it.next().map_or(Some(100_000), |p| p.parse().ok())?;
    if q == "max" {
        return Some((None, p));
    }
    Some((Some(q.parse().ok()?), p))
}

pub fn cpu(host: &Host, cg: &Cgroups) -> Option<CpuFigures> {
    let mut f = CpuFigures::default();
    // The binding quota is the level with the fewest CPUs.
    let mut best: Option<(i64, u64)> = None;
    let mut consider = |q: i64, p: u64| {
        if q > 0 && p > 0 {
            let cores = q as f64 / p as f64;
            if best.is_none_or(|(bq, bp)| cores < bq as f64 / bp as f64) {
                best = Some((q, p));
            }
        }
    };
    if let Some(c) = &cg.cpu {
        f.version = Some(c.version);
        for dir in c.levels() {
            match c.version {
                Version::V2 => {
                    let p = format!("{dir}/cpu.max");
                    if let Some((q, per)) = host.read_trim(&p).as_deref().and_then(parse_cpu_max) {
                        f.paths.push(p);
                        if f.period_us.is_none() {
                            f.period_us = Some(per);
                        }
                        if let Some(q) = q {
                            consider(q, per);
                        }
                    }
                }
                Version::V1 => {
                    let qp = format!("{dir}/cpu.cfs_quota_us");
                    let pp = format!("{dir}/cpu.cfs_period_us");
                    let q: Option<i64> = host.read_trim(&qp).and_then(|s| s.parse().ok());
                    let per = read_u64(host, &pp);
                    if let (Some(q), Some(per)) = (q, per) {
                        f.paths.push(qp);
                        f.paths.push(pp);
                        if f.period_us.is_none() {
                            f.period_us = Some(per);
                        }
                        consider(q, per);
                    }
                }
            }
        }
    }
    if let Some((q, p)) = best {
        f.quota_us = Some(q);
        f.period_us = Some(p);
        f.quota_cores = Some(q as f64 / p as f64);
    }
    if let Some(c) = &cg.cpuacct {
        f.version = f.version.or(Some(c.version));
        match c.version {
            Version::V2 => {
                let p = c.file("cpu.stat");
                if let Some(text) = host.read_trim(&p) {
                    f.paths.push(p);
                    for line in text.lines() {
                        let mut it = line.split_whitespace();
                        let (Some(k), Some(v)) = (it.next(), it.next()) else {
                            continue;
                        };
                        let Ok(v) = v.parse::<u64>() else { continue };
                        let secs = Some(v as f64 / 1e6);
                        match k {
                            "usage_usec" => f.usage_seconds = secs,
                            "user_usec" => f.user_seconds = secs,
                            "system_usec" => f.system_seconds = secs,
                            _ => {}
                        }
                    }
                }
            }
            Version::V1 => {
                let p = c.file("cpuacct.usage");
                if let Some(ns) = read_u64(host, &p) {
                    f.paths.push(p);
                    f.usage_seconds = Some(ns as f64 / 1e9);
                }
                let p = c.file("cpuacct.stat");
                if let Some(text) = host.read_trim(&p) {
                    f.paths.push(p);
                    let hz = host.clock_ticks() as f64;
                    for line in text.lines() {
                        let mut it = line.split_whitespace();
                        let (Some(k), Some(v)) = (it.next(), it.next()) else {
                            continue;
                        };
                        let Ok(v) = v.parse::<u64>() else { continue };
                        match k {
                            "user" => f.user_seconds = Some(v as f64 / hz),
                            "system" => f.system_seconds = Some(v as f64 / hz),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    f.paths.dedup();
    for p in &f.paths {
        if let Some(s) = host.read_trim(p) {
            f.raw.push((p.clone(), s));
        }
    }
    (!f.paths.is_empty()).then_some(f)
}

/// The cgroup's cumulative CPU time in seconds: `usage_usec` of `cpu.stat`
/// (v2) or `cpuacct.usage` (v1, nanoseconds).
pub fn usage_seconds(host: &Host, cg: &Cgroups) -> Option<f64> {
    let c = cg.cpuacct.as_ref()?;
    match c.version {
        Version::V2 => host.read_trim(&c.file("cpu.stat"))?.lines().find_map(|l| {
            let v = l.strip_prefix("usage_usec ")?.trim().parse::<u64>().ok()?;
            Some(v as f64 / 1e6)
        }),
        Version::V1 => read_u64(host, &c.file("cpuacct.usage")).map(|ns| ns as f64 / 1e9),
    }
}
