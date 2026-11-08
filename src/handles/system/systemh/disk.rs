//! `disk`: mounted filesystems from `/proc/self/mounts`, capacity and inodes
//! from `statvfs`, and I/O counters from `/proc/diskstats`. `statvfs` on a
//! hung network filesystem can block, so it runs on a worker thread and the
//! verb stops at `timeout_ms`, reporting what it has.

use super::args::DiskOptions;
use super::error::SysError;
use super::host::{FsStats, Host, statvfs_at, unescape_octal};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Pseudo filesystems with no storage of their own, skipped unless
/// `include_virtual=true`.
pub const VIRTUAL_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "ramfs",
    "securityfs",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "cgroup",
    "cgroup2",
    "pstore",
    "efivarfs",
    "bpf",
    "binfmt_misc",
    "mqueue",
    "hugetlbfs",
    "autofs",
    "nsfs",
    "rpc_pipefs",
    "nfsd",
    "selinuxfs",
    "squashfs",
    "iso9660",
    "udf",
];

pub fn is_virtual(fs_type: &str) -> bool {
    VIRTUAL_FS.contains(&fs_type)
}

/// One line of a mounts table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountLine {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
}

/// Parses `/proc/self/mounts`. Malformed lines are returned as warnings;
/// `Err` when the text has lines but none can be read.
pub fn parse_mounts(text: &str, warnings: &mut Vec<String>) -> Result<Vec<MountLine>, String> {
    let mut out = Vec::new();
    let mut bad = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || !f[1].starts_with('/') {
            bad += 1;
            warnings.push(format!("skipped malformed mounts line: {line:?}"));
            continue;
        }
        out.push(MountLine {
            device: unescape_octal(f[0]),
            mount_point: unescape_octal(f[1]),
            fs_type: f[2].to_string(),
        });
    }
    if out.is_empty() && bad > 0 {
        return Err(format!(
            "no readable line in the mounts table ({bad} malformed)"
        ));
    }
    Ok(out)
}

/// Reads the mounts table: `/proc/self/mounts`, else `/proc/mounts`.
pub fn read_mounts(host: &Host, warnings: &mut Vec<String>) -> Result<(String, String), SysError> {
    match host.read("/proc/self/mounts") {
        Ok(t) => Ok(("/proc/self/mounts".into(), t)),
        Err(first) => match host.read("/proc/mounts") {
            Ok(t) => {
                warnings.push(format!("{first}; used /proc/mounts"));
                Ok(("/proc/mounts".into(), t))
            }
            Err(e) => Err(SysError::new(
                "system.disk_mounts_unavailable",
                format!("{first}; {e}"),
            )),
        },
    }
}

/// `statvfs` of each mount point, on a worker thread, until `deadline`.
/// Returns one entry per mount point (None if not reached) and, on timeout,
/// the mount point that was still being read.
pub fn stat_all(
    host: &Host,
    mount_points: &[String],
    deadline: Instant,
) -> (Vec<Option<Result<FsStats, String>>>, Option<String>) {
    let (tx, rx) = mpsc::channel();
    let paths: Vec<(String, std::path::PathBuf)> = mount_points
        .iter()
        .map(|m| (m.clone(), host.path(m)))
        .collect();
    let hook = host.stat_hook();
    std::thread::spawn(move || {
        for (i, (mp, p)) in paths.into_iter().enumerate() {
            if let Some(h) = &hook {
                h(&mp);
            }
            if tx.send((i, statvfs_at(&p))).is_err() {
                return;
            }
        }
    });
    let mut out: Vec<Option<Result<FsStats, String>>> = vec![None; mount_points.len()];
    for _ in 0..mount_points.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((i, r)) => out[i] = Some(r),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let stuck = out
                    .iter()
                    .position(Option::is_none)
                    .map(|i| mount_points[i].clone());
                return (out, stuck);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    (out, None)
}

/// The whole-disk name in `/proc/diskstats` behind a mount: from the
/// mount point's device number via `/sys/dev/block` (a partition maps to
/// its parent disk), else from the device path (`/dev/sda1` -> `sda`).
pub fn io_device(host: &Host, mount_point: &str, device: &str) -> Option<String> {
    if let Some((maj, min)) = host.device_of(mount_point) {
        if maj != 0 {
            let link = format!("/sys/dev/block/{maj}:{min}");
            if let Some(real) = host.canonical(&link) {
                let name = real.rsplit('/').next().unwrap_or_default().to_string();
                if host.exists(&format!("{real}/partition")) {
                    let parent = real.rsplit('/').nth(1).unwrap_or_default();
                    if !parent.is_empty() {
                        return Some(parent.to_string());
                    }
                }
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    base_device_name(device.strip_prefix("/dev/")?)
}

/// `sda1` -> `sda`, `nvme0n1p2` -> `nvme0n1`, `mmcblk0p1` -> `mmcblk0`,
/// `xvdb3` -> `xvdb`; other names are kept.
pub fn base_device_name(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let digits_tail = |s: &str| s.len() - s.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    for prefix in ["nvme", "mmcblk", "loop", "nbd"] {
        if name.starts_with(prefix) {
            if let Some(pos) = name.rfind('p') {
                let tail = &name[pos + 1..];
                if pos > prefix.len() && !tail.is_empty() && digits_tail(tail) == tail.len() {
                    return Some(name[..pos].to_string());
                }
            }
            return Some(name.to_string());
        }
    }
    for prefix in ["sd", "hd", "vd", "xvd"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            let n = digits_tail(rest);
            if n > 0
                && n < rest.len()
                && rest[..rest.len() - n]
                    .chars()
                    .all(|c| c.is_ascii_lowercase())
            {
                return Some(name[..name.len() - n].to_string());
            }
            return Some(name.to_string());
        }
    }
    Some(name.to_string())
}

#[derive(Debug, Serialize, Clone)]
pub struct MountEntry {
    pub mount_point: String,
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,
    pub virtual_fs: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avail_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_free: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inodes_used_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_device: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_summary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IoDevice {
    pub name: String,
    pub maj_min: String,
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub time_reading_ms: u64,
    pub time_writing_ms: u64,
    pub ios_in_progress: u64,
    pub time_in_io_ms: u64,
    pub weighted_time_in_io_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct IoMetrics {
    pub available: bool,
    pub devices: Vec<IoDevice>,
}

#[derive(Debug, Serialize)]
pub struct DiskHuman {
    pub summaries: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DiskResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub mounts_truncated: bool,
    pub mounts: Vec<MountEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<IoMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<DiskHuman>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

pub fn tags(mount_point: &str) -> Vec<String> {
    let t = match mount_point {
        "/" => "rootfs",
        "/home" => "home",
        "/tmp" => "tmp",
        "/var" => "var",
        "/usr" => "usr",
        "/boot" => "boot",
        p if p.starts_with("/home/") => "home",
        p if p.starts_with("/var/") => "var",
        p if p.starts_with("/boot/") => "boot",
        p if p.starts_with("/mnt/") => "data",
        p if p.starts_with("/media/") => "media",
        _ => return Vec::new(),
    };
    vec![t.to_string()]
}

/// "1.5 GiB" style sizes (binary units).
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn pct(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| (10_000.0 * part as f64 / whole as f64).round() / 100.0)
}

pub fn fill_stats(e: &mut MountEntry, st: &FsStats) {
    e.total_bytes = Some(st.total_bytes);
    e.used_bytes = Some(st.used_bytes);
    e.free_bytes = Some(st.free_bytes);
    e.avail_bytes = Some(st.avail_bytes);
    e.used_pct = pct(st.used_bytes, st.total_bytes);
    e.free_pct = pct(st.free_bytes, st.total_bytes);
    e.inodes_total = Some(st.inodes_total);
    e.inodes_used = Some(st.inodes_used);
    e.inodes_free = Some(st.inodes_free);
    e.inodes_used_pct = pct(st.inodes_used, st.inodes_total);
}

/// Parses `/proc/diskstats` rows for the named devices.
pub fn parse_diskstats(text: &str, names: &BTreeSet<String>) -> Vec<IoDevice> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 || !names.contains(f[2]) {
            continue;
        }
        let n: Vec<u64> = f[3..14].iter().filter_map(|s| s.parse().ok()).collect();
        if n.len() != 11 {
            continue;
        }
        // Sectors in /proc/diskstats are always 512 bytes.
        out.push(IoDevice {
            name: f[2].to_string(),
            maj_min: format!("{}:{}", f[0], f[1]),
            reads_completed: n[0],
            sectors_read: n[2],
            time_reading_ms: n[3],
            writes_completed: n[4],
            sectors_written: n[6],
            time_writing_ms: n[7],
            ios_in_progress: n[8],
            time_in_io_ms: n[9],
            weighted_time_in_io_ms: n[10],
            read_bytes: n[2].saturating_mul(512),
            write_bytes: n[6].saturating_mul(512),
        });
    }
    out
}

fn normalize(mp: &str) -> String {
    let t = mp.trim_end_matches('/');
    if t.is_empty() { "/".into() } else { t.into() }
}

pub fn disk(host: &Host, o: &DiskOptions) -> Result<DiskResponse, SysError> {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(o.timeout_ms);
    let now = host.now_unix_ms();
    let mut warnings = Vec::new();
    let (mounts_path, text) = read_mounts(host, &mut warnings)?;
    let all = parse_mounts(&text, &mut warnings).map_err(|e| {
        SysError::new(
            "system.disk_mounts_parse_error",
            format!("{mounts_path}: {e}"),
        )
    })?;

    let wanted_mps: Vec<String> = o.mount_points.iter().map(|m| normalize(m)).collect();
    for m in &wanted_mps {
        if !all.iter().any(|l| &l.mount_point == m) {
            return Err(SysError::new(
                "system.disk_mount_not_found",
                format!("{m} is not a mount point (not in {mounts_path})"),
            ));
        }
    }
    for d in &o.devices {
        if !all.iter().any(|l| &l.device == d) {
            return Err(SysError::new(
                "system.disk_mount_not_found",
                format!("device {d} is not mounted (not in {mounts_path})"),
            ));
        }
    }

    let mut selected: Vec<MountLine> = all
        .into_iter()
        .filter(|l| wanted_mps.is_empty() || wanted_mps.contains(&l.mount_point))
        .filter(|l| o.devices.is_empty() || o.devices.contains(&l.device))
        .filter(|l| o.fs_types.is_empty() || o.fs_types.contains(&l.fs_type))
        .filter(|l| o.include_virtual || !is_virtual(&l.fs_type))
        .collect();
    let truncated = selected.len() > o.max_mounts as usize;
    if truncated {
        warnings.push(format!(
            "{} mounts match; only the first max_mounts={} are reported",
            selected.len(),
            o.max_mounts
        ));
        selected.truncate(o.max_mounts as usize);
    }

    let mps: Vec<String> = selected.iter().map(|l| l.mount_point.clone()).collect();
    let (stats, stuck) = stat_all(host, &mps, deadline);
    let mut mounts = Vec::new();
    for (line, st) in selected.iter().zip(stats) {
        let Some(st) = st else { continue };
        let mut e = MountEntry {
            mount_point: line.mount_point.clone(),
            device: line.device.clone(),
            fs_type: o.include_fs_types.then(|| line.fs_type.clone()),
            virtual_fs: is_virtual(&line.fs_type),
            total_bytes: None,
            used_bytes: None,
            free_bytes: None,
            avail_bytes: None,
            used_pct: None,
            free_pct: None,
            inodes_total: None,
            inodes_used: None,
            inodes_free: None,
            inodes_used_pct: None,
            io_device: None,
            tags: tags(&line.mount_point),
            human_summary: None,
        };
        match st {
            Ok(st) => fill_stats(&mut e, &st),
            Err(err) => warnings.push(format!("statvfs {} failed: {err}", line.mount_point)),
        }
        if o.include_io {
            e.io_device = io_device(host, &line.mount_point, &line.device);
        }
        if o.include_human {
            e.human_summary = Some(match (e.total_bytes, e.used_bytes, e.used_pct) {
                (Some(t), Some(u), Some(p)) => format!(
                    "{}: {} total, {} used ({p:.1}%)",
                    e.mount_point,
                    human_bytes(t),
                    human_bytes(u)
                ),
                _ => format!("{}: stats unavailable", e.mount_point),
            });
        }
        mounts.push(e);
    }

    let diskstats = (o.include_io || o.include_raw).then(|| host.read("/proc/diskstats"));
    let io = o.include_io.then(|| match &diskstats {
        Some(Ok(t)) => {
            let names: BTreeSet<String> =
                mounts.iter().filter_map(|m| m.io_device.clone()).collect();
            IoMetrics {
                available: true,
                devices: parse_diskstats(t, &names),
            }
        }
        Some(Err(e)) => {
            warnings.push(format!("I/O counters not available: {e}"));
            IoMetrics {
                available: false,
                devices: Vec::new(),
            }
        }
        None => IoMetrics {
            available: false,
            devices: Vec::new(),
        },
    });
    let human = o.include_human.then(|| DiskHuman {
        summaries: mounts
            .iter()
            .filter_map(|m| m.human_summary.clone())
            .collect(),
    });
    let raw = o.include_raw.then(|| {
        let mut r = json!({ "mounts": text });
        if let Some(Ok(t)) = &diskstats {
            r["diskstats"] = json!(t);
        }
        r
    });
    let paths = o.include_paths.then(|| {
        let mut p = json!({ "mounts": mounts_path });
        if o.include_io {
            p["diskstats"] = json!("/proc/diskstats");
        }
        p
    });
    let error = stuck.map(|mp| {
        SysError::new(
            "system.timeout",
            format!(
                "timed out after {} ms waiting for statvfs on {mp}; {} of {} mounts reported",
                o.timeout_ms,
                mounts.len(),
                selected.len()
            ),
        )
        .to_json()
    });
    Ok(DiskResponse {
        ok: error.is_none(),
        timestamp_unix_ms: now,
        mounts_truncated: truncated,
        mounts,
        io,
        human,
        raw,
        paths,
        error,
        warnings,
    })
}
