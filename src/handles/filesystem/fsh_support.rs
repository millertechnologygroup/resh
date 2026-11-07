//! Shared pieces of the fs handle: the options each verb accepts, the mount
//! table, path matching, typed argument readers and external tool runs.

use crate::core::process::AsyncBoundedOutput as _;
use serde_json::Value;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use tokio::process::Command as AsyncCommand;

/// The include/exclude filters shared by several verbs.
const FILTERS: [&str; 6] = [
    "include_mountpoints",
    "exclude_mountpoints",
    "include_types",
    "exclude_types",
    "include_sources",
    "exclude_sources",
];

macro_rules! with_filters {
    ($($opt:literal),* $(,)?) => {
        &[
            $($opt,)*
            "include_mountpoints",
            "exclude_mountpoints",
            "include_types",
            "exclude_types",
            "include_sources",
            "exclude_sources",
        ]
    };
}

pub(super) const LIST_MOUNTS_OPTIONS: &[&str] = with_filters!(
    "paths",
    "include_readonly",
    "include_readwrite",
    "include_pseudo",
    "include_loop",
    "include_network",
    "normalize_paths",
    "resolve_labels",
    "resolve_fs_features",
    "timeout_ms",
);

pub(super) const USAGE_OPTIONS: &[&str] = with_filters!(
    "mode",
    "paths",
    "units",
    "human_readable",
    "include_inodes",
    "include_readonly",
    "normalize_paths",
    "threshold_used_percent_min",
    "threshold_used_percent_max",
    "timeout_ms",
);

pub(super) const SNAPSHOT_OPTIONS: &[&str] = with_filters!(
    "format",
    "include_usage",
    "include_inodes",
    "include_fs_metadata",
    "include_os_metadata",
    "normalize_paths",
    "timeout_ms",
);

pub(super) const QUOTA_OPTIONS: &[&str] = &[
    "path",
    "subject",
    "subject_type",
    "all_subjects",
    "units",
    "include_space",
    "include_inodes",
    "include_grace",
    "resolve_uid_gid",
    "timeout_ms",
];

pub(super) const QUOTA_SUMMARY_OPTIONS: &[&str] = with_filters!(
    "subject",
    "subject_type",
    "all_subjects",
    "units",
    "include_space",
    "include_inodes",
    "include_grace",
    "resolve_uid_gid",
    "timeout_ms",
);

pub(super) const MOUNT_OPTIONS: &[&str] = &[
    "target",
    "source",
    "type",
    "options",
    "read_only",
    "bind",
    "remount",
    "network",
    "create_target",
    "make_parents",
    "fail_if_mounted",
    "dry_run",
    "timeout_ms",
];

pub(super) const UNMOUNT_OPTIONS: &[&str] = &[
    "target",
    "by",
    "force",
    "lazy",
    "detach_children",
    "fail_if_not_mounted",
    "dry_run",
    "timeout_ms",
];

pub(super) const RESIZE_OPTIONS: &[&str] = &[
    "target",
    "size",
    "delta",
    "by",
    "size_units",
    "mode",
    "allow_shrink",
    "min_free_space_percent",
    "manage_underlying_volume",
    "volume_resize_only",
    "filesystem_resize_only",
    "require_unmounted_for_shrink",
    "force",
    "dry_run",
    "timeout_ms",
];

pub(super) const CHECK_OPTIONS: &[&str] = &[
    "target",
    "by",
    "filesystem_type",
    "mode",
    "allow_repair",
    "aggressiveness",
    "allow_online_check",
    "require_unmounted_for_repair",
    "skip_if_mounted",
    "force",
    "btrfs_use_scrub",
    "btrfs_allow_offline_check",
    "dry_run",
    "timeout_ms",
];

/// The options `verb` accepts (aliases resolved), or `None` for a verb that
/// is not an fs operation.
pub(super) fn options_for(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "list-mounts" => LIST_MOUNTS_OPTIONS,
        "usage" => USAGE_OPTIONS,
        "snapshot" => SNAPSHOT_OPTIONS,
        "quota" => QUOTA_OPTIONS,
        "quota_summary" => QUOTA_SUMMARY_OPTIONS,
        "mount" => MOUNT_OPTIONS,
        "unmount" | "umount" => UNMOUNT_OPTIONS,
        "resize" => RESIZE_OPTIONS,
        "check" | "fsck" => CHECK_OPTIONS,
        _ => return None,
    })
}

/// The first argument key `verb` does not accept.
pub(super) fn unknown_option<'a>(
    keys: impl IntoIterator<Item = &'a String>,
    allowed: &[&str],
) -> Option<&'a String> {
    let mut keys: Vec<&String> = keys.into_iter().collect();
    keys.sort();
    keys.into_iter().find(|k| !allowed.contains(&k.as_str()))
}

/// The refusal for argument `bad`, with a suggestion when it looks like a
/// typo of an accepted one.
pub(super) fn unknown_option_message(verb: &str, bad: &str, allowed: &[&str]) -> String {
    let mut msg = format!("unknown argument {bad:?} for fs {verb}");
    if let Some(s) = did_you_mean(bad, allowed) {
        msg.push_str(&format!("; did you mean {s:?}?"));
    }
    msg.push_str(&format!(
        " (accepted: {}); nothing was done",
        allowed.join(", ")
    ));
    msg
}

/// The accepted name closest to `input`, if it is close enough to be a
/// likely typo (edit distance at most 2, or 1 for short names).
pub(super) fn did_you_mean<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let input = input.to_ascii_lowercase().replace('-', "_");
    let limit = if input.len() <= 4 { 1 } else { 2 };
    candidates
        .iter()
        .map(|c| (edit_distance(&input, c), *c))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Every include/exclude filter list must name something: an empty entry
/// would silently match nothing (or everything).
pub(super) fn check_filter_lists(lists: &[(&str, &[String])]) -> Result<(), String> {
    for (name, list) in lists {
        if list.iter().any(|s| s.trim().is_empty()) {
            return Err(format!("{name} cannot contain empty entries"));
        }
    }
    Ok(())
}

/// The filter options as `(name, list)` pairs, in a fixed order.
pub(super) fn filter_pairs<'a>(lists: [&'a [String]; 6]) -> [(&'static str, &'a [String]); 6] {
    [
        (FILTERS[0], lists[0]),
        (FILTERS[1], lists[1]),
        (FILTERS[2], lists[2]),
        (FILTERS[3], lists[3]),
        (FILTERS[4], lists[4]),
        (FILTERS[5], lists[5]),
    ]
}

// --- typed argument readers (for verbs parsed key by key) -----------------

pub(super) fn bool_value(key: &str, value: &Value) -> Result<bool, String> {
    let parsed = match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => crate::core::lenient::parse_bool(s),
        _ => None,
    };
    parsed.ok_or_else(|| {
        format!("invalid value for {key}: {value} (expected true/false, 1/0, yes/no or on/off)")
    })
}

pub(super) fn u64_value(key: &str, value: &Value) -> Result<u64, String> {
    let parsed = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| format!("invalid value for {key}: {value} (expected a whole number)"))
}

pub(super) fn string_value(key: &str, value: &Value) -> Result<String, String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        _ => Err(format!("invalid value for {key}: {value} (expected text)")),
    }
}

/// A comma-separated list (or a JSON array of strings). Empty items are an
/// error, not silently dropped.
pub(super) fn list_value(key: &str, value: &Value) -> Result<Vec<String>, String> {
    let items: Vec<String> = match value {
        Value::String(s) => s.split(',').map(|p| p.trim().to_string()).collect(),
        Value::Array(a) => a
            .iter()
            .map(|v| v.as_str().map(|s| s.trim().to_string()))
            .collect::<Option<_>>()
            .ok_or_else(|| format!("invalid value for {key}: expected text items"))?,
        _ => {
            return Err(format!(
                "invalid value for {key}: {value} (expected a list)"
            ));
        }
    };
    if items.iter().any(|i| i.is_empty()) {
        return Err(format!("{key} cannot contain empty entries"));
    }
    Ok(items)
}

// --- paths -----------------------------------------------------------------

/// `path` made absolute against the current directory and lexically
/// normalized (no `.`, `..`, repeated or trailing slashes). Symlinks are not
/// followed, so a stale network mount is never touched.
pub(super) fn absolute(path: &str) -> String {
    let p = Path::new(path);
    let joined: PathBuf = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(p)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out.to_string_lossy().into_owned()
}

/// True when `path` is `prefix` or lies below it, compared by whole path
/// components, so `/homex` is not under `/home`.
pub(super) fn path_is_under(path: &str, prefix: &str) -> bool {
    Path::new(path).starts_with(Path::new(prefix))
}

/// The mount table entry whose target holds `path` (the last mounted one
/// when several are stacked). `path` should be absolute.
pub(super) fn mount_for_path<'a>(
    mounts: &'a [super::RawMountInfo],
    path: &str,
) -> Option<&'a super::RawMountInfo> {
    let mut best: Option<&super::RawMountInfo> = None;
    for m in mounts {
        if path_is_under(path, &m.target) && best.is_none_or(|b| m.target.len() >= b.target.len()) {
            best = Some(m);
        }
    }
    best
}

/// True when two device or file names refer to the same thing: equal text,
/// the same file after following symlinks (`/dev/disk/by-uuid/...`), a
/// `UUID=`/`LABEL=` tag that resolves to it, or an image file attached to
/// the loop device `mounted`.
pub(super) fn same_source(mounted: &str, requested: &str) -> bool {
    if mounted == requested {
        return true;
    }
    let resolve = |s: &str| -> Option<PathBuf> {
        let tagged = s
            .strip_prefix("UUID=")
            .map(|u| format!("/dev/disk/by-uuid/{u}"))
            .or_else(|| {
                s.strip_prefix("LABEL=")
                    .map(|l| format!("/dev/disk/by-label/{l}"))
            });
        let p = tagged.unwrap_or_else(|| s.to_string());
        if !p.starts_with('/') {
            return None;
        }
        std::fs::canonicalize(p).ok()
    };
    let (Some(a), Some(b)) = (resolve(mounted), resolve(requested)) else {
        return false;
    };
    if a == b {
        return true;
    }
    loop_backing_file(&a).is_some_and(|f| f == b)
}

/// The file behind loop device `dev`, from sysfs.
pub(super) fn loop_backing_file(dev: &Path) -> Option<PathBuf> {
    let name = dev.file_name()?.to_str()?;
    if !name.starts_with("loop") {
        return None;
    }
    let text = std::fs::read_to_string(format!("/sys/block/{name}/loop/backing_file")).ok()?;
    std::fs::canonicalize(text.trim()).ok()
}

// --- mount table -----------------------------------------------------------

/// Decodes the octal escapes the kernel writes for space, tab, newline and
/// backslash in mount table fields (`\040` and so on).
pub(super) fn unescape_mount_field(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let v = (bytes[i + 1] - b'0') as u32 * 64
                + (bytes[i + 2] - b'0') as u32 * 8
                + (bytes[i + 3] - b'0') as u32;
            if v <= 255 {
                out.push(v as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `/proc/mounts` format. Lines with fewer than four fields are
/// skipped.
pub(super) fn parse_mount_table(content: &str) -> Vec<super::RawMountInfo> {
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            Some(super::RawMountInfo {
                source: unescape_mount_field(parts[0]),
                target: unescape_mount_field(parts[1]),
                fstype: unescape_mount_field(parts[2]),
                options: unescape_mount_field(parts[3]),
                dump: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0),
                pass: parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(test)]
thread_local! {
    /// Unit tests replace the mount table with this text.
    pub(super) static MOUNTS_OVERRIDE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
    /// Unit tests run external tools from this directory instead of PATH.
    pub(super) static TOOL_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The mount table of this process's mount namespace.
pub(super) fn read_mount_table() -> io::Result<Vec<super::RawMountInfo>> {
    #[cfg(test)]
    if let Some(text) = MOUNTS_OVERRIDE.with(|m| m.borrow().clone()) {
        if text == "<missing>" {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no mount table"));
        }
        return Ok(parse_mount_table(&text));
    }
    let content = std::fs::read_to_string("/proc/self/mounts")?;
    Ok(parse_mount_table(&content))
}

/// True for a mount option list (`rw,relatime,...`) that has the `ro` flag.
pub(super) fn has_option(options: &str, wanted: &str) -> bool {
    options.split(',').any(|o| o.trim() == wanted)
}

// --- external tools ----------------------------------------------------------

/// A command for external tool `name`. Unit tests may redirect it to a fake.
pub(super) fn tool(name: &str) -> AsyncCommand {
    #[cfg(test)]
    if let Some(dir) = TOOL_DIR.with(|d| d.borrow().clone()) {
        return AsyncCommand::new(dir.join(name));
    }
    AsyncCommand::new(name)
}

/// Runs `cmd` with captured output under the operation deadline. Past the
/// deadline the tool and everything it started are stopped, and the stage
/// ends with exit status 124.
pub(super) async fn run(cmd: &mut AsyncCommand) -> io::Result<Output> {
    let result = cmd.bounded_output().await;
    if result
        .as_ref()
        .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
    {
        TIMED_OUT.with(|t| t.set(true));
    }
    result
}

thread_local! {
    /// Set when a tool run by this thread was stopped at the deadline. The
    /// verb runs on the calling thread (a current-thread runtime).
    static TIMED_OUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether a tool was stopped at the deadline since the last call; clears
/// the flag.
pub(super) fn take_timed_out() -> bool {
    TIMED_OUT.with(|t| t.replace(false))
}

/// True when external tool `name` can be found.
pub(super) fn tool_available(name: &str) -> bool {
    #[cfg(test)]
    if let Some(dir) = TOOL_DIR.with(|d| d.borrow().clone()) {
        return dir.join(name).is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let p = dir.join(name);
        std::fs::metadata(&p)
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false)
    })
}

/// Text of the tool's stderr and stdout, trimmed, for error messages.
pub(super) fn tool_message(output: &Output) -> String {
    let err = String::from_utf8_lossy(&output.stderr);
    let out = String::from_utf8_lossy(&output.stdout);
    let text = format!("{} {}", err.trim(), out.trim());
    text.trim().to_string()
}

/// True when the tool's message says the caller lacks privileges.
pub(super) fn is_permission_message(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("permission denied")
        || m.contains("operation not permitted")
        || m.contains("must be superuser")
        || m.contains("only root can")
}

// --- tool output parsers -------------------------------------------------------

/// `Key: value` from `dumpe2fs -h` style output.
pub(super) fn colon_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == key).then(|| v.trim().parse().ok())?
    })
}

/// `(block size, data blocks)` from `xfs_info` output (the `data` section).
pub(super) fn xfs_data_geometry(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.trim_start().starts_with("data"))?;
    let field = |name: &str| -> Option<u64> {
        let rest = line.split(&format!("{name}=")).nth(1)?;
        rest.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    };
    Some((field("bsize")?, field("blocks")?))
}

/// `(devid, device size, sector size)` from
/// `btrfs inspect-internal dump-super` output (the `dev_item` fields describe
/// the device the superblock was read from).
pub(super) fn btrfs_super_geometry(text: &str) -> Option<(u64, u64, u64)> {
    let field = |name: &str| -> Option<u64> {
        text.lines().find_map(|l| {
            let mut w = l.split_whitespace();
            if w.next() == Some(name) {
                w.next()?.parse().ok()
            } else {
                None
            }
        })
    };
    Some((
        field("dev_item.devid")?,
        field("dev_item.total_bytes")?,
        field("sectorsize").unwrap_or(4096),
    ))
}

/// One line of `quota -v -w -p` output.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct QuotaLine {
    pub filesystem: String,
    pub blocks: u64,
    pub block_soft: u64,
    pub block_hard: u64,
    pub block_grace: u64,
    pub files: u64,
    pub file_soft: u64,
    pub file_hard: u64,
    pub file_grace: u64,
}

/// Parses `quota -v -w -p` output: after the header, one line per
/// filesystem with nine fields. A `*` after a usage marks an exceeded soft
/// limit. Grace values are seconds since the epoch, 0 when not running.
pub(super) fn parse_quota_report(text: &str) -> Vec<QuotaLine> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            if w.len() != 9 {
                return None;
            }
            let n = |i: usize| -> Option<u64> { w[i].trim_end_matches('*').parse().ok() };
            Some(QuotaLine {
                filesystem: w[0].to_string(),
                blocks: n(1)?,
                block_soft: n(2)?,
                block_hard: n(3)?,
                block_grace: n(4)?,
                files: n(5)?,
                file_soft: n(6)?,
                file_hard: n(7)?,
                file_grace: n(8)?,
            })
        })
        .collect()
}

/// One subject of `repquota -O csv -p` output: the name and its usage in
/// the same field order as `QuotaLine`.
pub(super) fn parse_repquota_csv(text: &str) -> Vec<(String, QuotaLine)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            if f.len() != 11 {
                return None;
            }
            let n = |i: usize| -> Option<u64> {
                let s = f[i].trim();
                if s.is_empty() {
                    Some(0)
                } else {
                    s.parse().ok()
                }
            };
            Some((
                f[0].to_string(),
                QuotaLine {
                    filesystem: String::new(),
                    blocks: n(3)?,
                    block_soft: n(4)?,
                    block_hard: n(5)?,
                    block_grace: n(6)?,
                    files: n(7)?,
                    file_soft: n(8)?,
                    file_hard: n(9)?,
                    file_grace: n(10)?,
                },
            ))
        })
        .collect()
}

/// Parses a size: a byte count, or a number with a `K`, `M`, `G` or `T`
/// suffix (powers of 1024, optional `B`/`iB`). A leading `+` or `-` is kept
/// in the sign. A bare number is a count of `unit_bytes`.
pub(super) fn parse_signed_size(text: &str, unit_bytes: u64) -> Result<i128, String> {
    let s = text.trim();
    let (sign, body) = match s.as_bytes().first() {
        Some(b'+') => (1i128, &s[1..]),
        Some(b'-') => (-1i128, &s[1..]),
        _ => (1i128, s),
    };
    let body = body.trim();
    if body.is_empty() {
        return Err(format!("invalid size {text:?}"));
    }
    let split = body
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(body.len());
    let (num, unit) = body.split_at(split);
    let mult: u64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" => unit_bytes,
        "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        "T" | "TB" | "TIB" => 1 << 40,
        other => return Err(format!("unknown size unit {other:?} in {text:?}")),
    };
    let bytes: i128 = if num.contains('.') {
        let f: f64 = num
            .parse()
            .map_err(|_| format!("invalid number in size {text:?}"))?;
        if !f.is_finite() {
            return Err(format!("invalid number in size {text:?}"));
        }
        (f * mult as f64) as i128
    } else {
        let n: u128 = num
            .parse()
            .map_err(|_| format!("invalid number in size {text:?}"))?;
        (n as i128)
            .checked_mul(mult as i128)
            .ok_or_else(|| format!("size {text:?} is too large"))?
    };
    if bytes > u64::MAX as i128 {
        return Err(format!("size {text:?} is too large"));
    }
    Ok(sign * bytes)
}

/// Renders a JSON value as YAML.
pub(super) fn to_yaml<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_yaml::to_string(value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_fields_are_unescaped() {
        assert_eq!(unescape_mount_field(r"/mnt/my\040disk"), "/mnt/my disk");
        assert_eq!(unescape_mount_field(r"a\011b\012c\134d"), "a\tb\nc\\d");
        assert_eq!(unescape_mount_field(r"/plain"), "/plain");
        assert_eq!(unescape_mount_field(r"trailing\04"), r"trailing\04");
    }

    #[test]
    fn mount_table_parsing_keeps_fields() {
        let t = parse_mount_table(
            "/dev/sda1 / ext4 rw,relatime 0 1\n/dev/sdb1 /mnt/a\\040b xfs ro 0 0\nbad line\n",
        );
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].pass, 1);
        assert_eq!(t[1].target, "/mnt/a b");
    }

    #[test]
    fn paths_compare_by_component() {
        assert!(path_is_under("/home/a", "/home"));
        assert!(path_is_under("/home", "/home"));
        assert!(!path_is_under("/homex", "/home"));
        assert!(path_is_under("/anything", "/"));
        assert_eq!(absolute("/a//b/./c/../d/"), "/a/b/d");
        assert!(absolute("rel").starts_with('/'));
    }

    #[test]
    fn options_are_matched_by_token() {
        assert!(has_option("rw,ro", "ro"));
        assert!(!has_option("rw,errors=remount-ro", "ro"));
    }

    #[test]
    fn sizes_parse_with_sign_and_units() {
        assert_eq!(parse_signed_size("200G", 1).unwrap(), 200 << 30);
        assert_eq!(parse_signed_size("+50M", 1).unwrap(), 50 << 20);
        assert_eq!(parse_signed_size("-10G", 1).unwrap(), -(10i128 << 30));
        assert_eq!(parse_signed_size("1024", 1024).unwrap(), 1 << 20);
        assert_eq!(parse_signed_size("1.5K", 1).unwrap(), 1536);
        assert!(parse_signed_size("10Q", 1).is_err());
        assert!(parse_signed_size("", 1).is_err());
        assert!(parse_signed_size("-", 1).is_err());
        assert!(parse_signed_size("99999999999T", 1).is_err());
    }

    #[test]
    fn quota_report_lines_parse() {
        let text = "Disk quotas for user alice (uid 1001): \n     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n     /dev/loop0    1504*   1000    2000 1794659264       3      10      20       0\n";
        let l = parse_quota_report(text);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].filesystem, "/dev/loop0");
        assert_eq!(l[0].blocks, 1504);
        assert_eq!(l[0].block_grace, 1794659264);
        assert_eq!(l[0].file_hard, 20);
    }

    #[test]
    fn repquota_csv_parses() {
        let text = "User,BlockStatus,FileStatus,BlockUsed,BlockSoftLimit,BlockHardLimit,BlockGrace,FileUsed,FileSoftLimit,FileHardLimit,FileGrace\nroot,ok,ok,20,0,0,0,2,0,0,0\nalice,soft,ok,1504,1000,2000,1794659264,3,10,20,0\n";
        let rows = parse_repquota_csv(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].0, "alice");
        assert_eq!(rows[1].1.block_soft, 1000);
    }

    #[test]
    fn tool_geometry_parsers() {
        assert_eq!(
            colon_field(
                "Block count:              76800\nBlock size:  4096\n",
                "Block count"
            ),
            Some(76800)
        );
        let xfs = "meta-data=/dev/loop1 isize=512 agcount=4, agsize=19200 blks\ndata     =                       bsize=4096   blocks=76800, imaxpct=25\nnaming   =version 2              bsize=4096   ascii-ci=0, ftype=1\n";
        assert_eq!(xfs_data_geometry(xfs), Some((4096, 76800)));
        let btrfs = "total_bytes\t\t1610612736\nsectorsize\t\t4096\ndev_item.total_bytes\t1610612736\ndev_item.devid\t\t1\n";
        assert_eq!(btrfs_super_geometry(btrfs), Some((1, 1610612736, 4096)));
    }

    #[test]
    fn unknown_options_are_found() {
        let keys = vec!["target".to_string(), "bogus".to_string()];
        assert_eq!(
            unknown_option(&keys, MOUNT_OPTIONS).map(String::as_str),
            Some("bogus")
        );
        let keys = vec!["target".to_string()];
        assert!(unknown_option(&keys, MOUNT_OPTIONS).is_none());
    }

    #[test]
    fn list_values_refuse_empty_items() {
        assert_eq!(
            list_value("o", &Value::from("a, b")).unwrap(),
            vec!["a", "b"]
        );
        assert!(list_value("o", &Value::from("a,,b")).is_err());
        assert!(bool_value("b", &Value::from("ture")).is_err());
        assert!(u64_value("t", &Value::from("soon")).is_err());
    }
}
