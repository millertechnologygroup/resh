//! v1.0.5-beta regression tests that need the real `resh` binary: archive
//! extraction size limits, and `fs mount` / `user add` operands that look
//! like options. Each test runs the binary in its own temporary directory,
//! with fake `mount`, `umount`, `useradd`, `groupadd` and `usermod` on PATH
//! that record their argv and do nothing else.

mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::{FileOptions, ZipWriter};

/// Records every invocation as `CALL\0<program>\0<arg>\0...END\0`.
const RECORDING_FAKE: &str = r#"#!/bin/sh
{ printf 'CALL\0%s\0' "$(basename "$0")"; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG"
exit 0
"#;

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        std::fs::create_dir(f.bin()).unwrap();
        for name in ["mount", "umount", "useradd", "groupadd", "usermod"] {
            f.script(name, RECORDING_FAKE);
        }
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn log(&self) -> PathBuf {
        self.path().join("invocations.log")
    }

    fn script(&self, name: &str, body: &str) {
        common::write_executable(&self.bin().join(name), body);
    }

    fn resh(&self) -> Command {
        let dir = self.path();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(dir)
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("HOME", dir)
            .env("USER", "resh-test")
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("XDG_STATE_HOME", dir.join("state"))
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("RESH_TEST_LOG", self.log());
        cmd
    }

    /// Programs the fakes recorded, in order.
    fn programs_called(&self) -> Vec<String> {
        let Ok(raw) = std::fs::read(self.log()) else {
            return vec![];
        };
        let fields: Vec<_> = raw.split(|b| *b == 0).collect();
        fields
            .windows(2)
            .filter(|w| w[0] == b"CALL")
            .map(|w| String::from_utf8_lossy(w[1]).into_owned())
            .collect()
    }

    /// Every file and directory under `dir`, relative to it, sorted.
    fn tree(&self, dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                out.push(p.strip_prefix(dir).unwrap().display().to_string());
                if e.file_type().unwrap().is_dir() {
                    stack.push(p);
                }
            }
        }
        out.sort();
        out
    }
}

struct Run {
    code: i32,
    json: Value,
    stderr: String,
}

fn run(cmd: &mut Command) -> Run {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(stdout.trim()).unwrap_or(Value::Null),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// archive://.extract size limits
// ---------------------------------------------------------------------------

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        z.start_file(
            *name,
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

fn le16(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

/// Overwrite the uncompressed size recorded for entry `index` (central
/// directory and local header); the data and CRC are unchanged.
fn set_recorded_size(zip: &mut [u8], index: usize, size: u32) {
    let eocd = zip.len() - 22;
    assert_eq!(&zip[eocd..eocd + 4], b"PK\x05\x06");
    let mut p = le32(zip, eocd + 16);
    for i in 0..le16(zip, eocd + 10) {
        assert_eq!(&zip[p..p + 4], b"PK\x01\x02");
        let local = le32(zip, p + 42);
        if i == index {
            zip[p + 24..p + 28].copy_from_slice(&size.to_le_bytes());
            zip[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
        }
        p += 46 + le16(zip, p + 28) + le16(zip, p + 30) + le16(zip, p + 32);
    }
}

fn extract(f: &Fixture, archive: &str, extra: &[&str]) -> Run {
    let mut cmd = f.resh();
    cmd.arg("archive://.extract")
        .arg(format!("archive={archive}"))
        .arg("destination=out");
    cmd.args(extra);
    run(&mut cmd)
}

fn assert_extract_refused(r: &Run) {
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert_eq!(r.json["ok"], false, "{}", r.json);
    assert_eq!(
        r.json["error"][0], "archive.extract_archive_read_error",
        "{}",
        r.json
    );
    assert!(r.json["summary"].is_null(), "{}", r.json);
    assert!(r.stderr.contains("archive.extract_archive_read_error"));
}

#[test]
fn archive_extract_limits_count_the_bytes_written() {
    for limit in ["max_file_bytes=100", "max_total_bytes=100"] {
        let f = Fixture::new();
        let mut zip = zip_bytes(&[("big.bin", &vec![0u8; 64 * 1024])]);
        set_recorded_size(&mut zip, 0, 10);
        std::fs::write(f.path().join("t.zip"), &zip).unwrap();
        let r = extract(&f, "t.zip", &[limit]);
        assert_extract_refused(&r);
        assert_eq!(
            f.tree(&f.path().join("out")),
            Vec::<String>::new(),
            "{limit}"
        );
    }
}

#[test]
fn archive_extract_within_limits_reports_real_sizes() {
    let f = Fixture::new();
    std::fs::write(
        f.path().join("t.zip"),
        zip_bytes(&[("a.txt", b"hello"), ("d/b.txt", b"world")]),
    )
    .unwrap();
    let r = extract(&f, "t.zip", &["max_file_bytes=5", "max_total_bytes=10"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json["ok"], true);
    assert_eq!(r.json["summary"]["bytes_written"], 10);
    assert_eq!(r.json["query"]["max_file_bytes"], 5);
    assert_eq!(
        std::fs::read(f.path().join("out/d/b.txt")).unwrap(),
        b"world"
    );
}

#[test]
fn archive_extract_failure_keeps_existing_files() {
    let f = Fixture::new();
    std::fs::create_dir(f.path().join("out")).unwrap();
    std::fs::write(f.path().join("out/big.bin"), b"original").unwrap();
    let mut zip = zip_bytes(&[("big.bin", &vec![0u8; 64 * 1024])]);
    set_recorded_size(&mut zip, 0, 10);
    std::fs::write(f.path().join("t.zip"), &zip).unwrap();
    let r = extract(&f, "t.zip", &["max_file_bytes=100", "overwrite=true"]);
    assert_extract_refused(&r);
    assert_eq!(f.tree(&f.path().join("out")), vec!["big.bin"]);
    assert_eq!(
        std::fs::read(f.path().join("out/big.bin")).unwrap(),
        b"original"
    );
}

#[test]
fn raw_extract_over_a_limit_writes_nothing() {
    let f = Fixture::new();
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&vec![0u8; 64 * 1024]).unwrap();
    std::fs::write(f.path().join("data.gz"), enc.finish().unwrap()).unwrap();
    let r = extract(
        &f,
        "data.gz",
        &["format=raw", "compression=gzip", "max_file_bytes=100"],
    );
    assert_extract_refused(&r);
    assert_eq!(f.tree(&f.path().join("out")), Vec::<String>::new());
}

/// A limit that cannot be read is refused like the other extract option
/// errors (exit 1, `[code] message` on stderr, nothing on stdout) before the
/// destination is created, instead of meaning "no limit".
#[test]
fn archive_extract_refuses_unreadable_limits() {
    for (arg, code) in [
        (
            "max_file_bytes=1e6",
            "archive.extract_invalid_max_file_size",
        ),
        ("max_file_bytes=-1", "archive.extract_invalid_max_file_size"),
        ("max_file_bytes=", "archive.extract_invalid_max_file_size"),
        ("max_total_bytes=1.5", "archive.extract_invalid_max_size"),
        (
            "max_total_bytes=18446744073709551616",
            "archive.extract_invalid_max_size",
        ),
        ("max_total_bytes=10MB", "archive.extract_invalid_max_size"),
    ] {
        let f = Fixture::new();
        std::fs::write(f.path().join("t.zip"), zip_bytes(&[("a.txt", b"hello")])).unwrap();
        let out = f
            .resh()
            .args([
                "archive://.extract",
                "archive=t.zip",
                "destination=out",
                arg,
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{arg}: {stderr}");
        assert!(out.stdout.is_empty(), "{arg}");
        assert!(stderr.starts_with(&format!("[{code}] ")), "{arg}: {stderr}");
        assert!(!f.path().join("out").exists(), "{arg}");
    }
    let f = Fixture::new();
    std::fs::write(f.path().join("t.zip"), zip_bytes(&[("a.txt", b"hello")])).unwrap();
    let r = extract(&f, "t.zip", &["max_file_bytes=0"]);
    assert_extract_refused(&r);
    let r = extract(&f, "t.zip", &["max_file_bytes=18446744073709551615"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json["summary"]["bytes_written"], 5);
}

// ---------------------------------------------------------------------------
// fs://local.mount
// ---------------------------------------------------------------------------

#[test]
fn fs_mount_refuses_option_shaped_operands_before_running() {
    for (field, args) in [
        ("source", ["source=-Pprobe", "target=/nonexistent/resh-7a"]),
        ("target", ["source=/dev/null", "target=-probe"]),
        ("target", ["source=/dev/null", "target=--probe-target-only"]),
    ] {
        for dry_run in [false, true] {
            let f = Fixture::new();
            let mut cmd = f.resh();
            cmd.arg("fs://local.mount").args(args);
            if dry_run {
                cmd.arg("dry_run=true");
            }
            let r = run(&mut cmd);
            assert_eq!(r.code, 1, "{args:?}: {}", r.stderr);
            assert!(
                r.stderr.contains(&format!("{field} cannot start with '-'")),
                "{}",
                r.stderr
            );
            assert!(f.programs_called().is_empty(), "{:?}", f.programs_called());
            let created: Vec<_> = f
                .tree(f.path())
                .into_iter()
                .filter(|p| p.contains("probe"))
                .collect();
            assert!(created.is_empty(), "{created:?}");
        }
    }
}

#[test]
fn fs_mount_dry_run_plans_operands_after_a_separator() {
    let f = Fixture::new();
    let r = run(f.resh().args([
        "fs://local.mount",
        "source=/dev/sdz9",
        "target=/nonexistent/resh-7a",
        "type=ext4",
        "create_target=false",
        "dry_run=true",
    ]));
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.json["plan"]["mount_commands"][0],
        "mount -t ext4 -- /dev/sdz9 /nonexistent/resh-7a"
    );
    assert!(f.programs_called().is_empty());
}

// ---------------------------------------------------------------------------
// user://.add primary_group
// ---------------------------------------------------------------------------

#[test]
fn user_add_refuses_option_shaped_primary_group_before_running() {
    for dry_run in [false, true] {
        let f = Fixture::new();
        let mut cmd = f.resh();
        cmd.args(["user://reshtest7a.add", "primary_group=-probe"]);
        if dry_run {
            cmd.arg("dry_run=true");
        }
        let r = run(&mut cmd);
        assert_eq!(r.code, 1, "{}", r.stderr);
        assert!(r.stderr.contains("user.group_name_invalid"), "{}", r.stderr);
        assert!(r.stderr.contains("primary_group"), "{}", r.stderr);
        assert!(f.programs_called().is_empty(), "{:?}", f.programs_called());
    }
}

#[test]
fn user_add_dry_run_plans_operands_after_a_separator() {
    let f = Fixture::new();
    let r = run(f.resh().args([
        "user://reshtest7a.add",
        "uid=54321",
        "primary_group=reshtest7a.team",
        "dry_run=true",
    ]));
    assert_eq!(r.code, 0, "{}", r.stderr);
    let planned: Vec<String> = r.json["planned_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(
        planned[0].starts_with("groupadd -g ") && planned[0].ends_with(" -- reshtest7a.team"),
        "{planned:?}"
    );
    assert!(planned[1].ends_with(" -- reshtest7a"), "{planned:?}");
    assert!(f.programs_called().is_empty());
}
