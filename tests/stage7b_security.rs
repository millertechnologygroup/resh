//! v1.0.5-beta regression tests that need the real `resh` binary: the limit
//! on tar header data (PAX extended headers, GNU long names and long links)
//! read for one archive member. Each test runs the binary in its own
//! temporary directory. Fixtures are built in memory and stay small: an
//! oversized header declares gigabytes but carries 2 MiB.

use assert_cmd::Command;
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use tar::{EntryType, Header};
use tempfile::TempDir;

const LIMIT: usize = 1024 * 1024;
const LIMIT_MESSAGE: &str = "tar header data for one archive member exceeds 1048576 bytes";

struct Run {
    code: i32,
    json: Value,
    stderr: String,
}

fn resh(dir: &Path, args: &[&str]) -> Run {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Tar stream built header by header.
#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    fn header(&mut self, mut h: Header) -> &mut Self {
        h.set_cksum();
        self.0.extend_from_slice(h.as_bytes());
        self
    }

    fn data(&mut self, data: &[u8]) -> &mut Self {
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().div_ceil(512) * 512, 0);
        self
    }

    fn member(&mut self, kind: EntryType, name: &str, data: &[u8]) -> &mut Self {
        let mut h = Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        self.header(h).data(data)
    }

    fn file(&mut self, name: &str, data: &[u8]) -> &mut Self {
        self.member(EntryType::Regular, name, data)
    }

    /// A header of `kind` declaring `declared` bytes, followed by only
    /// `present` bytes of data.
    fn declares(&mut self, kind: EntryType, declared: u64, present: usize) -> &mut Self {
        let mut h = Header::new_ustar();
        h.set_path("meta").unwrap();
        h.set_entry_type(kind);
        h.set_size(declared);
        self.header(h);
        self.0.resize(self.0.len() + present, b'a');
        self
    }

    fn end(&mut self) -> Vec<u8> {
        self.0.resize(self.0.len() + 1024, 0);
        std::mem::take(&mut self.0)
    }
}

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let rest = key.len() + value.len() + 3;
    let mut len = rest + 1;
    while len != rest + len.to_string().len() {
        len = rest + len.to_string().len();
    }
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// PAX data of exactly `len` bytes: one comment record.
fn pax_of_len(len: usize) -> Vec<u8> {
    let mut value = len - 12;
    loop {
        let rec = pax_record("comment", &vec![b'c'; value]);
        match rec.len().cmp(&len) {
            std::cmp::Ordering::Equal => return rec,
            std::cmp::Ordering::Greater => value -= 1,
            std::cmp::Ordering::Less => value += 1,
        }
    }
}

fn gzip(tar: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(tar).unwrap();
    e.finish().unwrap()
}

fn xz(tar: &[u8]) -> Vec<u8> {
    let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
    e.write_all(tar).unwrap();
    e.finish().unwrap()
}

fn zstd(tar: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(tar, 3).unwrap()
}

/// The first member is preceded by a PAX header declaring 8 GiB, 2 MiB of
/// which is present.
fn oversized_pax() -> Vec<u8> {
    Tar::default()
        .declares(EntryType::XHeader, 8 << 30, 2 * LIMIT)
        .file("a.txt", b"hello")
        .end()
}

fn assert_list_refused(dir: &Path, archive: &str) {
    let r = resh(dir, &["archive://.list", &format!("archive={archive}")]);
    assert_eq!(r.code, 1, "{archive}: {}", r.stderr);
    assert_eq!(
        r.stderr.trim(),
        format!("[archive.list_internal_error] {LIMIT_MESSAGE}"),
        "{archive}"
    );
}

fn assert_json_refused(r: &Run, code: &str) {
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert_eq!(r.json["ok"], false, "{}", r.json);
    assert_eq!(r.json["error"][0], code, "{}", r.json);
    assert_eq!(r.json["error"][1], LIMIT_MESSAGE, "{}", r.json);
}

fn tree(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .map(|e| {
            let e = e.unwrap();
            e.path().strip_prefix(dir).unwrap().display().to_string()
        })
        .collect();
    out.sort();
    out
}

#[test]
fn oversized_header_data_is_refused_by_every_tar_verb() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let archive = gzip(&oversized_pax());
    assert!(archive.len() < 64 * 1024);
    std::fs::write(dir.join("t.tar.gz"), &archive).unwrap();

    assert_list_refused(dir, "t.tar.gz");

    let r = resh(dir, &["archive://.info", "archive=t.tar.gz"]);
    assert_json_refused(&r, "archive.info_archive_read_error");

    let r = resh(
        dir,
        &[
            "archive://.extract",
            "archive=t.tar.gz",
            "destination=out",
            "max_total_bytes=100",
        ],
    );
    assert_json_refused(&r, "archive.extract_archive_read_error");
    assert_eq!(tree(&dir.join("out")), Vec::<String>::new());

    // test reports the header error on the entry and fails the archive.
    let r = resh(dir, &["archive://.test", "archive=t.tar.gz"]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert_eq!(r.json["ok"], false);
    assert_eq!(r.json["error"][0], "archive.test_entry_failed");
    assert_eq!(r.json["summary"]["valid"], false);
    let entry = &r.json["entries"][0];
    assert_eq!(entry["error_code"], "archive.test_entry_header_error");
    assert_eq!(entry["error_message"], LIMIT_MESSAGE);

    // add and remove read the existing archive first and leave it as it was.
    std::fs::write(dir.join("new.txt"), b"new").unwrap();
    let r = resh(
        dir,
        &[
            "archive://.add",
            "archive=t.tar.gz",
            r#"inputs=["new.txt"]"#,
        ],
    );
    assert_json_refused(&r, "archive.add_archive_write_error");
    let r = resh(
        dir,
        &[
            "archive://.remove",
            "archive=t.tar.gz",
            r#"paths=["a.txt"]"#,
        ],
    );
    assert_json_refused(&r, "archive.remove_archive_read_error");
    assert_eq!(std::fs::read(dir.join("t.tar.gz")).unwrap(), archive);
}

#[test]
fn every_compression_is_limited_after_decompression() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let tar = oversized_pax();
    std::fs::write(dir.join("t.tar"), &tar).unwrap();
    std::fs::write(dir.join("t.tar.gz"), gzip(&tar)).unwrap();
    std::fs::write(dir.join("t.tar.xz"), xz(&tar)).unwrap();
    std::fs::write(dir.join("t.tar.zst"), zstd(&tar)).unwrap();
    for name in ["t.tar", "t.tar.gz", "t.tar.xz", "t.tar.zst"] {
        assert_list_refused(dir, name);
    }
}

#[test]
fn oversized_gnu_long_name_and_long_link_are_refused() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    for kind in [EntryType::GNULongName, EntryType::GNULongLink] {
        let tar = Tar::default()
            .file("first.txt", b"1")
            .declares(kind, 8 << 30, 2 * LIMIT)
            .file("a.txt", b"hello")
            .end();
        std::fs::write(dir.join("t.tar.gz"), gzip(&tar)).unwrap();
        assert_list_refused(dir, "t.tar.gz");
        let r = resh(
            dir,
            &["archive://.extract", "archive=t.tar.gz", "destination=out"],
        );
        assert_json_refused(&r, "archive.extract_archive_read_error");
    }
}

#[test]
fn stacked_headers_for_one_member_count_together() {
    // x + L + K, each under the limit, together over it.
    let third = LIMIT / 3;
    let tar = Tar::default()
        .member(EntryType::XHeader, "PaxHeader", &pax_of_len(third))
        .member(EntryType::GNULongName, "././@LongLink", &vec![b'n'; third])
        .member(EntryType::GNULongLink, "././@LongLink", &vec![b'l'; third])
        .member(EntryType::Symlink, "s", b"")
        .end();
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("t.tar.gz"), gzip(&tar)).unwrap();
    assert_list_refused(tmp.path(), "t.tar.gz");
}

#[test]
fn header_data_at_the_limit_is_accepted_and_one_byte_more_is_refused() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    // PAX header block + data + member header block == the limit.
    for (pax_len, ok) in [
        (LIMIT - 1024 - 512, true),
        (LIMIT - 1024, true),
        (LIMIT - 1023, false),
    ] {
        let tar = Tar::default()
            .member(EntryType::XHeader, "PaxHeader", &pax_of_len(pax_len))
            .file("a.txt", b"hello")
            .end();
        std::fs::write(dir.join("t.tar.gz"), gzip(&tar)).unwrap();
        if ok {
            let r = resh(dir, &["archive://.list", "archive=t.tar.gz"]);
            assert_eq!(r.code, 0, "{pax_len}: {}", r.stderr);
            assert_eq!(r.json["manifest"][0]["path"], "a.txt");
        } else {
            assert_list_refused(dir, "t.tar.gz");
        }
    }
}

#[test]
fn malformed_and_truncated_archives_still_fail() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    // A PAX header whose declared size runs past the end of the archive.
    let tar = Tar::default().declares(EntryType::XHeader, 4096, 100).end();
    std::fs::write(dir.join("short.tar"), &tar).unwrap();
    // A gzip stream cut in half.
    let gz = gzip(&Tar::default().file("a.txt", &[7u8; 50_000]).end());
    std::fs::write(dir.join("cut.tar.gz"), &gz[..gz.len() / 2]).unwrap();
    for name in ["short.tar", "cut.tar.gz"] {
        let r = resh(
            dir,
            &[
                "archive://.extract",
                &format!("archive={name}"),
                "destination=out",
            ],
        );
        assert_eq!(r.code, 1, "{name}: {}", r.stderr);
        assert_eq!(r.json["error"][0], "archive.extract_archive_read_error");
        assert_ne!(r.json["error"][1], LIMIT_MESSAGE, "{name}");
    }
}

/// Ordinary metadata, global PAX headers, empty files and large contents
/// behave as before.
#[test]
fn legitimate_archives_are_listed_tested_and_extracted() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let long = format!("{}/long.txt", "d".repeat(200));
    let big = vec![0u8; 4 * LIMIT];
    let mut b = tar::Builder::new(Vec::new());
    let mut global = Header::new_ustar();
    let global_data = pax_record("comment", b"global");
    global.set_path("pax_global_header").unwrap();
    global.set_entry_type(EntryType::XGlobalHeader);
    global.set_mode(0o644);
    global.set_uid(0);
    global.set_gid(0);
    global.set_mtime(0);
    global.set_size(global_data.len() as u64);
    global.set_cksum();
    b.append(&global, &global_data[..]).unwrap();
    b.append_pax_extensions([
        ("comment", &vec![b'x'; 60 * 1024][..]),
        ("SCHILY.xattr.user.note", &vec![b'y'; 64 * 1024][..]),
    ])
    .unwrap();
    for (name, data) in [
        ("a.txt", &b"hello"[..]),
        ("empty.txt", &b""[..]),
        (long.as_str(), &b"long"[..]),
        ("big.bin", &big[..]),
    ] {
        let mut h = Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        b.append_data(&mut h, name, data).unwrap();
    }
    std::fs::write(dir.join("t.tar.gz"), gzip(&b.into_inner().unwrap())).unwrap();

    let r = resh(dir, &["archive://.list", "archive=t.tar.gz"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let paths: Vec<&str> = r.json["manifest"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.ends_with(&["a.txt", "empty.txt", long.as_str(), "big.bin"]),
        "{paths:?}"
    );
    assert!(r.json["summary"]["bytes_total"].as_u64().unwrap() as usize >= big.len());

    let r = resh(dir, &["archive://.test", "archive=t.tar.gz"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json["summary"]["valid"], true);

    let r = resh(dir, &["archive://.info", "archive=t.tar.gz"]);
    assert_eq!(r.code, 0, "{}", r.stderr);

    let r = resh(
        dir,
        &["archive://.extract", "archive=t.tar.gz", "destination=out"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let out = dir.join("out");
    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read(out.join("empty.txt")).unwrap(), b"");
    assert_eq!(std::fs::read(out.join(&long)).unwrap(), b"long");
    assert_eq!(std::fs::read(out.join("big.bin")).unwrap(), big);
}
