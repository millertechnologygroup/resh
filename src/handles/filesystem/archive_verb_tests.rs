//! Dispatch tests for every archive verb: each call goes through
//! `Handle::call` with `Args`, as the CLI does, inside a temporary directory.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

struct Run {
    status: Status,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Run {
    fn exit(&self) -> i32 {
        self.status.exit_code()
    }

    /// The error code: from the JSON report, else from `[code]` on stderr.
    fn code(&self) -> String {
        if let Some(c) = self.json["error"][0].as_str() {
            return c.to_string();
        }
        let s = self.stderr.trim_start_matches("Error: ");
        s.strip_prefix('[')
            .and_then(|r| r.split(']').next())
            .unwrap_or("")
            .to_string()
    }

    fn ok(&self) -> &Self {
        assert!(
            self.status.ok && self.json["ok"] == true,
            "expected success: {}\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    /// Asserts a failure with `code` and exit status `exit`.
    fn fails(&self, code: &str, exit: i32) -> &Self {
        assert_eq!(self.code(), code, "{}\n{}", self.stdout, self.stderr);
        assert_eq!(self.exit(), exit, "{code}: {}", self.stderr);
        if exit == 2 && self.json.is_null() {
            assert!(self.stdout.is_empty(), "usage error printed a report");
        }
        self
    }
}

fn call(verb: &str, kv: &[(&str, &str)]) -> Run {
    let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
    let args: Args = kv
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut stdin = std::io::empty();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = {
        let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
        h.call(verb, &args, &mut io).unwrap()
    };
    let stdout = String::from_utf8(out).unwrap();
    let json = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    Run {
        status,
        stdout,
        stderr: String::from_utf8(err).unwrap(),
        json,
    }
}

struct Fx {
    tmp: TempDir,
}

impl Fx {
    /// data/a.txt, data/sub/b.txt, data/link -> a.txt, data/.hidden,
    /// new.txt.
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let d = tmp.path();
        fs::create_dir_all(d.join("data/sub")).unwrap();
        fs::write(d.join("data/a.txt"), "hello\n").unwrap();
        fs::write(d.join("data/sub/b.txt"), "world\n").unwrap();
        fs::write(d.join("data/.hidden"), "h").unwrap();
        symlink("a.txt", d.join("data/link")).unwrap();
        fs::write(d.join("new.txt"), "new\n").unwrap();
        Fx { tmp }
    }

    fn p(&self, rel: &str) -> String {
        self.tmp.path().join(rel).to_string_lossy().into_owned()
    }

    fn dir(&self) -> String {
        self.p("").trim_end_matches('/').to_string()
    }

    /// Creates `name` from `data` with the handle.
    fn archive(&self, name: &str, extra: &[(&str, &str)]) -> String {
        let out = self.p(name);
        let base = self.dir();
        let mut kv = vec![
            ("output", out.as_str()),
            ("sources", r#"["data"]"#),
            ("base_dir", base.as_str()),
        ];
        kv.extend_from_slice(extra);
        call("create", &kv).ok();
        out
    }

    fn list(&self, archive: &str) -> Vec<String> {
        let r = call("list", &[("archive", archive)]);
        r.ok();
        r.json["manifest"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                m["path"]
                    .as_str()
                    .unwrap()
                    .trim_end_matches('/')
                    .to_string()
            })
            .collect()
    }

    fn leftovers(&self) -> Vec<String> {
        walkdir::WalkDir::new(self.tmp.path())
            .into_iter()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.contains("tmp_archive") || n.contains("resh-tmp") || n.contains(".resh-extract")
            })
            .collect()
    }
}

const TAR_FORMATS: &[&str] = &["t.tar", "t.tar.gz", "t.tgz", "t.tar.xz", "t.tar.zst"];
const ALL_FORMATS: &[&str] = &[
    "t.tar",
    "t.tar.gz",
    "t.tgz",
    "t.tar.xz",
    "t.tar.zst",
    "t.zip",
];

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn tar_headers(path: &str) -> Vec<(String, tar::Header)> {
    let f = File::open(path).unwrap();
    let r: Box<dyn Read> = if path.ends_with(".gz") || path.ends_with(".tgz") {
        Box::new(GzDecoder::new(f))
    } else if path.ends_with(".xz") {
        Box::new(XzDecoder::new(f))
    } else if path.ends_with(".zst") {
        Box::new(ZstdDecoder::new(f).unwrap())
    } else {
        Box::new(f)
    };
    let mut a = tar::Archive::new(r);
    a.entries()
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.path().unwrap().to_string_lossy().into_owned(),
                e.header().clone(),
            )
        })
        .collect()
}

fn header<'a>(h: &'a [(String, tar::Header)], name: &str) -> &'a tar::Header {
    &h.iter()
        .find(|(n, _)| n.trim_end_matches('/') == name)
        .unwrap_or_else(|| panic!("{name} not in archive"))
        .1
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// A file of incompressible-ish data, large enough that xz level 9 takes
/// well over a millisecond.
fn big_file(path: &str) {
    let mut data = Vec::with_capacity(8 << 20);
    let mut x: u32 = 1;
    while data.len() < 8 << 20 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.extend_from_slice(&x.to_le_bytes());
    }
    fs::write(path, data).unwrap();
}

// ---------------------------------------------------------------- create --

#[test]
fn create_every_format_round_trips() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        assert_eq!(
            sorted(fx.list(&a)),
            [
                "data",
                "data/.hidden",
                "data/a.txt",
                "data/link",
                "data/sub",
                "data/sub/b.txt"
            ],
            "{name}"
        );
        let dest = fx.p("out");
        call("extract", &[("archive", &a), ("destination", &dest)]).ok();
        assert_eq!(
            fs::read_to_string(fx.p("out/data/sub/b.txt")).unwrap(),
            "world\n"
        );
        let link = fs::read_link(fx.p("out/data/link")).unwrap();
        assert_eq!(link, Path::new("a.txt"), "{name}: symlink kept");
        call("test", &[("archive", &a)]).ok();
    }
}

#[test]
fn create_reports_result_and_format() {
    let fx = Fx::new();
    let out = fx.p("x.tar.xz");
    let base = fx.dir();
    let r = call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
        ],
    );
    r.ok();
    assert_eq!(r.json["result"]["format_detected"], "tar.xz");
    assert_eq!(r.json["result"]["files_archived"], 4);
    assert_eq!(r.json["result"]["directories_archived"], 2);
    assert_eq!(r.json["result"]["total_size_bytes"], 13);
    assert_eq!(
        r.json["result"]["compressed_size_bytes"],
        fs::metadata(&out).unwrap().len()
    );
    assert_eq!(r.json["query"]["base_dir"], base);
    assert!(fx.leftovers().is_empty());
}

#[test]
fn create_gzip_single_file() {
    let fx = Fx::new();
    let out = fx.p("a.txt.gz");
    let src = fx.p("data/a.txt");
    fs::set_permissions(&src, fs::Permissions::from_mode(0o640)).unwrap();
    call(
        "create",
        &[
            ("output", &out),
            ("format", "gzip"),
            ("sources", &format!("[\"{src}\"]")),
        ],
    )
    .ok();
    let mut s = String::new();
    GzDecoder::new(File::open(&out).unwrap())
        .read_to_string(&mut s)
        .unwrap();
    assert_eq!(s, "hello\n");
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o640
    );

    // A directory or several files are refused, and nothing is written.
    let out2 = fx.p("d.gz");
    let base = fx.dir();
    call(
        "create",
        &[
            ("output", &out2),
            ("format", "gzip"),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
        ],
    )
    .fails("archive.create_invalid_sources", 2);
    assert!(!Path::new(&out2).exists());
}

#[test]
fn create_compression_levels() {
    let fx = Fx::new();
    let base = fx.dir();
    for (name, good, bad) in [
        ("l.tar.gz", "9", "10"),
        ("l.zip", "1", "0"),
        ("l.tar.xz", "9", "10"),
        ("l.tar.zst", "22", "23"),
    ] {
        let out = fx.p(name);
        call(
            "create",
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
                ("compression_level", good),
            ],
        )
        .ok();
        fs::remove_file(&out).unwrap();
        call(
            "create",
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
                ("compression_level", bad),
            ],
        )
        .fails("archive.create_invalid_compression_level", 2);
        assert!(!Path::new(&out).exists());
    }
    for level in ["1", "0", "x"] {
        call(
            "create",
            &[
                ("output", &fx.p("l.tar")),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
                ("compression_level", level),
            ],
        )
        .fails("archive.create_invalid_compression_level", 2);
    }
}

#[test]
fn create_filters_and_hidden_files() {
    let fx = Fx::new();
    fs::create_dir(fx.p("data/.git")).unwrap();
    fs::write(fx.p("data/.git/config"), "c").unwrap();
    let base = fx.dir();
    let a = fx.p("f.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("include_hidden", "false"),
            ("exclude_patterns", r#"["*/sub/*"]"#),
        ],
    )
    .ok();
    assert_eq!(
        sorted(fx.list(&a)),
        ["data", "data/a.txt", "data/link", "data/sub"]
    );

    let a = fx.p("g.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("include_patterns", r#"["*.txt"]"#),
        ],
    )
    .ok();
    assert_eq!(sorted(fx.list(&a)), ["data/a.txt", "data/sub/b.txt"]);

    // Glob sources are matched under base_dir; `*` also matches '/'.
    let a = fx.p("h.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data/*.txt"]"#),
            ("base_dir", &base),
        ],
    )
    .ok();
    assert_eq!(sorted(fx.list(&a)), ["data/a.txt", "data/sub/b.txt"]);

    for (k, v) in [
        ("include_patterns", r#"["[x"]"#),
        ("exclude_patterns", "*.txt"),
    ] {
        call(
            "create",
            &[
                ("output", &fx.p("i.tar")),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
                (k, v),
            ],
        )
        .fails("archive.create_invalid_pattern", 2);
    }
}

#[test]
fn create_follow_symlinks() {
    let fx = Fx::new();
    let base = fx.dir();
    for (follow, symlink_kept) in [("false", true), ("true", false)] {
        let a = fx.p(&format!("s{follow}.tar"));
        call(
            "create",
            &[
                ("output", &a),
                ("sources", r#"["data/link"]"#),
                ("base_dir", &base),
                ("follow_symlinks", follow),
            ],
        )
        .ok();
        let h = tar_headers(&a);
        assert_eq!(
            header(&h, "data/link").entry_type().is_symlink(),
            symlink_kept
        );
    }
}

#[test]
fn create_overwrite_and_self_exclusion() {
    let fx = Fx::new();
    let base = fx.dir();
    let a = fx.p("o.tar");
    fs::write(&a, "keep").unwrap();
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
        ],
    )
    .fails("archive.create_output_exists", 1);
    assert_eq!(fs::read(&a).unwrap(), b"keep");
    // The existing output is replaced and never archived into itself.
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["."]"#),
            ("base_dir", &base),
            ("overwrite", "yes"),
        ],
    )
    .ok();
    let names = fx.list(&a);
    assert!(names.contains(&"data/a.txt".to_string()), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("o.tar")), "{names:?}");
    // A directory output is refused.
    call(
        "create",
        &[
            ("output", &fx.p("data")),
            ("sources", r#"["new.txt"]"#),
            ("base_dir", &base),
            ("format", "tar"),
            ("overwrite", "true"),
        ],
    )
    .fails("archive.create_invalid_output", 2);
}

#[test]
fn create_preserve_permissions_and_timestamps() {
    let fx = Fx::new();
    fs::set_permissions(fx.p("data/a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    filetime::set_file_mtime(
        fx.p("data/a.txt"),
        filetime::FileTime::from_unix_time(1_000_000_000, 0),
    )
    .unwrap();
    let base = fx.dir();
    let a = fx.p("p.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data/a.txt"]"#),
            ("base_dir", &base),
        ],
    )
    .ok();
    let h = tar_headers(&a);
    assert_eq!(header(&h, "data/a.txt").mode().unwrap() & 0o7777, 0o600);
    assert_eq!(header(&h, "data/a.txt").mtime().unwrap(), 1_000_000_000);

    let a = fx.p("q.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data/a.txt", "data/sub"]"#),
            ("base_dir", &base),
            ("preserve_permissions", "false"),
            ("preserve_timestamps", "false"),
        ],
    )
    .ok();
    let h = tar_headers(&a);
    assert_eq!(header(&h, "data/a.txt").mode().unwrap() & 0o7777, 0o644);
    assert_eq!(header(&h, "data/sub").mode().unwrap() & 0o7777, 0o755);
    assert!(header(&h, "data/a.txt").mtime().unwrap() >= now_unix() - 60);

    // Zip stores the same.
    let z = fx.p("p.zip");
    call(
        "create",
        &[
            ("output", &z),
            ("sources", r#"["data/a.txt"]"#),
            ("base_dir", &base),
        ],
    )
    .ok();
    let mut zip = ZipArchive::new(File::open(&z).unwrap()).unwrap();
    assert_eq!(zip.by_index(0).unwrap().unix_mode().unwrap() & 0o777, 0o600);
}

#[test]
fn create_limits() {
    let fx = Fx::new();
    let base = fx.dir();
    let a = fx.p("m.tar");
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("max_files", "2"),
        ],
    )
    .fails("archive.create_max_files_exceeded", 1);
    fs::write(fx.p("data/big"), vec![0u8; 2 << 20]).unwrap();
    call(
        "create",
        &[
            ("output", &a),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("max_size_mb", "1"),
        ],
    )
    .fails("archive.create_max_size_exceeded", 1);
    assert!(!Path::new(&a).exists());
    for (k, v, code) in [
        ("max_files", "-1", "archive.create_invalid_max_files"),
        ("max_size_mb", "1.5", "archive.create_invalid_max_size"),
        (
            "max_size_mb",
            "18446744073709551615",
            "archive.create_invalid_max_size",
        ),
    ] {
        call(
            "create",
            &[
                ("output", &a),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
                (k, v),
            ],
        )
        .fails(code, 2);
    }
}

#[test]
fn create_progress_goes_to_stderr() {
    let fx = Fx::new();
    let base = fx.dir();
    let r = call(
        "create",
        &[
            ("output", &fx.p("p.zip")),
            ("sources", r#"["data/sub"]"#),
            ("base_dir", &base),
            ("progress", "true"),
        ],
    );
    r.ok();
    assert_eq!(
        r.stderr,
        "archive create: [1/2] data/sub\narchive create: [2/2] data/sub/b.txt\n"
    );
    let r = call(
        "create",
        &[
            ("output", &fx.p("q.zip")),
            ("sources", r#"["data/sub"]"#),
            ("base_dir", &base),
        ],
    );
    assert_eq!(r.stderr, "");
}

#[test]
fn create_argument_errors() {
    let fx = Fx::new();
    let base = fx.dir();
    let out = fx.p("e.tar");
    let cases: &[(&[(&str, &str)], &str)] = &[
        (
            &[("sources", r#"["data"]"#)],
            "archive.create_invalid_output",
        ),
        (
            &[("output", ""), ("sources", r#"["data"]"#)],
            "archive.create_invalid_output",
        ),
        (&[("output", &out)], "archive.create_invalid_sources"),
        (
            &[("output", &out), ("sources", "[]")],
            "archive.create_invalid_sources",
        ),
        (
            &[("output", &out), ("sources", "data")],
            "archive.create_invalid_sources",
        ),
        (
            &[("output", &out), ("sources", r#"[""]"#)],
            "archive.create_invalid_sources",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("format", "rar"),
            ],
            "archive.create_invalid_format",
        ),
        (
            &[("output", &fx.p("e.unknown")), ("sources", r#"["data"]"#)],
            "archive.create_invalid_format",
        ),
        (
            &[("output", &fx.p("e.7z")), ("sources", r#"["data"]"#)],
            "archive.create_compression_failed",
        ),
        (
            &[("output", &fx.p("e.xz")), ("sources", r#"["data"]"#)],
            "archive.create_compression_failed",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("base_dir", "/nonexistent-dir"),
            ],
            "archive.create_invalid_base_dir",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("password", "x"),
            ],
            "archive.create_password_not_supported",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("overwrite", "maybe"),
            ],
            "archive.create_invalid_argument",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("progress", "2"),
            ],
            "archive.create_invalid_argument",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("format_output", "yaml"),
            ],
            "archive.create_invalid_argument",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("timeout_ms", "0"),
            ],
            "archive.create_invalid_argument",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("dry_run", "true"),
            ],
            "archive.create_invalid_argument",
        ),
        (
            &[
                ("output", &out),
                ("sources", r#"["data"]"#),
                ("ovewrite", "true"),
            ],
            "archive.create_invalid_argument",
        ),
    ];
    for (kv, code) in cases {
        let mut kv = kv.to_vec();
        if !kv.iter().any(|(k, _)| *k == "base_dir") {
            kv.push(("base_dir", &base));
        }
        call("create", &kv).fails(code, 2);
    }
    assert!(!Path::new(&out).exists());
    let r = call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["data"]"#),
            ("ovewrite", "true"),
        ],
    );
    assert!(
        r.stderr.contains("did you mean \"overwrite\"?"),
        "{}",
        r.stderr
    );
}

#[test]
fn create_source_errors() {
    let fx = Fx::new();
    let base = fx.dir();
    let out = fx.p("s.tar");
    call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["missing"]"#),
            ("base_dir", &base),
        ],
    )
    .fails("archive.create_source_not_found", 1);
    call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["../outside"]"#),
            ("base_dir", &fx.p("data")),
        ],
    )
    .fails("archive.create_source_not_found", 1);
    fs::write(fx.p("outside.txt"), "o").unwrap();
    call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["../outside.txt"]"#),
            ("base_dir", &fx.p("data")),
        ],
    )
    .fails("archive.create_invalid_sources", 2);
    // An absolute source outside base_dir is stored without its leading /.
    let abs = fx.p("new.txt");
    call(
        "create",
        &[
            ("output", &out),
            ("sources", &format!("[\"{abs}\"]")),
            ("base_dir", &fx.p("data")),
        ],
    )
    .ok();
    assert_eq!(fx.list(&out), [abs.trim_start_matches('/')]);
    if !is_root() {
        fs::set_permissions(fx.p("data/sub"), fs::Permissions::from_mode(0o000)).unwrap();
        call(
            "create",
            &[
                ("output", &fx.p("d.tar")),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
            ],
        )
        .fails("archive.create_source_permission_denied", 1);
        fs::set_permissions(fx.p("data/sub"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(fx.p("ro")).unwrap();
        fs::set_permissions(fx.p("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        call(
            "create",
            &[
                ("output", &fx.p("ro/x.tar")),
                ("sources", r#"["data"]"#),
                ("base_dir", &base),
            ],
        )
        .fails("archive.create_permission_denied", 1);
        fs::set_permissions(fx.p("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn create_timeout_leaves_no_output() {
    let fx = Fx::new();
    big_file(&fx.p("data/big.bin"));
    let out = fx.p("slow.tar.xz");
    let base = fx.dir();
    let r = call(
        "create",
        &[
            ("output", &out),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("compression_level", "9"),
            ("timeout_ms", "1"),
        ],
    );
    r.fails("archive.create_timeout", 124);
    assert!(!Path::new(&out).exists());
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

#[test]
fn create_text_output() {
    let fx = Fx::new();
    let base = fx.dir();
    let r = call(
        "create",
        &[
            ("output", &fx.p("t.tar")),
            ("sources", r#"["data"]"#),
            ("base_dir", &base),
            ("format_output", "text"),
        ],
    );
    assert!(r.status.ok);
    assert!(r.stdout.starts_with("Archive Creation\n"), "{}", r.stdout);
    assert!(r.stdout.is_ascii());
}

// --------------------------------------------------------------- extract --

#[test]
fn extract_every_format() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let r = call("extract", &[("archive", &a), ("destination", &fx.p("out"))]);
        r.ok();
        assert_eq!(r.json["summary"]["entries_extracted"], 6, "{name}");
        assert_eq!(
            fs::read_to_string(fx.p("out/data/a.txt")).unwrap(),
            "hello\n"
        );
        assert!(
            fs::symlink_metadata(fx.p("out/data/link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    for (ext, data) in [
        ("gz", {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(b"raw").unwrap();
            e.finish().unwrap()
        }),
        ("xz", {
            let mut e = XzEncoder::new(Vec::new(), 6);
            e.write_all(b"raw").unwrap();
            e.finish().unwrap()
        }),
        ("zst", zstd::stream::encode_all(&b"raw"[..], 3).unwrap()),
    ] {
        let fx = Fx::new();
        let a = fx.p(&format!("blob.bin.{ext}"));
        fs::write(&a, data).unwrap();
        let r = call("extract", &[("archive", &a), ("destination", &fx.p("out"))]);
        r.ok();
        assert_eq!(fs::read(fx.p("out/blob.bin")).unwrap(), b"raw", "{ext}");
        assert_eq!(r.json["summary"]["format"], "raw");
    }
}

#[test]
fn extract_options() {
    let fx = Fx::new();
    let a = fx.archive("t.tar.gz", &[]);
    let dest = fx.p("o1");
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("includes", r#"["*.txt"]"#),
            ("excludes", r#"["*/sub/*"]"#),
        ],
    )
    .ok();
    assert!(Path::new(&fx.p("o1/data/a.txt")).exists());
    assert!(!Path::new(&fx.p("o1/data/sub/b.txt")).exists());

    let dest = fx.p("o2");
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("strip_components", "1"),
            ("allow_symlinks", "off"),
            ("include_manifest", "false"),
        ],
    )
    .ok();
    assert!(Path::new(&fx.p("o2/sub/b.txt")).exists());
    assert!(fs::symlink_metadata(fx.p("o2/link")).is_err());

    // overwrite=false skips with a warning, overwrite=true replaces.
    fs::write(fx.p("o2/a.txt"), "old").unwrap();
    let r = call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("strip_components", "1"),
        ],
    );
    r.ok();
    assert_eq!(fs::read_to_string(fx.p("o2/a.txt")).unwrap(), "old");
    assert!(r.json["warnings"].to_string().contains("overwrite=false"));
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("strip_components", "1"),
            ("overwrite", "true"),
        ],
    )
    .ok();
    assert_eq!(fs::read_to_string(fx.p("o2/a.txt")).unwrap(), "hello\n");

    let r = call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &fx.p("o3")),
            ("include_manifest", "false"),
        ],
    );
    r.ok();
    assert!(r.json["manifest"].is_null());
}

#[test]
fn extract_errors() {
    let fx = Fx::new();
    let a = fx.archive("t.tar", &[]);
    let dest = fx.p("out");
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("create_destination", "false"),
        ],
    )
    .fails("archive.extract_destination_missing", 1);
    call(
        "extract",
        &[("archive", &a), ("destination", &fx.p("new.txt"))],
    )
    .fails("archive.extract_invalid_destination", 2);
    call(
        "extract",
        &[("archive", &a), ("destination", &fx.p("new.txt/sub"))],
    )
    .fails("archive.extract_destination_create_failed", 1);
    call(
        "extract",
        &[("archive", &fx.p("none.tar")), ("destination", &dest)],
    )
    .fails("archive.extract_missing_archive", 1);
    assert!(!Path::new(&dest).exists());
    let r = call(
        "extract",
        &[
            ("archive", &fx.p("none.tar")),
            ("destination", &dest),
            ("fail_on_missing_archive", "false"),
        ],
    );
    r.ok();
    assert!(!Path::new(&dest).exists());
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("does not exist")
    );
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &dest),
            ("max_entries", "2"),
        ],
    )
    .fails("archive.extract_max_entries_exceeded", 1);
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call(
        "extract",
        &[("archive", &fx.p("x.7z")), ("destination", &dest)],
    )
    .fails("archive.extract_7z_unsupported", 2);
    fs::write(fx.p("bad.tar.gz"), "not gzip").unwrap();
    call(
        "extract",
        &[("archive", &fx.p("bad.tar.gz")), ("destination", &dest)],
    )
    .fails("archive.extract_archive_read_error", 1);
    call(
        "extract",
        &[
            ("archive", &fx.p("data")),
            ("destination", &dest),
            ("format", "tar"),
        ],
    )
    .fails("archive.extract_invalid_archive_path", 2);

    let usage: &[(&[(&str, &str)], &str)] = &[
        (
            &[("destination", "x")],
            "archive.extract_invalid_archive_path",
        ),
        (&[("archive", "")], "archive.extract_invalid_archive_path"),
        (
            &[("archive", "a.tar")],
            "archive.extract_invalid_destination",
        ),
        (
            &[("archive", "a.rar"), ("destination", "x")],
            "archive.extract_invalid_format_infer",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("format", "rar"),
            ],
            "archive.extract_invalid_format",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("compression", "lz4"),
            ],
            "archive.extract_invalid_compression",
        ),
        (
            &[
                ("archive", "a.zip"),
                ("destination", "x"),
                ("compression", "gzip"),
            ],
            "archive.extract_invalid_format_compression",
        ),
        (
            &[
                ("archive", "a.bin"),
                ("destination", "x"),
                ("format", "raw"),
            ],
            "archive.extract_invalid_format_compression",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("includes", "["),
            ],
            "archive.extract_invalid_include_pattern",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("excludes", r#"["a[" ]"#),
            ],
            "archive.extract_invalid_exclude_pattern",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("strip_components", "-1"),
            ],
            "archive.extract_invalid_strip_components",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("strip_components", "4294967296"),
            ],
            "archive.extract_invalid_strip_components",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("max_entries", "x"),
            ],
            "archive.extract_invalid_max_entries",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("max_total_bytes", "1k"),
            ],
            "archive.extract_invalid_max_size",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("max_file_bytes", "1k"),
            ],
            "archive.extract_invalid_max_file_size",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("follow_symlinks", "true"),
            ],
            "archive.extract_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("include_manifest", "nah"),
            ],
            "archive.extract_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("destination", "x"),
                ("destnation", "y"),
            ],
            "archive.extract_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("extract", kv).fails(code, 2);
    }
    if !is_root() {
        fs::create_dir(fx.p("ro")).unwrap();
        fs::set_permissions(fx.p("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        call("extract", &[("archive", &a), ("destination", &fx.p("ro"))])
            .fails("archive.extract_io_error", 1);
        fs::set_permissions(fx.p("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn extract_zip_symlinks_are_contained() {
    let fx = Fx::new();
    let z = fx.p("l.zip");
    let mut w = ZipWriter::new(File::create(&z).unwrap());
    w.add_symlink("in", "a.txt", FileOptions::default())
        .unwrap();
    w.add_symlink("out", "../../etc/passwd", FileOptions::default())
        .unwrap();
    w.finish().unwrap();
    let r = call("extract", &[("archive", &z), ("destination", &fx.p("o"))]);
    r.fails("archive.extract_symlink_rejected", 1);
    assert_eq!(fs::read_link(fx.p("o/in")).unwrap(), Path::new("a.txt"));
    assert!(fs::symlink_metadata(fx.p("o/out")).is_err());
}

#[test]
fn extract_timeout() {
    let fx = Fx::new();
    big_file(&fx.p("data/big.bin"));
    let a = fx.archive("big.tar.xz", &[]);
    call(
        "extract",
        &[
            ("archive", &a),
            ("destination", &fx.p("o")),
            ("timeout_ms", "1"),
        ],
    )
    .fails("archive.extract_timeout", 124);
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

// ------------------------------------------------------------------ list --

#[test]
fn list_every_format_and_options() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let r = call("list", &[("archive", &a)]);
        r.ok();
        // A zip symlink's data is its target ("a.txt").
        let link_bytes = if name.ends_with(".zip") { 5 } else { 0 };
        assert_eq!(r.json["summary"]["entries_total"], 6, "{name}");
        assert_eq!(r.json["summary"]["bytes_total"], 13 + link_bytes, "{name}");
        let m = r.json["manifest"].as_array().unwrap();
        let link = m.iter().find(|e| e["path"] == "data/link").unwrap();
        assert_eq!(link["is_symlink"], true, "{name}");
        let file = m.iter().find(|e| e["path"] == "data/a.txt").unwrap();
        assert!(
            file["mode"].is_string() && file["mtime_unix"].is_number(),
            "{name}"
        );

        let r = call(
            "list",
            &[
                ("archive", &a),
                ("include_metadata", "false"),
                ("include_compressed_size", "false"),
                ("includes", r#"["*.txt"]"#),
                ("excludes", r#"["*/sub/*"]"#),
            ],
        );
        r.ok();
        let m = r.json["manifest"].as_array().unwrap();
        assert_eq!(m.len(), 1, "{name}");
        assert!(
            m[0]["mode"].is_null()
                && m[0]["mtime_unix"].is_null()
                && m[0]["compressed_size"].is_null()
        );
        assert_eq!(r.json["summary"]["entries_listed"], 1);
    }
    let fx = Fx::new();
    let z = fx.archive("c.zip", &[]);
    let r = call("list", &[("archive", &z)]);
    assert!(r.json["manifest"][1]["compressed_size"].is_number());
}

#[test]
fn list_raw_stream_reports_decompressed_size() {
    let fx = Fx::new();
    let a = fx.p("data.txt.gz");
    call(
        "create",
        &[
            ("output", &a),
            ("format", "gzip"),
            ("sources", &format!("[\"{}\"]", fx.p("data/a.txt"))),
        ],
    )
    .ok();
    let r = call("list", &[("archive", &a)]);
    r.ok();
    assert_eq!(r.json["manifest"][0]["path"], "data.txt");
    assert_eq!(r.json["manifest"][0]["size"], 6);
    call("list", &[("archive", &a), ("max_total_bytes", "5")])
        .fails("archive.list_max_size_exceeded", 1);
}

#[test]
fn list_errors() {
    let fx = Fx::new();
    let a = fx.archive("t.tar", &[]);
    call("list", &[("archive", &a), ("max_entries", "5")])
        .fails("archive.list_max_entries_exceeded", 1);
    call("list", &[("archive", &a), ("max_total_bytes", "12")])
        .fails("archive.list_max_size_exceeded", 1);
    call("list", &[("archive", &fx.p("no.tar"))]).fails("archive.list_missing_archive", 1);
    let r = call(
        "list",
        &[
            ("archive", &fx.p("no.tar")),
            ("fail_on_missing_archive", "0"),
        ],
    );
    r.ok();
    assert_eq!(r.json["manifest"], json!([]));
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call("list", &[("archive", &fx.p("x.7z"))]).fails("archive.list_7z_unsupported", 2);
    // Unreadable data: stderr only, as in v1.0.5-beta.
    fs::write(fx.p("bad.zip"), "not a zip").unwrap();
    let r = call("list", &[("archive", &fx.p("bad.zip"))]);
    r.fails("archive.list_archive_read_error", 1);
    assert!(r.stdout.is_empty());
    call("list", &[("archive", &fx.p("data")), ("format", "tar")])
        .fails("archive.list_invalid_archive_path", 2);
    let usage: &[(&[(&str, &str)], &str)] = &[
        (&[], "archive.list_invalid_archive_path"),
        (
            &[("archive", "a.what")],
            "archive.list_invalid_format_infer",
        ),
        (
            &[("archive", "a.tar"), ("format", "rar")],
            "archive.list_invalid_format",
        ),
        (
            &[("archive", "a.tar"), ("compression", "rar")],
            "archive.list_invalid_compression",
        ),
        (
            &[("archive", "a.tar.xz"), ("compression", "gzip")],
            "archive.list_invalid_format_compression",
        ),
        (
            &[("archive", "a.tar"), ("includes", "x")],
            "archive.list_invalid_include_pattern",
        ),
        (
            &[("archive", "a.tar"), ("excludes", "[1]")],
            "archive.list_invalid_exclude_pattern",
        ),
        (
            &[("archive", "a.tar"), ("max_entries", "1e3")],
            "archive.list_invalid_max_entries",
        ),
        (
            &[("archive", "a.tar"), ("max_total_bytes", "-5")],
            "archive.list_invalid_max_size",
        ),
        (
            &[("archive", "a.tar"), ("include_metadata", "maybe")],
            "archive.list_invalid_argument",
        ),
        (
            &[("archive", "a.tar"), ("timeout_ms", "soon")],
            "archive.list_invalid_argument",
        ),
        (
            &[("archive", "a.tar"), ("dry_run", "true")],
            "archive.list_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("list", kv).fails(code, 2);
    }
}

#[test]
fn list_timeout() {
    let fx = Fx::new();
    big_file(&fx.p("data/big.bin"));
    let a = fx.archive("big.tar.xz", &[]);
    call("list", &[("archive", &a), ("timeout_ms", "1")]).fails("archive.list_timeout", 124);
}

// ------------------------------------------------------------------ test --

/// A zip whose second entry has a corrupted CRC.
fn zip_with_bad_crc(path: &str, entries: usize) {
    let mut w = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..entries {
        w.start_file(
            format!("f{i}.txt"),
            FileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        w.write_all(b"payload").unwrap();
    }
    let mut z = w.finish().unwrap().into_inner();
    // Flip a data byte of every entry but the first.
    let mut pos = 0;
    let mut n = 0;
    while let Some(i) = z[pos..].windows(7).position(|w| w == b"payload") {
        if n > 0 {
            z[pos + i] = b'X';
        }
        pos += i + 7;
        n += 1;
    }
    fs::write(path, z).unwrap();
}

#[test]
fn test_every_format_and_options() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let r = call("test", &[("archive", &a)]);
        r.ok();
        assert_eq!(r.json["summary"]["valid"], true);
        assert_eq!(r.json["summary"]["entries_tested"], 6, "{name}");
        let link_bytes = if name.ends_with(".zip") { 5 } else { 0 };
        assert_eq!(r.json["summary"]["bytes_tested"], 13 + link_bytes, "{name}");
        let r = call(
            "test",
            &[
                ("archive", &a),
                ("verify_data", "false"),
                ("report_entries", "false"),
            ],
        );
        r.ok();
        assert_eq!(r.json["summary"]["bytes_tested"], 0);
        assert!(r.json["entries"].is_null());
    }
}

#[test]
fn test_detects_damage() {
    let fx = Fx::new();
    let z = fx.p("bad.zip");
    zip_with_bad_crc(&z, 3);
    let r = call("test", &[("archive", &z)]);
    r.fails("archive.test_entry_failed", 1);
    assert_eq!(r.json["summary"]["valid"], false);
    assert_eq!(r.json["summary"]["stopped_early"], true);
    assert_eq!(
        r.json["entries"][1]["error_code"],
        "archive.test_entry_checksum_error"
    );
    let r = call("test", &[("archive", &z), ("stop_on_first_error", "false")]);
    assert_eq!(r.json["summary"]["entries_failed"], 2);
    assert_eq!(r.json["summary"]["entries_tested"], 3);

    // A truncated gzip stream.
    let a = fx.archive("t.tar.gz", &[]);
    big_file(&fx.p("data/big.bin"));
    let a2 = fx.archive("big.tar.gz", &[]);
    let bytes = fs::read(&a2).unwrap();
    fs::write(&a2, &bytes[..bytes.len() / 2]).unwrap();
    let r = call("test", &[("archive", &a2)]);
    assert_eq!(r.exit(), 1, "{}", r.stdout);
    assert_eq!(r.json["summary"]["valid"], false);

    let r = call("test", &[("archive", &a), ("max_file_bytes", "5")]);
    r.fails("archive.test_entry_failed", 1);
    assert!(
        r.json
            .to_string()
            .contains("archive.test_max_file_size_exceeded")
    );
    call("test", &[("archive", &a), ("max_total_bytes", "6")])
        .fails("archive.test_max_size_exceeded", 1);
    call("test", &[("archive", &a), ("max_entries", "3")])
        .fails("archive.test_max_entries_exceeded", 1);
}

#[test]
fn test_errors() {
    let fx = Fx::new();
    call("test", &[("archive", &fx.p("no.zip"))]).fails("archive.test_missing_archive", 1);
    let r = call(
        "test",
        &[
            ("archive", &fx.p("no.zip")),
            ("fail_on_missing_archive", "false"),
        ],
    );
    r.ok();
    assert_eq!(r.json["summary"]["valid"], false);
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call("test", &[("archive", &fx.p("x.7z"))]).fails("archive.test_7z_unsupported", 2);
    fs::write(fx.p("bad.zip"), "nope").unwrap();
    call("test", &[("archive", &fx.p("bad.zip"))]).fails("archive.test_archive_read_error", 1);
    big_file(&fx.p("data/big.bin"));
    let a = fx.archive("big.tar.xz", &[]);
    call("test", &[("archive", &a), ("timeout_ms", "1")]).fails("archive.test_timeout", 124);
    let usage: &[(&[(&str, &str)], &str)] = &[
        (&[], "archive.test_invalid_archive_path"),
        (&[("archive", "x.doc")], "archive.test_invalid_format_infer"),
        (
            &[("archive", "x.tar"), ("format", "doc")],
            "archive.test_invalid_format",
        ),
        (
            &[("archive", "x.tar"), ("compression", "doc")],
            "archive.test_invalid_compression",
        ),
        (
            &[("archive", "x.tgz"), ("compression", "none")],
            "archive.test_invalid_format_compression",
        ),
        (
            &[("archive", "x.tar"), ("max_entries", "")],
            "archive.test_invalid_max_entries",
        ),
        (
            &[("archive", "x.tar"), ("max_total_bytes", "x")],
            "archive.test_invalid_max_size",
        ),
        (
            &[("archive", "x.tar"), ("max_file_bytes", "x")],
            "archive.test_invalid_max_file_size",
        ),
        (
            &[("archive", "x.tar"), ("verify_data", "x")],
            "archive.test_invalid_argument",
        ),
        (
            &[("archive", "x.tar"), ("verify", "true")],
            "archive.test_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("test", kv).fails(code, 2);
    }
}

// ------------------------------------------------------------------ info --

#[test]
fn info_every_format() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let r = call("info", &[("archive", &a)]);
        r.ok();
        let s = &r.json["summary"];
        assert_eq!(
            (
                s["entries_total"].as_u64(),
                s["files"].as_u64(),
                s["directories"].as_u64(),
                s["symlinks"].as_u64()
            ),
            (Some(6), Some(3), Some(2), Some(1)),
            "{name}: {s}"
        );
        assert_eq!(s["uncompressed_bytes_total"], 13, "{name}");
        assert!(s["min_mtime_unix"].is_number(), "{name}");
        assert_eq!(s["encrypted"], false);
        let r = call("info", &[("archive", &a), ("scan_entries", "false")]);
        r.ok();
        assert!(r.json["summary"]["entries_total"].is_null());
        assert!(r.json["summary"]["compression_ratio"].is_null());
    }
}

#[test]
fn info_honors_compression_and_raw_size() {
    let fx = Fx::new();
    let a = fx.archive("t.tar.gz", &[]);
    let renamed = fx.p("archive.bin");
    fs::copy(&a, &renamed).unwrap();
    let r = call(
        "info",
        &[
            ("archive", &renamed),
            ("format", "tar"),
            ("compression", "gzip"),
        ],
    );
    r.ok();
    assert_eq!(r.json["summary"]["format"], "tar.gz");
    assert_eq!(r.json["summary"]["entries_total"], 6);
    let g = fx.p("a.gz");
    call(
        "create",
        &[
            ("output", &g),
            ("format", "gzip"),
            ("sources", &format!("[\"{}\"]", fx.p("data/a.txt"))),
        ],
    )
    .ok();
    let r = call("info", &[("archive", &g)]);
    r.ok();
    assert_eq!(r.json["summary"]["uncompressed_bytes_total"], 6);
}

#[test]
fn info_detects_encrypted_zip_entries() {
    let fx = Fx::new();
    let z = fx.p("enc.zip");
    let mut w = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(
        "s.txt",
        FileOptions::default().compression_method(CompressionMethod::Stored),
    )
    .unwrap();
    w.write_all(b"secret").unwrap();
    let mut bytes = w.finish().unwrap().into_inner();
    // Set the "encrypted" flag in the local and central headers.
    bytes[6] |= 1;
    let c = bytes.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    bytes[c + 8] |= 1;
    fs::write(&z, bytes).unwrap();
    let r = call("info", &[("archive", &z)]);
    r.ok();
    assert_eq!(r.json["summary"]["encrypted"], true);
    assert_eq!(r.json["details"]["zip"]["encrypted_entries"], 1);
}

#[test]
fn info_errors() {
    let fx = Fx::new();
    let a = fx.archive("t.zip", &[]);
    call("info", &[("archive", &a), ("max_entries", "1")])
        .fails("archive.info_max_entries_exceeded", 1);
    call("info", &[("archive", &a), ("max_total_bytes", "1")])
        .fails("archive.info_max_size_exceeded", 1);
    call("info", &[("archive", &fx.p("no.zip"))]).fails("archive.info_missing_archive", 1);
    let r = call(
        "info",
        &[
            ("archive", &fx.p("no.zip")),
            ("fail_on_missing_archive", "no"),
        ],
    );
    r.ok();
    assert!(r.json["summary"].is_null());
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call("info", &[("archive", &fx.p("x.7z"))]).fails("archive.info_7z_unsupported", 2);
    fs::write(fx.p("bad.tar.gz"), "nope").unwrap();
    call("info", &[("archive", &fx.p("bad.tar.gz"))]).fails("archive.info_archive_read_error", 1);
    big_file(&fx.p("data/big.bin"));
    let b = fx.archive("big.tar.xz", &[]);
    call("info", &[("archive", &b), ("timeout_ms", "1")]).fails("archive.info_timeout", 124);
    let usage: &[(&[(&str, &str)], &str)] = &[
        (&[("archive", "")], "archive.info_invalid_archive_path"),
        (&[("archive", "x")], "archive.info_invalid_format_infer"),
        (
            &[("archive", "x.tar"), ("format", "x")],
            "archive.info_invalid_format",
        ),
        (
            &[("archive", "x.tar"), ("compression", "x")],
            "archive.info_invalid_compression",
        ),
        (
            &[("archive", "x.zip"), ("compression", "xz")],
            "archive.info_invalid_format_compression",
        ),
        (
            &[("archive", "x.tar"), ("max_entries", "x")],
            "archive.info_invalid_max_entries",
        ),
        (
            &[("archive", "x.tar"), ("max_total_bytes", "x")],
            "archive.info_invalid_max_size",
        ),
        (
            &[("archive", "x.tar"), ("scan_entries", "x")],
            "archive.info_invalid_argument",
        ),
        (
            &[("archive", "x.tar"), ("scan", "x")],
            "archive.info_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("info", kv).fails(code, 2);
    }
}

// ------------------------------------------------------------------- add --

#[test]
fn add_every_format_keeps_existing_entries() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let base = fx.dir();
        let r = call(
            "add",
            &[
                ("archive", &a),
                ("inputs", &format!("[\"{}\"]", fx.p("new.txt"))),
                ("base_dir", &base),
            ],
        );
        r.ok();
        assert_eq!(r.json["summary"]["entries_before"], 6);
        assert_eq!(r.json["summary"]["entries_after"], 7);
        let link_bytes = if name.ends_with(".zip") { 5 } else { 0 };
        assert_eq!(
            r.json["summary"]["uncompressed_bytes_after"],
            17 + link_bytes
        );
        assert_eq!(r.json["details"]["added"], json!(["new.txt"]));
        call("extract", &[("archive", &a), ("destination", &fx.p("o"))]).ok();
        assert_eq!(
            fs::read_to_string(fx.p("o/new.txt")).unwrap(),
            "new\n",
            "{name}"
        );
        assert_eq!(
            fs::read_to_string(fx.p("o/data/a.txt")).unwrap(),
            "hello\n",
            "{name}"
        );
        assert_eq!(
            fs::read_link(fx.p("o/data/link")).unwrap(),
            Path::new("a.txt"),
            "{name}"
        );
        assert!(fx.leftovers().is_empty(), "{name}: {:?}", fx.leftovers());
    }
}

#[test]
fn add_overwrite_and_keep_existing_dirs() {
    for name in ["t.tar.zst", "t.zip"] {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let base = fx.dir();
        fs::write(fx.p("data/a.txt"), "changed\n").unwrap();
        let before = fs::read(&a).unwrap();
        let r = call(
            "add",
            &[
                ("archive", &a),
                ("inputs", r#"["data/a.txt"]"#),
                ("base_dir", &base),
            ],
        );
        // Relative inputs are relative to the working directory, so use an
        // absolute one.
        assert_eq!(r.code(), "archive.add_invalid_input");
        let input = format!("[\"{}\"]", fx.p("data/a.txt"));
        let r = call(
            "add",
            &[("archive", &a), ("inputs", &input), ("base_dir", &base)],
        );
        r.ok();
        assert_eq!(r.json["summary"]["entries_skipped"], 1);
        assert!(r.json["warnings"].to_string().contains("not rewritten"));
        assert_eq!(
            fs::read(&a).unwrap(),
            before,
            "{name}: nothing to add, unchanged"
        );
        let r = call(
            "add",
            &[
                ("archive", &a),
                ("inputs", &input),
                ("base_dir", &base),
                ("overwrite", "true"),
            ],
        );
        r.ok();
        assert_eq!(r.json["details"]["replaced"], json!(["data/a.txt"]));
        call("extract", &[("archive", &a), ("destination", &fx.p("o"))]).ok();
        assert_eq!(
            fs::read_to_string(fx.p("o/data/a.txt")).unwrap(),
            "changed\n"
        );

        // A directory input whose entry exists: kept silently by default,
        // treated like a file with keep_existing_dirs=false.
        let dir_input = format!("[\"{}\"]", fx.p("data/sub"));
        let r = call(
            "add",
            &[("archive", &a), ("inputs", &dir_input), ("base_dir", &base)],
        );
        r.ok();
        assert_eq!(
            r.json["summary"]["entries_skipped"], 1,
            "{name}: only b.txt"
        );
        let r = call(
            "add",
            &[
                ("archive", &a),
                ("inputs", &dir_input),
                ("base_dir", &base),
                ("keep_existing_dirs", "false"),
            ],
        );
        r.ok();
        assert_eq!(r.json["summary"]["entries_skipped"], 2, "{name}");
        let r = call(
            "add",
            &[
                ("archive", &a),
                ("inputs", &dir_input),
                ("base_dir", &base),
                ("overwrite", "true"),
            ],
        );
        assert_eq!(
            r.json["details"]["replaced"],
            json!(["data/sub/b.txt"]),
            "{name}"
        );
    }
}

#[test]
fn add_metadata_options() {
    let fx = Fx::new();
    let a = fx.archive("t.tar", &[]);
    let base = fx.dir();
    fs::set_permissions(fx.p("new.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    filetime::set_file_mtime(
        fx.p("new.txt"),
        filetime::FileTime::from_unix_time(1_100_000_000, 0),
    )
    .unwrap();
    let input = format!("[\"{}\", \"{}\"]", fx.p("new.txt"), fx.p("data/link"));
    let uid = unsafe { libc::getuid() } as u64;

    call(
        "add",
        &[("archive", &a), ("inputs", &input), ("base_dir", &base)],
    )
    .ok();
    let h = tar_headers(&a);
    let n = header(&h, "new.txt");
    assert_eq!(
        (
            n.mode().unwrap() & 0o7777,
            n.mtime().unwrap(),
            n.uid().unwrap()
        ),
        (0o600, 1_100_000_000, 0)
    );

    let a = fx.archive("u.tar", &[]);
    let input2 = format!("[\"{}\"]", fx.p("new.txt"));
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &input2),
            ("base_dir", &base),
            ("preserve_owner", "true"),
            ("preserve_permissions", "false"),
            ("preserve_timestamps", "false"),
        ],
    )
    .ok();
    let h = tar_headers(&a);
    let n = header(&h, "new.txt");
    assert_eq!(n.mode().unwrap() & 0o7777, 0o644);
    assert_eq!(n.uid().unwrap(), uid);
    assert!(n.mtime().unwrap() >= now_unix() - 60);

    let a = fx.archive("d.tar", &[]);
    fs::write(fx.p("zz.txt"), "z").unwrap();
    let input3 = format!("[\"{}\", \"{}\"]", fx.p("zz.txt"), fx.p("new.txt"));
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &input3),
            ("base_dir", &base),
            ("deterministic", "true"),
            ("preserve_owner", "true"),
        ],
    )
    .ok();
    let h = tar_headers(&a);
    let tail: Vec<&str> = h[h.len() - 2..].iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(tail, ["new.txt", "zz.txt"], "sorted");
    for (_, hd) in &h[h.len() - 2..] {
        assert_eq!(
            (hd.mtime().unwrap(), hd.uid().unwrap()),
            (DETERMINISTIC_MTIME, 0)
        );
    }

    // follow_symlinks=true stores the target's data.
    let a = fx.archive("f.tar", &[]);
    let input4 = format!("[\"{}\"]", fx.p("data/link"));
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &input4),
            ("base_dir", &fx.p("data")),
            ("follow_symlinks", "true"),
        ],
    )
    .ok();
    let h = tar_headers(&a);
    assert!(header(&h, "link").entry_type().is_file());
}

#[test]
fn add_backup_tmp_dir_globs_and_filters() {
    let fx = Fx::new();
    let a = fx.archive("t.tar.gz", &[]);
    let base = fx.dir();
    let original = fs::read(&a).unwrap();
    fs::create_dir(fx.p("work")).unwrap();
    fs::write(fx.p("work/x.log"), "x").unwrap();
    fs::write(fx.p("work/y.txt"), "y").unwrap();
    let r = call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &format!("[\"glob:{}/work/*\"]", base)),
            ("base_dir", &base),
            ("excludes", r#"["*.txt"]"#),
            ("backup_suffix", ".orig"),
            ("tmp_dir", &fx.p("work")),
        ],
    );
    r.ok();
    assert_eq!(r.json["details"]["added"], json!(["work/x.log"]));
    assert_eq!(fs::read(format!("{a}.orig")).unwrap(), original);
    // The suffix may be given without its dot.
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &format!("[\"{}\"]", fx.p("new.txt"))),
            ("base_dir", &base),
            ("backup_suffix", "orig"),
        ],
    )
    .ok();
    assert_ne!(fs::read(format!("{a}.orig")).unwrap(), original);
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &format!("[\"{}\"]", fx.p("work/y.txt"))),
            ("base_dir", &base),
            ("includes", r#"["*.log"]"#),
        ],
    )
    .ok();
    assert!(!fx.list(&a).contains(&"work/y.txt".to_string()));
    // The archive itself is never added.
    let r = call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &format!("[\"{base}\"]")),
            ("base_dir", &base),
        ],
    );
    r.ok();
    assert!(!fx.list(&a).iter().any(|n| n.ends_with("t.tar.gz")));
    assert!(fx.leftovers().is_empty());
}

#[test]
fn add_limits_and_errors_leave_the_archive_unchanged() {
    let fx = Fx::new();
    let a = fx.archive("t.tar", &[]);
    let base = fx.dir();
    let before = fs::read(&a).unwrap();
    let new = format!("[\"{}\"]", fx.p("new.txt"));
    let dir = format!("[\"{}\"]", fx.p("data"));
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &dir),
            ("base_dir", &base),
            ("max_entries", "2"),
        ],
    )
    .fails("archive.add_max_entries_exceeded", 1);
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &dir),
            ("base_dir", &base),
            ("max_total_bytes", "3"),
        ],
    )
    .fails("archive.add_max_size_exceeded", 1);
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &new),
            ("tmp_dir", &fx.p("nope")),
        ],
    )
    .fails("archive.add_io_error", 1);
    call("add", &[("archive", &fx.p("no.tar")), ("inputs", &new)])
        .fails("archive.add_missing_archive", 1);
    call(
        "add",
        &[("archive", &a), ("inputs", r#"["/nonexistent/file"]"#)],
    )
    .fails("archive.add_invalid_input", 2);
    call("add", &[("archive", &a), ("inputs", r#"["../x"]"#)])
        .fails("archive.add_invalid_input", 2);
    fs::write(fx.p("b.bak"), "x").unwrap();
    let victim = fx.p("victim");
    fs::write(&victim, "v").unwrap();
    symlink(&victim, format!("{a}.bak")).unwrap();
    call(
        "add",
        &[("archive", &a), ("inputs", &new), ("backup_suffix", "bak")],
    )
    .fails("archive.add_backup_failed", 1);
    assert_eq!(fs::read(&victim).unwrap(), b"v");
    big_file(&fx.p("big.bin"));
    call(
        "add",
        &[
            ("archive", &a),
            ("inputs", &format!("[\"{}\"]", fx.p("big.bin"))),
            ("timeout_ms", "1"),
        ],
    )
    .fails("archive.add_timeout", 124);
    assert_eq!(fs::read(&a).unwrap(), before);
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());

    fs::write(fx.p("bad.tar"), vec![7u8; 1024]).unwrap();
    call("add", &[("archive", &fx.p("bad.tar")), ("inputs", &new)])
        .fails("archive.add_archive_read_error", 1);
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call("add", &[("archive", &fx.p("x.7z")), ("inputs", &new)])
        .fails("archive.add_7z_unsupported", 2);
    let usage: &[(&[(&str, &str)], &str)] = &[
        (
            &[("inputs", r#"["a"]"#)],
            "archive.add_invalid_archive_path",
        ),
        (&[("archive", "a.tar")], "archive.add_invalid_input"),
        (
            &[("archive", "a.tar"), ("inputs", "[]")],
            "archive.add_invalid_input",
        ),
        (
            &[("archive", "a.tar"), ("inputs", "a")],
            "archive.add_invalid_input",
        ),
        (
            &[("archive", "a.tar"), ("inputs", r#"["glob:"]"#)],
            "archive.add_invalid_input",
        ),
        (
            &[("archive", "a.tar"), ("inputs", r#"["glob:a["]"#)],
            "archive.add_invalid_input",
        ),
        (
            &[("archive", "a.gz"), ("inputs", r#"["a"]"#)],
            "archive.add_unsupported_for_raw",
        ),
        (
            &[("archive", "a.what"), ("inputs", r#"["a"]"#)],
            "archive.add_invalid_format_infer",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("format", "x"),
            ],
            "archive.add_invalid_format",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("compression", "x"),
            ],
            "archive.add_invalid_compression",
        ),
        (
            &[
                ("archive", "a.zip"),
                ("inputs", r#"["a"]"#),
                ("compression", "xz"),
            ],
            "archive.add_invalid_format_compression",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("includes", "x"),
            ],
            "archive.add_invalid_include_pattern",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("excludes", "x"),
            ],
            "archive.add_invalid_exclude_pattern",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("max_entries", "x"),
            ],
            "archive.add_invalid_max_entries",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("max_total_bytes", "x"),
            ],
            "archive.add_invalid_max_size",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("backup_suffix", ""),
            ],
            "archive.add_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("backup_suffix", "a/b"),
            ],
            "archive.add_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("tmp_dir", ""),
            ],
            "archive.add_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("deterministic", "x"),
            ],
            "archive.add_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("inputs", r#"["a"]"#),
                ("fail_on_missing_archive", "true"),
            ],
            "archive.add_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("add", kv).fails(code, 2);
    }
}

// ---------------------------------------------------------------- remove --

#[test]
fn remove_every_format_by_path_pattern_and_prefix() {
    for name in ALL_FORMATS {
        let fx = Fx::new();
        let a = fx.archive(name, &[]);
        let r = call(
            "remove",
            &[
                ("archive", &a),
                ("paths", r#"["data/a.txt", "missing.txt"]"#),
            ],
        );
        r.ok();
        assert_eq!(
            r.json["details"]["removed"],
            json!(["data/a.txt"]),
            "{name}"
        );
        assert_eq!(r.json["details"]["not_found"], json!(["missing.txt"]));
        call(
            "remove",
            &[("archive", &a), ("patterns", r#"["*/.hidden"]"#)],
        )
        .ok();
        let r = call(
            "remove",
            &[("archive", &a), ("dir_prefixes", r#"["data/sub/"]"#)],
        );
        r.ok();
        assert_eq!(r.json["summary"]["dirs_removed"], 1, "{name}");
        assert_eq!(sorted(fx.list(&a)), ["data", "data/link"], "{name}");
        call("extract", &[("archive", &a), ("destination", &fx.p("o"))]).ok();
        assert_eq!(
            fs::read_link(fx.p("o/data/link")).unwrap(),
            Path::new("a.txt")
        );
        assert!(fx.leftovers().is_empty());
    }
}

#[test]
fn remove_dry_run_empty_dirs_backup_and_no_match() {
    for name in TAR_FORMATS.iter().chain(["t.zip"].iter()) {
        let fx = Fx::new();
        fs::create_dir(fx.p("data/empty")).unwrap();
        let a = fx.archive(name, &[]);
        let before = fs::read(&a).unwrap();
        let r = call(
            "remove",
            &[
                ("archive", &a),
                ("paths", r#"["data/sub/b.txt"]"#),
                ("dry_run", "true"),
            ],
        );
        r.ok();
        assert_eq!(
            r.json["summary"]["entries_removed"], 2,
            "{name}: b.txt and the emptied sub"
        );
        assert_eq!(fs::read(&a).unwrap(), before);
        let r = call("remove", &[("archive", &a), ("patterns", r#"["*.none"]"#)]);
        r.ok();
        assert!(r.json["warnings"].to_string().contains("did not match"));
        assert_eq!(fs::read(&a).unwrap(), before, "no match, not rewritten");

        let r = call(
            "remove",
            &[
                ("archive", &a),
                ("paths", r#"["data/sub/b.txt"]"#),
                ("remove_empty_dirs", "false"),
                ("backup_suffix", "bak"),
                ("tmp_dir", &fx.p("data")),
            ],
        );
        r.ok();
        assert_eq!(fs::read(format!("{a}.bak")).unwrap(), before);
        let names = fx.list(&a);
        assert!(names.contains(&"data/sub".to_string()), "{name}: {names:?}");
        // The directory that was already empty is always kept.
        call("remove", &[("archive", &a), ("paths", r#"["data/a.txt"]"#)]).ok();
        assert!(fx.list(&a).contains(&"data/empty".to_string()), "{name}");
    }
}

#[test]
fn remove_keeps_long_names() {
    let fx = Fx::new();
    let deep = format!("data/{}/f.txt", "d".repeat(150));
    fs::create_dir_all(fx.p(&deep).rsplit_once('/').unwrap().0).unwrap();
    fs::write(fx.p(&deep), "deep").unwrap();
    let a = fx.archive("t.tar.gz", &[]);
    call("remove", &[("archive", &a), ("paths", r#"["data/a.txt"]"#)]).ok();
    assert!(fx.list(&a).contains(&deep));
}

#[test]
fn remove_errors() {
    let fx = Fx::new();
    let a = fx.archive("t.zip", &[]);
    let before = fs::read(&a).unwrap();
    call(
        "remove",
        &[
            ("archive", &a),
            ("paths", r#"["data/a.txt"]"#),
            ("max_entries", "2"),
        ],
    )
    .fails("archive.remove_max_entries_exceeded", 1);
    call(
        "remove",
        &[
            ("archive", &a),
            ("paths", r#"["data/a.txt"]"#),
            ("max_total_bytes", "2"),
        ],
    )
    .fails("archive.remove_max_size_exceeded", 1);
    call(
        "remove",
        &[
            ("archive", &a),
            ("paths", r#"["data/a.txt"]"#),
            ("tmp_dir", &fx.p("nope")),
        ],
    )
    .fails("archive.remove_io_error", 1);
    let victim = fx.p("victim");
    fs::write(&victim, "v").unwrap();
    symlink(&victim, format!("{a}.bak")).unwrap();
    call(
        "remove",
        &[
            ("archive", &a),
            ("paths", r#"["data/a.txt"]"#),
            ("backup_suffix", ".bak"),
        ],
    )
    .fails("archive.remove_backup_failed", 1);
    assert_eq!(fs::read(&victim).unwrap(), b"v");
    assert_eq!(fs::read(&a).unwrap(), before);
    call(
        "remove",
        &[("archive", &fx.p("no.zip")), ("paths", r#"["a"]"#)],
    )
    .fails("archive.remove_missing_archive", 1);
    let r = call(
        "remove",
        &[
            ("archive", &fx.p("no.zip")),
            ("paths", r#"["a"]"#),
            ("fail_on_missing_archive", "off"),
        ],
    );
    r.ok();
    fs::write(fx.p("bad.zip"), "nope").unwrap();
    call(
        "remove",
        &[("archive", &fx.p("bad.zip")), ("paths", r#"["a"]"#)],
    )
    .fails("archive.remove_archive_read_error", 1);
    big_file(&fx.p("data/big.bin"));
    let b = fx.archive("big.tar.xz", &[]);
    let big_before = fs::read(&b).unwrap();
    call(
        "remove",
        &[
            ("archive", &b),
            ("paths", r#"["data/a.txt"]"#),
            ("timeout_ms", "1"),
        ],
    )
    .fails("archive.remove_timeout", 124);
    assert_eq!(fs::read(&b).unwrap(), big_before);
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
    fs::write(fx.p("x.7z"), "7z").unwrap();
    call(
        "remove",
        &[("archive", &fx.p("x.7z")), ("paths", r#"["a"]"#)],
    )
    .fails("archive.remove_7z_unsupported", 2);
    let usage: &[(&[(&str, &str)], &str)] = &[
        (
            &[("paths", r#"["a"]"#)],
            "archive.remove_invalid_archive_path",
        ),
        (&[("archive", "a.tar")], "archive.remove_nothing_to_remove"),
        (
            &[("archive", "a.tar"), ("paths", "[]")],
            "archive.remove_nothing_to_remove",
        ),
        (
            &[("archive", "a.tar"), ("paths", "a")],
            "archive.remove_invalid_argument",
        ),
        (
            &[("archive", "a.tar"), ("paths", r#"["./"]"#)],
            "archive.remove_invalid_argument",
        ),
        (
            &[("archive", "a.tar"), ("dir_prefixes", "x")],
            "archive.remove_invalid_argument",
        ),
        (
            &[("archive", "a.tar"), ("patterns", "x")],
            "archive.remove_invalid_pattern",
        ),
        (
            &[("archive", "a.tar"), ("patterns", r#"["a["]"#)],
            "archive.remove_invalid_pattern",
        ),
        (
            &[("archive", "a.xz"), ("paths", r#"["a"]"#)],
            "archive.remove_unsupported_for_raw",
        ),
        (
            &[("archive", "a"), ("paths", r#"["a"]"#)],
            "archive.remove_invalid_format_infer",
        ),
        (
            &[("archive", "a.tar"), ("paths", r#"["a"]"#), ("format", "x")],
            "archive.remove_invalid_format",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("compression", "x"),
            ],
            "archive.remove_invalid_compression",
        ),
        (
            &[
                ("archive", "a.tar.gz"),
                ("paths", r#"["a"]"#),
                ("compression", "zstd"),
            ],
            "archive.remove_invalid_format_compression",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("max_entries", "x"),
            ],
            "archive.remove_invalid_max_entries",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("max_total_bytes", "x"),
            ],
            "archive.remove_invalid_max_size",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("dry_run", "perhaps"),
            ],
            "archive.remove_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("dryrun", "true"),
            ],
            "archive.remove_invalid_argument",
        ),
        (
            &[
                ("archive", "a.tar"),
                ("paths", r#"["a"]"#),
                ("backup_suffix", ""),
            ],
            "archive.remove_invalid_argument",
        ),
    ];
    for (kv, code) in usage {
        call("remove", kv).fails(code, 2);
    }
}

// ------------------------------------------------------------------ help --

/// Every option name in a usage text (`key=` tokens).
fn usage_options(usage: &str) -> Vec<String> {
    let mut v: Vec<String> = usage
        .split(|c: char| c.is_whitespace() || c == '[' || c == ']')
        .filter_map(|w| w.split_once('=').map(|(k, _)| k.to_string()))
        .filter(|k| !k.is_empty() && !k.contains(':'))
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn help_usage_lists_exactly_the_accepted_options() {
    let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
    for verb in h.verbs() {
        let meta = ARCHIVE_HELP.verbs.iter().find(|v| v.name == *verb).unwrap();
        let usage = meta.detail.as_ref().unwrap().usage;
        let mut want: Vec<String> = archive_args::options_for(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        want.sort();
        assert_eq!(usage_options(usage), want, "{verb}");
    }
}

#[test]
fn help_alias_verbs_render_help() {
    for verb in ["help", "--help", "-h"] {
        let r = call(verb, &[]);
        assert!(r.status.ok);
        assert!(r.stdout.starts_with("Handle: archive\n"), "{}", r.stdout);
    }
    let r = call("list", &[("help", "")]);
    assert!(
        r.stdout.starts_with("Handle: archive\nVerb: list\n"),
        "{}",
        r.stdout
    );
}

#[test]
fn unknown_verb_is_an_error() {
    let h = ArchiveHandle::from_url(&Url::parse("archive://").unwrap()).unwrap();
    let mut stdin = std::io::empty();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut io = IoStreams::new(&mut stdin, &mut out, &mut err);
    assert!(h.call("explode", &Args::new(), &mut io).is_err());
}
