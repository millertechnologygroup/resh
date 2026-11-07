//! Binary tests for every fs verb. Read-only verbs run against the host's
//! mount table; verbs that change things run with fake tools first in PATH
//! (they only log their arguments) or on temporary image files, so nothing
//! on the host is mounted, unmounted, resized or repaired. The real tools
//! as root are exercised in tests/fs_docker.rs.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn resh() -> assert_cmd::Command {
    assert_cmd::cargo::cargo_bin_cmd!("resh")
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn ok(&self) -> Value {
        assert_eq!(self.code, 0, "stderr: {}", self.stderr);
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {}", self.stdout))
    }
    fn fails(&self, code: i32, needle: &str) {
        assert_eq!(
            self.code, code,
            "stdout {} stderr {}",
            self.stdout, self.stderr
        );
        assert!(
            self.stderr.contains(needle),
            "stderr {:?} lacks {needle:?}",
            self.stderr
        );
    }
}

fn run_with(path: Option<&Path>, args: &[&str]) -> Out {
    let mut cmd = resh();
    cmd.args(args);
    if let Some(dir) = path {
        let old = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{old}", dir.display()));
    }
    let out = cmd.output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn run(args: &[&str]) -> Out {
    run_with(None, args)
}

/// A directory of fake tools that log their arguments to `log`.
struct Fakes {
    dir: tempfile::TempDir,
}

impl Fakes {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        Fakes { dir }
    }
    fn bin(&self) -> PathBuf {
        self.dir.path().join("bin")
    }
    fn path(&self, rel: &str) -> String {
        self.dir.path().join(rel).to_string_lossy().into_owned()
    }
    fn tool(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = self.bin().join(name);
        let log = self.path("log");
        std::fs::write(
            &p,
            format!("#!/bin/sh\necho \"{name} $*\" >> '{log}'\n{body}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.path("log")).unwrap_or_default()
    }
    fn run(&self, args: &[&str]) -> Out {
        run_with(Some(&self.bin()), args)
    }
}

// --- list-mounts ---------------------------------------------------------

#[test]
fn list_mounts_example_runs() {
    let v = run(&["--json-pretty", "fs://local.list-mounts"]).ok();
    assert_eq!(v["verb"], "list-mounts");
    let mounts = v["mounts"].as_array().unwrap();
    assert!(mounts.iter().any(|m| m["target"] == "/"));
    assert!(mounts.iter().all(|m| m["pseudo"] == false));
}

#[test]
fn list_mounts_paths_and_filters() {
    let v = run(&["fs://local.list-mounts", "paths=/", "include_pseudo=true"]).ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 1);
    assert_eq!(v["mounts"][0]["target"], "/");
    let v = run(&[
        "fs://local.list-mounts",
        "include_types=proc",
        "include_pseudo=yes",
    ])
    .ok();
    assert!(
        v["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["fstype"] == "proc")
    );
    run(&["fs://local.list-mounts", "include_pseudo=perhaps"]).fails(2, "include_pseudo");
    run(&["fs://local.list-mounts", "include_lop=false"]).fails(2, "did you mean \"include_loop\"");
    run(&[
        "fs://local.list-mounts",
        "include_readonly=false",
        "include_readwrite=false",
    ])
    .fails(2, "nothing allowed");
}

// --- usage ---------------------------------------------------------------

#[test]
fn usage_example_runs() {
    let v = run(&["--json-pretty", "fs://local.usage", "units=megabytes"]).ok();
    assert_eq!(v["units"], "megabytes");
    assert!(!v["filesystems"].as_array().unwrap().is_empty());
}

#[test]
fn usage_paths_and_aggregate() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().to_str().unwrap();
    let v = run(&[
        "fs://local.usage",
        "mode=paths",
        &format!("paths={p}"),
        "human_readable=true",
    ])
    .ok();
    assert_eq!(v["path_to_filesystem"][0]["path"], p);
    assert!(v["filesystems"][0]["size_human"].is_string());
    let v = run(&[
        "fs://local.usage",
        "mode=aggregate",
        "include_mountpoints=/",
        "include_types=ext4,xfs,btrfs",
    ]);
    if v.code == 0 {
        assert!(v.ok()["aggregate"].is_object());
    } else {
        v.fails(1, "No filesystems selected");
    }
    run(&[
        "fs://local.usage",
        "mode=paths",
        "paths=/nonexistent/resh-x",
    ])
    .fails(1, "Path not found");
    run(&["fs://local.usage", "paths=/"]).fails(2, "mode=paths");
    run(&["fs://local.usage", "include_types=nosuchfs"]).fails(1, "No filesystems selected");
    run(&["fs://local.usage", "timeout_ms=0"]).fails(2, "timeout_ms");
    run(&["fs://local.usage", "dry_run=true"]).fails(2, "dry_run");
}

// --- snapshot ------------------------------------------------------------

#[test]
fn snapshot_example_and_formats() {
    let v = run(&["--json-pretty", "fs://local.snapshot", "format=json"]).ok();
    let lock: Value = serde_json::from_str(v["lockfile"].as_str().unwrap()).unwrap();
    assert_eq!(lock["lockfile_version"], "fs-lock/v1");
    let v = run(&["fs://local.snapshot", "format=yaml", "include_usage=false"]).ok();
    assert!(
        v["lockfile"]
            .as_str()
            .unwrap()
            .starts_with("lockfile_version: fs-lock/v1")
    );
    let v = run(&[
        "fs://local.snapshot",
        "format=text",
        "include_mountpoints=/",
        "include_types=proc",
    ])
    .ok();
    assert!(v["lockfile"].as_str().unwrap().starts_with("# fs-lock/v1"));
    run(&["fs://local.snapshot", "format=toml"]).fails(2, "invalid value for format");
}

// --- quota and quota_summary ---------------------------------------------

const QUOTA: &str = "echo 'Disk quotas for user root (uid 0): '; \
echo '     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace'; \
echo \"      $RESH_DEV    20   100    200 0       2      0      0       0\"";

/// The source device of the mount holding "/", from the host mount table.
fn root_source() -> String {
    let v = run(&["fs://local.list-mounts", "paths=/", "include_pseudo=true"]).ok();
    v["mounts"][0]["source"].as_str().unwrap().to_string()
}

#[test]
fn quota_with_a_fake_quota_tool() {
    let f = Fakes::new();
    f.tool("quota", &QUOTA.replace("$RESH_DEV", &root_source()));
    let v = f.run(&["fs://local.quota", "path=/", "subject=0"]).ok();
    assert_eq!(v["subjects"][0]["space"]["used"], 20 * 1024);
    assert_eq!(v["subjects"][0]["space"]["soft_limit"], 100 * 1024);
    assert!(f.log().contains("quota -v -w -p -u -- 0"));
    f.run(&["fs://local.quota", "path=/", "subject=no-such-user-resh"])
        .fails(1, "subject not found");
    f.run(&[
        "fs://local.quota",
        "path=/",
        "all_subjects=true",
        "subject=0",
    ])
    .fails(2, "contradictory");
    f.run(&["fs://local.quota", "units=kb"])
        .fails(2, "invalid value for units");
}

#[test]
fn quota_summary_with_a_fake_quota_tool() {
    let f = Fakes::new();
    f.tool("quota", &QUOTA.replace("$RESH_DEV", &root_source()));
    let v = f
        .run(&[
            "fs://local.quota_summary",
            "subject=0",
            "include_mountpoints=/",
        ])
        .ok();
    assert_eq!(v["summary"]["space"]["used"], 20 * 1024);
    f.run(&[
        "fs://local.quota_summary",
        "subject=0",
        "include_types=nosuchfs",
    ])
    .fails(1, "no filesystem matched");
    f.run(&["fs://local.quota_summary", "include_types=,"])
        .fails(2, "empty entries");
}

#[test]
fn quota_without_the_quota_tool_is_unsupported() {
    let f = Fakes::new();
    // Only the fake directory on PATH: no quota tool.
    let out = {
        let mut cmd = resh();
        cmd.args(["fs://local.quota", "path=/", "subject=0"]);
        cmd.env("PATH", f.bin());
        cmd.output().unwrap()
    };
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not supported"));
}

// --- mount / unmount -----------------------------------------------------

#[test]
fn mount_runs_the_mount_tool() {
    let f = Fakes::new();
    f.tool("mount", "exit 0");
    let target = f.path("mnt/data");
    let v = f
        .run(&[
            "fs://local.mount",
            &format!("target={target}"),
            "source=/srv/disk.img",
            "options=ro,noexec",
        ])
        .ok();
    assert_eq!(v["action"], "mounted");
    assert!(Path::new(&target).is_dir());
    assert_eq!(
        f.log().trim(),
        format!("mount -o ro,noexec -- /srv/disk.img {target}")
    );
}

#[test]
fn mount_dry_run_and_errors() {
    let f = Fakes::new();
    f.tool(
        "mount",
        "echo 'mount: /x: must be superuser to use mount.' >&2; exit 32",
    );
    let target = f.path("planned");
    let v = f
        .run(&[
            "fs://local.mount",
            &format!("target={target}"),
            "source=/dev/sdz1",
            "dry_run",
        ])
        .ok();
    assert_eq!(v["action"], "planned");
    assert!(!Path::new(&target).exists());
    f.run(&[
        "fs://local.mount",
        &format!("target={target}"),
        "source=/dev/sdz1",
    ])
    .fails(1, "Permission denied");
    assert!(
        !Path::new(&target).exists(),
        "a failed mount left its directory"
    );
    f.run(&["fs://local.mount", "target=-o", "source=/dev/sdz1"])
        .fails(2, "cannot start");
    f.run(&[
        "fs://local.mount",
        &format!("target={target}"),
        "read_only=ture",
    ])
    .fails(2, "read_only");
    f.run(&[
        "fs://local.mount",
        &format!("target={target}"),
        "source=/x",
        "dry_run=ture",
    ])
    .fails(2, "dry_run");
}

#[test]
fn mount_timeout_stops_the_tool() {
    let f = Fakes::new();
    f.tool("mount", "exec sleep 30");
    let target = f.path("slow");
    let start = std::time::Instant::now();
    let out = f.run(&[
        "fs://local.mount",
        &format!("target={target}"),
        "source=/dev/sdz1",
        "timeout_ms=300",
    ]);
    assert!(start.elapsed().as_secs() < 10);
    out.fails(124, "outcome unknown");
}

#[test]
fn unmount_and_umount() {
    let f = Fakes::new();
    f.tool("umount", "exit 0");
    let v = f
        .run(&["fs://local.unmount", "target=/nonexistent/resh-mnt"])
        .ok();
    assert_eq!(v["action"], "already_unmounted");
    let v = f
        .run(&[
            "fs://local.umount",
            "target=/nonexistent/resh-mnt",
            "dry_run=true",
        ])
        .ok();
    assert_eq!(v["plan"]["commands"], serde_json::json!([]));
    f.run(&[
        "fs://local.unmount",
        "target=/nonexistent/resh-mnt",
        "fail_if_not_mounted=true",
    ])
    .fails(1, "not mounted");
    f.run(&["fs://local.unmount", "target=/x", "by=uuid"])
        .fails(2, "by");
    f.run(&["fs://local.unmount"])
        .fails(2, "target is required");
    assert_eq!(f.log(), "", "umount never ran");
}

// --- resize --------------------------------------------------------------

#[test]
fn resize_an_image_file_with_fake_tools() {
    let f = Fakes::new();
    let img = f.path("disk.img");
    std::fs::write(&img, vec![0u8; 8192]).unwrap();
    f.tool("blkid", "echo ext4");
    f.tool(
        "dumpe2fs",
        "echo 'Block count: 262144'; echo 'Free blocks: 200000'; echo 'Block size: 4096'",
    );
    f.tool("resize2fs", "exit 0");
    let v = f
        .run(&[
            "fs://local.resize",
            &format!("target={img}"),
            "size=512M",
            "mode=shrink",
            "allow_shrink=true",
            "dry_run=true",
        ])
        .ok();
    assert_eq!(
        v["plan"]["steps"][0]["command"],
        format!("resize2fs {img} 524288K")
    );
    assert!(!f.log().contains("resize2fs "), "dry run ran resize2fs");
    let v = f
        .run(&[
            "fs://local.resize",
            &format!("target={img}"),
            "delta=-512M",
            "mode=auto",
            "allow_shrink=true",
        ])
        .ok();
    assert_eq!(v["action"], "success");
    assert!(f.log().contains(&format!("resize2fs {img} 524288K")));
}

#[test]
fn resize_errors() {
    let f = Fakes::new();
    f.run(&["fs://local.resize", "target=/nonexistent/x", "size=1G"])
        .fails(1, "no such device");
    f.run(&["fs://local.resize", "target=/x", "size=1G", "delta=+1G"])
        .fails(2, "both");
    f.run(&["fs://local.resize", "target=/x", "size=1G", "mode=shrink"])
        .fails(2, "allow_shrink");
    f.run(&["fs://local.resize", "target=/x", "size=0"])
        .fails(2, "greater than 0");
    f.run(&["fs://local.resize", "target=/x"])
        .fails(2, "exactly one");
}

// --- check / fsck --------------------------------------------------------

#[test]
fn check_a_real_ext4_image_read_only() {
    let mkfs = ["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let Some(mkfs) = mkfs else {
        eprintln!("mkfs.ext4 not installed; skipping");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    std::fs::File::create(&img)
        .unwrap()
        .set_len(16 << 20)
        .unwrap();
    let ok = std::process::Command::new(mkfs)
        .args(["-q", "-F"])
        .arg(&img)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let before = std::fs::read(&img).unwrap();
    let img = img.to_str().unwrap();
    let mut cmd = resh();
    cmd.args([
        "--json-pretty",
        "fs://local.check",
        &format!("target={img}"),
    ]);
    cmd.env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin");
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["analysis"]["filesystem_state"], "clean");
    assert_eq!(v["tool"]["command"], format!("fsck.ext4 -n {img}"));
    assert_eq!(
        std::fs::read(img).unwrap(),
        before,
        "a read-only check changed the image"
    );
}

#[test]
fn check_and_fsck_with_fake_tools() {
    let f = Fakes::new();
    let img = f.path("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    f.tool("blkid", "echo ext4");
    f.tool("fsck.ext4", "exit 4");
    let v = f
        .run(&["fs://local.fsck", &format!("target={img}"), "force=true"])
        .ok();
    assert_eq!(v["verb"], "check");
    assert_eq!(v["analysis"]["needs_repair"], true);
    assert_eq!(v["tool"]["command"], format!("fsck.ext4 -n -f {img}"));
    f.run(&["fs://local.check", &format!("target={img}"), "mode=repair"])
        .fails(2, "allow_repair");
    f.tool("fsck.ext4", "exit 8");
    f.run(&["fs://local.check", &format!("target={img}")])
        .fails(1, "exited with status 8");
    f.run(&["fs://local.check", "target=/nonexistent/dev"])
        .fails(1, "device not found");
    f.run(&["fs://local.check", &format!("target={img}"), "max_pass=2"])
        .fails(2, "max_pass");
}
