//! Verb tests for the fs handle, through `Handle::call` with string
//! arguments as the CLI passes them. External tools are replaced by fake
//! scripts (`support::TOOL_DIR`) and the mount table by fixed text
//! (`support::MOUNTS_OVERRIDE`), so nothing on the host is mounted, resized
//! or checked. The real tools are exercised in tests/fs_docker.rs.

use super::support::{MOUNTS_OVERRIDE, TOOL_DIR};
use super::*;
use crate::core::test_support::write_executable;

/// A fake tool environment for one test. Dropping it restores the real
/// tools and mount table.
struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        TOOL_DIR.with(|d| *d.borrow_mut() = Some(dir.path().join("bin")));
        MOUNTS_OVERRIDE.with(|m| *m.borrow_mut() = Some(String::new()));
        crate::core::process::clear_limit();
        Env { dir }
    }

    fn path(&self, rel: &str) -> String {
        self.dir.path().join(rel).to_string_lossy().into_owned()
    }

    /// Installs fake tool `name`: it logs its arguments, then runs `body`.
    fn tool(&self, name: &str, body: &str) {
        let log = self.path("log");
        write_executable(
            &self.dir.path().join("bin").join(name),
            &format!("#!/bin/sh\necho \"{name} $*\" >> '{log}'\n{body}\n"),
        );
    }

    fn mounts(&self, table: &str) {
        MOUNTS_OVERRIDE.with(|m| *m.borrow_mut() = Some(table.to_string()));
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("log")).unwrap_or_default()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        TOOL_DIR.with(|d| *d.borrow_mut() = None);
        MOUNTS_OVERRIDE.with(|m| *m.borrow_mut() = None);
        crate::core::process::clear_limit();
    }
}

/// Outcome of one call: exit status, stdout, and the failure reason.
struct Out {
    code: i32,
    stdout: String,
    reason: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!("not JSON ({e}): {:?} reason {:?}", self.stdout, self.reason)
        })
    }
    fn ok(&self) -> Value {
        assert_eq!(self.code, 0, "reason: {}", self.reason);
        self.json()
    }
    fn fails(&self, code: i32, needle: &str) {
        assert_eq!(
            self.code, code,
            "stdout {:?} reason {:?}",
            self.stdout, self.reason
        );
        assert!(
            self.reason.contains(needle),
            "reason {:?} lacks {needle:?}",
            self.reason
        );
    }
}

fn call(verb: &str, pairs: &[(&str, &str)]) -> Out {
    let h = FsHandle::new_for_test("local".to_string());
    let args: Args = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let st = h.call(verb, &args, &mut io).unwrap();
    crate::core::process::clear_limit();
    Out {
        code: st.exit_code(),
        stdout: String::from_utf8(o).unwrap(),
        reason: st.reason.unwrap_or_default(),
    }
}

const TABLE: &str = "/dev/sda1 / ext4 rw,relatime 0 1
proc /proc proc rw,nosuid 0 0
tmpfs /run tmpfs rw 0 0
/dev/sdb1 /mnt/data ext4 rw,errors=remount-ro 0 2
/dev/sdc1 /mnt/data/child xfs ro 0 0
/dev/sdc2 /mnt/datax ext4 rw 0 0
/dev/loop3 /mnt/my\\040disk ext4 rw 0 0
/dev/mapper/sloop /mnt/vg ext4 rw 0 0
server:/export /mnt/nfs nfs4 rw 0 0
";

// --- shared behavior -----------------------------------------------------------

#[test]
fn every_verb_refuses_unknown_and_misspelled_arguments() {
    let _env = Env::new();
    for verb in [
        "mount",
        "unmount",
        "umount",
        "snapshot",
        "quota",
        "quota_summary",
        "usage",
        "resize",
        "check",
        "fsck",
        "list-mounts",
    ] {
        let out = call(verb, &[("bogus", "1")]);
        out.fails(2, "unknown argument \"bogus\"");
        assert!(out.reason.contains("nothing was done"));
        let out = call(verb, &[("timeout_ms", "soon")]);
        assert_eq!(out.code, 2, "{verb}: {}", out.reason);
    }
    call("mount", &[("target", "/x"), ("read_onyl", "true")])
        .fails(2, "did you mean \"read_only\"");
    call("check", &[("target", "/x"), ("max_pass", "2")]).fails(2, "max_pass");
    // Verbs without a dry-run mode do not take dry_run at all.
    call("usage", &[("dry_run", "false")]).fails(2, "dry_run");
    call("bogus", &[]).fails(2, "unknown verb");
}

#[test]
fn option_lists_match_help_usage() {
    for verb in FS_HELP.verbs {
        let usage = verb.detail.as_ref().unwrap().usage;
        let mut in_usage: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        in_usage.sort();
        let mut accepted = support::options_for(verb.name).unwrap().to_vec();
        accepted.sort();
        assert_eq!(in_usage, accepted, "usage of {} disagrees", verb.name);
    }
}

#[test]
fn exit_codes_follow_the_project_convention() {
    assert_eq!(fs_exit_code(&FsError::InvalidMountConfig("x".into())), 2);
    assert_eq!(fs_exit_code(&FsError::ResizeShrinkNotAllowed), 2);
    assert_eq!(fs_exit_code(&FsError::CheckRepairNotAllowed), 2);
    assert_eq!(
        fs_exit_code(&FsError::ResizeInvalidTargetSize("x".into())),
        2
    );
    for timeout in [
        FsError::MountTimeout,
        FsError::UnmountTimeout,
        FsError::SnapshotTimeout,
        FsError::QuotaTimeout,
        FsError::QuotaSummaryTimeout,
        FsError::UsageTimeout,
        FsError::ResizeTimeout,
        FsError::CheckTimeout,
        FsError::ListMountsTimeout,
    ] {
        assert_eq!(fs_exit_code(&timeout), 124);
    }
    for failure in [
        FsError::NotMounted("x".into()),
        FsError::MountPermissionDenied,
        FsError::QuotaNotEnabled("x".into()),
        FsError::CheckMustBeOffline("x".into()),
        FsError::ResizeTargetExceedsDevice,
        FsError::PathNotFound("x".into()),
    ] {
        assert_eq!(fs_exit_code(&failure), 1);
    }
}

#[test]
fn a_tool_that_outlives_timeout_ms_is_stopped() {
    let env = Env::new();
    env.tool("mount", "exec sleep 30");
    let target = env.path("m");
    let start = std::time::Instant::now();
    let out = call(
        "mount",
        &[
            ("target", &target),
            ("source", "/dev/sdz1"),
            ("timeout_ms", "300"),
        ],
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_ne!(out.code, 0);
    let lost = crate::core::process::take_lost().expect("the tool was recorded as stopped");
    assert!(lost.tool.ends_with("mount"));
    // The directory created for the mount is kept: whether the mount
    // happened is unknown.
}

#[test]
fn mount_table_missing_is_reported() {
    let env = Env::new();
    env.mounts("<missing>");
    call("list-mounts", &[]).fails(1, "not supported");
    call("snapshot", &[]).fails(1, "not supported");
    call("usage", &[]).fails(1, "not supported");
    call("unmount", &[("target", "/mnt/x")]).fails(1, "mount table");
}

// --- mount ---------------------------------------------------------------

#[test]
fn mount_runs_mount_with_operands_after_a_separator() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let target = env.path("m/sub");
    let v = call(
        "mount",
        &[
            ("target", &target),
            ("source", "/dev/sdz1"),
            ("type", "ext4"),
            ("options", "noatime,nodev"),
            ("read_only", "yes"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "mounted");
    assert_eq!(v["created_target"], true);
    assert_eq!(v["read_only"], true);
    assert!(Path::new(&target).is_dir());
    assert_eq!(
        env.log().trim(),
        format!("mount -t ext4 -o noatime,nodev,ro -- /dev/sdz1 {target}")
    );
}

#[test]
fn mount_dry_run_plans_without_side_effects() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let target = env.path("new/dir");
    let v = call(
        "mount",
        &[
            ("target", &target),
            ("source", "/dev/sdz1"),
            ("type", "ext4"),
            ("options", "noatime"),
            ("dry_run", "true"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "planned");
    assert_eq!(v["dry_run"], true);
    assert_eq!(
        v["plan"]["create_directory"][0],
        format!("mkdir -p {target}")
    );
    assert_eq!(
        v["plan"]["mount_commands"][0],
        format!("mount -t ext4 -o noatime -- /dev/sdz1 {target}")
    );
    assert!(!Path::new(&target).exists());
    assert_eq!(env.log(), "");
}

#[test]
fn mount_is_idempotent_and_refuses_conflicts() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    env.mounts(TABLE);
    let v = call(
        "mount",
        &[
            ("target", "/mnt/data"),
            ("source", "/dev/sdb1"),
            ("type", "ext4"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "already_mounted");
    assert_eq!(v["details"]["from_existing"], true);
    call(
        "mount",
        &[("target", "/mnt/data/"), ("source", "/dev/sdz9")],
    )
    .fails(1, "Conflicting mount");
    call(
        "mount",
        &[
            ("target", "/mnt/data"),
            ("source", "/dev/sdb1"),
            ("type", "xfs"),
        ],
    )
    .fails(1, "Conflicting mount");
    call(
        "mount",
        &[
            ("target", "/mnt/data"),
            ("source", "/dev/sdb1"),
            ("fail_if_mounted", "true"),
        ],
    )
    .fails(1, "already mounted");
    assert_eq!(env.log(), "", "no mount ran");
}

#[test]
fn mount_remount_needs_an_existing_mount() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    env.mounts(TABLE);
    call("mount", &[("target", "/mnt/none"), ("remount", "true")]).fails(1, "not mounted");
    let v = call(
        "mount",
        &[
            ("target", "/mnt/data"),
            ("remount", "true"),
            ("options", "ro"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "remounted");
    assert_eq!(env.log().trim(), "mount -o remount -o ro -- /mnt/data");
}

#[test]
fn mount_refuses_invalid_arguments_before_doing_anything() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let t = env.path("never");
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "target is required"),
        (&[("target", "")], "target is required"),
        (
            &[("target", "-o"), ("source", "/dev/x")],
            "target cannot start",
        ),
        (
            &[("target", &t), ("source", "--bind")],
            "source cannot start",
        ),
        (&[("target", &t), ("source", "")], "source cannot be empty"),
        (&[("target", &t), ("bind", "true")], "bind mounts require"),
        (
            &[("target", &t), ("remount", "1"), ("fail_if_mounted", "1")],
            "contradictory",
        ),
        (
            &[("target", &t), ("source", "/x"), ("type", "ext4;x")],
            "type must be",
        ),
        (
            &[("target", &t), ("source", "/x"), ("options", "a,,b")],
            "empty entries",
        ),
        (
            &[("target", &t), ("source", "/x"), ("options", "a b")],
            "whitespace",
        ),
        (
            &[("target", &t), ("source", "/x"), ("read_only", "maybe")],
            "read_only",
        ),
        (
            &[("target", &t), ("source", "/x"), ("create_target", "2")],
            "create_target",
        ),
        (
            &[("target", &t), ("source", "/x"), ("dry_run", "ture")],
            "dry_run",
        ),
        (&[("target", &t), ("network", "true")], "require a source"),
        (
            &[("target", &t), ("source", "/srv/a"), ("network", "true")],
            "network source",
        ),
        (
            &[
                ("target", &t),
                ("source", "srv:/a"),
                ("network", "true"),
                ("type", "ext4"),
            ],
            "not a network filesystem",
        ),
        (
            &[
                ("target", &t),
                ("source", "/x"),
                ("bind", "1"),
                ("network", "1"),
            ],
            "contradictory",
        ),
    ];
    for (args, needle) in cases {
        call("mount", args).fails(2, needle);
    }
    assert!(!Path::new(&t).exists());
    assert_eq!(env.log(), "");
}

#[test]
fn mount_network_share_is_accepted() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let t = env.path("nfs");
    let v = call(
        "mount",
        &[
            ("target", &t),
            ("source", "server:/export"),
            ("type", "nfs4"),
            ("network", "true"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "mounted");
}

#[test]
fn mount_failures_leave_no_directory_behind() {
    let env = Env::new();
    env.tool(
        "mount",
        "echo 'mount: /x: must be superuser to use mount.' >&2; exit 32",
    );
    let t = env.path("a/b/c");
    call("mount", &[("target", &t), ("source", "/dev/sdz1")]).fails(1, "Permission denied");
    assert!(!Path::new(&env.path("a")).exists());

    env.tool(
        "mount",
        "echo 'mount: wrong fs type, bad option' >&2; exit 32",
    );
    call("mount", &[("target", &t), ("source", "/dev/sdz1")]).fails(1, "wrong fs type");
    assert!(!Path::new(&env.path("a")).exists());

    // Without the tool.
    std::fs::remove_file(env.dir.path().join("bin/mount")).unwrap();
    call("mount", &[("target", &t), ("source", "/dev/sdz1")]).fails(1, "mount tool");
}

#[test]
fn mount_target_creation_rules() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let missing = env.path("missing");
    call(
        "mount",
        &[
            ("target", &missing),
            ("source", "/x"),
            ("create_target", "false"),
        ],
    )
    .fails(1, "create_target=false");
    call(
        "mount",
        &[
            ("target", &env.path("p/q")),
            ("source", "/x"),
            ("make_parents", "no"),
        ],
    )
    .fails(1, "make_parents=false");
    let file = env.path("file");
    std::fs::write(&file, "x").unwrap();
    call("mount", &[("target", &file), ("source", "/x")]).fails(2, "not a directory");
    // An existing directory is used as is.
    let dir = env.path("exists");
    std::fs::create_dir(&dir).unwrap();
    let v = call("mount", &[("target", &dir), ("source", "/x")]).ok();
    assert_eq!(v["created_target"], false);
}

#[test]
fn mount_relative_target_is_made_absolute() {
    let env = Env::new();
    env.tool("mount", "exit 0");
    let v = call(
        "mount",
        &[("target", "rel/dir"), ("source", "/x"), ("dry_run", "true")],
    )
    .ok();
    let t = v["target"].as_str().unwrap();
    assert!(t.starts_with('/') && t.ends_with("/rel/dir"), "{t}");
}

// --- unmount -------------------------------------------------------------

const NESTED: &str = "/dev/sdb1 /mnt/data ext4 rw 0 0
/dev/sdc1 /mnt/data/child ext4 rw 0 0
/dev/sdc2 /mnt/data/child/deep ext4 rw 0 0
/dev/sdd1 /mnt/datax ext4 rw 0 0
";

#[test]
fn unmount_dry_run_orders_children_deepest_first() {
    let env = Env::new();
    env.tool("umount", "exit 0");
    env.mounts(NESTED);
    let v = call(
        "unmount",
        &[
            ("target", "/mnt/data/"),
            ("detach_children", "true"),
            ("lazy", "true"),
            ("force", "true"),
            ("dry_run", "true"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "planned");
    assert_eq!(
        v["plan"]["order"],
        json!(["/mnt/data/child/deep", "/mnt/data/child", "/mnt/data"])
    );
    assert_eq!(v["plan"]["commands"][2], "umount -l -f -- /mnt/data");
    assert_eq!(env.log(), "");
}

#[test]
fn unmount_runs_umount_and_reports() {
    let env = Env::new();
    env.tool("umount", "exit 0");
    env.mounts(NESTED);
    let v = call("umount", &[("target", "/mnt/datax")]).ok();
    assert_eq!(v["action"], "unmounted");
    assert_eq!(v["verb"], "unmount");
    assert_eq!(v["unmounted"][0]["source"], "/dev/sdd1");
    assert_eq!(env.log().trim(), "umount -- /mnt/datax");
}

#[test]
fn unmount_by_source_and_auto() {
    let env = Env::new();
    env.tool("umount", "exit 0");
    env.mounts(NESTED);
    let v = call("unmount", &[("target", "/dev/sdc1"), ("by", "source")]).ok();
    assert_eq!(v["unmounted"][0]["target"], "/mnt/data/child");
    let v = call("unmount", &[("target", "/dev/sdd1"), ("by", "auto")]).ok();
    assert_eq!(v["unmounted"][0]["target"], "/mnt/datax");
    // by=target does not match a source.
    let v = call("unmount", &[("target", "/dev/sdd1")]).ok();
    assert_eq!(v["action"], "already_unmounted");
    call("unmount", &[("target", "/mnt/data"), ("by", "label")]).fails(2, "by");
}

#[test]
fn unmount_not_mounted() {
    let env = Env::new();
    env.tool("umount", "exit 0");
    env.mounts(NESTED);
    let v = call("unmount", &[("target", "/mnt/none"), ("dry_run", "true")]).ok();
    assert_eq!(v["action"], "already_unmounted");
    assert_eq!(v["dry_run"], true);
    call(
        "unmount",
        &[("target", "/mnt/none"), ("fail_if_not_mounted", "true")],
    )
    .fails(1, "not mounted");
    assert_eq!(env.log(), "");
}

#[test]
fn unmount_failures_are_reported_with_what_was_done() {
    let env = Env::new();
    env.mounts(NESTED);
    // The middle mount is busy: the deepest is unmounted, the parent skipped.
    env.tool(
        "umount",
        "case \"$2\" in /mnt/data/child) echo 'umount: target is busy.' >&2; exit 32;; esac; exit 0",
    );
    let out = call(
        "unmount",
        &[("target", "/mnt/data"), ("detach_children", "true")],
    );
    out.fails(1, "some mounts were not unmounted");
    let v = out.json();
    assert_eq!(v["action"], "partially_unmounted");
    assert_eq!(v["unmounted"][0]["target"], "/mnt/data/child/deep");
    assert_eq!(v["errors"][0]["code"], "fs.unmount_busy");
    assert_eq!(v["skipped"][0]["target"], "/mnt/data");

    env.tool(
        "umount",
        "echo 'umount: /mnt/datax: must be superuser to unmount.' >&2; exit 32",
    );
    let out = call("unmount", &[("target", "/mnt/datax")]);
    out.fails(1, "nothing was unmounted");
    assert_eq!(
        out.json()["errors"][0]["code"],
        "fs.unmount_permission_denied"
    );

    std::fs::remove_file(env.dir.path().join("bin/umount")).unwrap();
    call("unmount", &[("target", "/mnt/datax")]).fails(1, "umount tool");
}

#[test]
fn unmount_refuses_invalid_arguments() {
    let _env = Env::new();
    call("unmount", &[]).fails(2, "target is required");
    call("unmount", &[("target", "-l")]).fails(2, "cannot start");
    call("unmount", &[("target", "/x"), ("lazy", "perhaps")]).fails(2, "lazy");
    call("unmount", &[("target", "/x"), ("dry_run", "nah")]).fails(2, "dry_run");
}

// --- snapshot ------------------------------------------------------------

fn df_tool(env: &Env) {
    env.tool(
        "df",
        "case \"$2\" in -i) echo 'Filesystem Inodes IUsed IFree IUse% Mounted on'; \
         echo 'dev 1000 250 750 25% /';; \
         *) echo 'Filesystem 1-blocks Used Available Capacity Mounted on'; \
         echo 'dev 1073741824 268435456 805306368 25% /';; esac",
    );
}

#[test]
fn snapshot_formats() {
    let env = Env::new();
    env.mounts(TABLE);
    df_tool(&env);
    let v = call("snapshot", &[]).ok();
    assert_eq!(v["format"], "json");
    let lock: Value = serde_json::from_str(v["lockfile"].as_str().unwrap()).unwrap();
    assert_eq!(lock["lockfile_version"], "fs-lock/v1");
    assert_eq!(lock["mounts"].as_array().unwrap().len(), 9);
    assert_eq!(lock["mounts"][0]["usage"]["size_bytes"], 1073741824u64);
    assert_eq!(v["parsed"]["mount_count"], 9);
    assert_eq!(v["parsed"]["filters_applied"], false);

    let v = call("snapshot", &[("format", "yaml"), ("include_types", "ext4")]).ok();
    let lock: serde_yaml::Value = serde_yaml::from_str(v["lockfile"].as_str().unwrap()).unwrap();
    assert_eq!(lock["lockfile_version"].as_str(), Some("fs-lock/v1"));
    assert_eq!(lock["mounts"].as_sequence().unwrap().len(), 5);

    let v = call(
        "snapshot",
        &[
            ("format", "text"),
            ("include_mountpoints", "/mnt/my disk"),
            ("include_inodes", "true"),
        ],
    )
    .ok();
    let text = v["lockfile"].as_str().unwrap();
    assert!(
        text.contains("/dev/loop3 on /mnt/my disk type=ext4"),
        "{text}"
    );
    assert!(text.contains("inodes=1000"));
    assert_eq!(v["parsed"]["mount_count"], 1);
}

#[test]
fn snapshot_filters_and_switches() {
    let env = Env::new();
    env.mounts(TABLE);
    df_tool(&env);
    let v = call(
        "snapshot",
        &[
            ("include_mountpoints", "/mnt/data"),
            ("include_usage", "false"),
            ("include_fs_metadata", "false"),
            ("include_os_metadata", "false"),
        ],
    )
    .ok();
    let lock: Value = serde_json::from_str(v["lockfile"].as_str().unwrap()).unwrap();
    let targets: Vec<&str> = lock["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["target"].as_str().unwrap())
        .collect();
    assert_eq!(targets, ["/mnt/data", "/mnt/data/child"]);
    assert!(lock["mounts"][0].get("usage").is_none());
    assert!(lock.get("host").is_none());
    assert_eq!(env.log(), "", "include_usage=false runs no df");

    call("snapshot", &[("format", "xml")]).fails(2, "format");
    call("snapshot", &[("include_types", "ext4,")]).fails(2, "empty entries");
    call("snapshot", &[("include_usage", "sometimes")]).fails(2, "boolean");
}

// --- list-mounts ---------------------------------------------------------

#[test]
fn list_mounts_classifies_and_filters() {
    let env = Env::new();
    env.mounts(TABLE);
    let v = call("list-mounts", &[]).ok();
    let mounts = v["mounts"].as_array().unwrap();
    let find = |t: &str| mounts.iter().find(|m| m["target"] == t);
    assert!(find("/proc").is_none(), "pseudo hidden by default");
    assert!(find("/run").is_none());
    assert_eq!(find("/mnt/my disk").unwrap()["loop"], true);
    assert_eq!(find("/mnt/vg").unwrap()["loop"], false);
    assert_eq!(find("/mnt/nfs").unwrap()["network"], true);
    assert_eq!(find("/mnt/data/child").unwrap()["read_only"], true);
    assert_eq!(find("/mnt/data").unwrap()["read_only"], false);

    let v = call("list-mounts", &[("include_pseudo", "true")]).ok();
    assert!(
        v["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["target"] == "/proc")
    );

    let v = call(
        "list-mounts",
        &[("include_readwrite", "false"), ("include_network", "false")],
    )
    .ok();
    let only: Vec<&str> = v["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["target"].as_str().unwrap())
        .collect();
    assert_eq!(only, ["/mnt/data/child"]);

    let v = call(
        "list-mounts",
        &[
            ("include_mountpoints", "/mnt/data"),
            ("exclude_types", "xfs"),
            ("include_loop", "false"),
        ],
    )
    .ok();
    assert_eq!(v["mounts"].as_array().unwrap().len(), 1);
    assert_eq!(v["filters"]["include_loop"], false);

    call(
        "list-mounts",
        &[
            ("include_readonly", "false"),
            ("include_readwrite", "false"),
        ],
    )
    .fails(2, "nothing allowed");
    call("list-mounts", &[("paths", "/a,")]).fails(2, "empty entries");
}

#[test]
fn list_mounts_paths_select_the_backing_mount() {
    let env = Env::new();
    env.mounts(TABLE);
    let v = call(
        "list-mounts",
        &[("paths", "/mnt/data/child/x,/mnt/datax/y,/mnt/dat")],
    )
    .ok();
    let targets: Vec<&str> = v["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["target"].as_str().unwrap())
        .collect();
    assert_eq!(targets, ["/", "/mnt/data/child", "/mnt/datax"]);
}

#[test]
fn list_mounts_resolves_labels_and_features() {
    let env = Env::new();
    env.mounts(
        "/dev/sdb1 /mnt/a ext4 rw 0 0\n/dev/sdc1 /mnt/b xfs rw 0 0\n/dev/sdd1 /mnt/c btrfs rw 0 0\n",
    );
    env.tool("blkid", "echo LABEL=DATA; echo UUID=1234");
    env.tool(
        "tune2fs",
        "echo 'Filesystem features:      has_journal extent'; echo 'Block size:               4096'; echo 'Inode size:\t          256'",
    );
    env.tool(
        "xfs_info",
        "echo 'meta-data=/dev/sdc1 isize=512 agcount=4, agsize=1 blks'; \
         echo '         =                       crc=1        finobt=1, sparse=0'; \
         echo 'data     =                       bsize=4096   blocks=76800, imaxpct=25'; \
         echo 'naming   =version 2              bsize=8192   ascii-ci=0, ftype=1'",
    );
    env.tool(
        "btrfs",
        "printf 'sectorsize\\t\\t4096\\nincompat_flags\\t\\t0x341\\n\\t\\t\\t( MIXED_BACKREF |\\n\\t\\t\\t  NO_HOLES )\\n'",
    );
    let v = call(
        "list-mounts",
        &[("resolve_labels", "true"), ("resolve_fs_features", "true")],
    )
    .ok();
    let m = &v["mounts"];
    assert_eq!(m[0]["device"]["label"], "DATA");
    assert_eq!(
        m[0]["fs_features"]["features"],
        json!(["has_journal", "extent"])
    );
    assert_eq!(m[0]["fs_features"]["inode_size"], 256);
    assert_eq!(m[1]["fs_features"]["block_size"], 4096);
    assert_eq!(m[1]["fs_features"]["inode_size"], 512);
    assert_eq!(
        m[1]["fs_features"]["features"],
        json!(["crc", "finobt", "ftype"])
    );
    assert_eq!(
        m[2]["fs_features"]["features"],
        json!(["mixed_backref", "no_holes"])
    );
}

// --- usage ---------------------------------------------------------------

#[test]
fn usage_reports_each_mount() {
    let env = Env::new();
    env.mounts(TABLE);
    df_tool(&env);
    let v = call(
        "usage",
        &[
            ("include_types", "ext4"),
            ("units", "megabytes"),
            ("human_readable", "true"),
        ],
    )
    .ok();
    let fss = v["filesystems"].as_array().unwrap();
    assert_eq!(fss.len(), 5);
    let data = fss.iter().find(|f| f["target"] == "/mnt/data").unwrap();
    assert_eq!(data["size"], 1024);
    assert_eq!(data["used"], 256);
    assert_eq!(data["size_human"], "1.0G");
    assert_eq!(data["read_only"], false, "errors=remount-ro is not ro");
    assert_eq!(data["inodes"]["total"], 1000);
    assert!(env.log().contains("df -P -B1 -- /mnt/my disk"));
}

#[test]
fn usage_modes_and_thresholds() {
    let env = Env::new();
    env.mounts(TABLE);
    df_tool(&env);
    let v = call(
        "usage",
        &[("mode", "aggregate"), ("include_mountpoints", "/mnt/data")],
    )
    .ok();
    assert_eq!(v["aggregate"]["size"], 2u64 * 1073741824);
    let v = call("usage", &[("mode", "paths"), ("paths", &env.path(""))]).ok();
    assert_eq!(v["filesystems"][0]["target"], "/");
    assert_eq!(v["path_to_filesystem"][0]["target"], "/");
    let v = call("usage", &[("threshold_used_percent_min", "30")]).ok();
    assert_eq!(v["filesystems"], json!([]));
    let v = call(
        "usage",
        &[
            ("include_readonly", "false"),
            ("include_mountpoints", "/mnt/data"),
        ],
    )
    .ok();
    assert_eq!(v["filesystems"].as_array().unwrap().len(), 1);
}

#[test]
fn usage_errors() {
    let env = Env::new();
    env.mounts(TABLE);
    df_tool(&env);
    call("usage", &[("paths", "/")]).fails(2, "mode=paths");
    call("usage", &[("mode", "paths")]).fails(2, "paths cannot be empty");
    call("usage", &[("mode", "list")]).fails(2, "mode");
    call("usage", &[("units", "furlongs")]).fails(2, "units");
    call("usage", &[("threshold_used_percent_min", "101")]).fails(2, "between 0 and 100");
    call(
        "usage",
        &[
            ("threshold_used_percent_min", "60"),
            ("threshold_used_percent_max", "50"),
        ],
    )
    .fails(2, "cannot be greater");
    call("usage", &[("timeout_ms", "0")]).fails(2, "timeout_ms");
    call(
        "usage",
        &[("mode", "paths"), ("paths", "/nonexistent/resh-x")],
    )
    .fails(1, "Path not found");
    call("usage", &[("include_types", "zfs")]).fails(1, "No filesystems selected");
}

#[test]
fn usage_skips_unreadable_mounts_with_a_warning() {
    let env = Env::new();
    env.mounts("/dev/sda1 / ext4 rw 0 0\nserver:/x /mnt/nfs nfs rw 0 0\n");
    env.tool(
        "df",
        "case \"$4\" in /mnt/nfs) echo 'df: stale file handle' >&2; exit 1;; esac; \
         echo 'Filesystem 1-blocks Used Available Capacity Mounted on'; echo 'd 100 50 50 50% /'",
    );
    let v = call("usage", &[("include_inodes", "false")]).ok();
    assert_eq!(v["filesystems"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["warnings"][0],
        "skipped /mnt/nfs: usage statistics could not be read"
    );
}

// --- quota and quota_summary -----------------------------------------------

const QUOTA_REPORT: &str = "echo 'Disk quotas for user root (uid 0): '; \
echo '     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace'; \
echo '      /dev/sdb1    1504*   1000    2000 1       3      10      20       0'; \
exit 1";

#[test]
fn quota_reports_one_subject() {
    let env = Env::new();
    env.tool("quota", QUOTA_REPORT);
    // The path must exist, so the fake table mounts /dev/sdb1 on a temp
    // directory.
    env.mounts(&format!(
        "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 {} ext4 rw 0 0\n",
        env.path("")
    ));
    let v = call("quota", &[("path", &env.path("")), ("subject", "0")]).ok();
    assert_eq!(v["filesystem"]["source"], "/dev/sdb1");
    assert_eq!(v["subject_query"]["subject_type"], "user");
    assert_eq!(v["subject_query"]["resolved_uid"], 0);
    let s = &v["subjects"][0];
    assert_eq!(s["space"]["used"], 1504 * 1024);
    assert_eq!(s["space"]["soft_limit"], 1000 * 1024);
    assert_eq!(s["space"]["grace_exceeded"], true, "grace ended at epoch 1");
    assert_eq!(s["inodes"]["used"], 3);
    assert_eq!(s["inodes"]["grace_time_remaining_sec"], Value::Null);
    assert!(env.log().contains("quota -v -w -p -u -- 0"));

    let v = call(
        "quota",
        &[
            ("path", &env.path("")),
            ("subject", "0"),
            ("units", "blocks"),
            ("include_grace", "false"),
            ("include_inodes", "false"),
        ],
    )
    .ok();
    let s = &v["subjects"][0];
    assert_eq!(s["space"]["used"], 1504);
    assert!(s["space"].get("grace_exceeded").is_none());
    assert!(s["inodes"].is_null());
}

#[test]
fn quota_subject_types() {
    let env = Env::new();
    env.mounts(&format!("/dev/sdb1 {} ext4 rw 0 0\n", env.path("")));
    env.tool("quota", QUOTA_REPORT);
    let p = env.path("");
    let v = call(
        "quota",
        &[("path", &p), ("subject", "0"), ("subject_type", "group")],
    )
    .ok();
    assert_eq!(v["subjects"][0]["subject_type"], "group");
    assert!(env.log().contains("quota -v -w -p -g -- 0"));
    let v = call(
        "quota",
        &[("path", &p), ("subject", "42"), ("subject_type", "project")],
    )
    .ok();
    assert_eq!(v["subjects"][0]["gid"], 42);
    assert!(env.log().contains("quota -v -w -p -P -- 42"));
    let v = call(
        "quota",
        &[
            ("path", &p),
            ("subject", "someone"),
            ("resolve_uid_gid", "false"),
        ],
    )
    .ok();
    assert_eq!(v["subjects"][0]["uid"], Value::Null);
    assert!(env.log().contains("quota -v -w -p -u -- someone"));
    call("quota", &[("path", &p), ("subject", "no-such-user-resh")]).fails(1, "subject not found");
    call(
        "quota",
        &[
            ("path", &p),
            ("subject", "no-such-project"),
            ("subject_type", "project"),
        ],
    )
    .fails(1, "subject not found");
    call("quota", &[("path", &p), ("subject_type", "everyone")]).fails(2, "subject_type");
}

#[test]
fn quota_failures() {
    let env = Env::new();
    let p = env.path("");
    env.mounts(&format!("/dev/sdz1 {p} ext4 rw 0 0\n"));
    env.tool("quota", QUOTA_REPORT);
    call("quota", &[("path", &p), ("subject", "0")]).fails(1, "not enabled");
    call("quota", &[("path", "/nonexistent/resh"), ("subject", "0")]).fails(1, "Path not found");
    env.tool("quota", "echo 'quota: cannot open quotafile' >&2; exit 1");
    call("quota", &[("path", &p), ("subject", "0")]).fails(1, "cannot open quotafile");
    std::fs::remove_file(env.dir.path().join("bin/quota")).unwrap();
    call("quota", &[("path", &p), ("subject", "0")]).fails(1, "not supported");
    call(
        "quota",
        &[("path", &p), ("subject", "0"), ("all_subjects", "true")],
    )
    .fails(2, "contradictory");
    call(
        "quota",
        &[("include_space", "false"), ("include_inodes", "false")],
    )
    .fails(2, "include_space");
    call("quota", &[("subject", "-x")]).fails(2, "cannot start");
    call("quota", &[("path", "")]).fails(2, "path cannot be empty");
}

const REPQUOTA: &str = "echo 'User,BlockStatus,FileStatus,BlockUsed,BlockSoftLimit,BlockHardLimit,BlockGrace,FileUsed,FileSoftLimit,FileHardLimit,FileGrace'; \
echo 'root,ok,ok,20,0,0,0,2,0,0,0'; echo '#4242,soft,ok,1504,1000,2000,1,3,10,20,0'";

#[test]
fn quota_all_subjects_uses_repquota() {
    let env = Env::new();
    let p = env.path("");
    env.mounts(&format!("/dev/sdb1 {p} ext4 rw 0 0\n"));
    env.tool("repquota", REPQUOTA);
    let v = call("quota", &[("path", &p), ("all_subjects", "true")]).ok();
    assert_eq!(v["subject_query"]["subject"], "*");
    let subjects = v["subjects"].as_array().unwrap();
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0]["subject"], "#4242");
    assert_eq!(subjects[0]["uid"], 4242);
    assert_eq!(subjects[1]["subject"], "root");
    assert_eq!(subjects[1]["uid"], 0);
    assert!(env.log().contains(&format!("repquota -O csv -p -u -- {p}")));

    env.tool(
        "repquota",
        "echo 'repquota: Mountpoint (or device) /x not found or has no quota enabled.' >&2; exit 1",
    );
    call("quota", &[("path", &p), ("all_subjects", "true")]).fails(1, "not enabled");
}

#[test]
fn quota_summary_single_and_all() {
    let env = Env::new();
    env.mounts(
        "/dev/sdb1 /mnt/a ext4 rw 0 0\n/dev/sdb1 /mnt/a-bind ext4 rw 0 0\n/dev/sdc1 /mnt/b xfs rw 0 0\nproc /proc proc rw 0 0\n",
    );
    env.tool("quota", QUOTA_REPORT);
    let v = call("quota_summary", &[("subject", "0")]).ok();
    assert_eq!(v["filesystems"].as_array().unwrap().len(), 1);
    assert_eq!(v["filesystems_without_quotas"][0]["target"], "/mnt/b");
    assert_eq!(v["filesystems_without_quotas"].as_array().unwrap().len(), 1);
    assert_eq!(v["summary"]["space"]["used"], 1504 * 1024);
    assert_eq!(v["summary"]["space"]["any_grace_exceeded"], true);

    call(
        "quota_summary",
        &[("subject", "0"), ("include_types", "xfs")],
    )
    .fails(1, "none of the 1 selected filesystems");
    call(
        "quota_summary",
        &[("subject", "0"), ("include_mountpoints", "/srv")],
    )
    .fails(1, "no filesystem matched");
    call("quota_summary", &[("include_types", ",")]).fails(2, "empty entries");

    env.tool(
        "repquota",
        &format!(
            "case \"$6\" in /mnt/a) {REPQUOTA};; \
             /mnt/b) echo 'repquota: Mountpoint /mnt/b not found or has no quota enabled.' >&2; exit 1;; esac"
        ),
    );
    let v = call("quota_summary", &[("all_subjects", "true")]).ok();
    assert_eq!(v["all_subjects"], true);
    assert_eq!(v["subjects"].as_array().unwrap().len(), 2);
    assert_eq!(v["subjects"][0]["space"]["used"], 1504 * 1024);
    assert_eq!(v["filesystems_without_quotas"][0]["target"], "/mnt/b");

    env.tool(
        "repquota",
        &format!(
            "case \"$6\" in /mnt/a) {REPQUOTA};; /mnt/b) echo 'repquota: I/O error' >&2; exit 1;; esac"
        ),
    );
    let v = call("quota_summary", &[("all_subjects", "true")]).ok();
    assert_eq!(v["partial_failures"][0]["target"], "/mnt/b");
}

// --- resize --------------------------------------------------------------

/// Fakes for an ext4 filesystem of `blocks` 4 KiB blocks on a device of
/// `device_bytes`.
fn ext4_tools(env: &Env, blocks: u64, free_blocks: u64, device_bytes: u64) {
    env.tool(
        "dumpe2fs",
        &format!(
            "echo 'Block count:              {blocks}'; echo 'Free blocks:  {free_blocks}'; echo 'Block size:               4096'"
        ),
    );
    env.tool("blockdev", &format!("echo {device_bytes}"));
    env.tool("resize2fs", "exit 0");
    env.tool("lsblk", "echo part");
}

#[test]
fn resize_grows_a_mounted_ext4_filesystem() {
    let env = Env::new();
    env.mounts(TABLE);
    ext4_tools(&env, 262144, 1000, 3 << 30);
    let v = call("resize", &[("target", "/mnt/data"), ("size", "2G")]).ok();
    assert_eq!(v["action"], "success");
    assert_eq!(v["previous_size_bytes"], 1u64 << 30);
    assert_eq!(v["requested_size_bytes"], 2u64 << 30);
    assert_eq!(v["actions"][0]["command"], "resize2fs /dev/sdb1 2097152K");
    assert!(env.log().contains("resize2fs /dev/sdb1 2097152K"));

    // delta, size_units and force
    let v = call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("delta", "+512"),
            ("size_units", "megabytes"),
            ("force", "true"),
            ("dry_run", "true"),
        ],
    )
    .ok();
    assert_eq!(v["action"], "plan");
    assert_eq!(
        v["plan"]["steps"][0]["command"],
        "resize2fs -f /dev/sdb1 1572864K"
    );
    assert!(!env.log().contains("1572864K"), "dry run ran resize2fs");
}

#[test]
fn resize_noop_and_limits() {
    let env = Env::new();
    env.mounts(TABLE);
    ext4_tools(&env, 262144, 1000, 3 << 30);
    assert_eq!(
        call("resize", &[("target", "/mnt/data"), ("size", "1G")]).ok()["action"],
        "noop"
    );
    call("resize", &[("target", "/mnt/data"), ("size", "4G")]).fails(1, "exceeds device capacity");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "512M"),
            ("mode", "auto"),
            ("allow_shrink", "true"),
        ],
    )
    .fails(1, "unmounted");
    call("resize", &[("target", "/mnt/data"), ("size", "512M")]).fails(2, "mode=shrink");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "2G"),
            ("mode", "shrink"),
            ("allow_shrink", "1"),
        ],
    )
    .fails(2, "growing needs");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("delta", "-2G"),
            ("mode", "auto"),
            ("allow_shrink", "1"),
        ],
    )
    .fails(2, "resulting size");
    assert!(!env.log().contains("resize2fs"), "nothing was resized");
}

#[test]
fn resize_shrink_checks_free_space() {
    let env = Env::new();
    env.mounts(TABLE);
    // 1 GiB filesystem with 0.75 GiB used.
    ext4_tools(&env, 262144, 65536, 3 << 30);
    env.tool(
        "df",
        "echo 'Filesystem 1-blocks Used Available Capacity Mounted on'; echo 'd 1073741824 805306368 1 75% /'",
    );
    let shrink = |size: &str| {
        call(
            "resize",
            &[
                ("target", "/mnt/data"),
                ("size", size),
                ("mode", "shrink"),
                ("allow_shrink", "true"),
                ("require_unmounted_for_shrink", "false"),
            ],
        )
    };
    shrink("800M").fails(1, "minimum free space");
    let v = shrink("900M").ok();
    assert_eq!(v["summary"]["shrink"], true);
    assert!(env.log().contains("resize2fs /dev/sdb1 921600K"));
}

#[test]
fn resize_xfs_and_btrfs() {
    let env = Env::new();
    env.mounts("/dev/sdc1 /mnt/x xfs rw 0 0\n/dev/sdd1 /mnt/b btrfs rw 0 0\n");
    env.tool(
        "xfs_info",
        "echo 'data     =                       bsize=4096   blocks=262144, imaxpct=25'",
    );
    env.tool("xfs_growfs", "exit 0");
    env.tool("blockdev", "echo 4294967296");
    env.tool(
        "btrfs",
        "printf 'sectorsize\\t4096\\ndev_item.total_bytes\\t1073741824\\ndev_item.devid\\t\\t1\\n'",
    );
    env.tool("lsblk", "echo part");
    let v = call("resize", &[("target", "/mnt/x"), ("size", "1536M")]).ok();
    assert_eq!(v["actions"][0]["command"], "xfs_growfs -D 393216 /mnt/x");
    call(
        "resize",
        &[
            ("target", "/mnt/x"),
            ("size", "512M"),
            ("mode", "auto"),
            ("allow_shrink", "1"),
        ],
    )
    .fails(1, "not supported for filesystem type: xfs");
    call(
        "resize",
        &[("target", "/mnt/x"), ("size", "2G"), ("force", "1")],
    )
    .fails(2, "force applies to ext3/ext4");

    let v = call("resize", &[("target", "/mnt/b"), ("size", "2G")]).ok();
    assert_eq!(
        v["actions"][0]["command"],
        "btrfs filesystem resize 1:2147483648 /mnt/b"
    );
}

#[test]
fn resize_unmounted_and_unsupported_targets() {
    let env = Env::new();
    env.mounts(TABLE);
    let img = env.path("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    env.tool("blkid", "echo xfs");
    call("resize", &[("target", &img), ("size", "1G")]).fails(1, "while mounted");
    env.tool("blkid", "exit 2");
    call("resize", &[("target", &img), ("size", "1G")]).fails(1, "no filesystem found");
    call("resize", &[("target", "/mnt/nfs"), ("size", "1G")]).fails(1, "nfs4");
    call("resize", &[("target", "/nonexistent/x"), ("size", "1G")]).fails(1, "no such device");
    call(
        "resize",
        &[
            ("target", "/nonexistent/x"),
            ("size", "1G"),
            ("by", "mountpoint"),
        ],
    )
    .fails(1, "no filesystem is mounted");
    call("resize", &[("target", &env.path("")), ("size", "1G")]).fails(1, "not a mount point");
}

#[test]
fn resize_with_the_volume_manager() {
    let env = Env::new();
    env.mounts(TABLE);
    ext4_tools(&env, 262144, 1000, 1 << 30);
    env.tool("lvextend", "exit 0");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "2G"),
            ("manage_underlying_volume", "true"),
        ],
    )
    .fails(1, "Volume management");
    env.tool("lsblk", "echo lvm");
    let v = call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "2G"),
            ("manage_underlying_volume", "true"),
        ],
    )
    .ok();
    assert_eq!(
        v["actions"][0]["command"],
        "lvextend -L 2147483648b -- /dev/sdb1"
    );
    assert_eq!(v["actions"][1]["command"], "resize2fs /dev/sdb1 2097152K");

    // A failure after the volume step says what was already done.
    env.tool("resize2fs", "echo 'resize2fs: Device busy' >&2; exit 1");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "2G"),
            ("manage_underlying_volume", "true"),
        ],
    )
    .fails(1, "already done: lvextend");
    call(
        "resize",
        &[
            ("target", "/mnt/data"),
            ("size", "2G"),
            ("volume_resize_only", "true"),
        ],
    )
    .fails(2, "needs manage_underlying_volume");
}

#[test]
fn resize_refuses_invalid_arguments() {
    let _env = Env::new();
    let cases: &[(&[(&str, &str)], i32, &str)] = &[
        (&[("size", "1G")], 2, "target is required"),
        (&[("target", "/x")], 2, "exactly one"),
        (
            &[("target", "/x"), ("size", "1G"), ("delta", "+1G")],
            2,
            "both",
        ),
        (&[("target", "/x"), ("size", "0")], 2, "greater than 0"),
        (&[("target", "/x"), ("size", "-1G")], 2, "greater than 0"),
        (&[("target", "/x"), ("delta", "0")], 2, "must not be 0"),
        (&[("target", "/x"), ("size", "10Q")], 2, "unknown size unit"),
        (
            &[
                ("target", "/x"),
                ("size", "1G"),
                ("min_free_space_percent", "150"),
            ],
            2,
            "between 0",
        ),
        (
            &[("target", "/x"), ("size", "1G"), ("mode", "shrink")],
            2,
            "allow_shrink",
        ),
        (
            &[("target", "/x"), ("size", "1G"), ("mode", "sideways")],
            2,
            "mode",
        ),
        (&[("target", "/x"), ("size", "1G"), ("by", "uuid")], 2, "by"),
        (&[("target", "-x"), ("size", "1G")], 2, "cannot start"),
        (
            &[
                ("target", "/x"),
                ("size", "1G"),
                ("volume_resize_only", "1"),
                ("filesystem_resize_only", "1"),
            ],
            2,
            "mutually exclusive",
        ),
    ];
    for (args, code, needle) in cases {
        call("resize", args).fails(*code, needle);
    }
}

// --- check ---------------------------------------------------------------

fn image(env: &Env) -> String {
    let img = env.path("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();
    img
}

#[test]
fn check_runs_the_right_tool_and_reads_its_status() {
    let env = Env::new();
    let img = image(&env);
    env.tool("blkid", "echo ext4");
    env.tool("fsck.ext4", "echo clean; exit 0");
    let v = call("check", &[("target", &img)]).ok();
    assert_eq!(v["tool"]["command"], format!("fsck.ext4 -n {img}"));
    assert_eq!(v["analysis"]["filesystem_state"], "clean");
    assert_eq!(v["action"], "check");

    env.tool("fsck.ext4", "exit 4");
    let v = call("fsck", &[("target", &img), ("aggressiveness", "normal")]).ok();
    assert_eq!(v["analysis"]["filesystem_state"], "errors_detected");
    assert_eq!(v["tool"]["command"], format!("fsck.ext4 -n -f {img}"));

    env.tool("fsck.ext4", "exit 1");
    let v = call(
        "check",
        &[
            ("target", &img),
            ("mode", "repair"),
            ("allow_repair", "true"),
            ("aggressiveness", "aggressive"),
        ],
    )
    .ok();
    assert_eq!(v["analysis"]["repaired"], true);
    assert_eq!(v["tool"]["command"], format!("fsck.ext4 -y -f {img}"));

    env.tool("fsck.ext4", "echo 'e2fsck: Bad magic number' >&2; exit 8");
    call("check", &[("target", &img)]).fails(1, "exited with status 8");
}

#[test]
fn check_dry_run_and_skip() {
    let env = Env::new();
    let img = image(&env);
    env.tool("blkid", "echo ext4");
    env.tool("fsck.ext4", "exit 0");
    let v = call(
        "check",
        &[
            ("target", &img),
            ("mode", "repair"),
            ("allow_repair", "1"),
            ("dry_run", "1"),
        ],
    )
    .ok();
    assert_eq!(v["plan"]["arguments"], json!(["-p", img]));
    assert_eq!(v["plan"]["requires_unmount_for_repair"], true);
    assert!(!env.log().contains("fsck.ext4"));

    env.mounts(TABLE);
    let v = call(
        "check",
        &[("target", "/mnt/data"), ("skip_if_mounted", "true")],
    )
    .ok();
    assert_eq!(v["summary"]["status"], "skipped");
}

#[test]
fn check_mounted_policies() {
    let env = Env::new();
    env.mounts(TABLE);
    env.tool("fsck.ext4", "exit 0");
    env.tool("xfs_repair", "exit 0");
    call(
        "check",
        &[
            ("target", "/mnt/data"),
            ("mode", "repair"),
            ("allow_repair", "true"),
        ],
    )
    .fails(1, "unmounted");
    call(
        "check",
        &[("target", "/mnt/data"), ("allow_online_check", "false")],
    )
    .fails(1, "offline");
    // mode=auto only checks a filesystem that is mounted read-write.
    let v = call(
        "check",
        &[
            ("target", "/mnt/data"),
            ("mode", "auto"),
            ("allow_repair", "true"),
            ("dry_run", "1"),
        ],
    )
    .ok();
    assert_eq!(v["plan"]["arguments"][0], "-n");
    // A read-only ext mount may be repaired.
    env.mounts("/dev/sdb1 /mnt/ro ext4 ro 0 0\n");
    let v = call(
        "check",
        &[
            ("target", "/mnt/ro"),
            ("mode", "repair"),
            ("allow_repair", "true"),
        ],
    )
    .ok();
    assert_eq!(v["tool"]["command"], "fsck.ext4 -p /dev/sdb1");
    // xfs_repair cannot check a mounted read-write filesystem.
    env.mounts("/dev/sdc1 /mnt/x xfs rw 0 0\n");
    call("check", &[("target", "/mnt/x")]).fails(1, "offline");
}

#[test]
fn check_btrfs_and_vfat() {
    let env = Env::new();
    env.mounts("/dev/sdd1 /mnt/b btrfs rw 0 0\n");
    env.tool("btrfs", "echo 'Error summary:    no errors found'; exit 0");
    let v = call("check", &[("target", "/dev/sdd1"), ("by", "device")]).ok();
    assert_eq!(v["tool"]["command"], "btrfs scrub start -B -r /mnt/b");
    assert_eq!(v["analysis"]["filesystem_state"], "clean");
    env.tool(
        "btrfs",
        "echo 'Error summary: csum=2 Uncorrectable: 2'; exit 3",
    );
    let v = call("check", &[("target", "/mnt/b")]).ok();
    assert_eq!(v["analysis"]["needs_repair"], true);
    env.tool("btrfs", "echo 'ERROR: scrub failed'; exit 1");
    call("check", &[("target", "/mnt/b")]).fails(1, "exited with status 1");
    call(
        "check",
        &[("target", "/mnt/b"), ("btrfs_use_scrub", "false")],
    )
    .fails(1, "offline");
    env.tool("btrfs", "echo 'ERROR: errors found in fs roots'; exit 1");
    let v = call(
        "check",
        &[
            ("target", "/mnt/b"),
            ("btrfs_use_scrub", "false"),
            ("btrfs_allow_offline_check", "true"),
        ],
    )
    .ok();
    assert_eq!(
        v["tool"]["command"],
        "btrfs check --readonly --force /dev/sdd1"
    );
    assert_eq!(v["analysis"]["filesystem_state"], "errors_detected");

    let img = image(&env);
    env.tool("blkid", "echo vfat");
    env.tool("fsck.vfat", "exit 1");
    let v = call("check", &[("target", &img)]).ok();
    assert_eq!(v["analysis"]["filesystem_state"], "errors_detected");
    call(
        "check",
        &[("target", &img), ("aggressiveness", "aggressive")],
    )
    .fails(2, "aggressiveness applies");
    call("check", &[("target", &img), ("force", "true")]).fails(2, "force applies");
}

#[test]
fn check_target_errors() {
    let env = Env::new();
    env.mounts(TABLE);
    let img = image(&env);
    env.tool("blkid", "exit 2");
    call("check", &[("target", &img)]).fails(1, "no filesystem found");
    call("check", &[("target", "/nonexistent/dev")]).fails(1, "device not found");
    call("check", &[("target", &env.path(""))]).fails(1, "neither a mount point");
    call("check", &[("target", "/mnt/none"), ("by", "mountpoint")])
        .fails(1, "no filesystem is mounted");
    call("check", &[("target", "/mnt/nfs")]).fails(1, "nfs4");
    env.tool("blkid", "echo ext4");
    call("check", &[("target", &img)]).fails(1, "Check tool not available: fsck.ext4");
    std::fs::remove_file(env.dir.path().join("bin/blkid")).unwrap();
    call("check", &[("target", &img)]).fails(1, "blkid");
}

#[test]
fn check_refuses_invalid_arguments() {
    let _env = Env::new();
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[], "target"),
        (&[("target", "-n")], "cannot start"),
        (
            &[("target", "/x"), ("mode", "repair")],
            "allow_repair=false",
        ),
        (&[("target", "/x"), ("mode", "fix")], "mode"),
        (
            &[("target", "/x"), ("aggressiveness", "max")],
            "aggressiveness",
        ),
        (
            &[("target", "/x"), ("filesystem_type", "zfs")],
            "not supported",
        ),
        (&[("target", "/x"), ("timeout_ms", "0")], "timeout_ms"),
        (&[("target", "/x"), ("allow_repair", "sure")], "boolean"),
    ];
    for (args, needle) in cases {
        call("check", args).fails(2, needle);
    }
}

#[test]
fn help_verb_lists_the_verbs() {
    let out = call("help", &[]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("list-mounts"));
}
