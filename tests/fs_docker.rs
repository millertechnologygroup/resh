//! End-to-end tests of the fs verbs that need root and block devices. They
//! run inside a throwaway privileged Docker container, on image files and
//! loop devices created there; nothing is mounted, resized or checked on the
//! host. Run with `cargo test --features e2e-docker --test fs_docker`.
//!
//! Each scenario is one container run of a bash script. The script's `r`
//! function runs `resh` and stores stdout, stderr and the exit status in a
//! host temp directory, which the test then reads.
#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const IMAGE: &str = "resh-fs-e2e:1";
const DOCKERFILE: &str = "FROM ubuntu:24.04\n\
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
--no-install-recommends xfsprogs btrfs-progs quota dosfstools e2fsprogs \
util-linux && rm -rf /var/lib/apt/lists/*\n";

/// Helpers available to every scenario script.
const PRELUDE: &str = r#"
set -u
r() { local n=$1; shift; resh "$@" >/out/$n.out 2>/out/$n.err; echo $? >/out/$n.rc; }
ru() { local u=$1 n=$2; shift 2
  su "$u" -s /bin/bash -c "$(printf '%q ' resh "$@") >/out/$n.out 2>/out/$n.err; echo \$? >/out/$n.rc"; }
save() { local n=$1; shift; "$@" >/out/$n.out 2>&1; echo $? >/out/$n.rc; }
# Loop device nodes for the free indexes; the kernel's loop devices are
# shared with the host, so only free ones are ever attached.
for i in $(seq 0 63); do [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i; done
LOOPS=""
attach() { local d; d=$(losetup -f --show "$1"); LOOPS="$LOOPS $d"; echo "$d"; }
finish() { umount -R /mnt/* 2>/dev/null; umount /home 2>/dev/null
  for d in $LOOPS; do losetup -d "$d" 2>/dev/null; done; chmod -R a+rwX /out; }
trap finish EXIT
mkdir -p /srv /mnt
chmod 777 /out
"#;

fn image() -> &'static str {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", IMAGE, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("docker build");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(DOCKERFILE.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "docker build failed");
    });
    IMAGE
}

struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn read(&self, name: &str, ext: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(format!("{name}.{ext}")))
            .unwrap_or_else(|_| panic!("no {ext} for step {name}"))
    }
    fn rc(&self, name: &str) -> i32 {
        self.read(name, "rc").trim().parse().unwrap()
    }
    fn out(&self, name: &str) -> String {
        self.read(name, "out")
    }
    fn err(&self, name: &str) -> String {
        self.read(name, "err")
    }
    fn json(&self, name: &str) -> Value {
        let out = self.out(name);
        serde_json::from_str(&out).unwrap_or_else(|e| {
            panic!(
                "step {name}: stdout is not JSON ({e}): {out}\nstderr: {}",
                self.err(name)
            )
        })
    }
    /// Asserts the exit status, printing the step's output on failure.
    fn expect(&self, name: &str, code: i32) {
        let rc = self.rc(name);
        assert_eq!(
            rc,
            code,
            "step {name}: stdout {}\nstderr {}",
            self.out(name),
            self.err(name)
        );
    }
    fn ok(&self, name: &str) -> Value {
        self.expect(name, 0);
        self.json(name)
    }
}

fn scenario(script: &str) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_resh");
    let output = Command::new("docker")
        .args(["run", "--rm", "--privileged"])
        .arg("-v")
        .arg(format!("{bin}:/usr/local/bin/resh:ro"))
        .arg("-v")
        .arg(format!("{}:/out", dir.path().display()))
        .arg(image())
        .args(["bash", "-c"])
        .arg(format!("{PRELUDE}\n{script}\nexit 0"))
        .output()
        .expect("docker run");
    assert!(
        output.status.success(),
        "scenario script failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Path::new(dir.path()).exists());
    Run { dir }
}

#[test]
fn mount_and_unmount() {
    let r = scenario(
        r#"
truncate -s 64M /srv/disk.img && mkfs.ext4 -q /srv/disk.img
truncate -s 64M /srv/other.img && mkfs.ext4 -q /srv/other.img
r mount_example --json-pretty fs://local.mount target=/mnt/data source=/srv/disk.img
save table1 grep ' /mnt/data ' /proc/mounts
r mount_again fs://local.mount target=/mnt/data source=/srv/disk.img
r mount_fail_if fs://local.mount target=/mnt/data source=/srv/disk.img fail_if_mounted=true
r mount_conflict fs://local.mount target=/mnt/data source=/srv/other.img
r mount_wrongtype fs://local.mount target=/mnt/data source=/srv/disk.img type=xfs
r remount_ro fs://local.mount target=/mnt/data remount=true options=ro
save table2 grep ' /mnt/data ' /proc/mounts
r remount_missing fs://local.mount target=/mnt/none remount=true
mkdir -p /srv/src && echo hi > /srv/src/f
r bind fs://local.mount target=/mnt/bind source=/srv/src bind=true read_only=true
save bind_content cat /mnt/bind/f
r bind_again fs://local.mount target=/mnt/bind source=/srv/src bind=true read_only=true
r dry fs://local.mount target=/mnt/new/sub source=/srv/other.img dry_run=true
save dry_exists test -e /mnt/new
r nocreate fs://local.mount target=/mnt/nocreate source=/srv/other.img create_target=false
r noparents fs://local.mount target=/mnt/np/a source=/srv/other.img make_parents=false
r badsrc fs://local.mount target=/mnt/bad/deep source=/srv/nonexistent.img
save badsrc_exists test -e /mnt/bad
r badtype fs://local.mount target=/mnt/bt source=/srv/other.img type=xfs
r net_invalid fs://local.mount target=/mnt/n source=/srv/other.img network=true
r net_dry fs://local.mount target=/mnt/nfs source=server:/export type=nfs network=true dry_run=true
r net_dry_given fs://local.mount target=/mnt/nfs source=server:/export type=nfs network=true options=_netdev,ro dry_run=true
r unknown_arg fs://local.mount target=/mnt/x source=/srv/other.img read_onyl=true
r bad_bool fs://local.mount target=/mnt/x source=/srv/other.img read_only=maybe
save badbool_exists test -e /mnt/x
useradd -m bob
ru bob perm fs://local.mount target=/tmp/bobmnt source=tmpfs type=tmpfs
mkdir -p /mnt/parent && mount -t tmpfs t1 /mnt/parent
mkdir -p /mnt/parent/c/d && mount -t tmpfs t2 /mnt/parent/c && mkdir -p /mnt/parent/c/d
mount -t tmpfs t3 /mnt/parent/c/d
r children_dry fs://local.unmount target=/mnt/parent detach_children=true dry_run=true
r children fs://local.unmount target=/mnt/parent detach_children=true
save children_left grep -c ' /mnt/parent' /proc/mounts
mkdir -p /mnt/busy && mount -t tmpfs t4 /mnt/busy
(cd /mnt/busy && exec sleep 60) & BUSY=$!
sleep 0.5
r busy fs://local.unmount target=/mnt/busy
kill $BUSY; wait $BUSY 2>/dev/null
r unmount_example --json-pretty fs://local.unmount target=/mnt/data
r unmount_again fs://local.unmount target=/mnt/data
r unmount_fail_not fs://local.unmount target=/mnt/data fail_if_not_mounted=true
r mount_other fs://local.mount target=/mnt/o source=/srv/other.img
r unmount_by_source fs://local.unmount target=/srv/other.img by=source
save other_left grep -c ' /mnt/o ' /proc/mounts
r umount_alias fs://local.umount target=/mnt/bind/ lazy=true
r bad_by fs://local.unmount target=/mnt/bind by=label
"#,
    );

    let v = r.ok("mount_example");
    assert_eq!(v["action"], "mounted");
    assert_eq!(v["source"], "/srv/disk.img");
    assert_eq!(v["created_target"], true);
    assert!(r.out("table1").contains("ext4"));

    assert_eq!(r.ok("mount_again")["action"], "already_mounted");
    r.expect("mount_fail_if", 1);
    assert!(r.err("mount_fail_if").contains("already mounted"));
    assert!(
        r.err("mount_fail_if")
            .starts_with("Error: [fs.already_mounted] "),
        "{}",
        r.err("mount_fail_if")
    );
    r.expect("mount_conflict", 1);
    assert!(r.err("mount_conflict").contains("Conflicting mount"));
    assert!(
        r.err("mount_conflict")
            .starts_with("Error: [fs.conflicting_mount] ")
    );
    r.expect("mount_wrongtype", 1);

    assert_eq!(r.ok("remount_ro")["action"], "remounted");
    assert!(r.out("table2").contains(" ro,"));
    r.expect("remount_missing", 1);
    assert!(r.err("remount_missing").contains("not mounted"));

    assert_eq!(r.ok("bind")["action"], "mounted");
    assert_eq!(r.out("bind_content").trim(), "hi");
    assert_eq!(r.ok("bind_again")["action"], "already_mounted");

    let dry = r.ok("dry");
    assert_eq!(dry["action"], "planned");
    assert_eq!(dry["plan"]["create_directory"][0], "mkdir -p /mnt/new/sub");
    assert_eq!(
        dry["plan"]["mount_commands"][0],
        "mount -- /srv/other.img /mnt/new/sub"
    );
    assert_ne!(r.rc("dry_exists"), 0, "dry run created the target");

    r.expect("nocreate", 1);
    assert!(r.err("nocreate").contains("create_target=false"));
    r.expect("noparents", 1);
    r.expect("badsrc", 1);
    assert_ne!(r.rc("badsrc_exists"), 0, "failed mount left its directory");
    r.expect("badtype", 1);
    r.expect("net_invalid", 2);
    assert!(
        r.err("net_invalid")
            .starts_with("Error: [fs.invalid_mount_config] ")
    );
    // network=true adds _netdev, once.
    assert_eq!(
        r.ok("net_dry")["plan"]["mount_commands"][0],
        "mount -t nfs -o _netdev -- server:/export /mnt/nfs"
    );
    assert_eq!(
        r.ok("net_dry_given")["plan"]["mount_commands"][0],
        "mount -t nfs -o _netdev,ro -- server:/export /mnt/nfs"
    );
    r.expect("unknown_arg", 2);
    assert!(r.err("unknown_arg").contains("did you mean \"read_only\""));
    r.expect("bad_bool", 2);
    assert_ne!(r.rc("badbool_exists"), 0);
    r.expect("perm", 1);
    assert!(
        r.err("perm").contains("Permission denied"),
        "{}",
        r.err("perm")
    );

    let plan = r.ok("children_dry");
    assert_eq!(
        plan["plan"]["order"],
        serde_json::json!(["/mnt/parent/c/d", "/mnt/parent/c", "/mnt/parent"])
    );
    let done = r.ok("children");
    assert_eq!(done["unmounted"].as_array().unwrap().len(), 3);
    assert_eq!(r.out("children_left").trim(), "0");

    r.expect("busy", 1);
    let busy = r.json("busy");
    assert_eq!(busy["action"], "failed");
    assert_eq!(busy["errors"][0]["error"]["code"], "fs.unmount_busy");
    assert_eq!(busy["error"]["code"], "fs.unmount_busy");
    assert!(r.err("busy").starts_with("Error: [fs.unmount_busy] "));

    assert_eq!(r.ok("unmount_example")["action"], "unmounted");
    assert_eq!(r.ok("unmount_again")["action"], "already_unmounted");
    r.expect("unmount_fail_not", 1);
    r.ok("mount_other");
    assert_eq!(r.ok("unmount_by_source")["action"], "unmounted");
    assert_eq!(r.out("other_left").trim(), "0");
    assert_eq!(r.ok("umount_alias")["action"], "unmounted");
    r.expect("bad_by", 2);
}

#[test]
fn resize_ext4_xfs_btrfs() {
    let r = scenario(
        r#"
truncate -s 1G /srv/disk.img && mkfs.ext4 -q /srv/disk.img && truncate -s 3G /srv/disk.img
mkdir -p /mnt/data && mount /srv/disk.img /mnt/data
r resize_example --json-pretty fs://local.resize target=/mnt/data size=2G
save size_after dumpe2fs -h /srv/disk.img
r noop fs://local.resize target=/mnt/data size=2G
r exceeds fs://local.resize target=/mnt/data size=4G
r delta_dry fs://local.resize target=/mnt/data delta=+512M dry_run=true
save size_dry dumpe2fs -h /srv/disk.img
r delta fs://local.resize target=/mnt/data delta=+512M
r shrink_mounted fs://local.resize target=/mnt/data size=1G mode=auto allow_shrink=true
r shrink_grow_mode fs://local.resize target=/mnt/data size=1G
r shrink_not_allowed fs://local.resize target=/mnt/data size=1G mode=shrink
r grow_shrink_mode fs://local.resize target=/mnt/data size=3G mode=shrink allow_shrink=true
r lvm fs://local.resize target=/mnt/data size=3G manage_underlying_volume=true
r zero fs://local.resize target=/mnt/data size=0
r negative fs://local.resize target=/mnt/data delta=-10T mode=auto allow_shrink=true
r badsize fs://local.resize target=/mnt/data size=12Q
r both fs://local.resize target=/mnt/data size=1G delta=+1G
dd if=/dev/urandom of=/mnt/data/fill bs=1M count=600 status=none
umount /mnt/data
r minfree fs://local.resize target=/srv/disk.img size=700M mode=shrink allow_shrink=true force=true
r shrink_offline fs://local.resize target=/srv/disk.img delta=-1G mode=shrink allow_shrink=true force=true
save size_shrunk dumpe2fs -h /srv/disk.img
truncate -s 1G /srv/xfs.img && mkfs.xfs -q /srv/xfs.img && truncate -s 2G /srv/xfs.img
mkdir -p /mnt/x && mount /srv/xfs.img /mnt/x
r xfs_grow fs://local.resize target=/mnt/x size=1536M
save xfs_after xfs_info /mnt/x
r xfs_shrink fs://local.resize target=/mnt/x size=1G mode=auto allow_shrink=true
r xfs_force fs://local.resize target=/mnt/x size=1600M force=true
umount /mnt/x
r xfs_unmounted fs://local.resize target=/srv/xfs.img size=1600M
truncate -s 1G /srv/b.img && mkfs.btrfs -q /srv/b.img && truncate -s 2G /srv/b.img
mkdir -p /mnt/b && mount /srv/b.img /mnt/b
r btrfs_grow fs://local.resize target=/mnt/b size=1536M
r btrfs_shrink fs://local.resize target=/mnt/b size=1G mode=auto allow_shrink=true
save btrfs_after btrfs inspect-internal dump-super $(awk '$2=="/mnt/b"{print $1}' /proc/mounts)
mkdir -p /mnt/t && mount -t tmpfs t /mnt/t
r tmpfs fs://local.resize target=/mnt/t size=1G
r notfound fs://local.resize target=/nonexistent size=1G
r notmounted_dir fs://local.resize target=/srv size=1G
"#,
    );

    let v = r.ok("resize_example");
    assert_eq!(v["action"], "success");
    assert_eq!(v["requested_size_bytes"], 2u64 << 30);
    assert_eq!(v["final_size_bytes"], 2u64 << 30);
    assert_eq!(v["previous_size_bytes"], 1u64 << 30);
    let cmd = v["actions"][0]["command"].as_str().unwrap();
    assert!(
        cmd.starts_with("resize2fs /dev/loop") && cmd.ends_with(" 2097152K"),
        "{cmd}"
    );
    let count = |name: &str| -> u64 {
        r.out(name)
            .lines()
            .find(|l| l.starts_with("Block count:"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap()
            * 4096
    };
    assert_eq!(count("size_after"), 2 << 30);

    assert_eq!(r.ok("noop")["action"], "noop");
    r.expect("exceeds", 1);
    assert!(r.err("exceeds").contains("exceeds device capacity"));
    let dry = r.ok("delta_dry");
    assert_eq!(dry["action"], "plan");
    assert_eq!(dry["requested_size_bytes"], (2u64 << 30) + (512 << 20));
    assert_eq!(count("size_dry"), 2 << 30, "dry run resized");
    assert_eq!(
        r.ok("delta")["final_size_bytes"],
        (2u64 << 30) + (512 << 20)
    );

    r.expect("shrink_mounted", 1);
    assert!(r.err("shrink_mounted").contains("unmounted"));
    r.expect("shrink_grow_mode", 2);
    r.expect("shrink_not_allowed", 2);
    r.expect("grow_shrink_mode", 2);
    r.expect("lvm", 1);
    assert!(r.err("lvm").contains("Volume management"));
    r.expect("zero", 2);
    r.expect("negative", 2);
    r.expect("badsize", 2);
    r.expect("both", 2);

    r.expect("minfree", 1);
    assert!(r.err("minfree").contains("minimum free space"));
    let s = r.ok("shrink_offline");
    assert_eq!(s["summary"]["shrink"], true);
    assert_eq!(count("size_shrunk"), (1u64 << 30) + (512 << 20));

    let x = r.ok("xfs_grow");
    assert!(
        x["actions"][0]["command"]
            .as_str()
            .unwrap()
            .starts_with("xfs_growfs -D 393216 ")
    );
    assert_eq!(x["final_size_bytes"], 1536u64 << 20);
    assert!(r.out("xfs_after").contains("blocks=393216"));
    r.expect("xfs_shrink", 1);
    assert!(r.err("xfs_shrink").contains("xfs"));
    r.expect("xfs_force", 2);
    r.expect("xfs_unmounted", 1);
    assert!(r.err("xfs_unmounted").contains("while mounted"));

    assert_eq!(r.ok("btrfs_grow")["final_size_bytes"], 1536u64 << 20);
    assert_eq!(r.ok("btrfs_shrink")["final_size_bytes"], 1u64 << 30);
    assert!(r.out("btrfs_after").lines().any(
        |l| l.split_whitespace().collect::<Vec<_>>() == ["dev_item.total_bytes", "1073741824"]
    ));

    r.expect("tmpfs", 1);
    assert!(r.err("tmpfs").contains("tmpfs"));
    r.expect("notfound", 1);
    r.expect("notmounted_dir", 1);
}

#[test]
fn check_and_repair() {
    let r = scenario(
        r#"
truncate -s 64M /srv/disk.img && mkfs.ext4 -q /srv/disk.img
r check_example --json-pretty fs://local.check target=/srv/disk.img
r fsck_alias fs://local.fsck target=/srv/disk.img aggressiveness=normal
debugfs -w -R "write /etc/hostname f" /srv/disk.img >/dev/null 2>&1
debugfs -w -R "sif /f links_count 7" /srv/disk.img >/dev/null 2>&1
r corrupt fs://local.check target=/srv/disk.img force=true
r repair_not_allowed fs://local.check target=/srv/disk.img mode=repair
r repair_dry fs://local.check target=/srv/disk.img mode=repair allow_repair=true aggressiveness=aggressive dry_run=true
r repair fs://local.check target=/srv/disk.img mode=repair allow_repair=true aggressiveness=aggressive
r after fs://local.check target=/srv/disk.img force=true
mkdir -p /mnt/data && mount /srv/disk.img /mnt/data
r mounted_repair fs://local.check target=/mnt/data mode=repair allow_repair=true
r offline fs://local.check target=/mnt/data allow_online_check=false
r skip fs://local.check target=/mnt/data skip_if_mounted=true
r mounted fs://local.check target=/mnt/data
r auto_mounted fs://local.check target=/mnt/data mode=auto allow_repair=true dry_run=true
umount /mnt/data
truncate -s 300M /srv/xfs.img && mkfs.xfs -q /srv/xfs.img
r xfs fs://local.check target=/srv/xfs.img
r xfs_aggr fs://local.check target=/srv/xfs.img aggressiveness=normal
mkdir -p /mnt/x && mount /srv/xfs.img /mnt/x
r xfs_mounted fs://local.check target=/mnt/x
umount /mnt/x
truncate -s 300M /srv/b.img && mkfs.btrfs -q /srv/b.img
r btrfs fs://local.check target=/srv/b.img
mkdir -p /mnt/b && mount /srv/b.img /mnt/b
r scrub fs://local.check target=/mnt/b
r btrfs_mounted_check fs://local.check target=/mnt/b btrfs_use_scrub=false
r btrfs_mounted_offline fs://local.check target=/mnt/b btrfs_use_scrub=false btrfs_allow_offline_check=true
umount /mnt/b
truncate -s 64M /srv/fat.img && mkfs.vfat /srv/fat.img >/dev/null
r vfat fs://local.check target=/srv/fat.img
truncate -s 8M /srv/blank.img
r nofs fs://local.check target=/srv/blank.img
r dir fs://local.check target=/srv
r missing fs://local.check target=/dev/nonexistent
r badtype fs://local.check target=/srv/disk.img filesystem_type=zfs
r maxpass fs://local.check target=/srv/disk.img max_pass=2
"#,
    );

    let v = r.ok("check_example");
    assert_eq!(v["analysis"]["filesystem_state"], "clean");
    assert_eq!(v["tool"]["command"], "fsck.ext4 -n /srv/disk.img");
    assert_eq!(v["verb"], "check");
    let a = r.ok("fsck_alias");
    assert_eq!(a["tool"]["command"], "fsck.ext4 -n -f /srv/disk.img");

    let c = r.ok("corrupt");
    assert_eq!(c["analysis"]["filesystem_state"], "errors_detected");
    assert_eq!(c["analysis"]["needs_repair"], true);
    r.expect("repair_not_allowed", 2);
    let plan = r.ok("repair_dry");
    assert_eq!(
        plan["plan"]["arguments"],
        serde_json::json!(["-y", "-f", "/srv/disk.img"])
    );
    let fixed = r.ok("repair");
    assert_eq!(fixed["analysis"]["repaired"], true, "{fixed}");
    assert_eq!(r.ok("after")["analysis"]["filesystem_state"], "clean");

    r.expect("mounted_repair", 1);
    assert!(r.err("mounted_repair").contains("unmounted"));
    r.expect("offline", 1);
    assert_eq!(r.ok("skip")["summary"]["status"], "skipped");
    assert_eq!(r.ok("mounted")["filesystem"]["mounted"], true);
    // mode=auto does not repair a filesystem mounted read-write.
    assert_eq!(r.ok("auto_mounted")["plan"]["arguments"][0], "-n");

    assert_eq!(r.ok("xfs")["tool"]["command"], "xfs_repair -n /srv/xfs.img");
    r.expect("xfs_aggr", 2);
    r.expect("xfs_mounted", 1);
    assert!(r.err("xfs_mounted").contains("offline"));

    assert_eq!(r.ok("btrfs")["analysis"]["filesystem_state"], "clean");
    let s = r.ok("scrub");
    assert_eq!(s["tool"]["command"], "btrfs scrub start -B -r /mnt/b");
    assert_eq!(s["analysis"]["filesystem_state"], "clean");
    r.expect("btrfs_mounted_check", 1);
    assert_eq!(
        r.ok("btrfs_mounted_offline")["analysis"]["filesystem_state"],
        "clean"
    );

    assert_eq!(r.ok("vfat")["tool"]["command"], "fsck.vfat -n /srv/fat.img");
    r.expect("nofs", 1);
    assert!(r.err("nofs").contains("no filesystem found"));
    r.expect("dir", 1);
    r.expect("missing", 1);
    r.expect("badtype", 2);
    r.expect("maxpass", 2);
}

#[test]
fn quota_and_quota_summary() {
    let r = scenario(
        r#"
useradd -M alice
truncate -s 300M /srv/q.img && mkfs.ext4 -q -O quota -E quotatype=usrquota:grpquota /srv/q.img
mount -o usrquota,grpquota /srv/q.img /home
setquota -u alice 1000 20000 100 200 /home
mkdir /home/alice && chown alice:alice /home/alice
su alice -s /bin/bash -c 'dd if=/dev/zero of=/home/alice/f bs=1K count=1500 status=none'
r quota_example --json-pretty fs://local.quota path=/home subject=alice
r summary_example --json-pretty fs://local.quota_summary subject=alice
r all fs://local.quota path=/home all_subjects=true
r summary_all fs://local.quota_summary all_subjects=true include_inodes=false
r group fs://local.quota path=/home/alice subject=alice subject_type=group
r blocks fs://local.quota path=/home subject=alice units=blocks include_grace=false
r by_uid fs://local.quota path=/home subject=$(id -u alice) subject_type=user
r nosubj fs://local.quota path=/home subject=nosuchuser
r notenabled fs://local.quota path=/ subject=alice
r nopath fs://local.quota path=/nonexistent
r summary_filtered fs://local.quota_summary subject=alice include_mountpoints=/nonexistent
r summary_none fs://local.quota_summary subject=alice exclude_mountpoints=/home
r conflict fs://local.quota path=/home subject=alice all_subjects=true
r neither fs://local.quota path=/home include_space=false include_inodes=false
ru alice self fs://local.quota path=/home
"#,
    );

    let v = r.ok("quota_example");
    let s = &v["subjects"][0];
    assert_eq!(s["subject"], "alice");
    assert_eq!(s["space"]["used"], 1504 * 1024);
    assert_eq!(s["space"]["soft_limit"], 1000 * 1024);
    assert_eq!(s["space"]["hard_limit"], 20000 * 1024);
    assert!(s["space"]["grace_time_remaining_sec"].as_u64().unwrap() > 0);
    assert_eq!(s["inodes"]["hard_limit"], 200);
    assert_eq!(v["filesystem"]["target"], "/home");

    let sum = r.ok("summary_example");
    assert_eq!(sum["summary"]["space"]["used"], 1504 * 1024);
    assert_eq!(sum["filesystems"].as_array().unwrap().len(), 1);

    let all = r.ok("all");
    let names: Vec<&str> = all["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["subject"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"alice") && names.contains(&"root"),
        "{names:?}"
    );
    let sa = r.ok("summary_all");
    assert!(sa["subjects"][0]["inodes"].is_null());
    assert_eq!(sa["all_subjects"], true);

    assert_eq!(r.ok("group")["subjects"][0]["subject_type"], "group");
    let b = r.ok("blocks");
    assert_eq!(b["subjects"][0]["space"]["used"], 1504);
    assert!(b["subjects"][0]["space"].get("grace_exceeded").is_none());
    assert_eq!(r.ok("by_uid")["subjects"][0]["space"]["used"], 1504 * 1024);

    r.expect("nosubj", 1);
    assert!(r.err("nosubj").contains("not found"));
    r.expect("notenabled", 1);
    assert!(r.err("notenabled").contains("not enabled"));
    r.expect("nopath", 1);
    r.expect("summary_filtered", 1);
    r.expect("summary_none", 1);
    r.expect("conflict", 2);
    r.expect("neither", 2);
    assert_eq!(r.ok("self")["subjects"][0]["subject"], "alice");
}

#[test]
fn list_mounts_usage_and_snapshot_see_container_mounts() {
    let r = scenario(
        r#"
truncate -s 64M /srv/disk.img && mkfs.ext4 -q -L DATA /srv/disk.img
mkdir -p "/mnt/my disk" && mount /srv/disk.img "/mnt/my disk"
truncate -s 300M /srv/b.img && mkfs.btrfs -q /srv/b.img
truncate -s 300M /srv/x.img && mkfs.xfs -q /srv/x.img
mkdir -p /mnt/b /mnt/x && mount /srv/b.img /mnt/b && mount /srv/x.img /mnt/x
r lm fs://local.list-mounts include_types=ext4,btrfs,xfs resolve_labels=true resolve_fs_features=true
r lm_paths fs://local.list-mounts "paths=/mnt/my disk/x,/mnt/b"
r usage fs://local.usage mode=paths "paths=/mnt/my disk" human_readable=true
r usage_agg fs://local.usage mode=aggregate include_types=ext4,xfs
r usage_none fs://local.usage include_types=nosuchfs
r snap_yaml fs://local.snapshot format=yaml include_types=ext4
r snap_text fs://local.snapshot format=text include_types=ext4 include_inodes=true
"#,
    );

    let lm = r.ok("lm");
    let mounts = lm["mounts"].as_array().unwrap();
    let ext = mounts.iter().find(|m| m["fstype"] == "ext4").unwrap();
    assert_eq!(ext["target"], "/mnt/my disk");
    assert_eq!(ext["loop"], true);
    assert_eq!(ext["device"]["label"], "DATA");
    assert_eq!(ext["fs_features"]["block_size"], 4096);
    let b = mounts.iter().find(|m| m["fstype"] == "btrfs").unwrap();
    assert_eq!(b["fs_features"]["block_size"], 4096);
    assert!(
        b["fs_features"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "skinny_metadata")
    );
    let x = mounts.iter().find(|m| m["fstype"] == "xfs").unwrap();
    assert_eq!(x["fs_features"]["block_size"], 4096);

    let lp = r.ok("lm_paths");
    assert_eq!(lp["mounts"].as_array().unwrap().len(), 2);

    let u = r.ok("usage");
    assert_eq!(u["filesystems"][0]["target"], "/mnt/my disk");
    assert!(u["filesystems"][0]["size_human"].is_string());
    assert_eq!(u["path_to_filesystem"][0]["target"], "/mnt/my disk");
    let agg = r.ok("usage_agg");
    assert_eq!(agg["filesystems"].as_array().unwrap().len(), 2);
    assert!(agg["aggregate"]["size"].as_u64().unwrap() > 0);
    r.expect("usage_none", 1);

    let y = r.ok("snap_yaml");
    let lock = y["lockfile"].as_str().unwrap();
    assert!(lock.starts_with("lockfile_version: fs-lock/v1"), "{lock}");
    assert!(lock.contains("target: /mnt/my disk"));
    let t = r.ok("snap_text");
    assert!(
        t["lockfile"]
            .as_str()
            .unwrap()
            .contains("on /mnt/my disk type=ext4")
    );
}

/// The example line and the top-level keys of the sample output from
/// `resh fs <verb> --help`.
fn help_example(verb: &str) -> (String, Vec<String>) {
    let out = Command::new(env!("CARGO_BIN_EXE_resh"))
        .args(["fs", verb, "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let example = text
        .split("Example:\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_string();
    let sample: String = text
        .split("Example Output:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .map(|l| format!("{}\n", l.strip_prefix("  ").unwrap_or(l)))
        .collect();
    let v: Value = serde_json::from_str(&sample).unwrap();
    let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    (example, keys)
}

/// Every example in `resh fs <verb> --help` for the verbs that need root
/// runs verbatim and prints an object with the keys of the help sample.
/// (list-mounts, usage and snapshot examples run on the host in
/// tests/fs_verbs.rs.)
#[test]
fn help_examples_run_as_documented() {
    let verbs = [
        "check",
        "fsck",
        "mount",
        "resize",
        "unmount",
        "umount",
        "quota",
        "quota_summary",
    ];
    let examples: Vec<(&str, String, Vec<String>)> = verbs
        .iter()
        .map(|v| {
            let (ex, keys) = help_example(v);
            (*v, ex, keys)
        })
        .collect();
    let step = |verb: &str| -> String {
        let ex = &examples.iter().find(|e| e.0 == verb).unwrap().1;
        format!("r {verb} {}", ex.strip_prefix("resh ").unwrap())
    };
    let script = format!(
        r#"
truncate -s 1G /srv/disk.img && mkfs.ext4 -q /srv/disk.img
{check}
{fsck}
truncate -s 3G /srv/disk.img
{mount}
{resize}
{unmount}
mount /srv/disk.img /mnt/data
{umount}
useradd -M alice
truncate -s 300M /srv/q.img && mkfs.ext4 -q -O quota -E quotatype=usrquota:grpquota /srv/q.img
mount -o usrquota,grpquota /srv/q.img /home
setquota -u alice 10240 12288 100000 120000 /home
{quota}
{quota_summary}
"#,
        check = step("check"),
        fsck = step("fsck"),
        mount = step("mount"),
        resize = step("resize"),
        unmount = step("unmount"),
        umount = step("umount"),
        quota = step("quota"),
        quota_summary = step("quota_summary"),
    );
    let r = scenario(&script);
    for (verb, example, keys) in &examples {
        let v = r.ok(verb);
        let mut got: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        got.sort();
        assert_eq!(
            &got, keys,
            "{example}: output keys differ from the help sample"
        );
    }
    assert_eq!(r.ok("resize")["final_size_bytes"], 2u64 << 30);
}
