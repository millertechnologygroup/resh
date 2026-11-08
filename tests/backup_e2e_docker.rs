//! End-to-end tests for `backup://` with real restic, borg, rsync and tar,
//! inside throwaway containers. The host-built `resh` binary is mounted
//! read-only; every repository, source tree and restore target is inside the
//! container (no network), and nothing on the host is changed.
//!
//! Image (built on first use): `resh-backup-e2e:1`, Debian 13 with restic,
//! borgbackup, rsync and tar from the distribution.
//!
//! Run with `cargo test --features e2e-docker --test backup_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const IMAGE: &str = "resh-backup-e2e:1";

fn ensure_image() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let have = Command::new("docker")
            .args(["image", "inspect", IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if have.success() {
            return;
        }
        let dockerfile = "FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
             apt-get install -y --no-install-recommends restic borgbackup rsync tar gzip \
             && rm -rf /var/lib/apt/lists/*\n";
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", IMAGE, "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(dockerfile.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "cannot build {IMAGE}");
    });
}

/// `r <tag> <command...>` prints `<tag>\t<exit>\t<stdout on one line>\t<stderr>`;
/// `check <name> <command...>` prints the command's output as base64.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(printf '%s' "$out" | tr '\n' ' ')" "$(tr '\n' ' ' < /tmp/err)"
}
check() {
  name=$1; shift
  printf 'check\t%s\t%s\n' "$name" "$("$@" 2>&1 | base64 -w0)"
}
mkdir -p /data/sub /repo
printf alpha > /data/a.conf
printf 'bravo!' > /data/b.txt
printf charlie > /data/sub/c.conf
printf 'correct horse\n' > /pw
chmod 600 /pw
"#;

struct Res {
    code: i32,
    json: Value,
    err: String,
}

struct Ctr {
    results: HashMap<String, Res>,
    checks: HashMap<String, String>,
    raw: String,
}

impl Ctr {
    fn parse(raw: String) -> Self {
        let mut results = HashMap::new();
        let mut checks = HashMap::new();
        for line in raw.lines() {
            let f: Vec<&str> = line.splitn(4, '\t').collect();
            if f[0] == "check" && f.len() >= 3 {
                let bytes = base64_decode(f[2]);
                checks.insert(
                    f[1].to_string(),
                    String::from_utf8_lossy(&bytes).into_owned(),
                );
            } else if f.len() == 4 {
                results.insert(
                    f[0].to_string(),
                    Res {
                        code: f[1].parse().unwrap_or(-1),
                        json: serde_json::from_str(f[2]).unwrap_or(Value::Null),
                        err: f[3].to_string(),
                    },
                );
            }
        }
        Ctr {
            results,
            checks,
            raw,
        }
    }

    fn get(&self, tag: &str) -> &Res {
        self.results
            .get(tag)
            .unwrap_or_else(|| panic!("no result {tag}:\n{}", self.raw))
    }

    #[track_caller]
    fn ok(&self, tag: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, 0, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["ok"], true, "{tag}: {}", r.json);
        &r.json
    }

    #[track_caller]
    fn fails(&self, tag: &str, exit: i32, code: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, exit, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["error"]["code"], code, "{tag}: {}", r.json);
        assert!(
            r.err.contains(&format!("Error: [{code}] ")),
            "{tag}: {}",
            r.err
        );
        &r.json
    }

    #[track_caller]
    fn check(&self, name: &str) -> &str {
        self.checks
            .get(name)
            .unwrap_or_else(|| panic!("no check {name}:\n{}", self.raw))
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let Some(v) = T.iter().position(|t| *t == c) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// Runs `script` (after PRELUDE) in a fresh container.
fn container(script: &str) -> Ctr {
    ensure_image();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-e",
            "TZ=UTC",
            "-v",
            &format!("{}:/usr/local/bin/resh:ro", env!("CARGO_BIN_EXE_resh")),
            IMAGE,
            "sh",
            "-c",
        ])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container failed: {raw}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ctr::parse(raw)
}

/// restic: init, create twice (same host, so one retention group), list, verify, restore (all and include) and
/// compare with the source, prune dry run and real prune, wrong password,
/// and a create stopped at the deadline.
#[test]
fn restic_end_to_end() {
    let c = container(
        r#"
restic init --repo /repo/restic --password-file /pw >/dev/null 2>&1 || echo INIT_FAILED
B="backend=restic repo_url=/repo/restic password_file=/pw"
r c1     resh backup://db.create src=/data $B tag=daily label=web01
sleep 1
r c2     resh backup://db.create src=/data $B tag=weekly label=web01
r list   resh backup://db.list $B
r listt  resh backup://db.list $B tag=daily
r vq     resh backup://db.verify $B
r vt     resh backup://db.verify $B mode=thorough
r rall   resh backup://db.restore $B snapshot_id=latest dest=/out
check diff diff -r /data /out/data
check mode stat -c %a /out
r rinc   resh backup://db.restore $B snapshot_id=latest dest=/inc 'include=/data/*.conf'
check inc sh -c 'cd /inc && find . -type f | sort'
r pdry   resh backup://db.prune $B keep_daily=1 dry_run=true
r after_dry resh backup://db.list $B
r prune  resh backup://db.prune $B keep_daily=1
r after  resh backup://db.list $B
printf 'wrong\n' > /bad
r badpw  resh backup://db.list backend=restic repo_url=/repo/restic password_file=/bad
r slow   resh backup://db.create src=/usr $B timeout_ms=300
sleep 1
check leftover sh -c 'for p in /proc/[0-9]*; do cat $p/comm 2>/dev/null; done | grep -c "^restic$" || true'
"#,
    );
    assert!(!c.raw.contains("INIT_FAILED"), "{}", c.raw);
    let c1 = c.ok("c1");
    let id1 = c1["result"]["snapshot"]["id"].as_str().unwrap();
    assert_eq!(id1.len(), 64, "{c1}");
    assert!(c1["result"]["snapshot"]["bytes_total"].as_u64().unwrap() >= 18);
    c.ok("c2");
    assert_eq!(c.ok("list")["result"]["total_count"], 2);
    let tagged = c.ok("listt");
    assert_eq!(tagged["result"]["total_count"], 1);
    assert_eq!(tagged["result"]["snapshots"][0]["label"], "web01");
    assert_eq!(tagged["result"]["snapshots"][0]["sources"][0], "/data");
    c.ok("vq");
    assert_eq!(c.ok("vt")["result"]["mode"], "thorough");

    let rall = c.ok("rall");
    assert_eq!(c.check("diff"), "", "restored tree differs");
    assert_eq!(c.check("mode").trim(), "700");
    assert!(
        rall["result"]["restored"]["files_restored"]
            .as_u64()
            .unwrap()
            >= 3,
        "{rall}"
    );
    c.ok("rinc");
    assert_eq!(c.check("inc"), "./data/a.conf\n");

    let dry = c.ok("pdry");
    assert_eq!(dry["result"]["dry_run_mode"], "backend");
    assert_eq!(dry["result"]["would_prune"]["snapshots_removed"], 1);
    assert_eq!(c.ok("after_dry")["result"]["total_count"], 2);
    assert_eq!(c.ok("prune")["result"]["pruned"]["snapshots_removed"], 1);
    assert_eq!(c.ok("after")["result"]["total_count"], 1);

    let bad = c.fails("badpw", 1, "backup.backend_failed");
    assert!(bad["error"]["details"]["exit_code"].as_i64().unwrap() != 0);

    let slow = c.get("slow");
    assert_eq!(slow.code, 124, "{} {}", slow.json, slow.err);
    assert_eq!(slow.json["error"]["code"], "backup.timeout");
    assert!(
        slow.err.contains("[backup.timeout] outcome unknown"),
        "{}",
        slow.err
    );
    assert_eq!(c.check("leftover").trim(), "0", "restic still running");
}

/// borg: init, create twice, list, verify (whole and one archive, with
/// --verify-data), restore (all and a path) and compare, prune dry run and
/// real prune, wrong passphrase, and a create stopped at the deadline.
#[test]
fn borg_end_to_end() {
    let c = container(
        r#"
BORG_PASSPHRASE='correct horse' borg init --encryption=repokey /repo/borg >/dev/null 2>&1 || echo INIT_FAILED
export BORG_BASE_DIR=/borgbase
B="backend=borg repo_url=/repo/borg password_file=/pw"
r c1     resh backup://db.create src=/data $B label=nightly
sleep 1
r c2     resh backup://db.create src=/data $B label=nightly
r list   resh backup://db.list $B
A1=$(resh backup://db.list $B | sed 's/.*"id":"\([^"]*\)".*/\1/')
r vq     resh backup://db.verify $B
r vone   resh backup://db.verify $B snapshot_id=$A1 mode=data
r rall   resh backup://db.restore $B snapshot_id=$A1 dest=/out
check diff diff -r /data /out/data
r rinc   resh backup://db.restore $B snapshot_id=$A1 dest=/inc include=data/sub
check inc sh -c 'cd /inc && find . -type f | sort'
r pdry   resh backup://db.prune $B keep_daily=1 dry_run=true
r after_dry resh backup://db.list $B
r prune  resh backup://db.prune $B keep_daily=1
r after  resh backup://db.list $B
printf 'wrong\n' > /bad
r badpw  resh backup://db.list backend=borg repo_url=/repo/borg password_file=/bad
r slow   resh backup://db.create src=/usr $B timeout_ms=300
sleep 1
check leftover sh -c 'for p in /proc/[0-9]*; do cat $p/comm 2>/dev/null; done | grep -c "^borg" || true'
"#,
    );
    assert!(!c.raw.contains("INIT_FAILED"), "{}", c.raw);
    let c1 = c.ok("c1");
    assert!(
        c1["result"]["snapshot"]["id"]
            .as_str()
            .unwrap()
            .starts_with("nightly_"),
        "{c1}"
    );
    // borg's original_size also counts item metadata.
    assert!(c1["result"]["snapshot"]["bytes_total"].as_u64().unwrap() >= 18);
    c.ok("c2");
    assert_eq!(c.ok("list")["result"]["total_count"], 2);
    c.ok("vq");
    c.ok("vone");

    let rall = c.ok("rall");
    assert_eq!(c.check("diff"), "", "restored tree differs");
    assert_eq!(rall["result"]["restored"]["files_restored"], 3);
    assert_eq!(rall["result"]["restored"]["bytes_restored"], 18);
    let rinc = c.ok("rinc");
    assert_eq!(c.check("inc"), "./data/sub/c.conf\n");
    assert_eq!(rinc["result"]["restored"]["files_restored"], 1);

    let dry = c.ok("pdry");
    assert_eq!(dry["result"]["would_prune"]["snapshots_removed"], 1);
    assert_eq!(c.ok("after_dry")["result"]["total_count"], 2);
    assert_eq!(c.ok("prune")["result"]["pruned"]["snapshots_removed"], 1);
    assert_eq!(c.ok("after")["result"]["total_count"], 1);

    c.fails("badpw", 1, "backup.backend_failed");

    let slow = c.get("slow");
    assert_eq!(slow.code, 124, "{} {}", slow.json, slow.err);
    assert_eq!(c.check("leftover").trim(), "0", "borg still running");
}

/// tar and rsync in the container, as root, with a restore diffed against
/// the source.
#[test]
fn tar_and_rsync_end_to_end() {
    let c = container(
        r#"
for b in tar rsync; do
  r c_$b    resh backup://db.create src=/data backend=$b repo_url=/repo/$b
  ID=$(resh backup://db.list backend=$b repo_url=/repo/$b | sed 's/.*"id":"\([^"]*\)".*/\1/')
  r v_$b    resh backup://db.verify backend=$b repo_url=/repo/$b mode=thorough
  r r_$b    resh backup://db.restore backend=$b repo_url=/repo/$b snapshot_id=$ID dest=/out_$b
  check d_$b sh -c "diff -r /data /out_$b/data"
  check m_$b stat -c %a /repo/$b
done
"#,
    );
    for b in ["tar", "rsync"] {
        c.ok(&format!("c_{b}"));
        c.ok(&format!("v_{b}"));
        let r = c.ok(&format!("r_{b}"));
        assert_eq!(r["result"]["restored"]["files_restored"], 3, "{b}: {r}");
        assert_eq!(r["result"]["restored"]["bytes_restored"], 18, "{b}");
        assert_eq!(c.check(&format!("d_{b}")), "", "{b}: restored tree differs");
        assert_eq!(c.check(&format!("m_{b}")).trim(), "700", "{b}");
    }
}
