//! End-to-end tests for `cron://` against real cron implementations and a
//! real systemd, inside throwaway containers. The host-built `resh` binary
//! is mounted read-only; every crontab, cron file, unit file and timer is
//! inside the container, and nothing on the host is changed.
//!
//! Images (built on first use):
//! - `resh-cron-cronie:1`: Fedora 42 with cronie (honors CRON_TZ, `crontab
//!   -V`, refuses `-u` to non-root users);
//! - `resh-cron-debian:1`: Debian 13 with Debian's cron (vixie);
//! - `resh-cron-systemd:1`: Debian 13 with systemd running as PID 1.
//!
//! Each image has the users `alice` and `bob`. Run with
//! `cargo test --features e2e-docker --test cron_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;

const CRONIE: &str = "resh-cron-cronie:1";
const DEBIAN: &str = "resh-cron-debian:1";
const SYSTEMD: &str = "resh-cron-systemd:1";

fn build(image: &str, dockerfile: &str) {
    let have = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if have.success() {
        return;
    }
    let mut child = Command::new("docker")
        .args(["build", "-q", "-t", image, "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(dockerfile.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "cannot build {image}");
}

fn ensure_images() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        build(
            CRONIE,
            "FROM fedora:42\nRUN dnf install -y --setopt=install_weak_deps=False cronie \
             util-linux && dnf clean all && useradd -m alice && useradd -m bob\n",
        );
        build(
            DEBIAN,
            "FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
             apt-get install -y --no-install-recommends cron && rm -rf /var/lib/apt/lists/* \
             && useradd -m alice && useradd -m bob\n",
        );
        build(
            SYSTEMD,
            "FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
             apt-get install -y --no-install-recommends systemd systemd-sysv dbus \
             && rm -rf /var/lib/apt/lists/*\n",
        );
    });
}

/// `r <tag> <command...>` prints `<tag>\t<exit>\t<stdout on one line>\t<stderr>`;
/// `A <tag> <resh args...>` runs resh as alice (through su, so USER is
/// alice); `check <name> <command...>` prints the command's output as
/// base64.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(printf '%s' "$out" | tr '\n' ' ')" "$(tr '\n' ' ' < /tmp/err)"
}
A() {
  tag=$1; shift
  q=""
  for a in "$@"; do q="$q '$a'"; done
  r "$tag" su alice -c "resh$q"
}
check() {
  name=$1; shift
  printf 'check\t%s\t%s\n' "$name" "$("$@" 2>&1 | base64 -w0)"
}
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
            r.err.starts_with(&format!("Error: [{code}] ")),
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

fn mount() -> String {
    format!("{}:/usr/local/bin/resh:ro", env!("CARGO_BIN_EXE_resh"))
}

/// Runs `script` (after PRELUDE) in a fresh container of `image`.
fn container(image: &str, script: &str) -> Ctr {
    ensure_images();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "-e",
            "TZ=UTC",
            "-v",
            &mount(),
            image,
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

// ===========================================================================
// crontab backends
// ===========================================================================

/// The user-crontab flow, run as alice: add, list, disable, enable, rm.
const USER_FLOW: &str = r#"
A add    cron://local.add backend=cron 'schedule=30 3 * * 1-5' 'command=/opt/rotate.sh >/dev/null 2>&1' id=rotate 'description=log rotation'
A add2   cron://local.add backend=cron schedule=@daily command=/opt/daily.sh
check after_add su alice -c 'crontab -l'
A list   cron://local.list include_next_run=true now_unix=1768435200
A dis    cron://local.disable id=rotate backend=cron scope=current
check after_dis su alice -c 'crontab -l'
A en     cron://local.enable id=rotate backend=cron scope=current
check after_en su alice -c 'crontab -l'
A rm     cron://local.rm id=rotate backend=cron scope=current
A rmagain cron://local.rm id=rotate backend=cron scope=current
check after_rm su alice -c 'crontab -l'
A other  cron://local.list scope=user users=bob
"#;

fn assert_user_flow(c: &Ctr) {
    let job = &c.ok("add")["job"];
    assert_eq!(job["location"]["user"], "alice");
    c.ok("add2");
    let added = "# job-id=rotate description=log rotation\n\
                 30 3 * * 1-5 /opt/rotate.sh >/dev/null 2>&1\n@daily /opt/daily.sh\n";
    assert!(
        c.check("after_add").ends_with(added),
        "{}",
        c.check("after_add")
    );
    let entries = c.ok("list")["entries"].as_array().unwrap().clone();
    let jobs: Vec<&Value> = entries
        .iter()
        .filter(|e| e["comment_only"] == false)
        .collect();
    assert_eq!(jobs.len(), 2, "{entries:?}");
    // 2026-01-15 (a Thursday) 00:00 UTC: weekdays 1-5 run that morning.
    assert_eq!(jobs[0]["next_run_iso8601"], "2026-01-15T03:30:00+00:00");
    assert_eq!(jobs[1]["next_run_iso8601"], "2026-01-16T00:00:00+00:00");
    c.ok("dis");
    assert!(
        c.check("after_dis")
            .contains("\n# 30 3 * * 1-5 /opt/rotate.sh"),
        "{}",
        c.check("after_dis")
    );
    c.ok("en");
    assert_eq!(c.check("after_en"), c.check("after_add"));
    assert_eq!(c.ok("rm")["removed"]["cron"][0]["id"], "rotate");
    c.fails("rmagain", 1, "cron.rm_no_match");
    assert!(
        !c.check("after_rm").contains("rotate"),
        "{}",
        c.check("after_rm")
    );
    assert!(c.check("after_rm").contains("@daily /opt/daily.sh"));
    // Another user's crontab cannot be read by alice: a warning.
    let w = c.ok("other")["warnings"][0].as_str().unwrap().to_string();
    assert!(w.contains("bob"), "{w}");
}

/// The system-file flow, run as root.
const ROOT_FLOW: &str = r#"
r sadd   resh cron://local.add backend=cron scope=system cron_file=/etc/cron.d/resh_e2e user=alice schedule=@hourly command=/opt/h.sh id=hourly
check cron_d cat /etc/cron.d/resh_e2e
r slist  resh cron://local.list scope=system match_source=resh_e2e
r sdis   resh cron://local.disable id=hourly backend=cron cron_file=/etc/cron.d/resh_e2e
check cron_d_dis cat /etc/cron.d/resh_e2e
r sen    resh cron://local.enable id=hourly backend=cron scope=system
r srm    resh cron://local.rm id=hourly backend=cron cron_file=/etc/cron.d/resh_e2e
check cron_d_rm cat /etc/cron.d/resh_e2e
r uadd   resh cron://local.add backend=cron scope=user user=bob schedule=@weekly command=/opt/w.sh
check bob crontab -u bob -l
r urm    resh cron://local.rm command=/opt/w.sh backend=cron scope=user users=bob
check bob_rm crontab -u bob -l
r badfile resh cron://local.rm id=x backend=cron cron_file=/etc/passwd
"#;

fn assert_root_flow(c: &Ctr) {
    c.ok("sadd");
    assert_eq!(
        c.check("cron_d"),
        "# job-id=hourly\n@hourly alice /opt/h.sh\n"
    );
    let e = &c.ok("slist")["entries"];
    assert_eq!(e[1]["user"], "alice");
    assert_eq!(e[1]["special"], "@hourly");
    c.ok("sdis");
    assert_eq!(
        c.check("cron_d_dis"),
        "# job-id=hourly\n# @hourly alice /opt/h.sh\n"
    );
    assert_eq!(c.ok("sen")["enabled"]["cron"][0]["user"], "alice");
    c.ok("srm");
    assert_eq!(c.check("cron_d_rm"), "\n");
    c.ok("uadd");
    assert!(
        c.check("bob").contains("@weekly /opt/w.sh"),
        "{}",
        c.check("bob")
    );
    c.ok("urm");
    assert!(
        !c.check("bob_rm").contains("/opt/w.sh"),
        "{}",
        c.check("bob_rm")
    );
    c.fails("badfile", 2, "cron.rm_invalid_argument");
}

#[test]
fn cronie_user_and_system_crontabs() {
    let c = container(
        CRONIE,
        &format!(
            "{USER_FLOW}{ROOT_FLOW}
A tzadd cron://local.add backend=cron 'schedule=0 2 * * *' command=/opt/de.sh id=de timezone=Europe/Berlin
check tz su alice -c 'crontab -l'
A tzlist cron://local.list include_next_run=true now_unix=1768435200
A tzrm cron://local.rm id=de backend=cron scope=current
check tz_rm su alice -c 'crontab -l'
"
        ),
    );
    assert_user_flow(&c);
    assert_root_flow(&c);
    // cronie: zoned jobs go in the CRON_TZ block.
    c.ok("tzadd");
    assert!(
        c.check("tz")
            .contains("CRON_TZ=Europe/Berlin\n# job-id=de\n0 2 * * * /opt/de.sh\n"),
        "{}",
        c.check("tz")
    );
    let entries = c.ok("tzlist")["entries"].as_array().unwrap().clone();
    let de = entries
        .iter()
        .find(|e| e["command"] == "/opt/de.sh")
        .unwrap();
    assert_eq!(de["timezone"], "Europe/Berlin");
    assert_eq!(de["next_run_iso8601"], "2026-01-15T02:00:00+01:00");
    c.ok("tzrm");
    assert!(
        !c.check("tz_rm").contains("CRON_TZ"),
        "{}",
        c.check("tz_rm")
    );
}

#[test]
fn debian_cron_user_and_system_crontabs() {
    let c = container(
        DEBIAN,
        &format!(
            "{USER_FLOW}{ROOT_FLOW}
A tzadd cron://local.add backend=cron schedule=@daily command=/opt/de.sh timezone=Europe/Berlin
A sys cron://local.list scope=system
"
        ),
    );
    assert_user_flow(&c);
    assert_root_flow(&c);
    // Debian's cron ignores CRON_TZ: refused before anything is written.
    c.fails("tzadd", 2, "cron.add_timezone_unsupported");
    // Debian's /etc/crontab: its run-parts jobs are listed, the commented
    // example line is a disabled job, the comment lines are comments.
    let e = c.ok("sys")["entries"].as_array().unwrap().clone();
    let hourly = e
        .iter()
        .find(|x| {
            x["command"]
                .as_str()
                .is_some_and(|c| c.contains("cron.hourly"))
        })
        .unwrap();
    assert_eq!(hourly["user"], "root");
    assert_eq!(hourly["enabled"], true);
    assert!(e.iter().any(|x| x["comment_only"] == true));
}

// ===========================================================================
// systemd
// ===========================================================================

/// A container running systemd as PID 1; removed on drop.
struct SystemdBox(String);

impl SystemdBox {
    fn start(tag: &str) -> Self {
        ensure_images();
        let name = format!("resh-cron-e2e-{}-{tag}", std::process::id());
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--privileged",
                "--cgroupns=private",
                "--network=none",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "-e",
                "TZ=UTC",
                "--name",
                &name,
                "-v",
                &mount(),
                SYSTEMD,
                "/lib/systemd/systemd",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let b = SystemdBox(name);
        // Wait for the manager to answer.
        for _ in 0..100 {
            let st = b.exec("systemctl is-system-running --wait >/dev/null 2>&1; systemctl show --property=Version");
            if st.contains("Version=") {
                return b;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("systemd did not start");
    }

    fn exec(&self, script: &str) -> String {
        let out = Command::new("docker")
            .args(["exec", &self.0, "sh", "-c"])
            .arg(format!("{PRELUDE}\n{script}"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn run(&self, script: &str) -> Ctr {
        Ctr::parse(self.exec(script))
    }
}

impl Drop for SystemdBox {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn systemd_timers_lifecycle() {
    let b = SystemdBox::start("life");
    let c = b.run(
        r#"
r add resh cron://local.add backend=systemd 'schedule=*/15 9-17 * * mon-fri' command=/bin/true id=poll unit_name=resh-poll timezone=Europe/Berlin
check timers systemctl list-timers --all --no-legend --plain
check cal systemctl show --property=TimersCalendar resh-poll.timer
check enabled systemctl is-enabled resh-poll.timer
r dis resh cron://local.disable id=poll backend=systemd
check enabled_dis systemctl is-enabled resh-poll.timer
check active_dis systemctl is-active resh-poll.timer
systemctl daemon-reload
check timers_dis systemctl list-timers --all --no-legend --plain
r dis2 resh cron://local.disable id=poll backend=systemd
r en resh cron://local.enable match_command=/bin/true backend=systemd unit_scope=system
check enabled_en systemctl is-enabled resh-poll.timer
check active_en systemctl is-active resh-poll.timer
r rmdry resh cron://local.rm unit_name=resh-poll backend=systemd dry_run=true
r rm resh cron://local.rm unit_name=resh-poll.timer backend=systemd
check files ls /etc/systemd/system
check timers_rm systemctl list-timers --all --no-legend --plain
r rm2 resh cron://local.rm unit_name=resh-poll backend=systemd
r user resh cron://local.add backend=systemd unit_scope=user schedule=@daily command=/bin/true
r both resh cron://local.disable unit_name=x unit_scope=user require_match=false
"#,
    );
    let job = &c.ok("add")["job"];
    assert_eq!(job["location"]["scope"], "system-unit");
    assert!(
        c.check("timers").contains("resh-poll.timer"),
        "{}",
        c.check("timers")
    );
    // systemd parsed the translated calendar expression.
    let cal = c.check("cal");
    assert!(
        cal.contains("OnCalendar=")
            && cal.contains("Europe/Berlin")
            && cal.contains("next_elapse="),
        "{cal}"
    );
    assert_eq!(c.check("enabled").trim(), "enabled");
    let d = &c.ok("dis")["disabled"]["systemd"][0];
    assert_eq!(d["timer_unit"], "resh-poll.timer");
    assert_eq!(d["stopped_now"], true);
    assert_eq!(c.check("enabled_dis").trim(), "disabled");
    assert_eq!(c.check("active_dis").trim(), "inactive");
    assert!(
        !c.check("timers_dis").contains("resh-poll"),
        "{}",
        c.check("timers_dis")
    );
    assert_eq!(c.ok("dis2")["already_disabled_count"]["systemd"], 1);
    // Not loaded any more, still found and enabled again.
    assert_eq!(c.ok("en")["enabled"]["systemd"][0]["id"], "poll");
    assert_eq!(c.check("enabled_en").trim(), "enabled");
    assert_eq!(c.check("active_en").trim(), "active");
    assert_eq!(c.ok("rmdry")["matched_count"]["systemd"], 1);
    c.ok("rm");
    assert!(
        !c.check("files").contains("resh-poll"),
        "{}",
        c.check("files")
    );
    assert!(
        !c.check("timers_rm").contains("resh-poll"),
        "{}",
        c.check("timers_rm")
    );
    c.fails("rm2", 1, "cron.rm_no_match");
    // No user manager for root in the container.
    c.fails("user", 1, "cron.add_systemd_unavailable");
    let w = c.ok("both")["warnings"][0].as_str().unwrap().to_string();
    assert!(w.contains("systemd timers were skipped"), "{w}");
}

/// `@reboot` becomes a boot timer that is enabled but not started (so the
/// job does not run when it is added); started, it runs the job once. A
/// schedule restricting both day fields becomes a timer with two calendars.
#[test]
fn systemd_reboot_and_either_day_timers() {
    let b = SystemdBox::start("boot");
    let c = b.run(
        r#"
r boot resh cron://local.add backend=systemd schedule=@reboot 'command=/usr/bin/touch /tmp/boot-ran' unit_name=resh-boot
check bunit cat /etc/systemd/system/resh-boot.timer
check benabled systemctl is-enabled resh-boot.timer
check bactive systemctl is-active resh-boot.timer
check bmono systemctl show --property=TimersMonotonic resh-boot.timer
check bran_before ls /tmp/boot-ran
systemctl start resh-boot.timer
sleep 2
check bran_after ls /tmp/boot-ran
r bdis resh cron://local.disable unit_name=resh-boot backend=systemd
r ben resh cron://local.enable unit_name=resh-boot backend=systemd
check benabled2 systemctl is-enabled resh-boot.timer
r or resh cron://local.add backend=systemd 'schedule=0 0 13 * fri' command=/bin/true unit_name=resh-f13
check ocal systemctl show --property=TimersCalendar resh-f13.timer
check otimers systemctl list-timers --all --no-legend --plain
"#,
    );
    assert_eq!(c.ok("boot")["job"]["schedule"], "OnBootSec=0");
    let unit = c.check("bunit");
    assert!(
        unit.contains("OnBootSec=0\n") && !unit.contains("OnCalendar"),
        "{unit}"
    );
    assert_eq!(c.check("benabled").trim(), "enabled");
    assert_eq!(c.check("bactive").trim(), "inactive");
    assert!(
        c.check("bmono").contains("OnBootUSec"),
        "{}",
        c.check("bmono")
    );
    assert!(
        c.check("bran_before").contains("No such file"),
        "the job ran when added"
    );
    assert_eq!(
        c.check("bran_after").trim(),
        "/tmp/boot-ran",
        "started, it runs"
    );
    c.ok("bdis");
    let en = c.ok("ben");
    assert_eq!(en["enabled"]["systemd"][0]["started_now"], false);
    assert!(en["warnings"][0].as_str().unwrap().contains("next boot"));
    assert_eq!(c.check("benabled2").trim(), "enabled");
    assert_eq!(
        c.ok("or")["job"]["schedule"],
        "OnCalendar=*-*-13 0:0; OnCalendar=Fri *-*-* 0:0"
    );
    let cal = c.check("ocal");
    assert_eq!(cal.matches("OnCalendar=").count(), 2, "{cal}");
    assert!(
        c.check("otimers").contains("resh-f13.timer"),
        "{}",
        c.check("otimers")
    );
}

/// Every translated schedule is a valid calendar expression with the runs
/// cron would have.
#[test]
fn systemd_accepts_every_translated_schedule() {
    let b = SystemdBox::start("cal");
    let schedules = [
        ("* * * * *", "2026-01-15 00:01:00"),
        ("*/15 * * * *", "2026-01-15 00:15:00"),
        ("0 9-17 * * *", "2026-01-15 09:00:00"),
        ("30 6 * * mon-fri", "2026-01-15 06:30:00"),
        ("0 0 * * 0", "2026-01-18 00:00:00"),
        ("0 3 1,15 * *", "2026-01-15 03:00:00"),
        ("0 0 */2 * 1", "2026-01-19 00:00:00"),
        ("@weekly", "2026-01-18 00:00:00"),
        ("@monthly", "2026-02-01 00:00:00"),
        // Both day fields restricted: two expressions; the Friday comes
        // first, as with cron's OR (the 13th is 2026-02-13).
        ("0 0 13 * fri", "2026-01-16 00:00:00"),
    ];
    let mut script = String::new();
    for (i, (s, _)) in schedules.iter().enumerate() {
        script.push_str(&format!(
            "r s{i} resh cron://local.add backend=systemd 'schedule={s}' command=/bin/true unit_name=t{i} dry_run=true\n"
        ));
    }
    let c = b.run(&script);
    let mut script = String::new();
    let mut counts = Vec::new();
    for (i, _) in schedules.iter().enumerate() {
        let cals: Vec<String> = c.ok(&format!("s{i}"))["job"]["schedule"]
            .as_str()
            .unwrap()
            .split("; ")
            .map(|e| format!("'{}'", e.trim_start_matches("OnCalendar=")))
            .collect();
        counts.push(cals.len());
        script.push_str(&format!(
            "check c{i} systemd-analyze calendar --base-time='2026-01-15 00:00:00 UTC' {}\n",
            cals.join(" ")
        ));
    }
    assert_eq!(
        counts.last(),
        Some(&2),
        "the OR schedule has two expressions"
    );
    let c = b.run(&script);
    for (i, (s, next)) in schedules.iter().enumerate() {
        let out = c.check(&format!("c{i}"));
        assert_eq!(out.matches("Next elapse:").count(), counts[i], "{s}: {out}");
        assert!(out.contains(next), "{s}: expected {next} in {out}");
    }
}
