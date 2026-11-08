//! End-to-end tests for `svc://` against a real systemd, running as PID 1
//! in throwaway privileged containers (one per test). Test units are
//! installed in the container's /usr/lib/systemd/system, like packaged
//! units: one that starts fine (`nginx`, so every help example runs
//! verbatim), one whose start job fails, one slow to start, a oneshot, a
//! templated unit, one slow to stop and one without an `[Install]` section. The host-built `resh` binary is mounted read-only;
//! nothing on the host is changed.
//!
//! Image: `resh-svc-e2e:1` (debian:13-slim with systemd and dbus, built on
//! first use).
//!
//! Run with `cargo test --features e2e-docker --test svc_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

const IMAGE: &str = "resh-svc-e2e:1";

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
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", IMAGE, "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"FROM debian:13-slim\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive \
                  apt-get install -y --no-install-recommends systemd systemd-sysv dbus \
                  && rm -rf /var/lib/apt/lists/*\n",
            )
            .unwrap();
        assert!(child.wait().unwrap().success(), "cannot build {IMAGE}");
    });
}

/// The test units, written before systemd is asked to reload.
const UNITS: &str = r#"
set -e
cd /usr/lib/systemd/system
cat > nginx.service <<'EOF'
[Unit]
Description=Fake nginx for resh tests
[Service]
Type=exec
ExecStart=/bin/sh -c 'echo "<3>open() failed (2: No such file)"; echo "<6>started"; echo "<3>upstream timed out (110)"; exec sleep infinity'
ExecReload=/bin/true
[Install]
WantedBy=multi-user.target
EOF
cat > resh-fail.service <<'EOF'
[Unit]
Description=Start job that fails after it began
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo starting; sleep 0.3; exit 3'
EOF
cat > resh-slow.service <<'EOF'
[Unit]
Description=Never becomes ready
[Service]
Type=notify
ExecStart=/bin/sleep 300
TimeoutStartSec=600
EOF
cat > resh-oneshot.service <<'EOF'
[Unit]
Description=Oneshot that succeeds
[Service]
Type=oneshot
ExecStart=/bin/true
EOF
cat > resh-worker@.service <<'EOF'
[Unit]
Description=Worker %i
[Service]
Type=exec
ExecStart=/bin/sleep infinity
EOF
cat > resh-stopslow.service <<'EOF'
[Unit]
Description=Slow to stop
[Service]
Type=exec
ExecStart=/bin/sleep infinity
ExecStop=/bin/sleep 300
TimeoutStopSec=600
EOF
cat > resh-noinstall.service <<'EOF'
[Unit]
Description=No install section
[Service]
Type=exec
ExecStart=/bin/sleep infinity
EOF
systemctl daemon-reload
"#;

struct Machine {
    id: String,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim()).unwrap_or(Value::Null)
    }
    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{}\n{}", self.out, self.err);
        self
    }
    /// Exit status and the error line's code (and the JSON error, if any).
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(self.code, exit, "{}\n{}", self.out, self.err);
        assert!(
            self.err
                .lines()
                .any(|l| l.starts_with(&format!("Error: [{code}] "))),
            "{}",
            self.err
        );
        if let Some(e) = self.json().get("error") {
            assert_eq!(e["code"], code, "{}", self.out);
        }
        self
    }
}

impl Machine {
    /// Boots systemd in a new container and installs the test units.
    fn boot() -> Machine {
        ensure_image();
        let bin = env!("CARGO_BIN_EXE_resh");
        let mount = format!("{bin}:/usr/local/bin/resh:ro");
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--privileged",
                "--network=none",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "-v",
                &mount,
                IMAGE,
                "/lib/systemd/systemd",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let b = Machine {
            id: String::from_utf8(out.stdout).unwrap().trim().to_string(),
        };
        let start = Instant::now();
        loop {
            let st = b.sh("systemctl is-system-running 2>/dev/null");
            if matches!(st.out.trim(), "running" | "degraded") {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "systemd did not boot: {}",
                st.out
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let r = b.sh(UNITS);
        assert_eq!(r.code, 0, "{}", r.err);
        b
    }

    fn sh(&self, script: &str) -> Run {
        let out = Command::new("docker")
            .args(["exec", &self.id, "sh", "-c", script])
            .output()
            .unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Runs `resh <words>` (as root unless `user` is given).
    fn resh_env(&self, env: &[&str], words: &[&str]) -> Run {
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for e in env {
            cmd.args(["-e", e]);
        }
        cmd.arg(&self.id).arg("resh").args(words);
        let out = cmd.output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn resh(&self, words: &[&str]) -> Run {
        self.resh_env(&[], words)
    }

    fn active(&self, unit: &str) -> String {
        self.sh(&format!("systemctl is-active {unit}"))
            .out
            .trim()
            .to_string()
    }
}

/// The example of each verb's help, from `resh svc <verb> --help`.
fn help_example(verb: &str) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_resh"))
        .args(["svc", verb, "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines().skip_while(|l| *l != "Example:");
    lines.next();
    let ex = lines.next().unwrap().trim().to_string();
    ex.split_whitespace().skip(1).map(str::to_string).collect()
}

#[test]
fn every_help_example_runs() {
    let b = Machine::boot();
    let run = |verb: &str| {
        let words = help_example(verb);
        assert!(words[0].starts_with("svc://nginx."), "{words:?}");
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        b.resh(&refs).ok()
    };
    let v = run("status").json();
    assert_eq!(v["active_state"], "inactive");
    assert_eq!(v["name"], "nginx.service");
    assert_eq!(v["description"], "Fake nginx for resh tests");
    let v = run("is-enabled").json();
    assert_eq!(v["enabled"], false);
    assert_eq!(v["unit_file_state"], "disabled");

    let v = run("start").json();
    assert_eq!(v["result"], "success");
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["active_state"], "active");
    assert_eq!(b.active("nginx"), "active");
    let v = b.resh(&["svc://nginx.status"]).ok().json();
    assert!(v["pid"].as_u64().unwrap() > 0, "{v}");
    assert!(!v["timestamps"]["active_enter"].as_str().unwrap().is_empty());

    let v = run("wait").json();
    assert_eq!(v["reached"], true);
    assert_eq!(v["timeout_ms"], 30000);

    let r = run("logs");
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines.len(), 2, "{}", r.out);
    assert!(
        lines[0].ends_with("open() failed (2: No such file)"),
        "{}",
        r.out
    );
    assert!(lines[1].ends_with("upstream timed out (110)"), "{}", r.out);

    run("reload");
    let v = run("restart").json();
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["active_state"], "active");

    let v = run("stop").json();
    assert_eq!(v["final_state"], "inactive");
    assert_eq!(v["reached_inactive"], true);
    assert_eq!(v["previous_state"], "active");
    assert_eq!(v["timeout_ms"], 5000);
    assert_eq!(b.active("nginx"), "inactive");

    let v = run("scale").json();
    assert_eq!(v["effective_count"], 1);
    assert_eq!(b.active("nginx"), "active");

    assert_eq!(run("enable").out, "");
    assert_eq!(b.sh("systemctl is-enabled nginx").out.trim(), "enabled");
    run("disable");
    assert_eq!(b.sh("systemctl is-enabled nginx").out.trim(), "disabled");
    run("mask");
    assert_eq!(b.sh("systemctl is-enabled nginx").out.trim(), "masked");
    run("unmask");
    assert_eq!(b.sh("systemctl is-enabled nginx").out.trim(), "disabled");
}

#[test]
fn start_and_restart_report_the_real_job_outcome() {
    let b = Machine::boot();
    // A start job that fails (known issue: used to report success).
    let r = b
        .resh(&["svc://resh-fail.start"])
        .fails(1, "svc.job_failed");
    let v = r.json();
    assert_eq!(v["job_result"], "failed");
    assert_eq!(v["result"], "failed");
    assert_eq!(v["active_state"], "failed");
    let r = b
        .resh(&["svc://resh-fail.restart"])
        .fails(1, "svc.job_failed");
    assert_eq!(r.json()["action"], "restart");

    // A oneshot is done (and inactive again) when its job succeeds.
    let v = b.resh(&["svc://resh-oneshot.start"]).ok().json();
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["active_state"], "inactive");

    // Slow to start: cancelled at the deadline.
    let t = Instant::now();
    let r = b
        .resh(&["svc://resh-slow.start", "timeout_ms=1500"])
        .fails(124, "svc.timeout");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    let v = r.json();
    assert_eq!(v["job_canceled"], true, "{v}");
    assert_eq!(v["result"], "timeout");
    assert!(r.err.contains("the job was cancelled"), "{}", r.err);
    // No job is left queued for it.
    assert_eq!(b.sh("systemctl list-jobs --no-legend").out.trim(), "");

    b.resh(&["svc://nosuch.start"]).fails(1, "svc.not_found");
    b.sh("systemctl mask resh-oneshot");
    b.resh(&["svc://resh-oneshot.start"]).fails(1, "svc.masked");
    // Starting an active service is a done job.
    b.resh(&["svc://nginx.start"]).ok();
    let v = b.resh(&["svc://nginx.start"]).ok().json();
    assert_eq!(v["job_result"], "done");
}

#[test]
fn stop_waits_and_cancels_at_the_deadline() {
    let b = Machine::boot();
    b.sh("systemctl start nginx resh-stopslow");
    let v = b.resh(&["svc://nginx.stop", "force=true"]).ok().json();
    assert_eq!(v["final_state"], "inactive");
    assert!(v["note"].as_str().unwrap().contains("force"));
    assert_eq!(v["timeout_ms"], 120000);
    // Stopping a stopped unit is fine.
    b.resh(&["svc://nginx.stop", "timeout=3000"]).ok();
    b.resh(&["svc://nosuch.stop"]).fails(1, "svc.not_found");

    let r = b
        .resh(&["svc://resh-stopslow.stop", "timeout_ms=1000"])
        .fails(124, "svc.timeout");
    let v = r.json();
    assert_eq!(v["requested"], true);
    assert_eq!(v["reached_inactive"], false);
    assert_eq!(v["job_canceled"], true, "{v}");
}

#[test]
fn reload_reports_job_and_refusals() {
    let b = Machine::boot();
    b.sh("systemctl start nginx");
    b.resh(&["svc://nginx.reload"]).ok();
    // No ExecReload: systemd refuses the job.
    b.sh("systemctl start resh-noinstall");
    let r = b
        .resh(&["svc://resh-noinstall.reload"])
        .fails(1, "svc.failed");
    assert!(r.err.contains("reload"), "{}", r.err);
    b.resh(&["svc://nosuch.reload"]).fails(1, "svc.not_found");
}

#[test]
fn unit_file_verbs_change_boot_configuration() {
    let b = Machine::boot();
    b.resh(&["svc://nginx.enable"]).ok();
    assert!(
        b.sh("test -L /etc/systemd/system/multi-user.target.wants/nginx.service")
            .code
            == 0
    );
    assert_eq!(
        b.resh(&["svc://nginx.is-enabled"]).ok().json()["enabled"],
        true
    );
    b.resh(&["svc://nginx.disable"]).ok();
    assert_eq!(
        b.resh(&["svc://nginx.is-enabled"]).ok().json()["enabled"],
        false
    );

    b.resh(&["svc://nginx.mask"]).ok();
    let v = b.resh(&["svc://nginx.is-enabled"]).ok().json();
    assert_eq!(v["unit_file_state"], "masked");
    b.resh(&["svc://nginx.start"]).fails(1, "svc.masked");
    b.resh(&["svc://nginx.unmask"]).ok();
    b.resh(&["svc://nginx.start"]).ok();

    let r = b.resh(&["svc://resh-noinstall.enable"]).ok();
    assert!(
        r.err
            .contains("warning: resh-noinstall.service has no [Install] section"),
        "{}",
        r.err
    );
    b.resh(&["svc://nosuch.enable"]).fails(1, "svc.not_found");
    b.resh(&["svc://nosuch.is-enabled"])
        .fails(1, "svc.not_found");
    let v = b.resh(&["svc://resh-oneshot.is-enabled"]).ok().json();
    assert_eq!(v["unit_file_state"], "static");
    assert_eq!(v["enabled"], true);
}

#[test]
fn wait_and_status() {
    let b = Machine::boot();
    let t = Instant::now();
    let r = b
        .resh(&["svc://nginx.wait", "timeout_ms=600"])
        .fails(124, "svc.timeout");
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(r.json()["reached"], false);
    assert_eq!(r.json()["active_state"], "inactive");
    b.resh(&["svc://nginx.wait", "state=inactive"]).ok();
    b.resh(&["svc://nosuch.wait"]).fails(1, "svc.not_found");
    // Waits for a start made by someone else.
    b.sh("(sleep 1; systemctl start nginx) >/dev/null 2>&1 &");
    let v = b
        .resh(&["svc://nginx.wait", "state=running", "timeout=8000"])
        .ok()
        .json();
    assert_eq!(v["reached"], true);

    let r = b.resh(&["svc://nosuch.status"]).fails(1, "svc.not_found");
    assert_eq!(r.json()["name"], "nosuch.service");
    b.resh(&["svc://resh-fail.start"]);
    let v = b.resh(&["svc://resh-fail.status"]).ok().json();
    assert_eq!(v["active_state"], "failed");
    assert_eq!(v["exit_status"], 3);
    // Instance names.
    b.resh(&["svc://resh-worker@7.start"]).ok();
    let v = b.resh(&["svc://resh-worker@7.status"]).ok().json();
    assert_eq!(v["name"], "resh-worker@7.service");
    assert_eq!(v["description"], "Worker 7");
}

#[test]
fn logs_filters_and_follows() {
    let b = Machine::boot();
    b.sh("systemctl start nginx");
    let r = b.resh(&["svc://nginx.logs"]).ok();
    assert!(r.out.contains("started"), "{}", r.out);
    let r = b
        .resh(&["svc://nginx.logs", "lines=1", "reverse=true"])
        .ok();
    assert_eq!(r.out.lines().count(), 1, "{}", r.out);
    let r = b
        .resh(&["svc://nginx.logs", "level=err", "reverse=true"])
        .ok();
    assert!(
        r.out
            .lines()
            .next()
            .unwrap()
            .ends_with("upstream timed out (110)"),
        "{}",
        r.out
    );
    let r = b
        .resh(&["svc://nginx.logs", "since=2000-01-01", "until=2000-01-02"])
        .ok();
    assert_eq!(r.out, "");
    b.resh(&["svc://nginx.logs", "since=not a time"])
        .fails(1, "svc.logs_failed");
    b.resh(&["svc://nosuch.logs"]).ok();

    // follow: timeout_ms is the run duration (exit 0); new lines stream.
    b.sh("(sleep 1; systemctl restart nginx) >/dev/null 2>&1 &");
    let t = Instant::now();
    let r = b
        .resh(&[
            "svc://nginx.logs",
            "follow=true",
            "lines=1",
            "timeout_ms=3000",
        ])
        .ok();
    assert!(t.elapsed() >= Duration::from_millis(2900));
    assert!(r.out.lines().count() >= 2, "{}", r.out);
    // journalctl was stopped.
    assert_ne!(b.sh("pgrep journalctl").code, 0);
}

#[test]
fn scale_templates_and_plain_units() {
    let b = Machine::boot();
    let v = b
        .resh(&["svc://resh-worker@.service.scale", "count=3"])
        .ok()
        .json();
    assert_eq!(v["template"], true);
    assert_eq!(v["effective_count"], 3);
    assert_eq!(v["instances_started"].as_array().unwrap().len(), 3);
    assert_eq!(b.active("resh-worker@3"), "active");
    let v = b
        .resh(&["svc://resh-worker@.service.scale", "count=1"])
        .ok()
        .json();
    assert_eq!(v["instances_stopped"].as_array().unwrap().len(), 2, "{v}");
    assert_eq!(v["effective_count"], 1);
    assert_eq!(b.active("resh-worker@2"), "inactive");

    b.sh("systemctl start nginx");
    let v = b.resh(&["svc://nginx.scale", "count=0"]).ok().json();
    assert_eq!(v["effective_count"], 0);
    assert_eq!(b.active("nginx"), "inactive");
    b.resh(&["svc://resh-fail.scale", "count=1"])
        .fails(1, "svc.job_failed");
    b.resh(&["svc://nosuch.scale", "count=1"])
        .fails(1, "svc.not_found");
}

#[test]
fn systemctl_route_without_dbus() {
    let b = Machine::boot();
    let sc = ["RESH_TEST_SVC_BACKEND=systemctl"];
    let v = b.resh_env(&sc, &["svc://nginx.start"]).ok().json();
    assert_eq!(v["job_result"], "done");
    assert_eq!(v["active_state"], "active");
    let v = b.resh_env(&sc, &["svc://nginx.status"]).ok().json();
    assert_eq!(v["active_state"], "active");
    assert!(v["pid"].as_u64().unwrap() > 0);
    b.resh_env(&sc, &["svc://resh-fail.start"])
        .fails(1, "svc.job_failed");
    b.resh_env(&sc, &["svc://nosuch.start"])
        .fails(1, "svc.not_found");
    b.resh_env(&sc, &["svc://nosuch.status"])
        .fails(1, "svc.not_found");
    b.resh_env(&sc, &["svc://nginx.reload"]).ok();
    let v = b.resh_env(&sc, &["svc://nginx.stop"]).ok().json();
    assert_eq!(v["final_state"], "inactive");
    b.resh_env(&sc, &["svc://nginx.enable"]).ok();
    assert_eq!(
        b.resh_env(&sc, &["svc://nginx.is-enabled"]).ok().json()["enabled"],
        true
    );
    b.resh_env(&sc, &["svc://nginx.disable"]).ok();
    b.resh_env(&sc, &["svc://nginx.mask"]).ok();
    b.resh_env(&sc, &["svc://nginx.start"])
        .fails(1, "svc.masked");
    b.resh_env(&sc, &["svc://nginx.unmask"]).ok();
    b.resh_env(&sc, &["svc://nosuch.is-enabled"])
        .fails(1, "svc.not_found");
    let v = b
        .resh_env(&sc, &["svc://resh-worker@.service.scale", "count=2"])
        .ok()
        .json();
    assert_eq!(v["effective_count"], 2);
    b.resh_env(&sc, &["svc://resh-worker@1.wait"]).ok();
    // At the deadline systemctl is stopped; its job cannot be cancelled.
    let r = b
        .resh_env(&sc, &["svc://resh-slow.start", "timeout_ms=1000"])
        .fails(124, "svc.timeout");
    assert_eq!(r.json()["action"], "start");

    // With the bus really gone, the D-Bus route falls back to systemctl.
    b.sh("systemctl stop dbus.socket dbus.service");
    let v = b.resh(&["svc://nginx.start"]).ok().json();
    assert_eq!(v["active_state"], "active");
    b.resh(&["svc://nginx.status"]).ok();
}

#[test]
fn unprivileged_callers_are_refused() {
    let b = Machine::boot();
    let as_nobody = |words: &str| {
        b.sh(&format!(
            "setpriv --reuid=nobody --regid=nogroup --clear-groups resh {words}"
        ))
    };
    let r = as_nobody("svc://nginx.start");
    assert_eq!(r.code, 1, "{}\n{}", r.out, r.err);
    assert!(
        r.err.contains("Error: [svc.permission_denied]"),
        "{}",
        r.err
    );
    assert_eq!(b.active("nginx"), "inactive");
    let r = as_nobody("svc://nginx.enable");
    assert!(
        r.err.contains("Error: [svc.permission_denied]"),
        "{}",
        r.err
    );
    // Reading the state needs no privileges.
    let r = as_nobody("svc://nginx.status");
    assert_eq!(r.code, 0, "{}", r.err);
}
