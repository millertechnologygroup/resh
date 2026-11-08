//! End-to-end tests for `proc://` that need root or another user, inside
//! throwaway containers: lowering nice values (CAP_SYS_NICE), raising hard
//! limits (CAP_SYS_RESOURCE), and acting on another user's process (as root,
//! and refused as `nobody`). Every process signalled, reniced or limited is
//! a `sleep` started inside the container. The host-built `resh` binary is
//! mounted read-only; nothing on the host is changed.
//!
//! Image: `debian:13-slim` (util-linux `setpriv` runs commands as nobody).
//!
//! Run with `cargo test --features e2e-docker --test proc_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;

const IMAGE: &str = "debian:13-slim";

/// `r <tag> <resh args...>` prints `<tag>\t<exit>\t<stdout>\t<stderr>` on
/// one line; `n <pid>` prints a process's nice value; `lim <pid> <row>`
/// its soft and hard limit. `R` runs resh as root, `NOBODY` as uid 65534.
const PRELUDE: &str = r#"
r() {
  tag=$1; shift
  out=$("$@" 2>/tmp/err); code=$?
  printf '%s\t%s\t%s\t%s\n' "$tag" "$code" "$(echo $out)" "$(cat /tmp/err)"
}
n() { awk '{print $19}' /proc/$1/stat; }
lim() { grep "^$2" /proc/$1/limits | awk '{print $(NF-2), $(NF-1)}'; }
NOBODY="setpriv --reuid=65534 --regid=65534 --clear-groups"
sleep 60 & P=$!
$NOBODY sleep 60 & Q=$!
sleep 0.2
"#;

/// One `r` line: exit code, parsed stdout, stderr.
struct Res {
    code: i32,
    json: Value,
    err: String,
}

struct Ctr {
    results: HashMap<String, Res>,
    /// Other lines (`check <name> <value>`), by name.
    checks: HashMap<String, String>,
    raw: String,
}

impl Ctr {
    fn get(&self, tag: &str) -> &Res {
        self.results
            .get(tag)
            .unwrap_or_else(|| panic!("no result {tag}:\n{}", self.raw))
    }
    fn ok(&self, tag: &str) -> &Value {
        let r = self.get(tag);
        assert_eq!(r.code, 0, "{tag}: {} {}", r.json, r.err);
        &r.json
    }
    fn fails(&self, tag: &str, exit: i32, code: &str) {
        let r = self.get(tag);
        assert_eq!(r.code, exit, "{tag}: {} {}", r.json, r.err);
        assert_eq!(r.json["error"]["code"], code, "{tag}: {}", r.json);
        assert!(
            r.err.starts_with(&format!("Error: [{code}] ")),
            "{tag}: {}",
            r.err
        );
    }
    fn check(&self, name: &str) -> &str {
        self.checks
            .get(name)
            .unwrap_or_else(|| panic!("no check {name}:\n{}", self.raw))
    }
}

/// Runs `script` (after PRELUDE) in a fresh container with `caps` added.
fn container(caps: &[&str], script: &str) -> Ctr {
    let bin = env!("CARGO_BIN_EXE_resh");
    let mount = format!("{bin}:/usr/local/bin/resh:ro");
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--network=none", "-v", &mount]);
    for c in caps {
        cmd.args(["--cap-add", c]);
    }
    let out = cmd
        .args([IMAGE, "sh", "-c"])
        .arg(format!("{PRELUDE}\n{script}"))
        .output()
        .unwrap();
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "container failed: {raw}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut results = HashMap::new();
    let mut checks = HashMap::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("check ") {
            let (k, v) = rest.split_once(' ').unwrap_or((rest, ""));
            checks.insert(k.to_string(), v.trim().to_string());
            continue;
        }
        let f: Vec<&str> = line.splitn(4, '\t').collect();
        if f.len() == 4 {
            results.insert(
                f[0].to_string(),
                Res {
                    code: f[1].parse().unwrap(),
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

#[test]
fn root_with_cap_sys_nice_lowers_nice_values() {
    let b = container(
        &["SYS_NICE"],
        r#"
r set10 resh proc://$P.nice.set value=10
r dec   resh proc://$P.nice.dec delta=5
echo "check after_dec $(n $P)"
r high  resh proc://$P.setPriority class=high
r rt    resh proc://$P.setPriority class=realtime
echo "check after_rt $(n $P)"
r set   resh proc://$P.nice.set value=-20
echo "check after_set $(n $P)"
r other resh proc://$Q.nice.set value=-3
echo "check other $(n $Q)"
r example resh proc://$Q.nice.set value=10
r example_dec resh --json-pretty proc://$Q.nice.dec delta=5
echo "check example $(n $Q)"
"#,
    );
    b.ok("set10");
    let dec = b.ok("dec");
    assert_eq!(dec["nice_before"], 10);
    assert_eq!(dec["nice_after"], 5);
    assert_eq!(b.check("after_dec"), "5");
    assert_eq!(b.ok("high")["nice"], -5);
    assert_eq!(b.ok("rt")["previous_nice"], -5);
    assert_eq!(b.check("after_rt"), "-10");
    assert_eq!(b.check("after_set"), "-20");
    b.ok("other");
    assert_eq!(b.check("other"), "-3");
    // The nice.dec help example, run as root.
    b.ok("example");
    assert_eq!(b.ok("example_dec")["nice_after"], 5);
    assert_eq!(b.check("example"), "5");
}

#[test]
fn root_without_cap_sys_nice_is_refused() {
    let b = container(
        &[],
        r#"
r set10 resh proc://$P.nice.set value=10
r dec   resh proc://$P.nice.dec delta=5
r prio  resh proc://$P.setPriority class=normal
echo "check nice $(n $P)"
r raise resh proc://$P.limits.set nofile=100:200
r back  resh proc://$P.limits.set nofile=:4096
echo "check nofile $(lim $P 'Max open files')"
"#,
    );
    b.ok("set10");
    b.fails("dec", 1, "proc.permission_denied");
    b.fails("prio", 1, "proc.permission_denied");
    assert_eq!(b.check("nice"), "10");
    b.ok("raise");
    b.fails("back", 1, "proc.permission_denied");
    assert_eq!(b.check("nofile"), "100 200");
}

#[test]
fn root_with_cap_sys_resource_raises_hard_limits() {
    let b = container(
        &["SYS_RESOURCE"],
        r#"
r lower resh proc://$P.limits.set nofile=100:200 core=0:0
r raise resh proc://$P.limits.set nofile=1000:4096 core=:unlimited
echo "check nofile $(lim $P 'Max open files')"
echo "check core $(lim $P 'Max core file size')"
r other resh proc://self.limits.set pid=$Q nofile=64:128 cpu=30s
echo "check other $(lim $Q 'Max open files')"
echo "check other_cpu $(lim $Q 'Max cpu time')"
r dry   resh proc://$Q.limits.set nofile=512:1024 dry_run=true
echo "check dry $(lim $Q 'Max open files')"
"#,
    );
    b.ok("lower");
    let raise = b.ok("raise");
    assert_eq!(raise["results"]["nofile"]["before"]["hard"], 200);
    assert_eq!(raise["results"]["nofile"]["after"]["hard"], 4096);
    assert_eq!(b.check("nofile"), "1000 4096");
    assert_eq!(b.check("core"), "0 unlimited");
    assert_eq!(b.ok("other")["results"]["cpu"]["after"]["soft"], 30);
    assert_eq!(b.check("other"), "64 128");
    assert_eq!(b.check("other_cpu"), "30 unlimited");
    assert_eq!(b.ok("dry")["dry_run"], true);
    assert_eq!(b.check("dry"), "64 128");
}

#[test]
fn root_signals_another_users_process() {
    let b = container(
        &[],
        r#"
r stop resh proc://$Q.stop
sleep 0.2
echo "check state $(awk '{print $3}' /proc/$Q/stat)"
r cont resh proc://$Q.cont
r usr1 resh proc://$Q.usr1
wait $Q; echo "check status $?"
"#,
    );
    assert_eq!(b.ok("stop")["signal"], "STOP");
    assert_eq!(b.check("state"), "T");
    b.ok("cont");
    assert_eq!(b.ok("usr1")["signal_num"], 10);
    // sh reports a death by signal n as 128 + n.
    assert_eq!(b.check("status"), "138");
}

#[test]
fn another_user_is_refused_and_nothing_changes() {
    let b = container(
        &["SYS_NICE", "SYS_RESOURCE"],
        r#"
r term  $NOBODY resh proc://$P.term
r zero  $NOBODY resh proc://$P.signal sig=0
r nice  $NOBODY resh proc://$P.nice.set value=19
r prio  $NOBODY resh proc://$P.setPriority class=idle
r inc   $NOBODY resh proc://$P.nice.inc delta=1
r lim   $NOBODY resh proc://$P.limits.set nofile=10
r limd  $NOBODY resh proc://$P.limits.set nofile=10 dry_run=true
r get   $NOBODY resh proc://$P.nice.get
r own   $NOBODY resh proc://$Q.nice.inc delta=2
r owndec $NOBODY resh proc://$Q.nice.dec delta=2
echo "check alive $(kill -0 $P && echo yes)"
echo "check nice $(n $P)"
echo "check nofile $(lim $P 'Max open files')"
echo "check own $(n $Q)"
"#,
    );
    for tag in ["term", "zero", "nice", "prio", "inc", "lim", "limd"] {
        b.fails(tag, 1, "proc.permission_denied");
    }
    // Reading a nice value is allowed for any process.
    assert_eq!(b.ok("get")["nice"], 0);
    assert_eq!(b.check("alive"), "yes");
    assert_eq!(b.check("nice"), "0");
    assert_ne!(b.check("nofile").split(' ').next(), Some("10"));
    // nobody's own process: raising works, lowering does not.
    assert_eq!(b.ok("own")["nice_after"], 2);
    b.fails("owndec", 1, "proc.permission_denied");
    assert_eq!(b.check("own"), "2");
}
