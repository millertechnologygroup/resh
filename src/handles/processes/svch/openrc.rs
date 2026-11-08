//! The svc verbs on OpenRC, through `rc-service`, `rc-status` and
//! `rc-update`. Each tool runs under the operation deadline; a tool still
//! running then is stopped (with everything it started) and the outcome is
//! reported as unknown (exit 124).

use super::{Ctx, Fail, Reply, Tools, run_tool};
use crate::core::status::exit;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(200);

/// Whether rc-service says the service does not exist.
pub(crate) fn service_missing(output: &str) -> bool {
    output.contains("does not exist")
}

fn missing(name: &str) -> Fail {
    Fail::new(
        exit::FAILED,
        "svc.not_found",
        format!("service '{name}' does not exist"),
    )
}

/// The first `pid <n>` / `pid: <n>` in rc-service output.
pub(crate) fn parse_pid(text: &str) -> Option<u32> {
    let lower = text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("pid") {
        let before_ok = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric();
        let after = rest[i + 3..].trim_start_matches(':').trim_start();
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if before_ok && !digits.is_empty() {
            return digits.parse().ok();
        }
        rest = &rest[i + 3..];
    }
    None
}

/// `(state, pid, raw output)`; state is `running` or `stopped_or_unknown`.
pub(crate) fn state(t: &Tools, c: &Ctx) -> Result<(String, Option<u32>, String), Fail> {
    let out = run_tool(&t.rc_service, &[&c.name, "status"], c.deadline)?;
    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if service_missing(&raw) {
        return Err(missing(&c.name));
    }
    let running = raw.contains("started") || raw.contains("running");
    let state = if running {
        "running"
    } else {
        "stopped_or_unknown"
    };
    Ok((state.to_string(), parse_pid(&raw), raw))
}

pub(crate) fn status(t: &Tools, c: &Ctx) -> Reply {
    match state(t, c) {
        Ok((state, pid, raw)) => Reply::ok(json!({
            "name": c.name,
            "backend": "openrc",
            "state": state,
            "pid": pid,
            "exit_status": null,
            "timestamps": null,
            "raw": raw,
        })),
        Err(f) => Reply::failed(Some(json!({"name": c.name, "backend": "openrc"})), f),
    }
}

/// Runs `rc-service <name> <action>` and checks it succeeded.
pub(crate) fn control(t: &Tools, c: &Ctx, action: &str) -> Result<(), Fail> {
    let out = run_tool(&t.rc_service, &[&c.name, action], c.deadline)?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if service_missing(&text) {
        return Err(missing(&c.name));
    }
    if !out.status.success() {
        return Err(Fail::new(
            exit::FAILED,
            "svc.failed",
            format!(
                "rc-service {} {action} failed ({}): {}",
                c.name,
                out.status,
                text.trim()
            ),
        ));
    }
    Ok(())
}

/// start and restart: rc-service waits until the service is started.
pub(crate) fn start(t: &Tools, c: &Ctx, action: &str) -> Reply {
    let obj = json!({"backend": "openrc", "name": c.name, "action": action});
    match control(t, c, action) {
        Ok(()) => {
            let mut obj = obj;
            obj["result"] = json!("success");
            if let Ok((state, _, _)) = state(t, c) {
                obj["state"] = json!(state);
            }
            Reply::ok(obj)
        }
        Err(f) => Reply::failed(Some(obj), f),
    }
}

pub(crate) fn stop(t: &Tools, c: &Ctx) -> Reply {
    let mut obj = json!({
        "name": c.name,
        "backend": "openrc",
        "action": "stop",
        "requested": false,
        "timeout_ms": c.timeout_ms,
    });
    let before = match state(t, c) {
        Ok(s) => s.0,
        Err(f) => return Reply::failed(Some(obj), f),
    };
    obj["previous_state"] = json!(before);
    if let Err(f) = control(t, c, "stop") {
        return Reply::failed(Some(obj), f);
    }
    obj["requested"] = json!(true);
    let after = state(t, c)
        .map(|s| s.0)
        .unwrap_or_else(|_| "stopped_or_unknown".to_string());
    obj["reached_inactive"] = json!(after != "running");
    obj["final_state"] = json!(after);
    if after == "running" {
        let f = Fail::new(
            exit::FAILED,
            "svc.failed",
            format!(
                "rc-service {} stop succeeded but the service still runs",
                c.name
            ),
        );
        return Reply::failed(Some(obj), f);
    }
    Reply::ok(obj)
}

pub(crate) fn reload(t: &Tools, c: &Ctx) -> Reply {
    match control(t, c, "reload") {
        Ok(()) => Reply::ok_empty(),
        Err(f) => Reply::failed(None, f),
    }
}

/// Whether the service exists (`rc-service --exists`).
fn exists(t: &Tools, c: &Ctx) -> Result<bool, Fail> {
    let out = run_tool(&t.rc_service, &["--exists", &c.name], c.deadline)?;
    Ok(out.status.success())
}

pub(crate) fn enable(t: &Tools, c: &Ctx, on: bool) -> Reply {
    match exists(t, c) {
        Ok(true) => {}
        Ok(false) => return Reply::failed(None, missing(&c.name)),
        Err(f) => return Reply::failed(None, f),
    }
    let action = if on { "add" } else { "del" };
    let out = match run_tool(&t.rc_update, &[action, &c.name, "default"], c.deadline) {
        Ok(o) => o,
        Err(f) => return Reply::failed(None, f),
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Adding a service already in the runlevel, or removing one that is
    // not, leaves the wanted state: not a failure.
    let already = text.contains("already installed") || text.contains("not in the runlevel");
    if !out.status.success() && !already {
        return Reply::failed(
            None,
            Fail::new(
                exit::FAILED,
                "svc.failed",
                format!(
                    "rc-update {action} {} default failed ({}): {}",
                    c.name,
                    out.status,
                    text.trim()
                ),
            ),
        );
    }
    Reply::ok_empty()
}

pub(crate) fn is_enabled(t: &Tools, c: &Ctx) -> Reply {
    let obj = json!({"name": c.name, "backend": "openrc"});
    match exists(t, c) {
        Ok(true) => {}
        Ok(false) => return Reply::failed(Some(obj), missing(&c.name)),
        Err(f) => return Reply::failed(Some(obj), f),
    }
    let out = match run_tool(&t.rc_update, &["show", "default"], c.deadline) {
        Ok(o) => o,
        Err(f) => return Reply::failed(Some(obj), f),
    };
    if !out.status.success() {
        let f = Fail::new(
            exit::FAILED,
            "svc.failed",
            format!(
                "rc-update show default failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        );
        return Reply::failed(Some(obj), f);
    }
    let listed = String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.split_whitespace().next() == Some(c.name.as_str()));
    let mut obj = obj;
    obj["enabled"] = json!(listed);
    Reply::ok(obj)
}

pub(crate) fn wait(t: &Tools, c: &Ctx, want_running: bool, wanted: &str) -> Reply {
    let mut obj = json!({
        "name": c.name,
        "backend": "openrc",
        "state": wanted,
        "timeout_ms": c.timeout_ms,
        "reached": false,
    });
    loop {
        match state(t, c) {
            Ok((s, _, _)) => {
                if (s == "running") == want_running {
                    obj["reached"] = json!(true);
                    return Reply::ok(obj);
                }
            }
            Err(f) if f.code == "svc.timeout" => break,
            Err(f) => return Reply::failed(Some(obj), f),
        }
        let now = Instant::now();
        if now >= c.deadline {
            break;
        }
        std::thread::sleep(POLL.min(c.deadline - now));
    }
    let f = Fail::new(
        exit::TIMEOUT,
        "svc.timeout",
        format!(
            "{} did not become {wanted} within timeout_ms={}",
            c.name, c.timeout_ms
        ),
    );
    Reply::failed(Some(obj), f)
}

pub(crate) fn scale(t: &Tools, c: &Ctx, count: u32) -> Reply {
    let mut obj: Value = json!({
        "name": c.name,
        "backend": "openrc",
        "desired_count": count,
        "note": "openrc scaling is min/max 1 only",
    });
    let running = match state(t, c) {
        Ok(s) => s.0 == "running",
        Err(f) => return Reply::failed(Some(obj), f),
    };
    let r = match (count, running) {
        (0, true) => control(t, c, "stop"),
        (n, false) if n > 0 => control(t, c, "start"),
        _ => Ok(()),
    };
    let now = state(t, c).map(|s| s.0 == "running").unwrap_or(false);
    obj["effective_count"] = json!(u32::from(now));
    match r {
        Ok(()) => Reply::ok(obj),
        Err(f) => Reply::failed(Some(obj), f),
    }
}
