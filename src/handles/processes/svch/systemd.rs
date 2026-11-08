//! The svc verbs on systemd, written against the [`Bus`] seam.
//!
//! Lifecycle verbs (start, stop, restart, reload, scale) queue a job and
//! wait for systemd's `JobRemoved` signal, so the result reports the job's
//! real outcome. At the deadline the job is cancelled; the result is exit
//! 124 either way, saying whether the cancel worked.

use super::bus::{Bus, BusErrKind, BusError, FileOp, JobWatch, UnitInfo};
use super::{Ctx, Fail, Reply};
use crate::core::status::exit;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Time between state checks in `wait`.
const POLL: Duration = Duration::from_millis(200);
/// Time to wait for the signal of a job just cancelled.
const CANCELLED_SIGNAL_WAIT: Duration = Duration::from_secs(2);

/// How a job ended.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JobEnd {
    /// systemd's job result.
    Result(String),
    /// The deadline passed first; `canceled` says whether the cancel worked.
    TimedOut { canceled: bool },
}

impl JobEnd {
    pub fn succeeded(&self) -> bool {
        matches!(self, JobEnd::Result(r) if r == "done" || r == "skipped")
    }
}

/// Maps a service-manager error to the svc error codes.
pub(crate) fn bus_fail(e: BusError, unit: &str) -> Fail {
    match e.kind {
        BusErrKind::NotFound => Fail::new(
            exit::FAILED,
            "svc.not_found",
            format!("unit {unit} not found: {}", e.msg),
        ),
        BusErrKind::Denied => Fail::new(
            exit::FAILED,
            "svc.permission_denied",
            format!(
                "not permitted for {unit} (run as root or add a polkit rule): {}",
                e.msg
            ),
        ),
        BusErrKind::Conflict => Fail::new(
            exit::FAILED,
            "svc.link_conflict",
            format!(
                "a file or link for {unit} is in the way (force=true replaces conflicting \
                 symlinks; a real file must be removed by hand): {}",
                e.msg
            ),
        ),
        BusErrKind::Masked => Fail::new(
            exit::FAILED,
            "svc.masked",
            format!("unit {unit} is masked: {}", e.msg),
        ),
        BusErrKind::Timeout => Fail::new(exit::TIMEOUT, "svc.timeout", e.msg),
        BusErrKind::Unavailable => Fail::new(
            exit::FAILED,
            "svc.backend_unavailable",
            format!("cannot reach systemd: {}", e.msg),
        ),
        BusErrKind::Other => Fail::new(exit::FAILED, "svc.failed", e.msg),
    }
}

fn not_found(unit: &str) -> Fail {
    Fail::new(
        exit::FAILED,
        "svc.not_found",
        format!("unit {unit} not found"),
    )
}

/// Loads `unit`; a unit that does not exist is `svc.not_found`.
fn existing(bus: &dyn Bus, unit: &str) -> Result<UnitInfo, Fail> {
    let info = bus.unit(unit).map_err(|e| bus_fail(e, unit))?;
    if info.load_state == "not-found" {
        return Err(not_found(unit));
    }
    Ok(info)
}

fn fmt_ts_us(us: u64) -> String {
    use chrono::{TimeZone, Utc};
    if us == 0 {
        return String::new();
    }
    let secs = (us / 1_000_000) as i64;
    let nsec = ((us % 1_000_000) * 1000) as u32;
    Utc.timestamp_opt(secs, nsec)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Waits for every job in `jobs` until `deadline`; cancels those still
/// running then.
pub(crate) fn run_jobs(
    bus: &dyn Bus,
    watch: &mut dyn JobWatch,
    jobs: &[String],
    deadline: Instant,
) -> Vec<JobEnd> {
    let mut ends: HashMap<&str, JobEnd> = HashMap::new();
    while ends.len() < jobs.len() {
        let Some(done) = watch.next(deadline) else {
            break;
        };
        if let Some(j) = jobs.iter().find(|j| **j == done.path) {
            ends.insert(j.as_str(), JobEnd::Result(done.result));
        }
    }
    let pending: Vec<&String> = jobs
        .iter()
        .filter(|j| !ends.contains_key(j.as_str()))
        .collect();
    if !pending.is_empty() {
        let mut canceled: HashMap<&str, bool> = HashMap::new();
        for j in &pending {
            canceled.insert(j.as_str(), bus.cancel_job(j).is_ok());
        }
        // A job can finish while it is being cancelled; its signal decides.
        let grace = Instant::now() + CANCELLED_SIGNAL_WAIT;
        while pending.iter().any(|j| !ends.contains_key(j.as_str())) {
            let Some(done) = watch.next(grace) else {
                break;
            };
            if let Some(j) = pending.iter().find(|j| ***j == done.path) {
                let end = if done.result == "canceled" {
                    JobEnd::TimedOut { canceled: true }
                } else {
                    JobEnd::Result(done.result)
                };
                ends.insert(j.as_str(), end);
            }
        }
        for j in pending {
            let c = canceled[j.as_str()];
            ends.entry(j.as_str())
                .or_insert(JobEnd::TimedOut { canceled: c });
        }
    }
    jobs.iter().map(|j| ends[j.as_str()].clone()).collect()
}

/// Queues one job and waits for it.
fn one_job(
    bus: &dyn Bus,
    method: &'static str,
    unit: &str,
    mode: &'static str,
    deadline: Instant,
) -> Result<JobEnd, Fail> {
    let mut watch = bus.watch_jobs().map_err(|e| bus_fail(e, unit))?;
    let job = bus.enqueue(method, unit, mode).map_err(|e| match e.kind {
        // The request may have reached systemd: the outcome is unknown.
        BusErrKind::Timeout => Fail::new(
            exit::TIMEOUT,
            "svc.timeout",
            format!(
                "{}; the {method} request for {unit} may or may not have been accepted",
                e.msg
            ),
        ),
        _ => bus_fail(e, unit),
    })?;
    Ok(run_jobs(bus, watch.as_mut(), &[job], deadline)
        .pop()
        .unwrap_or(JobEnd::TimedOut { canceled: false }))
}

/// The failure for a job that did not succeed.
fn job_fail(action: &str, unit: &str, end: &JobEnd, timeout_ms: u64) -> Fail {
    match end {
        JobEnd::Result(r) => Fail::new(
            exit::FAILED,
            "svc.job_failed",
            format!(
                "the {action} job for {unit} finished with result '{r}' \
                 (see svc://<service>.status and .logs)"
            ),
        ),
        JobEnd::TimedOut { canceled: true } => Fail::new(
            exit::TIMEOUT,
            "svc.timeout",
            format!(
                "timeout_ms={timeout_ms} passed before the {action} job for {unit} finished; \
                 the job was cancelled, but what it already did stays done"
            ),
        ),
        JobEnd::TimedOut { canceled: false } => Fail::new(
            exit::TIMEOUT,
            "svc.timeout",
            format!(
                "timeout_ms={timeout_ms} passed before the {action} job for {unit} finished \
                 and the job could not be cancelled; the outcome is unknown"
            ),
        ),
    }
}

fn job_fields(obj: &mut Value, end: &JobEnd) {
    match end {
        JobEnd::Result(r) => obj["job_result"] = json!(r),
        JobEnd::TimedOut { canceled } => {
            obj["job_result"] = Value::Null;
            obj["job_canceled"] = json!(canceled);
        }
    }
}

fn state_fields(bus: &dyn Bus, unit: &str, obj: &mut Value) {
    if let Ok(info) = bus.unit(unit) {
        obj["active_state"] = json!(info.active_state);
        obj["sub_state"] = json!(info.sub_state);
    }
}

pub(crate) fn status(bus: &dyn Bus, c: &Ctx) -> Reply {
    let base = json!({"name": c.unit, "backend": "systemd"});
    match existing(bus, &c.unit) {
        Err(f) => Reply::failed(Some(base), f),
        Ok(info) => Reply::ok(json!({
            "name": c.unit,
            "backend": "systemd",
            "active_state": info.active_state,
            "sub_state": info.sub_state,
            "description": info.description,
            "pid": info.pid,
            "exit_status": info.exit_status,
            "timestamps": {
                "active_enter": fmt_ts_us(info.active_enter_us),
                "active_exit": fmt_ts_us(info.active_exit_us),
                "inactive_enter": fmt_ts_us(info.inactive_enter_us),
            }
        })),
    }
}

pub(crate) fn is_enabled(bus: &dyn Bus, c: &Ctx) -> Reply {
    let mut obj = json!({"name": c.name, "backend": "systemd"});
    match bus.unit_file_state(&c.unit) {
        Ok(state) => {
            obj["enabled"] = json!(matches!(state.as_str(), "enabled" | "static" | "indirect"));
            obj["unit_file_state"] = json!(state);
            Reply::ok(obj)
        }
        Err(e) => Reply::failed(Some(obj), bus_fail(e, &c.unit)),
    }
}

/// start and restart.
/// Time between state checks while a started unit settles.
const SETTLE_POLL: Duration = Duration::from_millis(100);

/// Whether a unit whose start job succeeded is running as it should:
/// `active` or `reloading`; `activating`, except in `auto-restart` (it
/// exited and waits to be restarted); or, for a oneshot service without
/// `RemainAfterExit`, `inactive` after a successful run.
pub(crate) fn running_ok(i: &UnitInfo) -> bool {
    match i.active_state.as_str() {
        "active" | "reloading" => true,
        "activating" => i.sub_state != "auto-restart",
        "inactive" => {
            i.service_type == "oneshot"
                && !i.remain_after_exit
                && (i.result.is_empty() || i.result == "success")
        }
        _ => false,
    }
}

/// Watches `unit` for `settle` (bounded by the deadline) after a start
/// job succeeded: (true, last state) when it stayed running, otherwise
/// (false, the first state that was not, or `None` when it could not be
/// read).
fn settle(
    bus: &dyn Bus,
    unit: &str,
    settle: Duration,
    deadline: Instant,
) -> (bool, Option<UnitInfo>) {
    let end = (Instant::now() + settle).min(deadline);
    let mut last = None;
    loop {
        if let Ok(i) = bus.unit(unit) {
            if !running_ok(&i) {
                return (false, Some(i));
            }
            last = Some(i);
        }
        let now = Instant::now();
        if now >= end {
            return (last.is_some(), last);
        }
        std::thread::sleep(SETTLE_POLL.min(end - now));
    }
}

pub(crate) fn start(bus: &dyn Bus, c: &Ctx, action: &'static str, settle_for: Duration) -> Reply {
    let method = if action == "restart" {
        "RestartUnit"
    } else {
        "StartUnit"
    };
    let mut obj = json!({"backend": "systemd", "name": c.unit, "action": action});
    let end = match one_job(bus, method, &c.unit, "replace", c.deadline) {
        Ok(end) => end,
        Err(f) => {
            if f.code == "svc.timeout" {
                obj["result"] = json!("timeout");
                obj["job_canceled"] = json!(false);
            }
            return Reply::failed(Some(obj), f);
        }
    };
    job_fields(&mut obj, &end);
    if end.succeeded() {
        match settle(bus, &c.unit, settle_for, c.deadline) {
            (true, Some(i)) => {
                obj["active_state"] = json!(i.active_state);
                obj["sub_state"] = json!(i.sub_state);
                obj["result"] = json!("success");
                Reply::ok(obj)
            }
            (_, info) => {
                obj["result"] = json!("not_active");
                let state = match &info {
                    Some(i) => {
                        obj["active_state"] = json!(i.active_state);
                        obj["sub_state"] = json!(i.sub_state);
                        obj["unit_result"] = json!(i.result);
                        format!(
                            "{}/{} (result '{}')",
                            i.active_state,
                            i.sub_state,
                            if i.result.is_empty() {
                                "n/a"
                            } else {
                                &i.result
                            }
                        )
                    }
                    None => "unknown (its state could not be read)".to_string(),
                };
                let f = Fail::new(
                    exit::FAILED,
                    "svc.not_active",
                    format!(
                        "the {action} job for {} finished, but the unit is {state}; \
                         see svc://<service>.status and .logs",
                        c.unit
                    ),
                );
                Reply::failed(Some(obj), f)
            }
        }
    } else {
        state_fields(bus, &c.unit, &mut obj);
        obj["result"] = json!(if matches!(end, JobEnd::TimedOut { .. }) {
            "timeout"
        } else {
            "failed"
        });
        let f = job_fail(action, &c.unit, &end, c.timeout_ms);
        Reply::failed(Some(obj), f)
    }
}

fn is_inactive(state: &str) -> bool {
    matches!(state, "inactive" | "failed")
}

pub(crate) fn stop(bus: &dyn Bus, c: &Ctx, force: bool) -> Reply {
    let mut obj = json!({
        "name": c.unit,
        "backend": "systemd",
        "action": "stop",
        "requested": false,
        "timeout_ms": c.timeout_ms,
    });
    let before = match existing(bus, &c.unit) {
        Ok(i) => i,
        Err(f) => return Reply::failed(Some(obj), f),
    };
    obj["previous_state"] = json!(before.active_state);
    let mode = if force {
        "replace-irreversibly"
    } else {
        "replace"
    };
    let end = match one_job(bus, "StopUnit", &c.unit, mode, c.deadline) {
        Ok(end) => end,
        Err(f) => {
            if f.code == "svc.timeout" {
                obj["job_canceled"] = json!(false);
            }
            return Reply::failed(Some(obj), f);
        }
    };
    obj["requested"] = json!(true);
    obj["note"] = json!(if force {
        "stopped via force (StopUnit replace-irreversibly)"
    } else {
        "stopped via StopUnit"
    });
    job_fields(&mut obj, &end);
    let after = bus
        .unit(&c.unit)
        .map(|i| i.active_state)
        .unwrap_or_else(|_| "unknown".to_string());
    obj["reached_inactive"] = json!(is_inactive(&after));
    obj["final_state"] = json!(after);
    if end.succeeded() {
        Reply::ok(obj)
    } else {
        let f = job_fail("stop", &c.unit, &end, c.timeout_ms);
        Reply::failed(Some(obj), f)
    }
}

pub(crate) fn reload(bus: &dyn Bus, c: &Ctx) -> Reply {
    match one_job(bus, "ReloadUnit", &c.unit, "replace", c.deadline) {
        Ok(end) if end.succeeded() => Reply::ok_empty(),
        Ok(end) => Reply::failed(None, job_fail("reload", &c.unit, &end, c.timeout_ms)),
        Err(f) => Reply::failed(None, f),
    }
}

/// enable, disable, mask and unmask. Warnings go to `warn`.
pub(crate) fn unit_files(
    bus: &dyn Bus,
    c: &Ctx,
    op: FileOp,
    force: bool,
    warn: &mut Vec<String>,
) -> Reply {
    let changes = match bus.unit_files(op, &c.unit, force) {
        Ok(ch) => ch,
        Err(e) => {
            let mut f = bus_fail(e, &c.unit);
            if f.code == "svc.timeout" {
                f.msg
                    .push_str("; the unit files may or may not have been changed");
            }
            return Reply::failed(None, f);
        }
    };
    if op == FileOp::Enable
        && changes.carries_install_info == Some(false)
        && changes.changes.is_empty()
    {
        warn.push(format!(
            "{} has no [Install] section, so enable changed nothing; it can still be \
             started by other units or by hand",
            c.unit
        ));
    }
    if let Err(e) = bus.daemon_reload() {
        let mut f = bus_fail(e, &c.unit);
        f.msg = format!(
            "the unit files of {} were changed ({}), but reloading systemd failed: {}",
            c.unit,
            op.verb(),
            f.msg
        );
        return Reply::failed(None, f);
    }
    Reply::ok_empty()
}

pub(crate) fn wait(bus: &dyn Bus, c: &Ctx, want_active: bool, state: &str) -> Reply {
    let mut obj = json!({
        "name": c.name,
        "backend": "systemd",
        "state": state,
        "timeout_ms": c.timeout_ms,
        "reached": false,
    });
    loop {
        match bus.unit(&c.unit) {
            Ok(info) if info.load_state == "not-found" => {
                return Reply::failed(Some(obj), not_found(&c.unit));
            }
            Ok(info) => {
                let reached = if want_active {
                    info.active_state == "active"
                } else {
                    is_inactive(&info.active_state)
                };
                obj["active_state"] = json!(info.active_state);
                if reached {
                    obj["reached"] = json!(true);
                    return Reply::ok(obj);
                }
            }
            Err(e) if e.kind == BusErrKind::Timeout => break,
            Err(e) => return Reply::failed(Some(obj), bus_fail(e, &c.unit)),
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
            "{} did not become {state} within timeout_ms={}",
            c.unit, c.timeout_ms
        ),
    );
    Reply::failed(Some(obj), f)
}

/// The template prefix of `unit` (`worker` for `worker@.service`).
pub(crate) fn template_base(unit: &str) -> Option<&str> {
    unit.strip_suffix("@.service").filter(|b| !b.is_empty())
}

/// The instance number of `name` for template `base`, if it is one.
fn instance_of(base: &str, name: &str) -> Option<u32> {
    name.strip_prefix(base)?
        .strip_prefix('@')?
        .strip_suffix(".service")?
        .parse()
        .ok()
}

pub(crate) fn scale(bus: &dyn Bus, c: &Ctx, count: u32) -> Reply {
    match template_base(&c.unit) {
        Some(base) => scale_template(bus, c, base, count),
        None => scale_plain(bus, c, count),
    }
}

fn scale_template(bus: &dyn Bus, c: &Ctx, base: &str, count: u32) -> Reply {
    let mut obj = json!({
        "name": c.unit,
        "backend": "systemd",
        "desired_count": count,
        "template": true,
    });
    let units = match bus.list_units() {
        Ok(u) => u,
        Err(e) => return Reply::failed(Some(obj), bus_fail(e, &c.unit)),
    };
    let active: HashMap<u32, bool> = units
        .iter()
        .filter_map(|(n, st)| instance_of(base, n).map(|i| (i, st == "active")))
        .collect();
    let mut plan: Vec<(String, &'static str)> = Vec::new();
    for i in 1..=count {
        if !active.get(&i).copied().unwrap_or(false) {
            plan.push((format!("{base}@{i}.service"), "start"));
        }
    }
    let mut above: Vec<u32> = active
        .iter()
        .filter(|(i, a)| **i > count && **a)
        .map(|(i, _)| *i)
        .collect();
    above.sort_unstable();
    for i in above {
        plan.push((format!("{base}@{i}.service"), "stop"));
    }

    let mut errors: Vec<String> = Vec::new();
    let (mut started, mut stopped) = (Vec::new(), Vec::new());
    let mut timed_out = false;
    let mut watch = match bus.watch_jobs() {
        Ok(w) => w,
        Err(e) => return Reply::failed(Some(obj), bus_fail(e, &c.unit)),
    };
    let mut queued: Vec<(String, &'static str, String)> = Vec::new();
    for (unit, action) in plan {
        let method = if action == "start" {
            "StartUnit"
        } else {
            "StopUnit"
        };
        match bus.enqueue(method, &unit, "replace") {
            Ok(job) => queued.push((unit, action, job)),
            Err(e) => {
                if e.kind == BusErrKind::Timeout {
                    timed_out = true;
                }
                errors.push(format!("Failed to {action} {unit}: {}", e.msg));
            }
        }
    }
    let jobs: Vec<String> = queued.iter().map(|q| q.2.clone()).collect();
    let ends = run_jobs(bus, watch.as_mut(), &jobs, c.deadline);
    for ((unit, action, _), end) in queued.into_iter().zip(ends) {
        match (&end, action) {
            (e, "start") if e.succeeded() => started.push(unit),
            (e, _) if e.succeeded() => stopped.push(unit),
            (JobEnd::Result(r), _) => {
                errors.push(format!("Failed to {action} {unit}: job result '{r}'"))
            }
            (JobEnd::TimedOut { canceled }, _) => {
                timed_out = true;
                errors.push(format!(
                    "{action} of {unit} did not finish before the deadline (job {})",
                    if *canceled {
                        "cancelled"
                    } else {
                        "not cancelled"
                    }
                ));
            }
        }
    }
    let effective = bus
        .list_units()
        .map(|u| {
            u.iter()
                .filter(|(n, st)| st == "active" && instance_of(base, n).is_some())
                .count()
        })
        .ok();
    obj["instances_started"] = json!(started);
    obj["instances_stopped"] = json!(stopped);
    obj["effective_count"] = json!(effective);
    obj["note"] = json!("scaled systemd template unit");
    if errors.is_empty() {
        return Reply::ok(obj);
    }
    obj["errors"] = json!(errors);
    let f = if timed_out {
        Fail::new(
            exit::TIMEOUT,
            "svc.timeout",
            format!(
                "timeout_ms={} passed before every instance of {} was scaled; \
                 see errors and effective_count",
                c.timeout_ms, c.unit
            ),
        )
    } else {
        Fail::new(
            exit::FAILED,
            "svc.partial_failure",
            format!(
                "scaling {} completed with {} error(s); see errors",
                c.unit,
                errors.len()
            ),
        )
    };
    Reply::failed(Some(obj), f)
}

fn scale_plain(bus: &dyn Bus, c: &Ctx, count: u32) -> Reply {
    let mut obj = json!({
        "name": c.unit,
        "backend": "systemd",
        "desired_count": count,
        "template": false,
        "note": format!("non-template service scaled to {}", if count == 0 { 0 } else { 1 }),
    });
    let before = match existing(bus, &c.unit) {
        Ok(i) => i,
        Err(f) => return Reply::failed(Some(obj), f),
    };
    let active = before.active_state == "active";
    let job = match (count, active) {
        (0, true) => Some(("StopUnit", "stop")),
        (n, false) if n > 0 => Some(("StartUnit", "start")),
        _ => None,
    };
    let mut fail = None;
    if let Some((method, action)) = job {
        match one_job(bus, method, &c.unit, "replace", c.deadline) {
            Ok(end) if end.succeeded() => {}
            Ok(end) => fail = Some(job_fail(action, &c.unit, &end, c.timeout_ms)),
            Err(f) => fail = Some(f),
        }
    }
    let now_active = bus
        .unit(&c.unit)
        .map(|i| i.active_state == "active")
        .unwrap_or(false);
    obj["effective_count"] = json!(u32::from(now_active));
    match fail {
        None => Reply::ok(obj),
        Some(f) => Reply::failed(Some(obj), f),
    }
}
