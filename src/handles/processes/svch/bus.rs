//! The seam between the svc verbs and systemd. [`Bus`] is the small set of
//! service-manager operations the verbs need. [`ZbusBus`] implements it over
//! the system D-Bus; [`SystemctlBus`] over `systemctl`, used when the bus
//! cannot be reached. Unit tests use a scripted mock (see `tests.rs`).
//!
//! Every call is bounded by the operation deadline: a D-Bus call runs on a
//! helper thread and is abandoned (reported as [`BusErrKind::Timeout`]) when
//! the deadline passes; a `systemctl` run is stopped at the deadline.

use crate::core::process;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io;
use std::process::Command;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEST: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// Time allowed for cancelling a job once the deadline has passed.
pub(crate) const CANCEL_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BusErrKind {
    /// The service manager could not be reached at all.
    Unavailable,
    /// No such unit or unit file.
    NotFound,
    /// Refused for lack of privileges.
    Denied,
    /// The unit is masked.
    Masked,
    /// The deadline passed before the service manager answered.
    Timeout,
    /// Any other refusal or failure.
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct BusError {
    pub kind: BusErrKind,
    pub msg: String,
}

impl BusError {
    pub fn new(kind: BusErrKind, msg: impl Into<String>) -> Self {
        BusError {
            kind,
            msg: msg.into(),
        }
    }
}

/// The state of one unit.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct UnitInfo {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
    pub pid: u32,
    pub exit_status: i32,
    pub active_enter_us: u64,
    pub active_exit_us: u64,
    pub inactive_enter_us: u64,
}

/// A finished job: its object path and systemd's result (`done`, `failed`,
/// `canceled`, `timeout`, `dependency`, `skipped`, ...).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JobRemoved {
    pub path: String,
    pub result: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileOp {
    Enable,
    Disable,
    Mask,
    Unmask,
}

impl FileOp {
    pub fn verb(self) -> &'static str {
        match self {
            FileOp::Enable => "enable",
            FileOp::Disable => "disable",
            FileOp::Mask => "mask",
            FileOp::Unmask => "unmask",
        }
    }
}

/// What a unit-file change did.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct FileChanges {
    /// For enable: whether the unit file has an `[Install]` section.
    pub carries_install_info: Option<bool>,
    /// (type, file, destination) for each symlink created or removed.
    pub changes: Vec<(String, String, String)>,
}

/// Delivers finished jobs. Created before the jobs are queued, so no
/// result can be missed.
pub(crate) trait JobWatch {
    /// The next finished job, or `None` once `until` has passed.
    fn next(&mut self, until: Instant) -> Option<JobRemoved>;
}

pub(crate) trait Bus {
    /// Loads `unit` and reads its state. A unit that does not exist is
    /// reported with `load_state` `not-found`, not as an error.
    fn unit(&self, unit: &str) -> Result<UnitInfo, BusError>;
    /// The unit-file state (`enabled`, `disabled`, `static`, `masked`, ...).
    fn unit_file_state(&self, unit: &str) -> Result<String, BusError>;
    fn watch_jobs(&self) -> Result<Box<dyn JobWatch>, BusError>;
    /// Queues a job (`StartUnit`, `StopUnit`, `RestartUnit`, `ReloadUnit`)
    /// and returns its object path.
    fn enqueue(
        &self,
        method: &'static str,
        unit: &str,
        mode: &'static str,
    ) -> Result<String, BusError>;
    fn cancel_job(&self, job: &str) -> Result<(), BusError>;
    fn unit_files(&self, op: FileOp, unit: &str) -> Result<FileChanges, BusError>;
    /// Makes the service manager re-read unit files after a change.
    fn daemon_reload(&self) -> Result<(), BusError>;
    /// Loaded units as (name, active state).
    fn list_units(&self) -> Result<Vec<(String, String)>, BusError>;
}

// ---------------------------------------------------------------------------
// D-Bus

/// systemd over the system D-Bus (zbus).
pub(crate) struct ZbusBus {
    conn: zbus::blocking::Connection,
    deadline: Instant,
}

/// Runs `f` on a helper thread and waits for it until `until`.
fn timed<T, F>(until: Instant, what: &str, f: F) -> Result<T, BusError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, BusError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    let wait = until.saturating_duration_since(Instant::now());
    match rx.recv_timeout(wait) {
        Ok(r) => r,
        Err(_) => Err(BusError::new(
            BusErrKind::Timeout,
            format!("the service manager did not answer {what} before the deadline"),
        )),
    }
}

/// Classifies a D-Bus error by its error name.
pub(crate) fn classify(name: &str, desc: &str) -> BusError {
    let last = name.rsplit('.').next().unwrap_or(name);
    let kind = match last {
        "NoSuchUnit" | "FileNotFound" | "ENOENT" | "NoSuchFile" | "UnknownObject" => {
            BusErrKind::NotFound
        }
        "AccessDenied" | "InteractiveAuthorizationRequired" | "EPERM" | "EACCES" => {
            BusErrKind::Denied
        }
        "UnitMasked" => BusErrKind::Masked,
        "ServiceUnknown" | "NameHasNoOwner" | "NoServer" | "Disconnected" => {
            BusErrKind::Unavailable
        }
        _ => BusErrKind::Other,
    };
    let msg = if desc.is_empty() {
        name.to_string()
    } else {
        format!("{desc} ({name})")
    };
    BusError::new(kind, msg)
}

fn map_zbus(e: zbus::Error) -> BusError {
    use zbus::DBusError;
    match &e {
        zbus::Error::MethodError(name, desc, _) => {
            classify(name.as_str(), desc.as_deref().unwrap_or(""))
        }
        zbus::Error::FDO(f) => classify(f.name().as_str(), f.description().unwrap_or("")),
        zbus::Error::InputOutput(_) | zbus::Error::Address(_) | zbus::Error::Handshake(_) => {
            BusError::new(BusErrKind::Unavailable, e.to_string())
        }
        _ => BusError::new(BusErrKind::Other, e.to_string()),
    }
}

fn manager(conn: &zbus::blocking::Connection) -> Result<zbus::blocking::Proxy<'static>, BusError> {
    zbus::blocking::Proxy::new(conn, DEST, MANAGER_PATH, MANAGER).map_err(map_zbus)
}

type Props = HashMap<String, zvariant::OwnedValue>;

fn get_all(conn: &zbus::blocking::Connection, path: &str, iface: &str) -> Result<Props, BusError> {
    let p =
        zbus::blocking::Proxy::new(conn, DEST, path.to_string(), PROPERTIES).map_err(map_zbus)?;
    p.call("GetAll", &(iface,)).map_err(map_zbus)
}

fn prop<T: TryFrom<zvariant::OwnedValue>>(props: &Props, key: &str) -> Option<T> {
    props.get(key).and_then(|v| T::try_from(v.clone()).ok())
}

type ListedUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    zvariant::OwnedObjectPath,
    u32,
    String,
    zvariant::OwnedObjectPath,
);

impl ZbusBus {
    /// Connects to the system bus, within `deadline`.
    pub fn connect(deadline: Instant) -> Result<Self, BusError> {
        let conn = timed(deadline, "the connection", || {
            zbus::blocking::Connection::system().map_err(|e| {
                let mut b = map_zbus(e);
                if b.kind == BusErrKind::Other {
                    b.kind = BusErrKind::Unavailable;
                }
                b
            })
        })?;
        Ok(ZbusBus { conn, deadline })
    }

    fn run<T, F>(&self, what: &str, f: F) -> Result<T, BusError>
    where
        T: Send + 'static,
        F: FnOnce(zbus::blocking::Connection) -> Result<T, BusError> + Send + 'static,
    {
        let conn = self.conn.clone();
        timed(self.deadline, what, move || f(conn))
    }
}

impl Bus for ZbusBus {
    fn unit(&self, unit: &str) -> Result<UnitInfo, BusError> {
        let unit = unit.to_string();
        self.run("LoadUnit", move |conn| {
            let path: zvariant::OwnedObjectPath = manager(&conn)?
                .call("LoadUnit", &(unit.as_str(),))
                .map_err(map_zbus)?;
            let u = get_all(&conn, path.as_str(), "org.freedesktop.systemd1.Unit")?;
            let mut info = UnitInfo {
                load_state: prop(&u, "LoadState").unwrap_or_default(),
                active_state: prop(&u, "ActiveState").unwrap_or_default(),
                sub_state: prop(&u, "SubState").unwrap_or_default(),
                description: prop(&u, "Description").unwrap_or_default(),
                active_enter_us: prop(&u, "ActiveEnterTimestamp").unwrap_or(0),
                active_exit_us: prop(&u, "ActiveExitTimestamp").unwrap_or(0),
                inactive_enter_us: prop(&u, "InactiveEnterTimestamp").unwrap_or(0),
                ..UnitInfo::default()
            };
            // Only services have a main process.
            if let Ok(s) = get_all(&conn, path.as_str(), "org.freedesktop.systemd1.Service") {
                info.pid = prop(&s, "ExecMainPID").unwrap_or(0);
                info.exit_status = prop(&s, "ExecMainStatus").unwrap_or(0);
            }
            Ok(info)
        })
    }

    fn unit_file_state(&self, unit: &str) -> Result<String, BusError> {
        let unit = unit.to_string();
        self.run("GetUnitFileState", move |conn| {
            manager(&conn)?
                .call("GetUnitFileState", &(unit.as_str(),))
                .map_err(map_zbus)
        })
    }

    fn watch_jobs(&self) -> Result<Box<dyn JobWatch>, BusError> {
        let rx = self.run("Subscribe", move |conn| {
            let mgr = manager(&conn)?;
            // Without a subscriber systemd may not emit job signals.
            let _: Result<(), _> = mgr.call("Subscribe", &());
            let signals = mgr.receive_signal("JobRemoved").map_err(map_zbus)?;
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _keep = mgr;
                for m in signals {
                    let Ok((_id, path, _unit, result)) =
                        m.body::<(u32, zvariant::OwnedObjectPath, String, String)>()
                    else {
                        continue;
                    };
                    let job = JobRemoved {
                        path: path.as_str().to_string(),
                        result,
                    };
                    if tx.send(job).is_err() {
                        break;
                    }
                }
            });
            Ok(rx)
        })?;
        Ok(Box::new(ChannelWatch(rx)))
    }

    fn enqueue(
        &self,
        method: &'static str,
        unit: &str,
        mode: &'static str,
    ) -> Result<String, BusError> {
        let unit = unit.to_string();
        self.run(method, move |conn| {
            let job: zvariant::OwnedObjectPath = manager(&conn)?
                .call(method, &(unit.as_str(), mode))
                .map_err(map_zbus)?;
            Ok(job.as_str().to_string())
        })
    }

    fn cancel_job(&self, job: &str) -> Result<(), BusError> {
        let job = job.to_string();
        let conn = self.conn.clone();
        timed(Instant::now() + CANCEL_GRACE, "Cancel", move || {
            let p = zbus::blocking::Proxy::new(&conn, DEST, job, "org.freedesktop.systemd1.Job")
                .map_err(map_zbus)?;
            p.call::<_, _, ()>("Cancel", &()).map_err(map_zbus)
        })
    }

    fn unit_files(&self, op: FileOp, unit: &str) -> Result<FileChanges, BusError> {
        let files = vec![unit.to_string()];
        self.run("the unit-file change", move |conn| {
            let mgr = manager(&conn)?;
            let r = match op {
                FileOp::Enable => {
                    let (install, changes): (bool, Vec<(String, String, String)>) = mgr
                        .call("EnableUnitFiles", &(files, false, true))
                        .map_err(map_zbus)?;
                    FileChanges {
                        carries_install_info: Some(install),
                        changes,
                    }
                }
                FileOp::Disable => FileChanges {
                    carries_install_info: None,
                    changes: mgr
                        .call("DisableUnitFiles", &(files, false))
                        .map_err(map_zbus)?,
                },
                FileOp::Mask => FileChanges {
                    carries_install_info: None,
                    changes: mgr
                        .call("MaskUnitFiles", &(files, false, true))
                        .map_err(map_zbus)?,
                },
                FileOp::Unmask => FileChanges {
                    carries_install_info: None,
                    changes: mgr
                        .call("UnmaskUnitFiles", &(files, false))
                        .map_err(map_zbus)?,
                },
            };
            Ok(r)
        })
    }

    fn daemon_reload(&self) -> Result<(), BusError> {
        self.run("Reload", move |conn| {
            manager(&conn)?
                .call::<_, _, ()>("Reload", &())
                .map_err(map_zbus)
        })
    }

    fn list_units(&self) -> Result<Vec<(String, String)>, BusError> {
        self.run("ListUnits", move |conn| {
            let units: Vec<ListedUnit> =
                manager(&conn)?.call("ListUnits", &()).map_err(map_zbus)?;
            Ok(units.into_iter().map(|u| (u.0, u.3)).collect())
        })
    }
}

struct ChannelWatch(mpsc::Receiver<JobRemoved>);

impl JobWatch for ChannelWatch {
    fn next(&mut self, until: Instant) -> Option<JobRemoved> {
        let wait = until.saturating_duration_since(Instant::now());
        self.0.recv_timeout(wait).ok()
    }
}

// ---------------------------------------------------------------------------
// systemctl

/// systemd through `systemctl`, for hosts where the system bus cannot be
/// reached (systemctl then talks to systemd's private socket). systemctl
/// waits for each job itself, so `enqueue` returns once the job finished and
/// its result is handed to the watch.
pub(crate) struct SystemctlBus {
    systemctl: OsString,
    deadline: Instant,
    finished: Rc<RefCell<VecDeque<JobRemoved>>>,
    jobs: RefCell<u32>,
}

struct QueueWatch(Rc<RefCell<VecDeque<JobRemoved>>>);

impl JobWatch for QueueWatch {
    fn next(&mut self, until: Instant) -> Option<JobRemoved> {
        if let Some(j) = self.0.borrow_mut().pop_front() {
            return Some(j);
        }
        // Nothing else will arrive: the jobs ran synchronously.
        let wait = until.saturating_duration_since(Instant::now());
        std::thread::sleep(wait.min(Duration::from_millis(10)));
        None
    }
}

/// Classifies a failed systemctl run by its message.
pub(crate) fn classify_systemctl(stderr: &str) -> BusErrKind {
    let s = stderr.to_ascii_lowercase();
    if s.contains("not found") || s.contains("not loaded") || s.contains("does not exist") {
        BusErrKind::NotFound
    } else if s.contains("access denied")
        || s.contains("authentication required")
        || s.contains("permission denied")
        || s.contains("not permitted")
    {
        BusErrKind::Denied
    } else if s.contains("is masked") {
        BusErrKind::Masked
    } else if s.contains("failed to connect to bus") || s.contains("system has not been booted") {
        BusErrKind::Unavailable
    } else {
        BusErrKind::Other
    }
}

impl SystemctlBus {
    pub fn new(systemctl: OsString, deadline: Instant) -> Self {
        SystemctlBus {
            systemctl,
            deadline,
            finished: Rc::new(RefCell::new(VecDeque::new())),
            jobs: RefCell::new(0),
        }
    }

    /// Runs systemctl with `args`; returns (success, stdout, stderr).
    fn systemctl(&self, args: &[&str]) -> Result<(bool, String, String), BusError> {
        let mut cmd = Command::new(&self.systemctl);
        cmd.arg("--no-ask-password")
            .args(args)
            .env("SYSTEMD_COLORS", "0")
            .env("SYSTEMD_PAGER", "")
            .env("LC_ALL", "C");
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        match process::run(&mut cmd, Some(remaining)) {
            Ok(out) => Ok((
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            )),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                let lost = process::take_lost();
                let detail = match lost.map(|l| l.stopped) {
                    Some(process::Stopped::NotStarted) => "was not started",
                    Some(process::Stopped::StillRunning) => "could not be stopped",
                    _ => "was stopped",
                };
                Err(BusError::new(
                    BusErrKind::Timeout,
                    format!("systemctl {} {detail} at the deadline", args.join(" ")),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(BusError::new(
                BusErrKind::Unavailable,
                format!(
                    "the system bus is unavailable and {} was not found",
                    self.systemctl.to_string_lossy()
                ),
            )),
            Err(e) => Err(BusError::new(
                BusErrKind::Other,
                format!("cannot run {}: {e}", self.systemctl.to_string_lossy()),
            )),
        }
    }

    fn checked(&self, args: &[&str]) -> Result<String, BusError> {
        let (ok, out, err) = self.systemctl(args)?;
        if ok {
            Ok(out)
        } else {
            Err(BusError::new(
                classify_systemctl(&err),
                format!("systemctl {}: {err}", args.join(" ")),
            ))
        }
    }
}

/// Parses `systemctl show` output.
pub(crate) fn parse_show(stdout: &str) -> UnitInfo {
    let mut info = UnitInfo::default();
    for line in stdout.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "LoadState" => info.load_state = v.to_string(),
            "ActiveState" => info.active_state = v.to_string(),
            "SubState" => info.sub_state = v.to_string(),
            "Description" => info.description = v.to_string(),
            "ExecMainPID" => info.pid = v.parse().unwrap_or(0),
            "ExecMainStatus" => info.exit_status = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    info
}

impl Bus for SystemctlBus {
    fn unit(&self, unit: &str) -> Result<UnitInfo, BusError> {
        let out = self.checked(&[
            "show",
            "--property=LoadState,ActiveState,SubState,Description,ExecMainPID,ExecMainStatus",
            "--",
            unit,
        ])?;
        Ok(parse_show(&out))
    }

    fn unit_file_state(&self, unit: &str) -> Result<String, BusError> {
        // is-enabled exits non-zero for disabled units; only the state
        // printed on stdout matters, or the error on stderr.
        let (_, out, err) = self.systemctl(&["is-enabled", "--", unit])?;
        let state = out.lines().next().unwrap_or("").trim().to_string();
        // Recent systemctl prints `not-found` for a unit that does not exist.
        if state == "not-found" {
            return Err(BusError::new(
                BusErrKind::NotFound,
                format!("systemctl is-enabled: unit {unit} not found"),
            ));
        }
        if state.is_empty() {
            let kind = match classify_systemctl(&err) {
                BusErrKind::Other if err.to_ascii_lowercase().contains("no such file") => {
                    BusErrKind::NotFound
                }
                k => k,
            };
            return Err(BusError::new(kind, format!("systemctl is-enabled: {err}")));
        }
        Ok(state)
    }

    fn watch_jobs(&self) -> Result<Box<dyn JobWatch>, BusError> {
        Ok(Box::new(QueueWatch(self.finished.clone())))
    }

    fn enqueue(
        &self,
        method: &'static str,
        unit: &str,
        mode: &'static str,
    ) -> Result<String, BusError> {
        let verb = match method {
            "StartUnit" => "start",
            "StopUnit" => "stop",
            "RestartUnit" => "restart",
            "ReloadUnit" => "reload",
            other => {
                return Err(BusError::new(
                    BusErrKind::Other,
                    format!("{other} is not available through systemctl"),
                ));
            }
        };
        let mut args = vec![verb];
        if mode == "replace-irreversibly" {
            args.push("--job-mode=replace-irreversibly");
        }
        args.push("--");
        args.push(unit);
        let (ok, _, err) = self.systemctl(&args)?;
        let id = {
            let mut n = self.jobs.borrow_mut();
            *n += 1;
            *n
        };
        let path = format!("systemctl-job-{id}");
        let result = if ok {
            "done"
        } else {
            match classify_systemctl(&err) {
                // A job that ran and failed is a job result; anything else
                // was a refusal to queue it.
                BusErrKind::Other if err.contains("Job for") || err.contains("job") => "failed",
                kind => {
                    return Err(BusError::new(
                        kind,
                        format!("systemctl {verb} {unit}: {err}"),
                    ));
                }
            }
        };
        self.finished.borrow_mut().push_back(JobRemoved {
            path: path.clone(),
            result: result.to_string(),
        });
        Ok(path)
    }

    fn cancel_job(&self, _job: &str) -> Result<(), BusError> {
        Err(BusError::new(
            BusErrKind::Other,
            "a job started through systemctl cannot be cancelled by resh",
        ))
    }

    fn unit_files(&self, op: FileOp, unit: &str) -> Result<FileChanges, BusError> {
        let mut args = vec![op.verb()];
        if matches!(op, FileOp::Enable | FileOp::Mask) {
            args.push("--force");
        }
        args.extend(["--", unit]);
        let (ok, out, err) = self.systemctl(&args)?;
        if !ok {
            return Err(BusError::new(
                classify_systemctl(&err),
                format!("systemctl {} {unit}: {err}", op.verb()),
            ));
        }
        let mut changes = Vec::new();
        for line in out.lines().chain(err.lines()) {
            if let Some(rest) = line.strip_prefix("Created symlink ") {
                changes.push(("symlink".to_string(), rest.to_string(), String::new()));
            } else if let Some(rest) = line.strip_prefix("Removed ") {
                changes.push(("unlink".to_string(), rest.to_string(), String::new()));
            }
        }
        let carries_install_info = match op {
            FileOp::Enable => Some(!err.contains("no installation config")),
            _ => None,
        };
        Ok(FileChanges {
            carries_install_info,
            changes,
        })
    }

    fn daemon_reload(&self) -> Result<(), BusError> {
        // systemctl enable/disable/mask/unmask reload the daemon themselves.
        Ok(())
    }

    fn list_units(&self) -> Result<Vec<(String, String)>, BusError> {
        let out = self.checked(&["list-units", "--all", "--plain", "--no-legend", "--full"])?;
        Ok(out
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                let name = w.next()?.to_string();
                let _load = w.next()?;
                let active = w.next()?.to_string();
                Some((name, active))
            })
            .collect())
    }
}
