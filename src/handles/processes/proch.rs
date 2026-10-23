use anyhow::{Context, anyhow};
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

#[cfg(unix)]
use nix::sys::resource::{Resource, getrlimit, setrlimit};

#[derive(Debug)]
struct StreamData {
    encoding: String,
    auto_fallback: bool,
    bytes_read: usize,
    truncated: bool,
    data: String,
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("proc", |u| Ok(Box::new(ProcHandle::from_url(u)?)));
    reg.set_probe_url("proc", "proc://self");
}

/// Metadata for `resh proc --help` and `resh proc <verb> --help`.
static PROC_HELP: HandleHelp = HandleHelp {
    description: "The proc handle sends signals to running processes and adjusts their \
        scheduling priority through the kernel's kill and setpriority calls. It can also \
        read captured output logs and apply resource limits. The target is a numeric \
        process ID or self (the resh process itself), such as proc://1234.",
    usage: "resh proc://<pid|self>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "nice.get",
            definition: "Reports the current nice value of a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.nice.get",
                example: "resh --json-pretty proc://1234.nice.get",
                example_output: Some(
                    r#"{
  "nice": 0,
  "pid": 1234
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "io.peek",
            definition: "Reads the tail of a process's captured stdout or stderr log from \
                the resh state directory (~/.local/state/resh/proc/<pid>/) without blocking.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.io.peek [stream=stdout|stderr|both]\n  \
                    [max_bytes=<n>] [tail=<n>] [encoding=auto|utf8|base64]\n  \
                    [json=true|false]",
                example: "resh --json-pretty proc://1234.io.peek stream=stdout max_bytes=1024",
                example_output: Some(
                    r#"{
  "auto_fallback": false,
  "bytes_read": 26,
  "data": "worker started\nprocessing\n",
  "encoding": "utf8",
  "pid": 1234,
  "stream": "stdout",
  "truncated": false
}

Shown with --json-pretty. With stream=both, the per-stream fields are
nested under streams.stdout and streams.stderr; json=false prints the raw
stdout data. Reports an error if the log file does not exist."#,
                ),
            }),
        },
        VerbHelp {
            name: "signal",
            definition: "Sends a signal, given by name or number, to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.signal sig=<name|number>",
                example: "resh --json-pretty proc://1234.signal sig=TERM",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "signal"
}

Shown with --json-pretty. Accepted names are HUP, INT, QUIT, KILL, TERM,
STOP, CONT, USR1, USR2, PIPE, ALRM, and CHLD, with or without SIG."#,
                ),
            }),
        },
        VerbHelp {
            name: "term",
            definition: "Sends SIGTERM to a process to request graceful termination.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.term",
                example: "resh --json-pretty proc://1234.term",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "TERM",
  "signal_num": 15,
  "verb": "term"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "int",
            definition: "Sends SIGINT to a process, like pressing Ctrl+C.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.int",
                example: "resh --json-pretty proc://1234.int",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "INT",
  "signal_num": 2,
  "verb": "int"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "hup",
            definition: "Sends SIGHUP to a process, which many daemons treat as a reload request.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.hup",
                example: "resh --json-pretty proc://1234.hup",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "HUP",
  "signal_num": 1,
  "verb": "hup"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "kill",
            definition: "Sends SIGKILL to a process to terminate it immediately.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.kill",
                example: "resh --json-pretty proc://1234.kill",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "KILL",
  "signal_num": 9,
  "verb": "kill"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "stop",
            definition: "Sends SIGSTOP to a process to pause it.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.stop",
                example: "resh --json-pretty proc://1234.stop",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "STOP",
  "signal_num": 19,
  "verb": "stop"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "cont",
            definition: "Sends SIGCONT to a process to resume it after a stop.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.cont",
                example: "resh --json-pretty proc://1234.cont",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "CONT",
  "signal_num": 18,
  "verb": "cont"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "usr1",
            definition: "Sends SIGUSR1 to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.usr1",
                example: "resh --json-pretty proc://1234.usr1",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "USR1",
  "signal_num": 10,
  "verb": "usr1"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "usr2",
            definition: "Sends SIGUSR2 to a process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.usr2",
                example: "resh --json-pretty proc://1234.usr2",
                example_output: Some(
                    r#"{
  "ok": true,
  "pid": 1234,
  "signal": "USR2",
  "signal_num": 12,
  "verb": "usr2"
}

Shown for Linux with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.set",
            definition: "Sets the nice value of a process to an exact value from -20 to 19.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.nice.set value=<-20..19>",
                example: "resh --json-pretty proc://1234.nice.set value=10",
                example_output: Some(
                    r#"{
  "changed": true,
  "nice": 10,
  "pid": 1234
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.inc",
            definition: "Raises the nice value of a process by a delta, lowering its priority.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.nice.inc delta=<n>",
                example: "resh --json-pretty proc://1234.nice.inc delta=5",
                example_output: Some(
                    r#"{
  "changed": true,
  "delta": 5,
  "nice_after": 5,
  "nice_before": 0,
  "pid": 1234
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "nice.dec",
            definition: "Lowers the nice value of a process by a delta, raising its priority.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.nice.dec delta=<n>",
                example: "resh --json-pretty proc://1234.nice.dec delta=5",
                example_output: Some(
                    r#"{
  "changed": true,
  "delta": 5,
  "nice_after": 5,
  "nice_before": 10,
  "pid": 1234
}

Shown with --json-pretty. Lowering a nice value usually requires root."#,
                ),
            }),
        },
        VerbHelp {
            name: "setPriority",
            definition: "Sets the nice value of a process from a named priority class or an \
                explicit nice value.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.setPriority\n  \
                    [class=idle|background|normal|high|realtime] [nice=<-20..19>]",
                example: "resh --json-pretty proc://1234.setPriority class=background",
                example_output: Some(
                    r#"{
  "backend": "linux-setpriority",
  "class": "background",
  "nice": 10,
  "pid": 1234,
  "previous_nice": 0
}

Shown with --json-pretty. Classes map to nice values idle=19,
background=10, normal=0, high=-5, and realtime=-10; nice overrides class."#,
                ),
            }),
        },
        VerbHelp {
            name: "limits.set",
            definition: "Sets soft and hard resource limits through setrlimit, which always \
                applies them to the resh process itself rather than the target process.",
            detail: Some(VerbDetail {
                usage: "resh proc://<pid|self>.limits.set <resource>=<soft>[:<hard>] ...\n  \
                    [dry_run=true|false] [pid=<n>]",
                example: "resh --json-pretty proc://self.limits.set nofile=4096 dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "rlimit",
  "pid": 41872,
  "results": {
    "nofile": {
      "after": {
        "hard": 524288,
        "soft": 4096
      },
      "before": {
        "hard": 524288,
        "soft": 1024
      },
      "requested": "4096",
      "status": "ok"
    }
  }
}

Shown with --json-pretty. Resources are cpu, as, data, stack, core,
nofile, fsize, memlock, and nproc. Values accept unlimited, an s suffix
for seconds, and K, M, or G suffixes (powers of 1000)."#,
                ),
            }),
        },
    ],
};

pub struct ProcHandle {
    name: String, // Can be a PID or "self"
}

/// Parse a single target PID. Only 1..=pid_t::MAX is accepted: zero, negative
/// values and anything that would wrap on conversion address process groups
/// or every process (`kill(-1, ..)`), never one process.
fn parse_pid(s: &str) -> anyhow::Result<libc::pid_t> {
    let pid: u64 = s.parse().with_context(|| format!("invalid pid: {}", s))?;
    if pid == 0 {
        return Err(anyhow!("invalid pid: must be positive"));
    }
    libc::pid_t::try_from(pid).map_err(|_| {
        anyhow!(
            "invalid pid: {} is out of range (max {})",
            s,
            libc::pid_t::MAX
        )
    })
}

impl ProcHandle {
    pub fn from_url(u: &Url) -> anyhow::Result<Self> {
        // Accept host + path, strip leading slashes, parse as PID or "self"
        let mut name = String::new();
        if let Some(h) = u.host_str() {
            name.push_str(h);
        }
        if !u.path().is_empty() {
            if !name.is_empty() {
                name.push('/');
            }
            name.push_str(u.path().trim_start_matches('/'));
        }

        if name.is_empty() {
            return Err(anyhow!("invalid pid: missing"));
        }

        // Allow "self", numeric PID, or an in-URL help flag (proc://--help)
        if name == "self" || crate::core::help::is_help_flag(&name) {
            Ok(Self { name })
        } else {
            parse_pid(&name)?;
            Ok(Self { name })
        }
    }

    /// Resolve the name to an actual PID
    fn resolve_pid(&self) -> anyhow::Result<libc::pid_t> {
        if self.name == "self" {
            libc::pid_t::try_from(std::process::id())
                .map_err(|_| anyhow!("invalid pid: own pid out of range"))
        } else {
            parse_pid(&self.name)
        }
    }

    /// Get the nice value for the process
    #[cfg(unix)]
    fn get_nice(&self) -> anyhow::Result<i32> {
        let pid = self.resolve_pid()?;

        // Clear errno before the call
        unsafe { *libc::__errno_location() = 0 };

        let nice_value = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as u32) };

        // Check if an error occurred (getpriority can return -1 as a valid value)
        let errno = unsafe { *libc::__errno_location() };
        if errno != 0 {
            let error = std::io::Error::from_raw_os_error(errno);
            match errno {
                libc::ESRCH => return Err(anyhow!("no such process")),
                libc::EPERM => return Err(anyhow!("permission denied")),
                _ => return Err(anyhow!("getpriority failed: {}", error)),
            }
        }

        Ok(nice_value)
    }

    #[cfg(not(unix))]
    fn get_nice(&self) -> anyhow::Result<i32> {
        Err(anyhow!(
            "proc:// nice operations only supported on Unix-like systems"
        ))
    }

    /// Set the nice value for the process
    #[cfg(unix)]
    fn set_nice(&self, value: i32) -> anyhow::Result<()> {
        // Validate range
        if value < -20 || value > 19 {
            return Err(anyhow!("nice value out of range (-20..19)"));
        }

        let pid = self.resolve_pid()?;

        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as u32, value) };

        if result != 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::ESRCH) => return Err(anyhow!("no such process")),
                Some(libc::EPERM) => return Err(anyhow!("permission denied")),
                Some(libc::EACCES) => return Err(anyhow!("permission denied")),
                _ => return Err(anyhow!("setpriority failed: {}", error)),
            }
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn set_nice(&self, _value: i32) -> anyhow::Result<()> {
        Err(anyhow!(
            "proc:// nice operations only supported on Unix-like systems"
        ))
    }

    /// Handle nice-related operations
    fn handle_nice(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(e) => {
                let error_json = json!({
                    "pid": null,
                    "verb": verb,
                    "ok": false,
                    "error": e.to_string()
                });
                writeln!(io.stdout, "{}", error_json)?;
                writeln!(io.stderr, "Error: {}", e)?;
                return Ok(Status::err(1, e.to_string()));
            }
        };

        match verb {
            "nice.get" => match self.get_nice() {
                Ok(nice_value) => {
                    let success_json = json!({
                        "pid": pid,
                        "nice": nice_value
                    });
                    writeln!(io.stdout, "{}", success_json)?;
                    Ok(Status::ok())
                }
                Err(e) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    writeln!(io.stderr, "Error: {}", e)?;
                    Ok(Status::err(1, e.to_string()))
                }
            },
            "nice.set" => {
                let value_str = match args.get("value") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: value"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: value")?;
                        return Ok(Status::err(2, "missing arg: value"));
                    }
                };

                let value: i32 = match value_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "value must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: value must be an integer")?;
                        return Ok(Status::err(2, "value must be an integer"));
                    }
                };

                match self.set_nice(value) {
                    Ok(()) => {
                        let success_json = json!({
                            "pid": pid,
                            "nice": value,
                            "changed": true
                        });
                        writeln!(io.stdout, "{}", success_json)?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;

                        let code = if e.to_string().contains("out of range") {
                            3
                        } else if e.to_string().contains("permission denied") {
                            4
                        } else {
                            1
                        };
                        Ok(Status::err(code, e.to_string()))
                    }
                }
            }
            "nice.inc" => {
                let delta_str = match args.get("delta") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: delta"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: delta")?;
                        return Ok(Status::err(2, "missing arg: delta"));
                    }
                };

                let delta: i32 = match delta_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "delta must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: delta must be an integer")?;
                        return Ok(Status::err(2, "delta must be an integer"));
                    }
                };

                match self.get_nice() {
                    Ok(current) => {
                        let new_value = current + delta;
                        if new_value < -20 || new_value > 19 {
                            let error_json = json!({
                                "pid": pid,
                                "verb": verb,
                                "ok": false,
                                "error": "nice value out of range (-20..19)"
                            });
                            writeln!(io.stdout, "{}", error_json)?;
                            writeln!(io.stderr, "Error: nice value out of range (-20..19)")?;
                            return Ok(Status::err(3, "nice value out of range (-20..19)"));
                        }

                        match self.set_nice(new_value) {
                            Ok(()) => {
                                let success_json = json!({
                                    "pid": pid,
                                    "nice_before": current,
                                    "nice_after": new_value,
                                    "delta": delta,
                                    "changed": true
                                });
                                writeln!(io.stdout, "{}", success_json)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error_json = json!({
                                    "pid": pid,
                                    "verb": verb,
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error_json)?;
                                writeln!(io.stderr, "Error: {}", e)?;

                                let code = if e.to_string().contains("permission denied") {
                                    4
                                } else {
                                    1
                                };
                                Ok(Status::err(code, e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        Ok(Status::err(1, e.to_string()))
                    }
                }
            }
            "nice.dec" => {
                let delta_str = match args.get("delta") {
                    Some(v) => v,
                    None => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "missing arg: delta"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: missing arg: delta")?;
                        return Ok(Status::err(2, "missing arg: delta"));
                    }
                };

                let delta: i32 = match delta_str.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": "delta must be an integer"
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: delta must be an integer")?;
                        return Ok(Status::err(2, "delta must be an integer"));
                    }
                };

                match self.get_nice() {
                    Ok(current) => {
                        let new_value = current - delta;
                        if new_value < -20 || new_value > 19 {
                            let error_json = json!({
                                "pid": pid,
                                "verb": verb,
                                "ok": false,
                                "error": "nice value out of range (-20..19)"
                            });
                            writeln!(io.stdout, "{}", error_json)?;
                            writeln!(io.stderr, "Error: nice value out of range (-20..19)")?;
                            return Ok(Status::err(3, "nice value out of range (-20..19)"));
                        }

                        match self.set_nice(new_value) {
                            Ok(()) => {
                                let success_json = json!({
                                    "pid": pid,
                                    "nice_before": current,
                                    "nice_after": new_value,
                                    "delta": delta,
                                    "changed": true
                                });
                                writeln!(io.stdout, "{}", success_json)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error_json = json!({
                                    "pid": pid,
                                    "verb": verb,
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error_json)?;
                                writeln!(io.stderr, "Error: {}", e)?;

                                let code = if e.to_string().contains("permission denied") {
                                    4
                                } else {
                                    1
                                };
                                Ok(Status::err(code, e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        let error_json = json!({
                            "pid": pid,
                            "verb": verb,
                            "ok": false,
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        writeln!(io.stderr, "Error: {}", e)?;
                        Ok(Status::err(1, e.to_string()))
                    }
                }
            }
            _ => {
                let error_json = json!({
                    "pid": pid,
                    "verb": verb,
                    "ok": false,
                    "error": format!("unknown verb: {}", verb)
                });
                writeln!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, format!("unknown verb: {}", verb)))
            }
        }
    }

    /// Handle setPriority verb - class-based priority setting
    #[cfg(unix)]
    fn verb_set_priority(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(_) => {
                writeln!(io.stderr, "Error: invalid pid")?;
                return Ok(Status::err(1, "invalid pid"));
            }
        };

        // Get current nice value for the "previous_nice" field
        let previous_nice = match self.get_nice() {
            Ok(current) => current,
            Err(e) => {
                if e.to_string().contains("no such process") {
                    writeln!(io.stderr, "Error: no such process")?;
                    return Ok(Status::err(4, "no such process"));
                } else if e.to_string().contains("permission denied") {
                    writeln!(io.stderr, "Error: permission denied")?;
                    return Ok(Status::err(4, "permission denied"));
                } else {
                    let msg = format!("failed to get current priority: {}", e);
                    writeln!(io.stderr, "Error: {}", msg)?;
                    return Ok(Status::err(4, msg));
                }
            }
        };

        // Parse arguments
        let (target_nice, resolved_class) = if let Some(nice_str) = args.get("nice") {
            // If nice is provided, use it directly and override class
            match nice_str.parse::<i32>() {
                Ok(nice_val) => {
                    let clamped = nice_val.clamp(-20, 19);
                    let class = match clamped {
                        19 => "idle",
                        10 => "background",
                        0 => "normal",
                        -5 => "high",
                        -10 => "realtime",
                        _ => "custom",
                    };
                    (clamped, class.to_string())
                }
                Err(_) => {
                    writeln!(io.stderr, "Error: invalid nice value")?;
                    return Ok(Status::err(2, "invalid nice value"));
                }
            }
        } else {
            // Use class mapping
            let class = args.get("class").map(|s| s.as_str()).unwrap_or("normal");
            let nice_val = match class {
                "idle" => 19,
                "background" => 10,
                "normal" => 0,
                "high" => -5,
                "realtime" => -10,
                _ => {
                    writeln!(io.stderr, "Error: invalid class")?;
                    return Ok(Status::err(3, "invalid class"));
                }
            };
            (nice_val, class.to_string())
        };

        // Set the new priority using existing set_nice method
        match self.set_nice(target_nice) {
            Ok(()) => {
                let success_json = json!({
                    "pid": pid,
                    "class": resolved_class,
                    "nice": target_nice,
                    "previous_nice": previous_nice,
                    "backend": "linux-setpriority"
                });
                writeln!(io.stdout, "{}", success_json)?;
                Ok(Status::ok())
            }
            Err(e) => {
                if e.to_string().contains("no such process") {
                    writeln!(io.stderr, "Error: no such process")?;
                    Ok(Status::err(4, "no such process"))
                } else if e.to_string().contains("permission denied") {
                    writeln!(io.stderr, "Error: permission denied")?;
                    Ok(Status::err(4, "permission denied"))
                } else {
                    let msg = format!("setpriority failed: {}", e);
                    writeln!(io.stderr, "Error: {}", msg)?;
                    Ok(Status::err(4, msg))
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn verb_set_priority(&self, _args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        writeln!(
            io.stderr,
            "Error: setPriority not supported on this platform"
        )?;
        Ok(Status::err(5, "setPriority not supported on this platform"))
    }

    #[cfg(unix)]
    fn send_signal_internal(
        &self,
        _signal_name: &str,
        signal_num: libc::c_int,
    ) -> anyhow::Result<bool> {
        // Use libc::kill to send the signal
        let pid = self.resolve_pid()?;
        let result = unsafe { libc::kill(pid, signal_num) };

        if result == 0 {
            Ok(true)
        } else {
            let errno = std::io::Error::last_os_error();
            match errno.raw_os_error() {
                Some(libc::ESRCH) => Ok(false), // Process not found
                Some(libc::EPERM) => Err(anyhow!("permission denied")),
                _ => Err(anyhow!("kill failed: {}", errno)),
            }
        }
    }

    #[cfg(not(unix))]
    fn send_signal_internal(
        &self,
        _signal_name: &str,
        _signal_num: libc::c_int,
    ) -> anyhow::Result<bool> {
        Err(anyhow!("proc:// only supported on Unix-like systems"))
    }

    fn resolve_signal(verb: &str, args: &Args) -> anyhow::Result<(String, libc::c_int)> {
        match verb {
            "signal" => {
                let sig = args.get("sig").ok_or_else(|| anyhow!("missing arg: sig"))?;
                parse_signal_arg(sig)
            }
            "kill" => Ok(("KILL".to_string(), libc::SIGKILL)),
            "term" => Ok(("TERM".to_string(), libc::SIGTERM)),
            "int" => Ok(("INT".to_string(), libc::SIGINT)),
            "hup" => Ok(("HUP".to_string(), libc::SIGHUP)),
            "stop" => Ok(("STOP".to_string(), libc::SIGSTOP)),
            "cont" => Ok(("CONT".to_string(), libc::SIGCONT)),
            "usr1" => Ok(("USR1".to_string(), libc::SIGUSR1)),
            "usr2" => Ok(("USR2".to_string(), libc::SIGUSR2)),
            _ => Err(anyhow!("unknown verb: {}", verb)),
        }
    }

    fn handle_signal(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        #[cfg(not(unix))]
        {
            let pid = self.resolve_pid().unwrap_or(-1);
            let error_json = json!({
                "pid": pid,
                "verb": verb,
                "ok": false,
                "backend": "unsupported",
                "error": "proc:// only supported on Unix-like systems"
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(
                1,
                "proc:// only supported on Unix-like systems",
            ));
        }

        #[cfg(unix)]
        {
            let pid = match self.resolve_pid() {
                Ok(p) => p,
                Err(e) => {
                    let error_json = json!({
                        "pid": null,
                        "verb": verb,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(1, e.to_string()));
                }
            };

            let (signal_name, signal_num) = match Self::resolve_signal(verb, args) {
                Ok(result) => result,
                Err(e) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(1, e.to_string()));
                }
            };

            match self.send_signal_internal(&signal_name, signal_num) {
                Ok(true) => {
                    let success_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": true
                    });
                    writeln!(io.stdout, "{}", success_json)?;
                    Ok(Status::ok())
                }
                Ok(false) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": false,
                        "error": "process not found"
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    Ok(Status::err(3, "process not found"))
                }
                Err(e) => {
                    let error_json = json!({
                        "pid": pid,
                        "verb": verb,
                        "signal": signal_name,
                        "signal_num": signal_num,
                        "ok": false,
                        "error": e.to_string()
                    });
                    writeln!(io.stdout, "{}", error_json)?;

                    let code = if e.to_string().contains("permission denied") {
                        4
                    } else {
                        1
                    };
                    Ok(Status::err(code, e.to_string()))
                }
            }
        }
    }

    /// Handle io.peek verb - non-blocking peek at process output logs
    fn handle_io_peek(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let pid = match self.resolve_pid() {
            Ok(p) => p,
            Err(e) => {
                let error_json = json!({
                    "error": format!("invalid pid: {}", e)
                });
                writeln!(io.stdout, "{}", error_json)?;
                return Ok(Status::err(3, format!("invalid pid: {}", e)));
            }
        };

        // Parse arguments
        let stream = args.get("stream").map(|s| s.as_str()).unwrap_or("stdout");

        // Parse max_bytes with error handling
        let max_bytes = match args.get("max_bytes") {
            Some(s) => match s.parse::<usize>() {
                Ok(val) => val,
                Err(_) => {
                    let error_json = json!({
                        "error": "max_bytes must be a positive integer",
                        "pid": pid
                    })
                    .to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid max_bytes parameter".to_string()));
                }
            },
            None => 4096,
        };

        let encoding = args.get("encoding").map(|s| s.as_str()).unwrap_or("auto");

        // Parse tail with error handling
        let tail = match args.get("tail") {
            Some(s) => match s.parse::<usize>() {
                Ok(val) => val,
                Err(_) => {
                    let error_json = json!({
                        "error": "tail must be a positive integer",
                        "pid": pid
                    })
                    .to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid tail parameter".to_string()));
                }
            },
            None => max_bytes,
        };

        let json_mode = args
            .get("json")
            .map(|s| !matches!(s.as_str(), "false" | "0" | "no"))
            .unwrap_or(true);

        // Validate stream argument
        if !matches!(stream, "stdout" | "stderr" | "both") {
            let error_json = json!({
                "error": format!("invalid stream value: {}", stream)
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(3, format!("invalid stream value: {}", stream)));
        }

        // Validate encoding argument
        if !matches!(encoding, "auto" | "utf8" | "base64") {
            let error_json = json!({
                "error": format!("invalid encoding value: {}", encoding)
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(
                3,
                format!("invalid encoding value: {}", encoding),
            ));
        }

        // Check for raw mode constraints
        if !json_mode && (stream != "stdout") {
            let error_json = json!({
                "error": "raw mode (json=false) only allowed with stream=stdout"
            });
            writeln!(io.stdout, "{}", error_json)?;
            return Ok(Status::err(3, "raw mode only allowed with stream=stdout"));
        }

        // Get state directory and construct log paths
        let base = dirs::state_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let dir = base.join("resh").join("proc").join(pid.to_string());

        match stream {
            "stdout" => {
                let stdout_log = dir.join("stdout.log");
                match self.read_log_file(&stdout_log, max_bytes, tail, encoding) {
                    Ok(stream_data) => {
                        if json_mode {
                            let response = json!({
                                "pid": pid,
                                "stream": "stdout",
                                "encoding": stream_data.encoding,
                                "auto_fallback": stream_data.auto_fallback,
                                "bytes_read": stream_data.bytes_read,
                                "truncated": stream_data.truncated,
                                "data": stream_data.data
                            });
                            writeln!(io.stdout, "{}", response)?;
                        } else {
                            // Raw mode - write data directly
                            write!(io.stdout, "{}", stream_data.data)?;
                        }
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        Ok(Status::err(2, e.to_string()))
                    }
                }
            }
            "stderr" => {
                let stderr_log = dir.join("stderr.log");
                match self.read_log_file(&stderr_log, max_bytes, tail, encoding) {
                    Ok(stream_data) => {
                        let response = json!({
                            "pid": pid,
                            "stream": "stderr",
                            "encoding": stream_data.encoding,
                            "auto_fallback": stream_data.auto_fallback,
                            "bytes_read": stream_data.bytes_read,
                            "truncated": stream_data.truncated,
                            "data": stream_data.data
                        });
                        writeln!(io.stdout, "{}", response)?;
                        Ok(Status::ok())
                    }
                    Err(e) => {
                        let error_json = json!({
                            "error": e.to_string()
                        });
                        writeln!(io.stdout, "{}", error_json)?;
                        Ok(Status::err(2, e.to_string()))
                    }
                }
            }
            "both" => {
                let stdout_log = dir.join("stdout.log");
                let stderr_log = dir.join("stderr.log");

                let stdout_result = self.read_log_file(&stdout_log, max_bytes, tail, encoding);
                let stderr_result = self.read_log_file(&stderr_log, max_bytes, tail, encoding);

                let response = json!({
                    "pid": pid,
                    "streams": {
                        "stdout": match stdout_result {
                            Ok(data) => json!({
                                "encoding": data.encoding,
                                "auto_fallback": data.auto_fallback,
                                "bytes_read": data.bytes_read,
                                "truncated": data.truncated,
                                "data": data.data
                            }),
                            Err(e) => json!({
                                "error": e.to_string()
                            })
                        },
                        "stderr": match stderr_result {
                            Ok(data) => json!({
                                "encoding": data.encoding,
                                "auto_fallback": data.auto_fallback,
                                "bytes_read": data.bytes_read,
                                "truncated": data.truncated,
                                "data": data.data
                            }),
                            Err(e) => json!({
                                "error": e.to_string()
                            })
                        }
                    }
                });
                writeln!(io.stdout, "{}", response)?;
                Ok(Status::ok())
            }
            _ => unreachable!("stream validation should prevent this"),
        }
    }

    /// Read and process a log file according to the specified parameters
    fn read_log_file(
        &self,
        path: &PathBuf,
        max_bytes: usize,
        tail: usize,
        encoding: &str,
    ) -> anyhow::Result<StreamData> {
        use base64::Engine as _;

        if !path.exists() {
            return Err(anyhow!("log file not found: {}", path.display()));
        }

        let mut file = File::open(path)
            .with_context(|| format!("failed to open log file: {}", path.display()))?;

        // Get file length
        let file_len = file
            .metadata()
            .with_context(|| format!("failed to get file metadata: {}", path.display()))?
            .len();

        if file_len == 0 {
            return Ok(StreamData {
                encoding: "utf8".to_string(),
                auto_fallback: false,
                bytes_read: 0,
                truncated: false,
                data: String::new(),
            });
        }

        // Determine how many bytes to read from the end
        let bytes_to_read = std::cmp::min(file_len, tail as u64);

        if bytes_to_read > 0 {
            // Seek to the tail position
            file.seek(SeekFrom::End(-(bytes_to_read as i64)))
                .with_context(|| format!("failed to seek in log file: {}", path.display()))?;
        }

        // Read the bytes
        let mut buffer = vec![0u8; bytes_to_read as usize];
        let bytes_read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read log file: {}", path.display()))?;
        buffer.truncate(bytes_read);

        // Apply max_bytes limit if needed
        let truncated = bytes_read > max_bytes;
        if truncated {
            let start = bytes_read - max_bytes;
            buffer = buffer[start..].to_vec();
        }

        // Apply encoding
        match encoding {
            "utf8" => {
                let data = String::from_utf8_lossy(&buffer).into_owned();
                Ok(StreamData {
                    encoding: "utf8".to_string(),
                    auto_fallback: false,
                    bytes_read: buffer.len(),
                    truncated,
                    data,
                })
            }
            "base64" => {
                let data = base64::engine::general_purpose::STANDARD.encode(&buffer);
                Ok(StreamData {
                    encoding: "base64".to_string(),
                    auto_fallback: false,
                    bytes_read: buffer.len(),
                    truncated,
                    data,
                })
            }
            "auto" => match String::from_utf8(buffer.clone()) {
                Ok(utf8_string) => Ok(StreamData {
                    encoding: "utf8".to_string(),
                    auto_fallback: false,
                    bytes_read: buffer.len(),
                    truncated,
                    data: utf8_string,
                }),
                Err(_) => {
                    let data = base64::engine::general_purpose::STANDARD.encode(&buffer);
                    Ok(StreamData {
                        encoding: "base64".to_string(),
                        auto_fallback: true,
                        bytes_read: buffer.len(),
                        truncated,
                        data,
                    })
                }
            },
            _ => Err(anyhow!("invalid encoding: {}", encoding)),
        }
    }

    /// Main implementation of limits.set verb
    #[cfg(unix)]
    fn limits_set(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        // Determine target PID
        let target_pid = if let Some(pid_str) = args.get("pid") {
            match pid_str.parse::<i32>() {
                Ok(p) if p > 0 => p,
                _ => {
                    let error_json = json!({
                        "pid": null,
                        "backend": "rlimit",
                        "error": format!("invalid pid argument: '{}'", pid_str),
                        "resource": "pid"
                    });
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(
                        2,
                        format!("invalid pid argument: '{}'", pid_str),
                    ));
                }
            }
        } else {
            self.resolve_pid()?
        };

        // Check if this is check-only mode
        let check_only = crate::core::lenient::dry_run(args)?;

        let mut results = serde_json::Map::new();
        let mut overall_success = true;

        // Process each resource limit argument
        for (key, value) in args {
            // Skip special arguments
            if key == "pid" || key == "dry_run" {
                continue;
            }

            match self.process_resource_limit(key, value, target_pid, check_only) {
                Ok(resource_result) => {
                    results.insert(key.clone(), resource_result);
                }
                Err(e) => {
                    let error_result = json!({
                        "requested": value,
                        "status": "error",
                        "error": e.to_string()
                    });
                    results.insert(key.clone(), error_result);
                    overall_success = false;
                }
            }
        }

        // Generate final JSON response
        let response = json!({
            "pid": target_pid,
            "backend": "rlimit",
            "results": results
        });

        writeln!(io.stdout, "{}", response)?;

        if overall_success {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                1,
                "one or more resource limit operations failed",
            ))
        }
    }

    #[cfg(not(unix))]
    fn limits_set(&self, _args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let error_json = json!({
            "backend": "limits",
            "supported": false,
            "error": "resource limits not supported on this platform"
        });
        writeln!(io.stdout, "{}", error_json)?;
        Ok(Status::err(
            1,
            "resource limits not supported on this platform",
        ))
    }

    /// Process a single resource limit setting
    #[cfg(unix)]
    fn process_resource_limit(
        &self,
        name: &str,
        value: &str,
        _pid: i32,
        check_only: bool,
    ) -> anyhow::Result<serde_json::Value> {
        // Map resource name to nix Resource enum
        let resource = match self.map_resource_name(name)? {
            Some(r) => r,
            None => return Err(anyhow!("unknown resource: '{}'", name)),
        };

        // Get current limits
        let (current_soft, current_hard) = getrlimit(resource)
            .map_err(|e| anyhow!("failed to get current limits for {}: {}", name, e))?;

        // Parse the new limits
        let (new_soft, new_hard) = self.parse_limit_value(value, current_soft, current_hard)?;

        // Validate that soft <= hard
        if new_soft > new_hard {
            return Err(anyhow!(
                "soft limit ({}) cannot exceed hard limit ({})",
                new_soft,
                new_hard
            ));
        }

        // Apply the limits if not in check-only mode
        if !check_only {
            setrlimit(resource, new_soft, new_hard)
                .map_err(|e| anyhow!("failed to set limits for {}: {}", name, e))?;
        }

        // Build result JSON
        Ok(json!({
            "requested": value,
            "before": {
                "soft": current_soft,
                "hard": current_hard
            },
            "after": {
                "soft": new_soft,
                "hard": new_hard
            },
            "status": "ok"
        }))
    }

    /// Map resource names to nix Resource enum values
    #[cfg(unix)]
    fn map_resource_name(&self, name: &str) -> anyhow::Result<Option<Resource>> {
        let resource = match name {
            "cpu" => Some(Resource::RLIMIT_CPU),
            "as" => Some(Resource::RLIMIT_AS),
            "data" => Some(Resource::RLIMIT_DATA),
            "stack" => Some(Resource::RLIMIT_STACK),
            "core" => Some(Resource::RLIMIT_CORE),
            "nofile" => Some(Resource::RLIMIT_NOFILE),
            "fsize" => Some(Resource::RLIMIT_FSIZE),
            "memlock" => Some(Resource::RLIMIT_MEMLOCK),
            #[cfg(target_os = "linux")]
            "nproc" => Some(Resource::RLIMIT_NPROC),
            _ => None,
        };
        Ok(resource)
    }

    /// Parse limit value in various formats
    #[cfg(unix)]
    fn parse_limit_value(
        &self,
        value: &str,
        current_soft: u64,
        current_hard: u64,
    ) -> anyhow::Result<(u64, u64)> {
        if value.contains(':') {
            // Format: "soft:hard"
            let parts: Vec<&str> = value.splitn(2, ':').collect();
            let soft_str = parts[0];
            let hard_str = parts[1];

            let new_soft = if soft_str.is_empty() {
                current_soft
            } else {
                self.parse_single_limit(soft_str)?
            };

            let new_hard = if hard_str.is_empty() {
                current_hard
            } else {
                self.parse_single_limit(hard_str)?
            };

            Ok((new_soft, new_hard))
        } else {
            // Single value - set soft limit, keep hard unchanged
            let new_soft = self.parse_single_limit(value)?;
            Ok((new_soft, current_hard))
        }
    }

    /// Parse a single limit value (with potential suffixes)
    #[cfg(unix)]
    fn parse_single_limit(&self, value: &str) -> anyhow::Result<u64> {
        if value == "unlimited" {
            return Ok(u64::MAX); // RLIM_INFINITY equivalent
        }

        // Handle time suffixes for CPU
        if value.ends_with('s') {
            let num_str = &value[..value.len() - 1];
            return num_str
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid time value: '{}'", value));
        }

        // Handle SI suffixes for byte values
        if value.ends_with('K') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str
                .parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000);
        }

        if value.ends_with('M') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str
                .parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000);
        }

        if value.ends_with('G') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str
                .parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000_000);
        }

        // Plain number
        value
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid limit value: '{}'", value))
    }
}

impl Handle for ProcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "signal",
            "kill",
            "term",
            "int",
            "hup",
            "stop",
            "cont",
            "usr1",
            "usr2",
            "nice.get",
            "nice.set",
            "nice.inc",
            "nice.dec",
            "setPriority",
            "io.peek",
            "limits.set",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&PROC_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        // Check for help request before processing verbs
        if should_show_help(verb, args) {
            return self.display_help(args.get("verb").map(String::as_str), io);
        }

        match verb {
            "signal" | "kill" | "term" | "int" | "hup" | "stop" | "cont" | "usr1" | "usr2" => {
                self.handle_signal(verb, args, io)
            }
            "nice.get" | "nice.set" | "nice.inc" | "nice.dec" => self.handle_nice(verb, args, io),
            "setPriority" => self.verb_set_priority(args, io),
            "io.peek" => self.handle_io_peek(args, io),
            "limits.set" => self.limits_set(args, io),
            _ => {
                let pid = self.resolve_pid().unwrap_or(-1);
                let error_json = json!({
                    "pid": pid,
                    "verb": verb,
                    "ok": false,
                    "error": format!("unknown verb: {}", verb)
                });
                writeln!(io.stdout, "{}", error_json)?;
                Ok(Status::err(1, format!("unknown verb: {}", verb)))
            }
        }
    }
}

fn parse_signal_arg(sig: &str) -> anyhow::Result<(String, libc::c_int)> {
    // Try to parse as number first; the number is sent as given and only
    // the label comes from the platform's signal table.
    if let Ok(num) = sig.parse::<i32>() {
        return Ok((signal_label(num).to_string(), num));
    }

    // Parse as signal name (case-insensitive)
    let sig_upper = sig.to_uppercase();
    let sig_name = if sig_upper.starts_with("SIG") {
        &sig_upper[3..]
    } else {
        &sig_upper
    };

    let signal_num = match sig_name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "CHLD" => libc::SIGCHLD,
        _ => return Err(anyhow!("invalid signal: {}", sig)),
    };

    Ok((sig_name.to_string(), signal_num))
}

// ===========================================================================
// Helper functions for help display
// ===========================================================================

/// Check if help should be displayed. Matches whole tokens only, so a verb
/// or argument merely containing "-h" is not a help request.
fn should_show_help(method: &str, args: &Args) -> bool {
    method == "help"
        || method == "h"
        || crate::core::help::is_help_flag(method)
        || args.contains_key("help")
        || args.contains_key("h")
}

impl ProcHandle {
    /// Display the approved proc help (same text as `resh proc [<verb>] --help`).
    fn display_help(&self, verb: Option<&str>, io: &mut IoStreams) -> anyhow::Result<Status> {
        let text = crate::core::help::render_legacy("proc", &PROC_HELP, self.verbs(), verb);
        write!(io.stdout, "{}", text)?;
        Ok(Status::ok())
    }
}

/// Signal names by number, from the platform's libc constants (Linux
/// numbering on Linux: 10 = USR1, 12 = USR2, 17 = CHLD, 19 = STOP).
const SIGNAL_NAMES: &[(&str, libc::c_int)] = &[
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("CHLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
    ("URG", libc::SIGURG),
    ("XCPU", libc::SIGXCPU),
    ("XFSZ", libc::SIGXFSZ),
    ("VTALRM", libc::SIGVTALRM),
    ("PROF", libc::SIGPROF),
    ("WINCH", libc::SIGWINCH),
    ("IO", libc::SIGIO),
    ("SYS", libc::SIGSYS),
];

/// Name for a signal number, or "UNKNOWN".
fn signal_label(num: libc::c_int) -> &'static str {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if num == libc::SIGPWR {
            return "PWR";
        }
        if num == libc::SIGSTKFLT {
            return "STKFLT";
        }
    }
    SIGNAL_NAMES
        .iter()
        .find(|(_, n)| *n == num)
        .map(|(name, _)| *name)
        .unwrap_or("UNKNOWN")
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_signal_labels_follow_platform_numbering() {
        for (num, name) in [
            (libc::SIGHUP, "HUP"),
            (libc::SIGKILL, "KILL"),
            (libc::SIGUSR1, "USR1"),
            (libc::SIGUSR2, "USR2"),
            (libc::SIGTERM, "TERM"),
            (libc::SIGCHLD, "CHLD"),
            (libc::SIGCONT, "CONT"),
            (libc::SIGSTOP, "STOP"),
        ] {
            assert_eq!(
                parse_signal_arg(&num.to_string()).unwrap(),
                (name.to_string(), num)
            );
        }
        assert_eq!(
            parse_signal_arg("999").unwrap(),
            ("UNKNOWN".to_string(), 999)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn numeric_signal_labels_linux() {
        let label = |n: i32| parse_signal_arg(&n.to_string()).unwrap().0;
        assert_eq!(label(10), "USR1");
        assert_eq!(label(12), "USR2");
        assert_eq!(label(17), "CHLD");
        assert_eq!(label(18), "CONT");
        assert_eq!(label(19), "STOP");
        assert_eq!(label(20), "TSTP");
        assert_eq!(label(16), "STKFLT");
        assert_eq!(label(30), "PWR");
        assert_eq!(label(31), "SYS");
    }

    #[test]
    fn named_signals_round_trip() {
        assert_eq!(
            parse_signal_arg("sigusr1").unwrap(),
            ("USR1".to_string(), libc::SIGUSR1)
        );
        assert_eq!(
            parse_signal_arg("TERM").unwrap(),
            ("TERM".to_string(), libc::SIGTERM)
        );
        assert!(parse_signal_arg("bogus").is_err());
    }

    #[test]
    fn help_detection_is_exact() {
        let none = Args::new();
        assert!(should_show_help("help", &none));
        assert!(should_show_help("--help", &none));
        assert!(should_show_help("-h", &none));
        assert!(!should_show_help("signal", &none));
        assert!(!should_show_help("pre-hotfix", &none));
        assert!(!should_show_help("x-help", &none));
        let mut a = Args::new();
        a.insert("help".into(), "1".into());
        assert!(should_show_help("signal", &a));
    }

    #[test]
    fn help_url_forms_and_rendering() {
        let h = ProcHandle::from_url(&Url::parse("proc://--help").unwrap()).unwrap();
        let out = crate::core::help::render_legacy("proc", &PROC_HELP, h.verbs(), None);
        assert!(out.starts_with("Handle: proc"), "{out}");
        assert!(ProcHandle::from_url(&Url::parse("proc://my-hosts").unwrap()).is_err());
    }

    // SEC-03: no PID may wrap into 0 or a negative pid_t on its way to kill().
    // These tests only parse; no signal is ever sent.
    #[test]
    fn pid_parsing_rejects_out_of_range_values() {
        assert_eq!(parse_pid("1").unwrap(), 1);
        assert_eq!(parse_pid("4242").unwrap(), 4242);
        assert_eq!(
            parse_pid(&libc::pid_t::MAX.to_string()).unwrap(),
            libc::pid_t::MAX
        );
        for bad in [
            "0",
            "-1",
            "-4242",
            "2147483648",
            "4294967295",
            "4294967296",
            "18446744073709551615",
            "18446744073709551616",
            "99999999999999999999999",
            "",
            "12a",
            "0x10",
            "1.5",
            " 1",
        ] {
            assert!(parse_pid(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn proc_url_rejects_wrapping_pids() {
        for url in [
            "proc://4294967295",
            "proc://2147483648",
            "proc://0",
            "proc://-1",
        ] {
            assert!(
                ProcHandle::from_url(&Url::parse(url).unwrap()).is_err(),
                "{url}"
            );
        }
        let h = ProcHandle::from_url(&Url::parse("proc://2147483647").unwrap()).unwrap();
        assert_eq!(h.resolve_pid().unwrap(), 2147483647);
        let h = ProcHandle::from_url(&Url::parse("proc://self").unwrap()).unwrap();
        assert_eq!(h.resolve_pid().unwrap() as u32, std::process::id());
    }

    #[test]
    fn resolve_pid_rechecks_range_without_from_url() {
        // A handle built without from_url must still never yield -1.
        let h = ProcHandle {
            name: "4294967295".to_string(),
        };
        assert!(h.resolve_pid().is_err());
        let h = ProcHandle {
            name: "0".to_string(),
        };
        assert!(h.resolve_pid().is_err());
    }

    #[test]
    fn kill_stage_with_wrapping_pid_fails_before_dispatch() {
        let p = crate::core::parse::parse_stage("proc://4294967295.kill").unwrap();
        assert_eq!(p.verb, "kill");
        let url = Url::parse(&p.target).unwrap();
        assert!(ProcHandle::from_url(&url).is_err());
    }
}
