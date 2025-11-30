use anyhow::{anyhow, Context};
use serde_json::json;
use url::Url;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

#[cfg(unix)]
use nix::sys::resource::{getrlimit, setrlimit, Resource};

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
}

pub struct ProcHandle {
    name: String, // Can be a PID or "self"
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

        // Allow "self" or numeric PID
        if name == "self" {
            Ok(Self { name })
        } else {
            let pid: u32 = name.parse()
                .with_context(|| format!("invalid pid: {}", name))?;

            if pid == 0 {
                return Err(anyhow!("invalid pid: must be positive"));
            }

            Ok(Self { name })
        }
    }

    /// Resolve the name to an actual PID
    fn resolve_pid(&self) -> anyhow::Result<libc::pid_t> {
        if self.name == "self" {
            Ok(std::process::id() as libc::pid_t)
        } else {
            let pid: u32 = self.name.parse()
                .with_context(|| format!("invalid pid: {}", self.name))?;
            Ok(pid as libc::pid_t)
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
        Err(anyhow!("proc:// nice operations only supported on Unix-like systems"))
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
        Err(anyhow!("proc:// nice operations only supported on Unix-like systems"))
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
            "nice.get" => {
                match self.get_nice() {
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
                }
            }
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
                                
                                let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
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
                                
                                let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
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
                        _ => "custom"
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
        writeln!(io.stderr, "Error: setPriority not supported on this platform")?;
        Ok(Status::err(5, "setPriority not supported on this platform"))
    }

    #[cfg(unix)]
    fn send_signal_internal(&self, _signal_name: &str, signal_num: libc::c_int) -> anyhow::Result<bool> {
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
    fn send_signal_internal(&self, _signal_name: &str, _signal_num: libc::c_int) -> anyhow::Result<bool> {
        Err(anyhow!("proc:// only supported on Unix-like systems"))
    }

    fn resolve_signal(verb: &str, args: &Args) -> anyhow::Result<(String, libc::c_int)> {
        match verb {
            "signal" => {
                let sig = args.get("sig")
                    .ok_or_else(|| anyhow!("missing arg: sig"))?;
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
            return Ok(Status::err(1, "proc:// only supported on Unix-like systems"));
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
                    
                    let code = if e.to_string().contains("permission denied") { 4 } else { 1 };
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
                    }).to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid max_bytes parameter".to_string()));
                }
            },
            None => 4096
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
                    }).to_string();
                    writeln!(io.stdout, "{}", error_json)?;
                    return Ok(Status::err(3, "invalid tail parameter".to_string()));
                }
            },
            None => max_bytes
        };
        
        let json_mode = args.get("json")
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
            return Ok(Status::err(3, format!("invalid encoding value: {}", encoding)));
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
            _ => unreachable!("stream validation should prevent this")
        }
    }

    /// Read and process a log file according to the specified parameters
    fn read_log_file(&self, path: &PathBuf, max_bytes: usize, tail: usize, encoding: &str) -> anyhow::Result<StreamData> {
        use base64::Engine as _;
        
        if !path.exists() {
            return Err(anyhow!("log file not found: {}", path.display()));
        }

        let mut file = File::open(path)
            .with_context(|| format!("failed to open log file: {}", path.display()))?;

        // Get file length
        let file_len = file.metadata()
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
        let bytes_read = file.read(&mut buffer)
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
            "auto" => {
                match String::from_utf8(buffer.clone()) {
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
                }
            }
            _ => Err(anyhow!("invalid encoding: {}", encoding))
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
                    return Ok(Status::err(2, format!("invalid pid argument: '{}'", pid_str)));
                }
            }
        } else {
            self.resolve_pid()?
        };

        // Check if this is check-only mode
        let check_only = args.get("dry_run")
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false);

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
            Ok(Status::err(1, "one or more resource limit operations failed"))
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
        Ok(Status::err(1, "resource limits not supported on this platform"))
    }

    /// Process a single resource limit setting
    #[cfg(unix)]
    fn process_resource_limit(&self, name: &str, value: &str, _pid: i32, check_only: bool) -> anyhow::Result<serde_json::Value> {
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
            return Err(anyhow!("soft limit ({}) cannot exceed hard limit ({})", new_soft, new_hard));
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
    fn parse_limit_value(&self, value: &str, current_soft: u64, current_hard: u64) -> anyhow::Result<(u64, u64)> {
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
            return num_str.parse::<u64>()
                .map_err(|_| anyhow!("invalid time value: '{}'", value));
        }

        // Handle SI suffixes for byte values
        if value.ends_with('K') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000);
        }

        if value.ends_with('M') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000);
        }

        if value.ends_with('G') {
            let num_str = &value[..value.len() - 1];
            let base: u64 = num_str.parse()
                .map_err(|_| anyhow!("invalid byte value: '{}'", value))?;
            return Ok(base * 1_000_000_000);
        }

        // Plain number
        value.parse::<u64>()
            .map_err(|_| anyhow!("invalid limit value: '{}'", value))
    }
}

impl Handle for ProcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["signal", "kill", "term", "int", "hup", "stop", "cont", "usr1", "usr2", 
          "nice.get", "nice.set", "nice.inc", "nice.dec", "setPriority", "io.peek", "limits.set"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        match verb {
            "signal" | "kill" | "term" | "int" | "hup" | "stop" | "cont" | "usr1" | "usr2" => {
                self.handle_signal(verb, args, io)
            }
            "nice.get" | "nice.set" | "nice.inc" | "nice.dec" => {
                self.handle_nice(verb, args, io)
            }
            "setPriority" => {
                self.verb_set_priority(args, io)
            }
            "io.peek" => {
                self.handle_io_peek(args, io)
            }
            "limits.set" => {
                self.limits_set(args, io)
            }
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
    // Try to parse as number first
    if let Ok(num) = sig.parse::<i32>() {
        // Map common signal numbers to names for output
        let name = match num {
            1 => "HUP",
            2 => "INT", 
            3 => "QUIT",
            9 => "KILL",
            15 => "TERM",
            17 => "STOP", // Note: SIGSTOP is typically 19 on Linux, 17 on some other systems
            18 => "CONT", // Note: SIGCONT is typically 18 on Linux
            19 => "STOP", // Linux SIGSTOP
            20 => "CONT", // Some systems use 20 for CONT
            30 => "USR1",
            31 => "USR2",
            _ => "UNKNOWN",
        };
        return Ok((name.to_string(), num));
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