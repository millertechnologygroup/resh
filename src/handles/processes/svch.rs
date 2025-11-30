use anyhow::{Context, bail};
use percent_encoding;
use serde_json::{self, json};
use std::{thread, time::Duration};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::path::Path;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("svc", |u| Ok(Box::new(SvcHandle::from_url(u)?)));
}

#[derive(Debug, Clone)]
pub enum Backend {
    Systemd,
    OpenRc,
    Unknown,
}

pub struct SvcHandle {
    name: String,
}

impl SvcHandle {
    pub fn from_url(u: &Url) -> anyhow::Result<Self> {
        // Accept host + path, strip leading slashes, join with '/'
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
        Ok(Self { name })
    }

    fn detect_backend() -> Backend {
        if std::path::Path::new("/run/systemd/system").exists() || which::which("systemctl").is_ok()
        {
            return Backend::Systemd;
        }
        if which::which("rc-status").is_ok() || which::which("rc-service").is_ok() {
            return Backend::OpenRc;
        }
        Backend::Unknown
    }

    fn unit_name(&self) -> String {
        if self.name.ends_with(".service") {
            self.name.clone()
        } else {
            format!("{}.service", self.name)
        }
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

    fn status_systemd(&self) -> anyhow::Result<serde_json::Value> {
        // Try D-Bus first
        let dbus_result = self.status_systemd_dbus();
        if dbus_result.is_ok() {
            return dbus_result;
        }
        
        // Fallback to systemctl command
        self.status_systemd_fallback()
    }
    
    fn status_systemd_dbus(&self) -> anyhow::Result<serde_json::Value> {
        use zbus::blocking::Connection;
        let conn = Connection::system().context("Failed to connect to D-Bus")?;
        let manager = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        ).context("Failed to create Manager proxy")?;
        
        let unit = self.unit_name();
        let unit_path: zvariant::OwnedObjectPath = manager.call("GetUnit", &(unit.clone(),))
            .context("Failed to get unit path")?;
        
        let unit_proxy = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path.as_str(),
            "org.freedesktop.systemd1.Unit",
        ).context("Failed to create Unit proxy")?;

        let active_state: String = unit_proxy.get_property("ActiveState")
            .context("Failed to get ActiveState")?;
        let sub_state: String = unit_proxy.get_property("SubState")
            .context("Failed to get SubState")?;
        let description: String = unit_proxy.get_property("Description")
            .context("Failed to get Description")?;

        // Timestamps (usec)
        let active_enter_us: u64 = unit_proxy.get_property("ActiveEnterTimestamp").unwrap_or(0);
        let active_exit_us: u64 = unit_proxy.get_property("ActiveExitTimestamp").unwrap_or(0);
        let inactive_enter_us: u64 = unit_proxy.get_property("InactiveEnterTimestamp").unwrap_or(0);

        // ExecMainPID and ExecMainStatus (Service interface)
        let svc_proxy = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path.as_str(),
            "org.freedesktop.systemd1.Service",
        );
        let (pid, exit_status) = if let Ok(p) = &svc_proxy {
            let pid: u32 = p.get_property("ExecMainPID").unwrap_or(0);
            let st: i32 = p.get_property("ExecMainStatus").unwrap_or(0);
            (pid, st)
        } else {
            (0u32, 0i32)
        };

        let ts_active_enter = Self::fmt_ts_us(active_enter_us);
        let ts_active_exit = Self::fmt_ts_us(active_exit_us);
        let ts_inactive_enter = Self::fmt_ts_us(inactive_enter_us);

        Ok(json!({
            "name": unit,
            "backend": "systemd",
            "active_state": active_state,
            "sub_state": sub_state,
            "description": description,
            "pid": pid,
            "exit_status": exit_status,
            "timestamps": {
                "active_enter": ts_active_enter,
                "active_exit": ts_active_exit,
                "inactive_enter": ts_inactive_enter
            }
        }))
    }
    
    fn status_systemd_fallback(&self) -> anyhow::Result<serde_json::Value> {
        let unit = self.unit_name();
        let output = std::process::Command::new("systemctl")
            .args(["show", &unit])
            .output()
            .context("Failed to execute systemctl show")?;
            
        if !output.status.success() {
            anyhow::bail!("systemctl show failed with status: {}", output.status);
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut active_state = "unknown".to_string();
        let mut sub_state = "unknown".to_string();
        let mut description = "No description available".to_string();
        
        for line in stdout.lines() {
            if let Some(value) = line.strip_prefix("ActiveState=") {
                active_state = value.to_string();
            } else if let Some(value) = line.strip_prefix("SubState=") {
                sub_state = value.to_string();
            } else if let Some(value) = line.strip_prefix("Description=") {
                description = value.to_string();
            }
        }
        
        Ok(json!({
            "name": unit,
            "backend": "systemd",
            "active_state": active_state,
            "sub_state": sub_state,
            "description": description,
            "pid": 0,
            "exit_status": 0,
            "timestamps": {
                "active_enter": "",
                "active_exit": "",
                "inactive_enter": ""
            }
        }))
    }

    fn status_openrc(&self) -> anyhow::Result<serde_json::Value> {
        let svc = self.name.clone();
        
        // Try rc-service first
        let out = std::process::Command::new("rc-service")
            .arg(&svc)
            .arg("status")
            .output();
            
        let (state, pid, raw) = match out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                let combined = format!("{}{}", stdout, stderr);
                
                let state = if combined.contains("started") || combined.contains("running") {
                    "running"
                } else {
                    "stopped_or_unknown"
                };
                
                let pid = Self::parse_pid_from_output(&combined);
                (state.to_string(), pid, combined)
            }
            Err(_) => {
                // Fallback to rc-status
                let o2 = std::process::Command::new("rc-status")
                    .arg("-s")
                    .output()
                    .context("rc-status not available")?;
                let s2 = String::from_utf8_lossy(&o2.stdout);
                let found = s2.lines().find(|l| l.contains(&svc)).unwrap_or("");
                
                let state = if found.contains("started") || found.contains("running") {
                    "running"
                } else {
                    "stopped_or_unknown"
                };
                
                let pid = Self::parse_pid_from_output(found);
                (state.to_string(), pid, found.to_string())
            }
        };
        
        Ok(json!({
            "name": svc,
            "backend": "openrc",
            "state": state,
            "pid": pid,
            "exit_status": null,
            "timestamps": null,
            "raw": raw
        }))
    }
    
    fn parse_pid_from_output(text: &str) -> Option<u32> {
        use regex::Regex;
        // Look for patterns like "pid 123", "pid: 123", "(pid: 123)"
        let re = Regex::new(r"\bpid:?\s*(\d+)").unwrap();
        if let Some(caps) = re.captures(text) {
            caps.get(1)?.as_str().parse().ok()
        } else {
            None
        }
    }

    fn systemd_is_enabled(&self) -> anyhow::Result<bool> {
        use zbus::blocking::Connection;
        let conn = Connection::system()?;
        let manager = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )?;
        let unit = self.unit_name();
        // Try GetUnitFileState; fallback to systemctl is-enabled
        let state: Result<String, _> = manager.call("GetUnitFileState", &(unit.clone(),));
        if let Ok(s) = state {
            return Ok(s == "enabled" || s == "static" || s == "indirect");
        }
        let out = std::process::Command::new("systemctl")
            .arg("is-enabled")
            .arg(&unit)
            .output();
        match out {
            Ok(o) => Ok(String::from_utf8_lossy(&o.stdout).trim() == "enabled"),
            Err(e) => Err(e.into()),
        }
    }

    fn systemd_start(&self) -> anyhow::Result<()> {
        use zbus::blocking::Connection;
        
        // Try D-Bus first
        let dbus_result = (|| -> anyhow::Result<()> {
            let conn = Connection::system()?;
            let manager = zbus::blocking::Proxy::new(
                &conn,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            )?;
            let unit = self.unit_name();
            let _: zvariant::OwnedObjectPath = manager.call("StartUnit", &(unit, "replace"))?;
            Ok(())
        })();
        
        // If D-Bus fails, fallback to systemctl command
        if dbus_result.is_err() {
            let unit = self.unit_name();
            let status = std::process::Command::new("systemctl")
                .arg("start")
                .arg(&unit)
                .status();
            match status {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => bail!("systemctl start {} failed: {}", unit, s),
                Err(e) => bail!("systemctl not available: {}", e),
            }
        } else {
            dbus_result
        }
    }

    fn systemd_force_stop(&self) -> anyhow::Result<()> {
        use zbus::blocking::Connection;
        
        // Try aggressive stop with "replace-irreversibly" mode first
        let dbus_result = (|| -> anyhow::Result<()> {
            let conn = Connection::system()?;
            let manager = zbus::blocking::Proxy::new(
                &conn,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            )?;
            let unit = self.unit_name();
            let _: zvariant::OwnedObjectPath = manager.call("StopUnit", &(unit, "replace-irreversibly"))?;
            Ok(())
        })();
        
        // If D-Bus fails, fallback to systemctl kill + stop
        if dbus_result.is_err() {
            let unit = self.unit_name();
            
            // First try systemctl kill
            let _ = std::process::Command::new("systemctl")
                .args(["kill", "--signal=SIGTERM", &unit])
                .status();
            
            // Give it a moment, then try regular stop
            thread::sleep(Duration::from_millis(500));
            
            let status = std::process::Command::new("systemctl")
                .arg("stop")
                .arg(&unit)
                .status();
            match status {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => bail!("systemctl stop {} failed: {}", unit, s),
                Err(e) => bail!("systemctl not available: {}", e),
            }
        } else {
            dbus_result
        }
    }

    fn systemd_restart(&self) -> anyhow::Result<()> {
        use zbus::blocking::Connection;
        
        // Try D-Bus first
        let dbus_result = (|| -> anyhow::Result<()> {
            let conn = Connection::system()?;
            let manager = zbus::blocking::Proxy::new(
                &conn,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            )?;
            let unit = self.unit_name();
            let _: zvariant::OwnedObjectPath = manager.call("RestartUnit", &(unit, "replace"))?;
            Ok(())
        })();
        
        // If D-Bus fails, fallback to systemctl command
        if dbus_result.is_err() {
            let unit = self.unit_name();
            let status = std::process::Command::new("systemctl")
                .arg("restart")
                .arg(&unit)
                .status();
            match status {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => bail!("systemctl restart {} failed: {}", unit, s),
                Err(e) => bail!("systemctl not available: {}", e),
            }
        } else {
            dbus_result
        }
    }

    fn systemd_control(&self, action: &str) -> anyhow::Result<()> {
        use zbus::blocking::Connection;
        let conn = Connection::system()?;
        let manager = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )?;
        let unit = self.unit_name();
        match action {
            "start" => {
                let _: zvariant::OwnedObjectPath = manager.call("StartUnit", &(unit, "replace"))?;
            }
            "stop" => {
                let _: zvariant::OwnedObjectPath = manager.call("StopUnit", &(unit, "replace"))?;
            }
            "restart" => {
                let _: zvariant::OwnedObjectPath =
                    manager.call("RestartUnit", &(unit, "replace"))?;
            }
            "reload" => {
                let _: zvariant::OwnedObjectPath =
                    manager.call("ReloadUnit", &(unit, "replace"))?;
            }
            "enable" => {
                // EnableUnitFiles(files, runtime, force)
                let files: Vec<&str> = vec![&unit];
                let (_changes, _carr): (Vec<zvariant::OwnedValue>, bool) =
                    manager.call("EnableUnitFiles", &(files, false, true))?;
            }
            "disable" => {
                // DisableUnitFiles(files, runtime)
                let files: Vec<&str> = vec![&unit];
                let _changes: Vec<zvariant::OwnedValue> =
                    manager.call("DisableUnitFiles", &(files, false))?;
            }
            "mask" => {
                let files: Vec<&str> = vec![&unit];
                let (_changes, _carr): (Vec<zvariant::OwnedValue>, bool) =
                    manager.call("MaskUnitFiles", &(files, false, true))?;
            }
            "unmask" => {
                let files: Vec<&str> = vec![&unit];
                let _changes: Vec<zvariant::OwnedValue> =
                    manager.call("UnmaskUnitFiles", &(files, false))?;
            }
            _ => bail!("unsupported action"),
        }
        Ok(())
    }

    fn openrc_is_enabled(&self) -> anyhow::Result<bool> {
        // Check if service is in default runlevel
        let svc = self.name.clone();
        let out = std::process::Command::new("rc-update")
            .args(["show", "default"])
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                Ok(s.lines()
                    .any(|l| l.split_whitespace().next() == Some(svc.as_str())))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn openrc_start(&self) -> anyhow::Result<()> {
        let svc = self.name.clone();
        let status = std::process::Command::new("rc-service")
            .arg(&svc)
            .arg("start")
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => bail!("rc-service {} start failed: {}", svc, s),
            Err(e) => bail!("rc-service not available: {}", e),
        }
    }

    fn openrc_restart(&self) -> anyhow::Result<()> {
        let svc = self.name.clone();
        let status = std::process::Command::new("rc-service")
            .arg(&svc)
            .arg("restart")
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => bail!("rc-service {} restart failed: {}", svc, s),
            Err(e) => bail!("rc-service not available: {}", e),
        }
    }

    fn openrc_control(&self, action: &str) -> anyhow::Result<()> {
        let svc = self.name.clone();
        match action {
            "enable" => {
                // add to default runlevel
                let st = std::process::Command::new("rc-update")
                    .args(["add", &svc, "default"])
                    .status();
                match st {
                    Ok(s) if s.success() => (),
                    Ok(s) => bail!("rc-update add failed: {}", s),
                    Err(e) => bail!("rc-update missing: {}", e),
                }
            }
            "disable" => {
                let st = std::process::Command::new("rc-update")
                    .args(["del", &svc, "default"])
                    .status();
                match st {
                    Ok(s) if s.success() => (),
                    Ok(s) => bail!("rc-update del failed: {}", s),
                    Err(e) => bail!("rc-update missing: {}", e),
                }
            }
            "mask" | "unmask" => {
                bail!("mask/unmask unsupported on OpenRC");
            }
            action => {
                let status = std::process::Command::new("rc-service")
                    .arg(&svc)
                    .arg(action)
                    .status();
                match status {
                    Ok(s) if s.success() => (),
                    Ok(s) => bail!("rc-service {} {} failed: {}", svc, action, s),
                    Err(e) => bail!("rc-service not available: {}", e),
                }
            }
        }
        Ok(())
    }

    fn wait_until(&self, want_active: bool, timeout_ms: u64) -> anyhow::Result<bool> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            match Self::detect_backend() {
                Backend::Systemd => {
                    let st = self.status_systemd()?;
                    let active = st
                        .get("active_state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        == "active";
                    if active == want_active {
                        return Ok(true);
                    }
                }
                Backend::OpenRc => {
                    let st = self.status_openrc()?;
                    let running =
                        st.get("state").and_then(|v| v.as_str()).unwrap_or("") == "running";
                    if running == want_active {
                        return Ok(true);
                    }
                }
                Backend::Unknown => return Ok(false),
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    // Helper functions for logs functionality
    fn parse_lines_arg(args: &Args) -> usize {
        args.get("lines")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(200)
    }

    fn parse_bool_arg(args: &Args, key: &str) -> bool {
        args.get(key)
            .map(|s| s == "true")
            .unwrap_or(false)
    }

    fn map_log_level(level: &str) -> Option<&str> {
        match level {
            "debug" => Some("debug"),
            "info" => Some("info"),
            "warning" => Some("warning"),
            "err" | "error" => Some("err"),
            "crit" | "critical" => Some("crit"),
            _ => None,
        }
    }

    fn logs_systemd(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let mut cmd = Command::new("journalctl");
        cmd.arg("-u").arg(self.unit_name());
        cmd.arg("--no-pager");
        cmd.arg("--output=short-iso");

        let lines = Self::parse_lines_arg(args);
        cmd.arg("-n").arg(lines.to_string());

        if let Some(since) = args.get("since") {
            cmd.arg("--since").arg(since);
        }

        if let Some(until) = args.get("until") {
            cmd.arg("--until").arg(until);
        }

        if let Some(level) = args.get("level") {
            if let Some(priority) = Self::map_log_level(level) {
                cmd.arg("-p").arg(priority);
            }
        }

        if Self::parse_bool_arg(args, "reverse") {
            cmd.arg("-r");
        }

        if Self::parse_bool_arg(args, "follow") {
            cmd.arg("-f");
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .context("Failed to spawn journalctl")?;

        // Stream stdout to io.stdout
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        writeln!(io.stdout, "{}", line)?;
                        io.stdout.flush()?;
                    }
                    Err(e) => {
                        writeln!(io.stderr, "Error reading journalctl output: {}", e)?;
                        break;
                    }
                }
            }
        }

        let exit_status = child.wait()
            .context("Failed to wait for journalctl")?;

        if exit_status.success() {
            Ok(Status::ok())
        } else {
            let code = exit_status.code().unwrap_or(1);
            Ok(Status::err(code, format!("journalctl failed with exit code {}", code)))
        }
    }

    fn logs_openrc(&self, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        let possible_paths = [
            format!("/var/log/{}.log", self.name),
            format!("/var/log/{}/{}.log", self.name, self.name),
            format!("/var/log/{}/current", self.name),
        ];

        let mut log_path = None;
        for path in &possible_paths {
            if Path::new(path).is_file() {
                log_path = Some(path);
                break;
            }
        }

        let log_file = match log_path {
            Some(path) => path,
            None => {
                writeln!(io.stderr, "No logs found for service '{}'", self.name)?;
                writeln!(io.stderr, "Checked paths: {}", possible_paths.join(", "))?;
                return Ok(Status::err(2, "no logs found for service"));
            }
        };

        let lines = Self::parse_lines_arg(args);
        let reverse = Self::parse_bool_arg(args, "reverse");

        // Use tail command to get the last N lines
        let mut cmd = Command::new("tail");
        cmd.arg("-n").arg(lines.to_string());
        cmd.arg(log_file);

        if Self::parse_bool_arg(args, "follow") {
            cmd.arg("-f");
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .context("Failed to spawn tail command")?;

        // Collect lines if we need to reverse them, otherwise stream directly
        if reverse && !Self::parse_bool_arg(args, "follow") {
            let output = child.wait_with_output()
                .context("Failed to read tail output")?;

            if output.status.success() {
                let lines: Vec<&str> = std::str::from_utf8(&output.stdout)
                    .context("Invalid UTF-8 in log file")?
                    .lines()
                    .rev() // Reverse the order
                    .collect();

                for line in lines {
                    writeln!(io.stdout, "{}", line)?;
                }
                Ok(Status::ok())
            } else {
                let stderr = std::str::from_utf8(&output.stderr).unwrap_or("unknown error");
                writeln!(io.stderr, "tail failed: {}", stderr)?;
                Ok(Status::err(output.status.code().unwrap_or(1), "tail command failed"))
            }
        } else {
            // Stream output directly
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            writeln!(io.stdout, "{}", line)?;
                            io.stdout.flush()?;
                        }
                        Err(e) => {
                            writeln!(io.stderr, "Error reading log file: {}", e)?;
                            break;
                        }
                    }
                }
            }

            let exit_status = child.wait()
                .context("Failed to wait for tail command")?;

            if exit_status.success() {
                Ok(Status::ok())
            } else {
                let code = exit_status.code().unwrap_or(1);
                Ok(Status::err(code, format!("tail failed with exit code {}", code)))
            }
        }
    }

    fn scale_systemd(&self, count: u32, io: &mut IoStreams) -> anyhow::Result<Status> {
        // URL-decode the name first in case it contains encoded characters like %40 for @
        let decoded_name = percent_encoding::percent_decode(self.name.as_bytes())
            .decode_utf8()
            .unwrap_or(std::borrow::Cow::Borrowed(&self.name));
            
        // Determine if this is a template unit
        let is_template = decoded_name.ends_with("@.") || decoded_name.ends_with("@.service");
        
        if is_template {
            self.scale_systemd_template(count, io)
        } else {
            self.scale_systemd_non_template(count, io)
        }
    }

    fn scale_systemd_template(&self, count: u32, io: &mut IoStreams) -> anyhow::Result<Status> {
        use zbus::blocking::Connection;
        
        // URL-decode the name first in case it contains encoded characters like %40 for @
        let decoded_name = percent_encoding::percent_decode(self.name.as_bytes())
            .decode_utf8()
            .unwrap_or(std::borrow::Cow::Borrowed(&self.name));
        
        // Normalize service name to end with .service using the decoded name
        let base_unit = if decoded_name.ends_with("@.service") {
            decoded_name.to_string()
        } else if decoded_name.ends_with("@.") {
            format!("{}.service", decoded_name)
        } else {
            // Not a template, this shouldn't happen
            return self.scale_systemd_non_template(count, io);
        };

        let conn = Connection::system().context("Failed to connect to D-Bus")?;
        let manager = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        ).context("Failed to create Manager proxy")?;

        // List all loaded units to find existing instances
        let units: Vec<(String, String, String, String, String, String, zvariant::OwnedObjectPath, u32, String, zvariant::OwnedObjectPath)> = 
            manager.call("ListUnits", &()).context("Failed to list units")?;
        
        // Extract the base name without @.service suffix to create pattern
        let base_name = if let Some(stripped) = base_unit.strip_suffix("@.service") {
            stripped
        } else if let Some(stripped) = base_unit.strip_suffix("@.") {
            stripped
        } else {
            // If not a template unit, this shouldn't happen
            return self.scale_systemd_non_template(count, io);
        };
        
        // Find instances that match our template pattern
        let mut existing_instances = Vec::new();
        for (unit_name, _, _, active_state, _, _, _, _, _, _) in &units {
            if let Some(suffix) = unit_name.strip_prefix(&format!("{}@", base_name)) {
                if let Some(instance_part) = suffix.strip_suffix(".service") {
                    if let Ok(instance_num) = instance_part.parse::<u32>() {
                        existing_instances.push((instance_num, unit_name.clone(), active_state == "active"));
                    }
                }
            }
        }

        let mut instances_started = Vec::new();
        let mut instances_stopped = Vec::new();
        let mut errors = Vec::new();

        // Start instances 1 through count if they're not active
        for i in 1..=count {
            let instance_name = format!("{}@{}.service", base_name, i);
            let is_currently_active = existing_instances
                .iter()
                .find(|(num, _, _)| *num == i)
                .map(|(_, _, active)| *active)
                .unwrap_or(false);
            
            if !is_currently_active {
                let call_result: Result<zvariant::OwnedObjectPath, _> = manager.call("StartUnit", &(instance_name.clone(), "replace"));
                match call_result {
                    Ok(_) => instances_started.push(instance_name),
                    Err(e) => errors.push(format!("Failed to start {}: {}", instance_name, e)),
                }
            }
        }

        // Stop instances with numbers > count that are currently active
        for (instance_num, instance_name, is_active) in &existing_instances {
            if *instance_num > count && *is_active {
                let call_result: Result<zvariant::OwnedObjectPath, _> = manager.call("StopUnit", &(instance_name.clone(), "replace"));
                match call_result {
                    Ok(_) => instances_stopped.push(instance_name.clone()),
                    Err(e) => errors.push(format!("Failed to stop {}: {}", instance_name, e)),
                }
            }
        }

        // Count the final number of active instances
        let final_units: Vec<(String, String, String, String, String, String, zvariant::OwnedObjectPath, u32, String, zvariant::OwnedObjectPath)> = 
            manager.call("ListUnits", &()).unwrap_or_default();
        
        let effective_count = final_units.iter()
            .filter(|(unit_name, _, _, active_state, _, _, _, _, _, _)| {
                if let Some(suffix) = unit_name.strip_prefix(&format!("{}@", base_name)) {
                    if let Some(instance_part) = suffix.strip_suffix(".service") {
                        if instance_part.parse::<u32>().is_ok() {
                            return active_state == "active";
                        }
                    }
                }
                false
            })
            .count() as u32;

        let mut result = json!({
            "name": base_unit,
            "backend": "systemd",
            "desired_count": count,
            "template": true,
            "instances_started": instances_started,
            "instances_stopped": instances_stopped,
            "effective_count": effective_count,
            "note": "scaled systemd template unit"
        });

        if !errors.is_empty() {
            result["errors"] = json!(errors);
        }

        write!(io.stdout, "{}", serde_json::to_string(&result)?)?;
        
        if errors.is_empty() {
            Ok(Status::ok())
        } else {
            Ok(Status {
                ok: false,
                code: Some(1),
                reason: Some(format!("scaling completed with {} errors", errors.len())),
            })
        }
    }

    fn scale_systemd_non_template(&self, count: u32, io: &mut IoStreams) -> anyhow::Result<Status> {
        use zbus::blocking::Connection;
        
        let unit = self.unit_name();
        let conn = Connection::system().context("Failed to connect to D-Bus")?;
        let manager = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        ).context("Failed to create Manager proxy")?;

        // Get current state
        let current_status = self.status_systemd().unwrap_or_else(|_| json!({"active_state": "unknown"}));
        let current_active = current_status
            .get("active_state")
            .and_then(|v| v.as_str())
            .map(|s| s == "active")
            .unwrap_or(false);

        let mut error_msg = None;

        if count == 0 {
            // Stop the service if it's running
            if current_active {
                let call_result: Result<zvariant::OwnedObjectPath, _> = manager.call("StopUnit", &(unit.clone(), "replace"));
                if let Err(e) = call_result {
                    error_msg = Some(format!("Failed to stop {}: {}", unit, e));
                }
            }
        } else {
            // count >= 1: ensure service is started
            if !current_active {
                let call_result: Result<zvariant::OwnedObjectPath, _> = manager.call("StartUnit", &(unit.clone(), "replace"));
                if let Err(e) = call_result {
                    error_msg = Some(format!("Failed to start {}: {}", unit, e));
                }
            }
        }

        // Get final state
        let final_status = self.status_systemd().unwrap_or_else(|_| json!({"active_state": "unknown"}));
        let final_active = final_status
            .get("active_state")
            .and_then(|v| v.as_str())
            .map(|s| s == "active")
            .unwrap_or(false);

        let effective_count = if final_active { 1 } else { 0 };

        let mut result = json!({
            "name": unit,
            "backend": "systemd",
            "desired_count": count,
            "template": false,
            "effective_count": effective_count,
            "note": format!("non-template service scaled to {}", if count == 0 { "0" } else { "1" })
        });

        let has_error = error_msg.is_some();
        if let Some(error) = error_msg {
            result["error"] = json!(error);
        }

        write!(io.stdout, "{}", serde_json::to_string(&result)?)?;

        if has_error {
            Ok(Status {
                ok: false,
                code: Some(1),
                reason: Some("scaling failed".to_string()),
            })
        } else {
            Ok(Status::ok())
        }
    }

    fn scale_openrc(&self, count: u32, io: &mut IoStreams) -> anyhow::Result<Status> {
        let svc = self.name.clone();
        
        // Get current state
        let current_status = self.status_openrc().unwrap_or_else(|_| json!({"state": "unknown"}));
        let current_running = current_status
            .get("state")
            .and_then(|v| v.as_str())
            .map(|s| s == "running")
            .unwrap_or(false);

        let mut error_msg = None;
        
        if count == 0 {
            // Stop the service if it's running
            if current_running {
                if let Err(e) = self.openrc_control("stop") {
                    error_msg = Some(format!("Failed to stop {}: {}", svc, e));
                }
            }
        } else {
            // count >= 1: ensure service is started
            if !current_running {
                if let Err(e) = self.openrc_start() {
                    error_msg = Some(format!("Failed to start {}: {}", svc, e));
                }
            }
        }

        // Get final state
        let final_status = self.status_openrc().unwrap_or_else(|_| json!({"state": "unknown"}));
        let final_running = final_status
            .get("state")
            .and_then(|v| v.as_str())
            .map(|s| s == "running")
            .unwrap_or(false);

        let effective_count = if final_running { 1 } else { 0 };

        let mut result = json!({
            "name": svc,
            "backend": "openrc",
            "desired_count": count,
            "effective_count": effective_count,
            "note": "openrc scaling is min/max 1 only"
        });

        let has_error = error_msg.is_some();
        if let Some(error) = error_msg {
            result["error"] = json!(error);
        }

        write!(io.stdout, "{}", serde_json::to_string(&result)?)?;

        if has_error {
            Ok(Status {
                ok: false,
                code: Some(1),
                reason: Some("scaling failed".to_string()),
            })
        } else {
            Ok(Status::ok())
        }
    }
}

impl Handle for SvcHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "status",
            "restart",
            "start",
            "stop",
            "reload",
            "enable",
            "disable",
            "mask",
            "unmask",
            "is-enabled",
            "wait",
            "logs",
            "scale",
        ]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> anyhow::Result<Status> {
        match verb {
            "status" => {
                let backend = Self::detect_backend();
                let obj = match backend {
                    Backend::Systemd => match self.status_systemd() {
                        Ok(v) => v,
                        Err(e) => json!({
                            "name": self.unit_name(),
                            "backend": "systemd",
                            "error": e.to_string()
                        }),
                    },
                    Backend::OpenRc => match self.status_openrc() {
                        Ok(v) => v,
                        Err(e) => json!({
                            "name": self.name,
                            "backend": "openrc",
                            "error": e.to_string()
                        }),
                    },
                    Backend::Unknown => json!({
                        "name": self.name,
                        "backend": "unknown",
                        "error": "could not detect systemd or openrc"
                    }),
                };
                write!(io.stdout, "{}", serde_json::to_string(&obj)?)?;
                Ok(Status::ok())
            }
            "start" => {
                let backend = Self::detect_backend();
                match backend {
                    Backend::Systemd => {
                        match self.systemd_start() {
                            Ok(()) => {
                                let result = json!({
                                    "backend": "systemd",
                                    "name": self.unit_name(),
                                    "action": "start",
                                    "result": "success"
                                });
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "backend": "systemd",
                                    "name": self.unit_name(),
                                    "action": "start",
                                    "error": e.to_string()
                                });
                                writeln!(io.stderr, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("start failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::OpenRc => {
                        match self.openrc_start() {
                            Ok(()) => {
                                let result = json!({
                                    "backend": "openrc",
                                    "name": &self.name,
                                    "action": "start",
                                    "result": "success"
                                });
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "backend": "openrc",
                                    "name": &self.name,
                                    "action": "start",
                                    "error": e.to_string()
                                });
                                writeln!(io.stderr, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("start failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::Unknown => {
                        let error = json!({
                            "backend": "unknown",
                            "name": &self.name,
                            "action": "start",
                            "error": "no supported init system found"
                        });
                        writeln!(io.stderr, "{}", error)?;
                        Ok(Status {
                            ok: false,
                            code: Some(1),
                            reason: Some("no supported init system found".to_string()),
                        })
                    }
                }
            }
            "stop" => {
                let backend = Self::detect_backend();
                
                // Parse arguments
                let timeout_ms = args
                    .get("timeout")
                    .map(|s| s.parse::<u64>().context("timeout must be a positive integer"))
                    .transpose()?;
                
                let force = args
                    .get("force")
                    .map(|s| match s.as_str() {
                        "true" => Ok(true),
                        "false" => Ok(false),
                        _ => bail!("force must be 'true' or 'false'"),
                    })
                    .transpose()?
                    .unwrap_or(false);
                
                match backend {
                    Backend::Systemd => {
                        // Get initial state before stopping
                        let previous_state = self.status_systemd()
                            .ok()
                            .and_then(|v| v.get("active_state")?.as_str().map(|s| s.to_string()))
                            .unwrap_or("unknown".to_string());
                        
                        let stop_result = if force {
                            self.systemd_force_stop()
                        } else {
                            self.systemd_control("stop")
                        };
                        
                        match stop_result {
                            Ok(()) => {
                                let mut result = json!({
                                    "name": self.unit_name(),
                                    "backend": "systemd",
                                    "action": "stop",
                                    "requested": true,
                                    "previous_state": previous_state,
                                    "note": if force { "stopped via force" } else { "stopped via StopUnit" }
                                });
                                
                                if let Some(timeout) = timeout_ms {
                                    result["timeout_ms"] = timeout.into();
                                    // Wait for service to reach inactive state
                                    let reached_inactive = self.wait_until(false, timeout)?;
                                    result["reached_inactive"] = reached_inactive.into();
                                    
                                    // Get final state
                                    let final_state = self.status_systemd()
                                        .ok()
                                        .and_then(|v| v.get("active_state")?.as_str().map(|s| s.to_string()))
                                        .unwrap_or("unknown".to_string());
                                    result["final_state"] = final_state.into();
                                    
                                    if !reached_inactive {
                                        result["error"] = "timeout waiting for service to stop".into();
                                        writeln!(io.stdout, "{}", result)?;
                                        return Ok(Status {
                                            ok: false,
                                            code: Some(124),
                                            reason: Some("timeout waiting for service to stop".to_string()),
                                        });
                                    }
                                } else {
                                    // Get final state without waiting
                                    let final_state = self.status_systemd()
                                        .ok()
                                        .and_then(|v| v.get("active_state")?.as_str().map(|s| s.to_string()))
                                        .unwrap_or("unknown".to_string());
                                    result["final_state"] = final_state.into();
                                }
                                
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "name": self.unit_name(),
                                    "backend": "systemd",
                                    "action": "stop",
                                    "requested": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("stop failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::OpenRc => {
                        // Get initial state before stopping
                        let previous_state = self.status_openrc()
                            .ok()
                            .and_then(|v| v.get("state")?.as_str().map(|s| s.to_string()))
                            .unwrap_or("unknown".to_string());
                        
                        match self.openrc_control("stop") {
                            Ok(()) => {
                                let mut result = json!({
                                    "name": &self.name,
                                    "backend": "openrc",
                                    "action": "stop",
                                    "requested": true,
                                    "previous_state": previous_state
                                });
                                
                                if let Some(timeout) = timeout_ms {
                                    result["timeout_ms"] = timeout.into();
                                    // Wait for service to reach inactive state
                                    let reached_inactive = self.wait_until(false, timeout)?;
                                    result["reached_inactive"] = reached_inactive.into();
                                    
                                    // Get final state
                                    let final_state = self.status_openrc()
                                        .ok()
                                        .and_then(|v| v.get("state")?.as_str().map(|s| s.to_string()))
                                        .unwrap_or("stopped_or_unknown".to_string());
                                    result["final_state"] = final_state.into();
                                    
                                    if !reached_inactive {
                                        result["error"] = "timeout waiting for service to stop".into();
                                        writeln!(io.stdout, "{}", result)?;
                                        return Ok(Status {
                                            ok: false,
                                            code: Some(124),
                                            reason: Some("timeout waiting for service to stop".to_string()),
                                        });
                                    }
                                } else {
                                    // Get final state without waiting
                                    let final_state = self.status_openrc()
                                        .ok()
                                        .and_then(|v| v.get("state")?.as_str().map(|s| s.to_string()))
                                        .unwrap_or("stopped_or_unknown".to_string());
                                    result["final_state"] = final_state.into();
                                }
                                
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "name": &self.name,
                                    "backend": "openrc",
                                    "action": "stop",
                                    "requested": false,
                                    "error": e.to_string()
                                });
                                writeln!(io.stdout, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("stop failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::Unknown => {
                        let error = json!({
                            "name": &self.name,
                            "backend": "unknown",
                            "action": "stop",
                            "requested": false,
                            "error": "no supported init system found"
                        });
                        writeln!(io.stdout, "{}", error)?;
                        Ok(Status {
                            ok: false,
                            code: Some(1),
                            reason: Some("no supported init system found".to_string()),
                        })
                    }
                }
            }
            "restart" => {
                let backend = Self::detect_backend();
                match backend {
                    Backend::Systemd => {
                        match self.systemd_restart() {
                            Ok(()) => {
                                let result = json!({
                                    "backend": "systemd",
                                    "name": self.unit_name(),
                                    "action": "restart",
                                    "result": "success"
                                });
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "backend": "systemd",
                                    "name": self.unit_name(),
                                    "action": "restart",
                                    "error": e.to_string()
                                });
                                writeln!(io.stderr, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("restart failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::OpenRc => {
                        match self.openrc_restart() {
                            Ok(()) => {
                                let result = json!({
                                    "backend": "openrc",
                                    "name": &self.name,
                                    "action": "restart",
                                    "result": "success"
                                });
                                writeln!(io.stdout, "{}", result)?;
                                Ok(Status::ok())
                            }
                            Err(e) => {
                                let error = json!({
                                    "backend": "openrc",
                                    "name": &self.name,
                                    "action": "restart",
                                    "error": e.to_string()
                                });
                                writeln!(io.stderr, "{}", error)?;
                                Ok(Status {
                                    ok: false,
                                    code: Some(1),
                                    reason: Some(format!("restart failed: {}", e)),
                                })
                            }
                        }
                    }
                    Backend::Unknown => {
                        let error = json!({
                            "backend": "unknown",
                            "name": &self.name,
                            "action": "restart",
                            "error": "no supported init system found for restart"
                        });
                        writeln!(io.stderr, "{}", error)?;
                        Ok(Status {
                            ok: false,
                            code: Some(1),
                            reason: Some("no supported init system found for restart".to_string()),
                        })
                    }
                }
            }
            "reload" | "enable" | "disable" | "mask" | "unmask" => {
                let backend = Self::detect_backend();
                match backend {
                    Backend::Systemd => self.systemd_control(verb)?,
                    Backend::OpenRc => self.openrc_control(verb)?,
                    Backend::Unknown => bail!("no supported init system found"),
                }
                Ok(Status::ok())
            }
            "is-enabled" => {
                let backend = Self::detect_backend();
                let enabled = match backend {
                    Backend::Systemd => self.systemd_is_enabled().unwrap_or(false),
                    Backend::OpenRc => self.openrc_is_enabled().unwrap_or(false),
                    Backend::Unknown => false,
                };
                let out = json!({ "name": self.name, "enabled": enabled, "backend": format!("{:?}", backend).to_lowercase() });
                write!(io.stdout, "{}", out.to_string())?;
                return Ok(Status::ok());
            }
            "wait" => {
                let state = args.get("state").map(|s| s.as_str()).unwrap_or("active");
                let want_active = match state {
                    "active" | "running" => true,
                    "inactive" | "stopped" => false,
                    _ => true,
                };
                let timeout = args
                    .get("timeout")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(10_000);
                let ok = self.wait_until(want_active, timeout)?;
                let out = json!({ "name": self.name, "backend": format!("{:?}", Self::detect_backend()).to_lowercase(), "reached": ok, "state": state, "timeout_ms": timeout });
                write!(io.stdout, "{}", out.to_string())?;
                if ok {
                    Ok(Status::ok())
                } else {
                    Ok(Status {
                        ok: false,
                        code: Some(124),
                        reason: Some("timeout".into()),
                    })
                }
            }
            "logs" => {
                let backend = Self::detect_backend();
                match backend {
                    Backend::Systemd => self.logs_systemd(args, io),
                    Backend::OpenRc => self.logs_openrc(args, io),
                    Backend::Unknown => {
                        writeln!(io.stderr, "No supported init system found for logs")?;
                        Ok(Status::err(1, "no supported init system for logs"))
                    }
                }
            }
            "scale" => {
                // Parse count argument
                let count = match args.get("count") {
                    Some(count_str) => match count_str.parse::<u32>() {
                        Ok(c) => c,
                        Err(_) => {
                            let error = json!({
                                "name": self.name,
                                "backend": format!("{:?}", Self::detect_backend()).to_lowercase(),
                                "desired_count": count_str,
                                "error": "count must be a non-negative integer"
                            });
                            write!(io.stdout, "{}", error)?;
                            return Ok(Status {
                                ok: false,
                                code: Some(1),
                                reason: Some("invalid count parameter".to_string()),
                            });
                        }
                    },
                    None => {
                        let error = json!({
                            "name": self.name,
                            "backend": format!("{:?}", Self::detect_backend()).to_lowercase(),
                            "error": "count parameter is required"
                        });
                        write!(io.stdout, "{}", error)?;
                        return Ok(Status {
                            ok: false,
                            code: Some(1),
                            reason: Some("missing count parameter".to_string()),
                        });
                    }
                };

                let backend = Self::detect_backend();
                match backend {
                    Backend::Systemd => self.scale_systemd(count, io),
                    Backend::OpenRc => self.scale_openrc(count, io),
                    Backend::Unknown => {
                        let error = json!({
                            "name": self.name,
                            "backend": "unknown",
                            "desired_count": count,
                            "error": "scale not supported for backend: unknown"
                        });
                        write!(io.stdout, "{}", error)?;
                        Ok(Status {
                            ok: false,
                            code: Some(1),
                            reason: Some("scale not supported for unknown backend".to_string()),
                        })
                    }
                }
            }
            _ => {
                bail!("unknown verb for svc://: {}", verb)
            }
        }
    }
}
