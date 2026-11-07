//! `exec`: run a command on the remote host.

use super::args::ArgReader;
use super::conn::{
    ConnOptions, Prepared, SshTarget, UserRule, connection_error, parse_conn, posix_quote,
    run_error, shell_escape,
};
use super::runner::{Deadline, RunError, RunSpec, run_ssh_process};
use super::types::*;
use super::{Out, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use base64::prelude::*;
use std::collections::BTreeMap;
use std::time::Instant;

pub const DEFAULT_COMMAND_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 1_048_576;

/// First stderr line of a POSIX-mode command: the remote session's process
/// group, so a timed-out command can be stopped.
const PID_MARKER: &str = "RESH-PID:";

#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub conn: ConnOptions,
    pub command: String,
    pub command_args: Vec<String>,
    pub shell_mode: ShellMode,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub allocate_pty: bool,
    pub command_timeout_ms: u64,
    pub max_output_bytes: u64,
    pub trim_trailing_newlines: bool,
    pub capture_output: bool,
    pub output_encoding: Encoding,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

/// `KEY=value,KEY2=value2`.
fn parse_env(raw: &str) -> Result<BTreeMap<String, String>, SshError> {
    let mut env = BTreeMap::new();
    for pair in raw.split(',') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(SshError::InvalidArgument(format!(
                "env entry {pair:?} is not KEY=value"
            )));
        };
        let key = key.trim();
        let valid = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(SshError::InvalidArgument(format!(
                "env name {key:?} must be letters, digits and _ (not starting with a digit)"
            )));
        }
        env.insert(key.to_string(), value.to_string());
    }
    Ok(env)
}

pub fn parse(r: &ArgReader, target: &SshTarget) -> Result<ExecOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::DefaultToLocal)?;
    let command = match r.data("command", false)? {
        Some(c) if !c.trim().is_empty() => c,
        _ => return Err(SshError::CommandRequired),
    };
    let command_args = r
        .raw("command_args")
        .map(|s| {
            s.split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let env = match r.raw("env") {
        Some(raw) => parse_env(raw)?,
        None => BTreeMap::new(),
    };
    Ok(ExecOptions {
        conn,
        command,
        command_args,
        shell_mode: r
            .choice("shell_mode", ShellMode::VALUES)?
            .unwrap_or_default(),
        env,
        cwd: r.data("cwd", false)?,
        allocate_pty: r.bool("allocate_pty", false)?,
        command_timeout_ms: r.u64_or("command_timeout_ms", DEFAULT_COMMAND_TIMEOUT_MS)?,
        max_output_bytes: r.u64_or("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)?,
        trim_trailing_newlines: r.bool("trim_trailing_newlines", true)?,
        capture_output: r.bool("capture_output", true)?,
        output_encoding: r
            .choice("output_encoding", Encoding::VALUES)?
            .unwrap_or_default(),
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// Refuses `command_args`, `cwd` and `env` values whose meaning on the
/// remote host cannot be guaranteed: control characters in any mode, and
/// for cmd/PowerShell anything outside letters, digits and `_ . : / \ + @ -`.
/// The message names the field, never its value.
pub fn check_values(o: &ExecOptions) -> Result<(), String> {
    let windows = o.shell_mode.is_windows();
    let values = o
        .command_args
        .iter()
        .enumerate()
        .map(|(i, a)| (format!("command_args[{i}]"), a))
        .chain(o.cwd.iter().map(|c| ("cwd".to_string(), c)))
        .chain(o.env.iter().map(|(k, v)| (format!("env {k}"), v)));
    for (field, value) in values {
        if value.chars().any(char::is_control) {
            return Err(format!(
                "{field} must not contain line breaks or other control characters; nothing was run"
            ));
        }
        let windows_safe = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.:/\\+@-".contains(c));
        if windows && !windows_safe {
            return Err(format!(
                "{field} would need quoting, which shell_mode={} cannot pass through ssh \
                 exactly; put the complete command line in `command` instead; nothing was run",
                o.shell_mode.as_str()
            ));
        }
    }
    Ok(())
}

/// The exact command line the remote login shell receives (without the
/// process-group marker added on the wire for POSIX modes).
///
/// `command` is a command line by design and is sent as written; every
/// `command_args` element is quoted to stay exactly one argument (POSIX
/// single-quote rules); `env` and `cwd` become a leading `export` and `cd`.
pub fn build_command(o: &ExecOptions) -> Result<String, String> {
    check_values(o)?;
    match o.shell_mode {
        ShellMode::None | ShellMode::Sh | ShellMode::Bash => {
            let mut cmd = o.command.clone();
            for arg in &o.command_args {
                cmd.push(' ');
                cmd.push_str(&posix_quote(arg));
            }
            let mut prefix = String::new();
            if !o.env.is_empty() {
                let assigns: Vec<String> = o
                    .env
                    .iter()
                    .map(|(k, v)| format!("{k}={}", shell_escape(v)))
                    .collect();
                prefix.push_str(&format!("export {} && ", assigns.join(" ")));
            }
            if let Some(cwd) = &o.cwd {
                prefix.push_str(&format!("cd {} && ", shell_escape(cwd)));
            }
            let script = format!("{prefix}{cmd}");
            Ok(match o.shell_mode {
                ShellMode::Sh => format!("sh -c {}", shell_escape(&script)),
                ShellMode::Bash => format!("bash -c {}", shell_escape(&script)),
                _ => script,
            })
        }
        ShellMode::Cmd => {
            let mut cmd = o.command.clone();
            for arg in &o.command_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
            let mut prefix = String::new();
            for (k, v) in &o.env {
                prefix.push_str(&format!("set {k}={v}&& "));
            }
            if let Some(cwd) = &o.cwd {
                prefix.push_str(&format!("cd /d {cwd} && "));
            }
            Ok(format!("cmd /c \"{prefix}{cmd}\""))
        }
        ShellMode::Powershell => {
            let mut cmd = o.command.clone();
            for arg in &o.command_args {
                cmd.push(' ');
                cmd.push_str(arg);
            }
            let mut prefix = String::new();
            for (k, v) in &o.env {
                prefix.push_str(&format!("$env:{k}='{v}'; "));
            }
            if let Some(cwd) = &o.cwd {
                prefix.push_str(&format!("Set-Location '{cwd}'; "));
            }
            Ok(format!("powershell -Command \"{prefix}{cmd}\""))
        }
    }
}

/// The string sent to ssh: POSIX modes first report the session's process
/// group on stderr (sshd starts every session in a new session and group).
pub fn wire_command(o: &ExecOptions, raw: &str) -> String {
    if o.shell_mode.is_windows() {
        raw.to_string()
    } else {
        format!("printf '{PID_MARKER}%s\\n' $$ >&2; {raw}")
    }
}

/// Removes the marker line from stderr and returns the process group.
pub fn take_marker(stderr: &mut Vec<u8>) -> Option<u32> {
    if !stderr.starts_with(PID_MARKER.as_bytes()) {
        return None;
    }
    let end = stderr.iter().position(|b| *b == b'\n')?;
    let pid = std::str::from_utf8(&stderr[PID_MARKER.len()..end])
        .ok()?
        .trim()
        .parse()
        .ok();
    stderr.drain(..=end);
    pid
}

/// `data` without trailing `\n` and `\r\n` line ends (other whitespace stays).
fn trim_newlines(mut data: &[u8]) -> &[u8] {
    while let Some(rest) = data.strip_suffix(b"\n") {
        data = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    data
}

fn encode(data: &[u8], o: &ExecOptions) -> Option<String> {
    if !o.capture_output {
        return None;
    }
    let data = if o.trim_trailing_newlines {
        trim_newlines(data)
    } else {
        data
    };
    if data.is_empty() {
        return None;
    }
    Some(match o.output_encoding {
        Encoding::Utf8 => String::from_utf8_lossy(data).into_owned(),
        Encoding::Base64 => BASE64_STANDARD.encode(data),
    })
}

/// Why a completed run counts as a failure, or `None` for exit code 0.
pub fn exec_failure(result: &SshExecResult) -> Option<SshErrorDetails> {
    let (code, message) = if let Some(signal) = &result.signal {
        (
            "ssh.exec_signaled",
            format!("remote command was terminated by signal {signal}"),
        )
    } else {
        match result.exit_code {
            Some(0) => return None,
            Some(255) => {
                let detail = result
                    .stderr
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                (
                    "ssh.ssh_failed",
                    match detail {
                        Some(d) => format!("ssh failed (exit code 255): {d}"),
                        None => "ssh failed (exit code 255)".to_string(),
                    },
                )
            }
            Some(c) => (
                "ssh.remote_exit_nonzero",
                format!("remote command exited with code {c}"),
            ),
            None => (
                "ssh.exec_no_exit_code",
                "remote command ended without an exit code".to_string(),
            ),
        }
    };
    let mut details = std::collections::HashMap::new();
    if let Some(c) = result.exit_code {
        details.insert("exit_code".to_string(), c.to_string());
    }
    Some(SshErrorDetails {
        code: code.to_string(),
        message,
        details,
    })
}

fn exec_error(e: &SshError) -> SshErrorDetails {
    e.to_json()
}

/// Stops the remote session's process group after a timeout or interrupt,
/// through a second connection. Best effort; returns a warning.
fn stop_remote(o: &ExecOptions, prep: &Prepared, pgid: u32) -> String {
    let script = format!(
        "kill -s TERM -- -{pgid} 2>/dev/null; sleep 1; kill -s KILL -- -{pgid} 2>/dev/null; true"
    );
    let cmd = o.conn.command_line(prep, &[], Some(&script), false);
    let spec = RunSpec {
        timeout: Some(std::time::Duration::from_millis(
            o.conn.connect_timeout_ms.max(1000) + 5_000,
        )),
        ..Default::default()
    };
    match run_ssh_process(&cmd, &spec) {
        Ok(out) if out.success() => {
            format!("the remote command (process group {pgid}) was stopped")
        }
        Ok(out) => format!(
            "could not stop the remote command (process group {pgid}): {}",
            out.stderr_text()
        ),
        Err(_) => format!("could not stop the remote command (process group {pgid})"),
    }
}

pub fn run(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshExecResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: SshConnectionInfo::new(
            target.host.as_deref().unwrap_or("unknown"),
            target.port.unwrap_or(22),
            target.username.as_deref().unwrap_or("unknown"),
        ),
        command: None,
        result: Some(SshExecResult::not_executed()),
        timing: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshExecResponse,
                io: &mut IoStreams,
                details: SshErrorDetails,
                exit: i32|
     -> Result<Status> {
        let status = super::coded(exit, &details.code, &details.message);
        response.error = Some(details);
        write_response(io, out.format, response, format_text)?;
        Ok(status)
    };

    let o = match super::args::check_known("exec", args).and_then(|_| parse(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, exec_error(&e), e.exit_code()),
    };
    response.connection = SshConnectionInfo::new(&o.conn.host, o.conn.port, &o.conn.username);
    let raw = match build_command(&o) {
        Ok(raw) => raw,
        Err(message) => {
            let d = SshErrorDetails {
                code: "ssh.command_refused".into(),
                message,
                details: Default::default(),
            };
            return fail(&mut response, io, d, 2);
        }
    };
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, exec_error(&e), e.exit_code()),
    };
    response.command = Some(SshCommandInfo {
        raw: raw.clone(),
        shell_mode: o.shell_mode.as_str().to_string(),
        env: o.env.clone(),
        cwd: o.cwd.clone(),
        allocate_pty: o.allocate_pty,
    });

    if o.dry_run {
        response.ok = true;
        response
            .warnings
            .push("Dry run: command was not executed.".to_string());
        write_response(io, out.format, &response, format_text)?;
        return Ok(Status::ok());
    }

    let deadline = Deadline::new(o.timeout_ms);
    let cmd = o
        .conn
        .command_line(&prep, &[], Some(&wire_command(&o, &raw)), o.allocate_pty);
    let max = o.max_output_bytes;
    let start = Instant::now();
    let spec = RunSpec {
        max_stdout: max,
        // The marker line is not counted against the limit.
        max_stderr: max.saturating_add(64),
        timeout: deadline.bound(o.command_timeout_ms),
        ..Default::default()
    };
    let result = super::runner::run_with_marker(&cmd, &spec, PID_MARKER).map(|(out, _)| out);
    let command_ms = start.elapsed().as_millis() as u64;
    let mut output = match result {
        Ok(output) => output,
        Err((e, pgid)) => {
            let (code, message) = match &e {
                RunError::Timeout => (
                    "ssh.exec_timeout",
                    if deadline.expired() {
                        format!("timeout_ms={} passed", o.timeout_ms.unwrap_or(0))
                    } else {
                        format!(
                            "remote command timed out after command_timeout_ms={}",
                            o.command_timeout_ms
                        )
                    },
                ),
                RunError::Interrupted => ("ssh.interrupted", "interrupted".to_string()),
                _ => ("", String::new()),
            };
            if code.is_empty() {
                let err = run_error(e, SshError::Interrupted);
                response.command = None;
                response.result = None;
                return fail(&mut response, io, exec_error(&err), err.exit_code());
            }
            if let Some(pgid) = pgid {
                response.warnings.push(stop_remote(&o, &prep, pgid));
            } else if !o.shell_mode.is_windows() {
                response
                    .warnings
                    .push("the remote command may still be running".to_string());
            }
            response.result = None;
            response.timing = Some(SshTimingInfo {
                connect_ms: Some(0),
                command_ms: Some(command_ms),
            });
            let d = SshErrorDetails {
                code: code.to_string(),
                message,
                details: Default::default(),
            };
            return fail(&mut response, io, d, 124);
        }
    };
    if !o.shell_mode.is_windows() {
        take_marker(&mut output.stderr);
    }
    let result = SshExecResult {
        executed: true,
        exit_code: output.exit_code,
        signal: output.signal.map(|s| format!("SIGNAL {s}")),
        timed_out: false,
        output_truncated: output.stdout_overflow || output.stderr.len() as u64 > max,
        stdout: encode(&output.stdout, &o),
        stderr: encode(&output.stderr[..output.stderr.len().min(max as usize)], &o),
    };
    let failure = exec_failure(&result);
    if let (Some(f), Some(err)) = (&failure, connection_error(&cmd, &output)) {
        if f.code == "ssh.ssh_failed" {
            response.warnings.push(err.to_string());
        }
    }
    response.ok = failure.is_none();
    response.result = Some(result);
    response.timing = Some(SshTimingInfo {
        connect_ms: Some(0),
        command_ms: Some(command_ms),
    });
    match failure {
        None => {
            write_response(io, out.format, &response, format_text)?;
            Ok(Status::ok())
        }
        Some(f) => fail(&mut response, io, f, 1),
    }
}

pub fn format_text(response: &SshExecResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Exec\n");
    output.push_str("========\n");
    output.push_str(&format!("Host     : {}\n", response.connection.host));
    output.push_str(&format!("Port     : {}\n", response.connection.port));
    output.push_str(&format!("User     : {}\n", response.connection.username));
    output.push_str(&format!("Dry Run  : {}\n", response.dry_run));
    output.push('\n');
    if let Some(command) = &response.command {
        output.push_str(&format!("Command  : {}\n", command.raw));
    }
    if let Some(result) = &response.result {
        match result.exit_code {
            Some(c) => output.push_str(&format!("Exit Code: {c}\n")),
            None => output.push_str("Exit Code: (none)\n"),
        }
        output.push_str(&format!(
            "Timed Out: {}\n",
            if result.timed_out { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "Truncated: {}\n",
            if result.output_truncated { "yes" } else { "no" }
        ));
        output.push('\n');
        for (name, stream) in [("STDOUT", &result.stdout), ("STDERR", &result.stderr)] {
            output.push_str(&format!("{name}:\n"));
            match stream {
                Some(s) if !s.is_empty() => {
                    output.push_str(s);
                    if !s.ends_with('\n') {
                        output.push('\n');
                    }
                }
                _ => output.push_str("(none)\n"),
            }
            output.push('\n');
        }
    }
    if let Some(error) = &response.error {
        output.push_str("Error:\n");
        output.push_str(&format!("  Code   : {}\n", error.code));
        output.push_str(&format!("  Message: {}\n", error.message));
        output.push('\n');
    }
    output.push_str("Warnings:\n");
    if response.warnings.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for warning in &response.warnings {
            output.push_str(&format!("  - {warning}\n"));
        }
    }
    output
}
