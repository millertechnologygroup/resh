//! `test`: connection checks (connect, auth, exec, sftp, hostkey), each over
//! its own run of the system ssh client.

use super::args::{ArgReader, check_known};
use super::conn::{
    ConnOptions, Prepared, SshTarget, UserRule, connection_error, parse_conn, run_error,
};
use super::runner::{Deadline, ProcessOutput, RunError, RunSpec, SshCommandLine, run_ssh_process};
use super::types::*;
use super::{Out, coded, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use std::time::Instant;

pub const TEST_NAMES: &[&str] = &["connect", "auth", "exec", "sftp", "hostkey"];
pub const DEFAULT_STEP_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_OVERALL_TIMEOUT_MS: u64 = 15_000;

/// SSH_FXP_INIT, version 3: what an SFTP client sends first.
const SFTP_INIT: &[u8] = &[0, 0, 0, 5, 1, 0, 0, 0, 3];
/// SSH_FXP_VERSION: the server's answer.
const SFTP_VERSION: u8 = 2;

#[derive(Debug, Clone)]
pub struct TestOptions {
    pub conn: ConnOptions,
    pub tests: Vec<String>,
    pub exec_command: String,
    pub handshake_timeout_ms: u64,
    pub auth_timeout_ms: u64,
    pub sftp_timeout_ms: u64,
    pub exec_timeout_ms: u64,
    pub overall_timeout_ms: u64,
    pub allow_insecure_hostkey: bool,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

pub fn parse(r: &ArgReader, target: &SshTarget) -> Result<TestOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::Required)?;
    let mut tests: Vec<String> = Vec::new();
    for t in r
        .list("tests")?
        .unwrap_or_else(|| vec!["connect".into(), "auth".into()])
    {
        if !TEST_NAMES.contains(&t.as_str()) {
            return Err(SshError::TestInvalidTestName(t));
        }
        if !tests.contains(&t) {
            tests.push(t);
        }
    }
    let allow_insecure_hostkey = r.bool("allow_insecure_hostkey", false)?;
    if conn.known_hosts_mode == KnownHostsMode::Insecure && !allow_insecure_hostkey {
        return Err(SshError::TestInsecureHostkeyForbidden);
    }
    if allow_insecure_hostkey && conn.known_hosts_mode != KnownHostsMode::Insecure {
        return Err(SshError::InvalidArgument(
            "allow_insecure_hostkey only applies with known_hosts_mode=insecure".into(),
        ));
    }
    let exec_command = r.data("exec_command", false)?;
    if exec_command.is_some() && !tests.iter().any(|t| t == "exec") {
        return Err(SshError::InvalidArgument(
            "exec_command is only used by the exec test (add exec to tests)".into(),
        ));
    }
    Ok(TestOptions {
        conn,
        tests,
        exec_command: exec_command.unwrap_or_else(|| "echo ok".into()),
        handshake_timeout_ms: r.u64_or("handshake_timeout_ms", DEFAULT_STEP_TIMEOUT_MS)?,
        auth_timeout_ms: r.u64_or("auth_timeout_ms", DEFAULT_STEP_TIMEOUT_MS)?,
        sftp_timeout_ms: r.u64_or("sftp_timeout_ms", DEFAULT_STEP_TIMEOUT_MS)?,
        exec_timeout_ms: r.u64_or("exec_timeout_ms", DEFAULT_STEP_TIMEOUT_MS)?,
        overall_timeout_ms: r.u64_or("overall_timeout_ms", DEFAULT_OVERALL_TIMEOUT_MS)?,
        allow_insecure_hostkey,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// The host key ssh reported and how it was checked.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostKeySeen {
    pub algorithm: Option<String>,
    pub fingerprint: Option<String>,
    pub known: &'static str,
}

/// Reads `ssh -v` output: the server host key and the known_hosts result.
pub fn parse_hostkey_debug(stderr: &str) -> HostKeySeen {
    let mut seen = HostKeySeen {
        known: "unknown",
        ..Default::default()
    };
    for line in stderr.lines() {
        if let Some(rest) = line.split("Server host key: ").nth(1) {
            let mut it = rest.split_whitespace();
            seen.algorithm = it.next().map(str::to_string);
            seen.fingerprint = it.next().map(str::to_string);
        }
        if line.contains("is known and matches") {
            seen.known = "matched";
        } else if line.contains("Permanently added") {
            seen.known = "added";
        }
    }
    seen
}

struct Ctx<'a> {
    o: &'a TestOptions,
    prep: &'a Prepared,
    deadline: Deadline,
    hostkey: Option<HostKeySeen>,
}

enum Probe {
    Done(ProcessOutput, SshCommandLine),
    Failed(SshError),
}

impl Ctx<'_> {
    /// Runs one probe with `step_ms` plus the connect timeout, bounded by the
    /// overall deadline.
    fn run(
        &self,
        cmd: SshCommandLine,
        stdin: Option<&[u8]>,
        step_ms: u64,
        timeout: SshError,
    ) -> Probe {
        let step = if step_ms == 0 {
            0
        } else {
            step_ms.saturating_add(self.o.conn.connect_timeout_ms)
        };
        let spec = RunSpec {
            stdin,
            hold_stdin: stdin.is_some(),
            max_stdout: 64 * 1024,
            timeout: self.deadline.bound(step),
            ..Default::default()
        };
        match run_ssh_process(&cmd, &spec) {
            Ok(out) => Probe::Done(out, cmd),
            Err(RunError::Timeout) if self.deadline.expired() => {
                Probe::Failed(SshError::TestOverallTimeout)
            }
            Err(e) => Probe::Failed(run_error(e, timeout)),
        }
    }

    fn connect(&self) -> Result<Option<serde_json::Value>, SshError> {
        let cmd = self
            .o
            .conn
            .command_line(self.prep, &[], Some("true"), false);
        match self.run(
            cmd,
            None,
            self.o.handshake_timeout_ms,
            SshError::TestCheckTimeout("connect".into()),
        ) {
            Probe::Failed(e) => Err(e),
            Probe::Done(out, cmd) => match connection_error(&cmd, &out) {
                None | Some(SshError::AuthFailed(_)) => Ok(None),
                Some(SshError::HostKeyVerificationFailed(m)) => Err(SshError::TestHostkeyFailed(m)),
                Some(e) => Err(SshError::TestConnectFailed(e.to_string())),
            },
        }
    }

    fn auth(&self) -> Result<Option<serde_json::Value>, SshError> {
        let cmd = self
            .o
            .conn
            .command_line(self.prep, &[], Some("true"), false);
        match self.run(
            cmd,
            None,
            self.o.auth_timeout_ms,
            SshError::TestCheckTimeout("auth".into()),
        ) {
            Probe::Failed(e) => Err(e),
            Probe::Done(out, cmd) => match connection_error(&cmd, &out) {
                None => Ok(Some(serde_json::json!({
                    "method": format!("{:?}", self.prep.auth).to_lowercase()
                }))),
                Some(e) => Err(SshError::TestAuthFailed(e.to_string())),
            },
        }
    }

    fn exec(&self) -> Result<Option<serde_json::Value>, SshError> {
        let cmd = self
            .o
            .conn
            .command_line(self.prep, &[], Some(&self.o.exec_command), false);
        match self.run(
            cmd,
            None,
            self.o.exec_timeout_ms,
            SshError::TestCheckTimeout("exec".into()),
        ) {
            Probe::Failed(e) => Err(e),
            Probe::Done(out, cmd) => {
                if let Some(e) = connection_error(&cmd, &out) {
                    return Err(SshError::TestExecFailed(e.to_string()));
                }
                if out.success() {
                    Ok(Some(serde_json::json!({
                        "command": self.o.exec_command,
                        "exit_status": 0
                    })))
                } else {
                    Err(SshError::TestExecFailed(format!(
                        "exit status {}: {}",
                        out.exit_code.map_or("none".to_string(), |c| c.to_string()),
                        out.stderr_text()
                    )))
                }
            }
        }
    }

    fn sftp(&self) -> Result<Option<serde_json::Value>, SshError> {
        let cmd = self
            .o
            .conn
            .command_line(self.prep, &["-s".to_string()], Some("sftp"), false);
        match self.run(
            cmd,
            Some(SFTP_INIT),
            self.o.sftp_timeout_ms,
            SshError::TestCheckTimeout("sftp".into()),
        ) {
            Probe::Failed(e) => Err(e),
            Probe::Done(out, cmd) => {
                if let Some(e) = connection_error(&cmd, &out) {
                    return Err(SshError::TestSftpFailed(e.to_string()));
                }
                match out.stdout.get(4..9) {
                    Some([SFTP_VERSION, v0, v1, v2, v3]) => Ok(Some(serde_json::json!({
                        "protocol_version": u32::from_be_bytes([*v0, *v1, *v2, *v3])
                    }))),
                    _ => Err(SshError::TestSftpFailed(format!(
                        "the server did not answer as an SFTP subsystem: {}",
                        out.stderr_text()
                    ))),
                }
            }
        }
    }

    fn hostkey(&mut self) -> Result<Option<serde_json::Value>, SshError> {
        let c = &self.o.conn;
        let mut args: Vec<String> = vec!["-v".into(), "-p".into(), c.port.to_string()];
        for o in [
            format!("StrictHostKeyChecking={}", c.known_hosts_mode.ssh_value()),
            "BatchMode=yes".into(),
            "PreferredAuthentications=none".into(),
            "PubkeyAuthentication=no".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
        ] {
            args.push("-o".into());
            args.push(o);
        }
        if let Some(path) = &c.known_hosts_path {
            args.push("-o".into());
            args.push(format!("UserKnownHostsFile=\"{path}\""));
        }
        if c.connect_timeout_ms > 0 {
            args.push("-o".into());
            args.push(format!(
                "ConnectTimeout={}",
                c.connect_timeout_ms.div_ceil(1000)
            ));
        }
        args.extend(["-T".into(), "--".into(), c.destination(), "true".into()]);
        let cmd = SshCommandLine {
            program: "ssh".into(),
            args,
            env: vec![],
        };
        let out = match self.run(
            cmd,
            None,
            self.o.handshake_timeout_ms,
            SshError::TestCheckTimeout("hostkey".into()),
        ) {
            Probe::Failed(e) => return Err(e),
            Probe::Done(out, _) => out,
        };
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let mut seen = parse_hostkey_debug(&stderr);
        let mismatch = stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED");
        if stderr.contains("Host key verification failed") || mismatch {
            self.hostkey = Some(seen);
            return Err(SshError::TestHostkeyFailed(if mismatch {
                "the host key differs from the one in known_hosts".into()
            } else {
                "the host key is not in known_hosts".into()
            }));
        }
        if seen.algorithm.is_none() {
            let detail: Vec<&str> = stderr.lines().filter(|l| !l.starts_with("debug")).collect();
            return Err(SshError::TestHostkeyFailed(format!(
                "no host key was received: {}",
                detail.join("; ")
            )));
        }
        if seen.known == "unknown" && c.known_hosts_mode == KnownHostsMode::Insecure {
            seen.known = "unverified";
        }
        let details = serde_json::json!({
            "algorithm": seen.algorithm,
            "fingerprint": seen.fingerprint,
            "known_hosts": seen.known,
        });
        self.hostkey = Some(seen);
        Ok(Some(details))
    }
}

fn planned(name: &str) -> SshSingleTestResult {
    SshSingleTestResult {
        name: name.to_string(),
        status: TestStatus::Planned,
        duration_ms: None,
        details: None,
        error: None,
    }
}

fn skipped(name: &str, e: SshError) -> SshSingleTestResult {
    SshSingleTestResult {
        name: name.to_string(),
        status: TestStatus::Skipped,
        duration_ms: None,
        details: None,
        error: Some(e.to_json()),
    }
}

pub fn run(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshTestResponse {
        ok: false,
        dry_run: out.dry_run,
        target: SshTestTargetInfo {
            host: target.host.clone().unwrap_or_else(|| "unknown".into()),
            port: target.port.unwrap_or(22),
            username: target.username.clone().unwrap_or_else(|| "unknown".into()),
        },
        security: None,
        tests: vec![],
        summary: SshTestSummary {
            tests_requested: vec![],
            tests_run: 0,
            tests_passed: 0,
            tests_failed: 0,
            tests_skipped: 0,
            overall_duration_ms: 0,
        },
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshTestResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_text).map(|_| status)
    };
    let o = match check_known("test", args).and_then(|_| parse(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.target = SshTestTargetInfo {
        host: o.conn.host.clone(),
        port: o.conn.port,
        username: o.conn.username.clone(),
    };
    response.summary.tests_requested = o.tests.clone();
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    if o.dry_run {
        response.ok = true;
        response.tests = o.tests.iter().map(|t| planned(t)).collect();
        response.warnings.push(
            "Dry run: no network connections were made and no SSH tests were executed.".into(),
        );
        write_response(io, out.format, &response, format_text)?;
        return Ok(Status::ok());
    }
    if o.conn.known_hosts_mode == KnownHostsMode::Insecure {
        response
            .warnings
            .push("known_hosts_mode=insecure: host key verification is disabled".into());
    }

    let start = Instant::now();
    let overall = match (o.overall_timeout_ms, o.timeout_ms.filter(|t| *t > 0)) {
        (0, t) => t,
        (a, Some(b)) => Some(a.min(b)),
        (a, None) => Some(a),
    };
    let mut ctx = Ctx {
        o: &o,
        prep: &prep,
        deadline: Deadline::new(overall),
        hostkey: None,
    };
    let mut passed: Vec<&str> = Vec::new();
    let mut failed: Vec<&str> = Vec::new();
    let mut timed_out = false;
    for name in &o.tests {
        let name = name.as_str();
        if timed_out || ctx.deadline.expired() {
            timed_out = true;
            response
                .tests
                .push(skipped(name, SshError::TestOverallTimeout));
            continue;
        }
        let blocker = match name {
            "auth" => ["connect"].iter().find(|d| failed.contains(d)).copied(),
            "exec" | "sftp" => ["connect", "auth"]
                .iter()
                .find(|d| failed.contains(d))
                .copied(),
            _ => None,
        };
        if let Some(dep) = blocker {
            response.tests.push(skipped(
                name,
                SshError::TestDependencyFailed(format!("the {dep} check did not pass")),
            ));
            continue;
        }
        let t0 = Instant::now();
        let result = match name {
            "connect" => ctx.connect(),
            "auth" => ctx.auth(),
            "exec" => ctx.exec(),
            "sftp" => ctx.sftp(),
            _ => ctx.hostkey(),
        };
        if matches!(result, Err(SshError::TestOverallTimeout)) {
            timed_out = true;
        }
        let (status, details, error) = match result {
            Ok(d) => {
                passed.push(name);
                (TestStatus::Passed, d, None)
            }
            Err(e) => {
                failed.push(name);
                (TestStatus::Failed, None, Some(e.to_json()))
            }
        };
        response.tests.push(SshSingleTestResult {
            name: name.to_string(),
            status,
            duration_ms: Some(t0.elapsed().as_millis() as u64),
            details,
            error,
        });
    }
    let seen = ctx.hostkey.clone().unwrap_or_default();
    response.security = Some(SshTestSecurityInfo {
        known_hosts_mode: o.conn.known_hosts_mode.as_str().to_string(),
        known_hosts_path: o.conn.known_hosts_path.clone(),
        hostkey_algorithm: seen.algorithm,
        hostkey_fingerprint: seen.fingerprint,
        insecure_hostkey_allowed: o.allow_insecure_hostkey,
    });
    let count = |s: TestStatus| response.tests.iter().filter(|t| t.status == s).count();
    response.summary.tests_passed = count(TestStatus::Passed);
    response.summary.tests_failed = count(TestStatus::Failed);
    response.summary.tests_skipped = count(TestStatus::Skipped);
    response.summary.tests_run = response.summary.tests_passed + response.summary.tests_failed;
    response.summary.overall_duration_ms = start.elapsed().as_millis() as u64;
    if timed_out {
        return fail(&mut response, io, SshError::TestOverallTimeout);
    }
    if !failed.is_empty() {
        let e = SshError::TestFailed(format!(
            "{} of {} checks failed: {}",
            failed.len(),
            o.tests.len(),
            failed.join(", ")
        ));
        return fail(&mut response, io, e);
    }
    response.ok = true;
    write_response(io, out.format, &response, format_text)?;
    Ok(Status::ok())
}

pub fn format_text(response: &SshTestResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Test\n========\n\n");
    output.push_str(&format!("Host     : {}\n", response.target.host));
    output.push_str(&format!("Port     : {}\n", response.target.port));
    output.push_str(&format!("User     : {}\n", response.target.username));
    output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));
    if let Some(security) = &response.security {
        output.push_str("Security :\n");
        output.push_str(&format!(
            "  KnownHostsMode : {}\n",
            security.known_hosts_mode
        ));
        if let Some(path) = &security.known_hosts_path {
            output.push_str(&format!("  KnownHostsPath : {path}\n"));
        }
        if let (Some(algo), Some(fp)) = (&security.hostkey_algorithm, &security.hostkey_fingerprint)
        {
            output.push_str(&format!("  HostKey        : {algo} {fp}\n"));
        }
        output.push('\n');
    }
    output.push_str("Tests:\n");
    for test in &response.tests {
        let status = match test.status {
            TestStatus::Passed => "PASSED",
            TestStatus::Failed => "FAILED",
            TestStatus::Skipped => "SKIPPED",
            TestStatus::Planned => "PLANNED",
        };
        let duration = test
            .duration_ms
            .map(|ms| format!(" ({ms} ms)"))
            .unwrap_or_default();
        output.push_str(&format!("  - {} : {status}{duration}\n", test.name));
        if let Some(error) = &test.error {
            output.push_str(&format!("      Error: {}\n", error.message));
        }
    }
    let s = &response.summary;
    output.push_str("\nSummary:\n");
    output.push_str(&format!("  Requested : {}\n", s.tests_requested.join(", ")));
    output.push_str(&format!("  Run       : {}\n", s.tests_run));
    output.push_str(&format!("  Passed    : {}\n", s.tests_passed));
    output.push_str(&format!("  Failed    : {}\n", s.tests_failed));
    output.push_str(&format!("  Skipped   : {}\n", s.tests_skipped));
    output.push_str(&format!("  Duration  : {} ms\n\n", s.overall_duration_ms));
    super::transfer::push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_lines_are_read_from_debug_output() {
        let s = "debug1: Connecting to h [127.0.0.1] port 2222.\n\
                 debug1: Server host key: ssh-ed25519 SHA256:abc\n\
                 debug1: Host '[127.0.0.1]:2222' is known and matches the ED25519 host key.\n";
        let seen = parse_hostkey_debug(s);
        assert_eq!(seen.algorithm.as_deref(), Some("ssh-ed25519"));
        assert_eq!(seen.fingerprint.as_deref(), Some("SHA256:abc"));
        assert_eq!(seen.known, "matched");
        let seen = parse_hostkey_debug(
            "debug1: Server host key: ecdsa-sha2-nistp256 SHA256:x\nWarning: Permanently added 'h' (ECDSA) to the list of known hosts.\n",
        );
        assert_eq!(seen.known, "added");
        assert_eq!(parse_hostkey_debug("").algorithm, None);
    }
}
