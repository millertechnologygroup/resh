//! Dispatch tests: every verb through `Handle::call`, with ssh replaced by a
//! fake that runs the remote command with the local `sh` inside a temporary
//! "remote" directory (so the upload, download and key scripts really run),
//! or by a scripted reply.

use super::runner::{
    MOCK_MARKER_PGID, MOCK_SPAWN, MOCK_SSH, ProcessOutput, RunError, RunSpec, SshCommandLine,
    run_real_process,
};
use super::types::SshError;
use super::*;
use crate::core::registry::IoStreams;
use serde_json::Value;
use std::cell::RefCell;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const ED: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEP31YpA0Imm4x6v+o1r0O2XM9fZkMEDQUNAn9WtLLqt bob@laptop";
const ED_FP: &str = "SHA256:3xDjK+bg/gX0dncBKmABpUGbcOI6xx9mMC3MDjssIBU";
const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCUEhpO2JPXdV4Gm1Ftc0FS71xXGhAYaEboX5hxFOziEDKcWAOO/gGGB5nRy+FSBhIEiS+z2LwTyj/6NNg/nrM2owMGGDXJlbIBDEMHhMXRB0+VSTBPZR8rGv+r4xNTnB7aoGjg6uR8CFpTIbs7myfdlD9p58QqvrkFjUAYuhc3iKz8s6Q0299w292PyoIZVgdJyNSte1MZOhtgSLyTsaqItpNe379Z/lWFx7veYI0pypZuExA/xSKruzBJzePKYOtMbHx7u543B5Dw3WdI7yQfEshZj4iddbAwyQMs/mCDKKLtYhxSj9LjHo4lvnS4t/IKBDhbwk1iBEbkVhJKHJW3 rsa@x";
/// A user name that does not exist, so `~user` stays a relative path.
const NOUSER: &str = "reshnouser";

type Calls = Rc<RefCell<Vec<SshCommandLine>>>;

struct Run {
    status: Status,
    stdout: String,
    json: Value,
}

impl Run {
    fn code(&self) -> i32 {
        self.status.exit_code()
    }
    fn err(&self) -> &str {
        self.json["error"]["code"].as_str().unwrap_or("")
    }
}

fn call(url: &str, verb: &str, pairs: &[(&str, &str)]) -> Run {
    let h = SshHandle::from_url(&Url::parse(url).unwrap()).unwrap();
    let args: Args = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (mut i, mut o, mut e) = (
        Cursor::new(vec![]),
        Cursor::new(vec![]),
        Cursor::new(vec![]),
    );
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let status = h.call(verb, &args, &mut io).unwrap();
    let stdout = String::from_utf8(o.into_inner()).unwrap();
    // The last JSON document (tunnel prints a ready event first).
    let json = stdout
        .find("\n{")
        .filter(|_| stdout.starts_with("{\"event\""))
        .map(|i| serde_json::from_str(&stdout[i + 1..]).unwrap())
        .or_else(|| serde_json::from_str(&stdout).ok())
        .unwrap_or(Value::Null);
    Run {
        status,
        stdout,
        json,
    }
}

/// Installs a scripted ssh and records every command line.
fn mock<F>(mut reply: F) -> Calls
where
    F: FnMut(&SshCommandLine, &RunSpec) -> Result<ProcessOutput, RunError> + 'static,
{
    let calls: Calls = Default::default();
    let rec = calls.clone();
    MOCK_SSH.with(|m| {
        *m.borrow_mut() = Some(Box::new(move |cmd: &SshCommandLine, spec: &RunSpec| {
            rec.borrow_mut().push(cmd.clone());
            reply(cmd, spec)
        }))
    });
    MOCK_MARKER_PGID.with(|c| c.set(None));
    calls
}

fn out(code: i32, stdout: &[u8], stderr: &str) -> ProcessOutput {
    ProcessOutput {
        exit_code: Some(code),
        stdout: stdout.to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        ..Default::default()
    }
}

/// ssh that runs the remote command with `sh -c` in `remote`, honoring
/// stdin and the timeout. `-s sftp` and `ssh -v` probes get fixed answers.
fn local_remote(remote: &Path) -> Calls {
    let dir = remote.to_path_buf();
    mock(move |cmd, spec| {
        if cmd.args.iter().any(|a| a == "-s") {
            return Ok(out(0, &[0, 0, 0, 5, 2, 0, 0, 0, 3], ""));
        }
        if cmd.program == "ssh" && cmd.args.first().is_some_and(|a| a == "-v") {
            return Ok(out(
                255,
                b"",
                "debug1: Server host key: ssh-ed25519 SHA256:abc\n\
                 debug1: Host 'h' is known and matches the ED25519 host key.\n\
                 u@h: Permission denied (none).\n",
            ));
        }
        let sh = SshCommandLine {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("cd '{}' && {}", dir.display(), cmd.remote()),
            ],
            env: vec![("HOME".into(), dir.display().to_string())],
        };
        run_real_process(&sh, spec)
    })
}

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

// ------------------------------------------------------------- dispatch --

#[test]
fn every_verb_refuses_unknown_arguments_with_a_hint_and_runs_nothing() {
    for verb in VERBS {
        let calls = mock(|_, _| panic!("ssh must not run"));
        let r = call("ssh://u@h", verb, &[("formt", "json")]);
        assert_eq!(r.code(), 2, "{verb}");
        assert_eq!(r.err(), "ssh.invalid_argument", "{verb}");
        assert!(
            r.status
                .reason
                .as_deref()
                .unwrap()
                .contains("did you mean `format`"),
            "{verb}: {:?}",
            r.status.reason
        );
        assert_eq!(r.json["ok"], false);
        assert!(calls.borrow().is_empty());
    }
    let r = call("ssh://h", "config.get", &[("timeout_ms", "5")]);
    assert_eq!(r.code(), 2);
}

#[test]
fn every_verb_refuses_bad_booleans_and_formats() {
    for verb in VERBS {
        mock(|_, _| panic!("ssh must not run"));
        let r = call("ssh://u@h", verb, &[("dry_run", "maybe")]);
        assert_eq!(r.code(), 2, "{verb}");
        let r = call("ssh://u@h", verb, &[("format", "yaml")]);
        assert_eq!(r.code(), 2, "{verb}");
        assert_eq!(r.err(), "ssh.invalid_argument");
    }
}

#[test]
fn unknown_verb_and_help_forms() {
    let r = call("ssh://h", "exek", &[]);
    assert_eq!(r.code(), 2);
    assert!(r.status.reason.unwrap().contains("ssh.unknown_verb"));
    let r = call("ssh://--help", "help", &[("verb", "exec")]);
    assert!(r.stdout.starts_with("Handle: ssh\nVerb: exec\n"));
    let r = call("ssh://h", "upload", &[("help", "1")]);
    assert!(r.stdout.starts_with("Handle: ssh\nVerb: upload\n"));
    let r = call("ssh://h", "--help", &[]);
    assert!(r.stdout.starts_with("Handle: ssh\n\nDescription:"));
}

#[test]
fn every_emitted_error_code_is_valid() {
    use SshError::*;
    let s = String::new;
    let all = [
        InvalidArgument(s()),
        TargetConflict(s()),
        HostRequired,
        UsernameRequired,
        AuthMissingPassword,
        AgentUnavailable,
        IdentityNotFound(s()),
        IdentityInvalid(s()),
        ToolNotFound(s()),
        ConnectFailed(s()),
        HostKeyVerificationFailed(s()),
        AuthFailed(s()),
        IoError(s()),
        Interrupted,
        CommandRequired,
        UploadSourceMissing,
        UploadSourceNotFound(s()),
        UploadSourceReadError(s()),
        UploadInvalidSourceEncoding(s()),
        UploadTooLarge(1, 1),
        UploadDestMissing,
        UploadDestExists(s()),
        UploadDestIsDirectory(s()),
        UploadRemoteDirMissing(s()),
        UploadRemoteWriteFailed(s()),
        UploadTimeout(s()),
        UploadChecksumMismatch(s(), s()),
        DownloadSourceMissing,
        DownloadSourceNotFound(s()),
        DownloadSourceIsDirectory(s()),
        DownloadRemoteReadFailed(s()),
        DownloadTooLarge(1),
        DownloadDestMissing,
        DownloadDestExists(s()),
        DownloadLocalDirMissing(s()),
        DownloadLocalWriteFailed(s()),
        DownloadInvalidUtf8,
        DownloadTimeout(s()),
        DownloadChecksumMismatch(s(), s()),
        TunnelModeRequired,
        TunnelMissingRemoteDest,
        TunnelMissingLocalDest,
        TunnelWildcardBindForbidden(s()),
        TunnelBindFailed(1, s(), s()),
        TunnelForwardFailed(s()),
        TunnelClosed(s()),
        TunnelTimeout(1),
        KeysListCustomPathsRequired,
        KeysListRemoteReadFailed(s()),
        KeysListTooLarge(s(), 1),
        KeysListTimeout(s()),
        KeyAddMissingPublicKey,
        KeyAddInvalidPublicKey(s()),
        KeyAddCustomPathsRequired,
        KeyAddTargetMissing(s()),
        KeyAddTargetIsSymlink(s()),
        KeyAddFileTooLarge(s(), 1, 1),
        KeyAddRemoteReadFailed(s()),
        KeyAddRemoteWriteFailed(s()),
        KeyAddBackupFailed(s()),
        KeyAddPermissionsFailed(s()),
        KeyAddDuplicate,
        KeyAddConcurrentChange,
        KeyAddPublicKeyFileNotFound(s()),
        KeyAddPublicKeyFileReadFailed(s()),
        KeyAddTimeout(s()),
        ConfigGetHostRequired,
        ConfigGetReadFailed(s()),
        ConfigGetTooLarge(1),
        ConfigGetTooManyIncludes(1),
        ConfigGetTooManyHosts(1),
        TestInvalidTestName(s()),
        TestInsecureHostkeyForbidden,
        TestConnectFailed(s()),
        TestAuthFailed(s()),
        TestSftpFailed(s()),
        TestExecFailed(s()),
        TestHostkeyFailed(s()),
        TestDependencyFailed(s()),
        TestCheckTimeout(s()),
        TestOverallTimeout,
        TestFailed(s()),
    ];
    let doc = include_str!("../../../../docs/Network_RemoteOperations/ssh.md");
    let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
    codes.extend([
        "ssh.unknown_verb",
        "ssh.command_refused",
        "ssh.remote_exit_nonzero",
        "ssh.ssh_failed",
        "ssh.exec_signaled",
        "ssh.exec_no_exit_code",
        "ssh.exec_timeout",
    ]);
    for code in codes {
        assert!(crate::core::status::is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented in ssh.md"
        );
    }
    for e in &all {
        assert!([1, 2, 124].contains(&e.exit_code()), "{e:?}");
    }
}

// ------------------------------------------------------------------ exec --

#[test]
fn exec_runs_and_reports_output() {
    let d = tmp();
    let calls = local_remote(d.path());
    let r = call(
        "ssh://u@h:2222",
        "exec",
        &[
            ("command", "printf '<%s>' "),
            ("command_args", "a b,$(x),c"),
            ("env", "GREETING=hi there"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["stdout"], "<a b><$(x)><c>");
    assert_eq!(r.json["result"]["exit_code"], 0);
    assert_eq!(r.json["connection"]["port"], 2222);
    let line = calls.borrow()[0].args.join(" ");
    assert!(line.contains("-p 2222"), "{line}");
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "echo \"$GREETING\"; pwd"),
            ("env", "GREETING=hi there"),
            ("cwd", "/"),
        ],
    );
    assert_eq!(r.json["result"]["stdout"], "hi there\n/");
    assert_eq!(
        r.json["result"]["stderr"],
        Value::Null,
        "marker must be removed"
    );
}

#[test]
fn exec_failures_exit_1_with_codes() {
    let d = tmp();
    local_remote(d.path());
    let r = call("ssh://u@h", "exec", &[("command", "echo oops >&2; exit 3")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.err(), "ssh.remote_exit_nonzero");
    assert_eq!(r.json["result"]["exit_code"], 3);
    assert_eq!(r.json["result"]["stderr"], "oops");
    assert_eq!(r.json["error"]["details"]["exit_code"], "3");

    mock(|_, _| {
        Ok(out(
            255,
            b"",
            "ssh: connect to host h port 22: Connection refused",
        ))
    });
    let r = call("ssh://u@h", "exec", &[("command", "true")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.err(), "ssh.ssh_failed");

    mock(|_, _| {
        Ok(ProcessOutput {
            signal: Some(9),
            ..Default::default()
        })
    });
    let r = call("ssh://u@h", "exec", &[("command", "true")]);
    assert_eq!(r.err(), "ssh.exec_signaled");

    mock(|_, _| {
        Err(RunError::Spawn(
            "ssh".into(),
            std::io::ErrorKind::NotFound.into(),
        ))
    });
    let r = call("ssh://u@h", "exec", &[("command", "true")]);
    assert_eq!(r.code(), 1);
    assert_eq!(r.err(), "ssh.tool_not_found");
    assert!(r.json.get("result").is_none());
}

#[test]
fn exec_timeout_stops_the_remote_process_group() {
    let calls = mock(|cmd, _| {
        if cmd.remote().starts_with("kill ") {
            Ok(out(0, b"", ""))
        } else {
            Err(RunError::Timeout)
        }
    });
    MOCK_MARKER_PGID.with(|c| c.set(Some(4242)));
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "sleep 100"), ("command_timeout_ms", "50")],
    );
    assert_eq!(r.code(), 124);
    assert_eq!(r.err(), "ssh.exec_timeout");
    assert!(r.json.get("result").is_none());
    let calls = calls.borrow();
    assert_eq!(calls.len(), 2);
    assert!(
        calls[1].remote().contains("kill -s TERM -- -4242"),
        "{}",
        calls[1].remote()
    );
    assert!(r.json["warnings"][0].as_str().unwrap().contains("4242"));
}

#[test]
fn exec_real_timeout_with_local_shell() {
    let d = tmp();
    local_remote(d.path());
    let start = std::time::Instant::now();
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "sleep 20"), ("timeout_ms", "300")],
    );
    assert_eq!(r.code(), 124);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("timeout_ms")
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn exec_output_options() {
    let d = tmp();
    local_remote(d.path());
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "printf 'abc\\n\\n'"),
            ("output_encoding", "base64"),
        ],
    );
    assert_eq!(r.json["result"]["stdout"], "YWJj");
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "printf 'abc  \\n'"),
            ("trim_trailing_newlines", "false"),
        ],
    );
    assert_eq!(r.json["result"]["stdout"], "abc  \n");
    let r = call("ssh://u@h", "exec", &[("command", "printf 'abc  \\n'")]);
    assert_eq!(r.json["result"]["stdout"], "abc  ");
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "head -c 5000 /dev/zero | tr '\\0' x"),
            ("max_output_bytes", "10"),
        ],
    );
    assert_eq!(r.json["result"]["stdout"], "xxxxxxxxxx");
    assert_eq!(r.json["result"]["output_truncated"], true);
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "echo hi"), ("capture_output", "false")],
    );
    assert_eq!(r.json["result"]["stdout"], Value::Null);
    let r = call("ssh://u@h", "exec", &[("command", "cat")]);
    assert_eq!(r.code(), 0, "stdin must be empty, not inherited");
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "echo t"), ("format", "text")],
    );
    assert!(r.stdout.starts_with("SSH Exec\n"), "{}", r.stdout);
    let calls = mock(|_, _| Ok(out(0, b"", "")));
    call(
        "ssh://u@h",
        "exec",
        &[("command", "x"), ("allocate_pty", "true")],
    );
    assert!(calls.borrow()[0].args.contains(&"-tt".to_string()));
}

#[test]
fn exec_dry_run_and_refusals_run_nothing() {
    let calls = mock(|_, _| panic!("no ssh"));
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "ls"),
            ("command_args", "-l,a b"),
            ("cwd", "/srv/my app"),
            ("dry_run", "true"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["command"]["raw"], "cd '/srv/my app' && ls -l 'a b'");
    assert_eq!(r.json["result"]["executed"], false);
    for (pairs, code) in [
        (
            vec![
                ("command", "dir"),
                ("shell_mode", "cmd"),
                ("command_args", "a b"),
            ],
            "ssh.command_refused",
        ),
        (
            vec![("command", "ls"), ("shell_mode", "zsh")],
            "ssh.invalid_argument",
        ),
        (
            vec![("command", "ls"), ("command_args", "a\nb")],
            "ssh.command_refused",
        ),
        (
            vec![("command", "ls"), ("env", "1X=a")],
            "ssh.invalid_argument",
        ),
        (
            vec![("command", "ls"), ("env", "noequals")],
            "ssh.invalid_argument",
        ),
        (vec![("command", "  ")], "ssh.command_required"),
        (
            vec![("command", "ls"), ("host", "other")],
            "ssh.target_conflict",
        ),
        (
            vec![("command", "ls"), ("max_output_bytes", "-1")],
            "ssh.invalid_argument",
        ),
    ] {
        let r = call("ssh://u@h", "exec", &pairs);
        assert_eq!(r.code(), 2, "{pairs:?}");
        assert_eq!(r.err(), code, "{pairs:?}");
    }
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "x"),
            ("auth_method", "agent"),
            ("agent_socket", "/nonexistent/sock"),
        ],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.err(), "ssh.agent_unavailable");
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "x"), ("identity_path", "/nonexistent/key")],
    );
    assert_eq!(r.err(), "ssh.identity_not_found");
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "x"), ("identity_data", "not a key")],
    );
    assert_eq!(r.code(), 2);
    assert_eq!(r.err(), "ssh.identity_invalid");
    let r = call(
        "ssh://u@h",
        "exec",
        &[("command", "x"), ("auth_method", "password")],
    );
    assert_eq!(r.err(), "ssh.auth_missing_password");
    assert!(calls.borrow().is_empty());
}

#[test]
fn exec_password_and_identity_data_reach_ssh_safely() {
    let calls = mock(|_, _| Ok(out(0, b"ok", "")));
    let r = call("ssh://u:s3cret@h", "exec", &[("command", "true")]);
    assert_eq!(r.code(), 0);
    let c = calls.borrow()[0].clone();
    assert_eq!(c.program, "sshpass");
    assert!(!c.args.iter().any(|a| a.contains("s3cret")));
    assert!(c.env.contains(&("SSHPASS".into(), "s3cret".into())));
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----";
    let r = call(
        "ssh://u@h",
        "exec",
        &[
            ("command", "true"),
            ("identity_data", key),
            ("identity_passphrase", "pp"),
        ],
    );
    assert_eq!(r.code(), 0);
    let c = calls.borrow()[1].clone();
    let i = c.args.iter().position(|a| a == "-i").unwrap();
    let file = PathBuf::from(&c.args[i + 1]);
    assert!(!file.exists(), "the key file is removed after the run");
    assert!(c.args.contains(&"BatchMode=no".to_string()));
    assert!(c.env.iter().any(|(k, _)| k == "SSH_ASKPASS"));
    assert!(!c.args.iter().any(|a| a.contains("pp")));
}

// ------------------------------------------------------------ transfers --

#[test]
fn upload_writes_atomically_and_honors_options() {
    let d = tmp();
    local_remote(d.path());
    let local = d.path().join("local.txt");
    std::fs::write(&local, "hello upload\n").unwrap();
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source", &s(&local)),
            ("dest", "sub/dir/app.conf"),
            ("file_mode", "0640"),
            ("verify_checksum", "true"),
            ("mtime_epoch_ms", "1000000000000"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["checksum_verified"], true);
    let dest = d.path().join("sub/dir/app.conf");
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "hello upload\n");
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::metadata(&dest).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o640);
    assert_eq!(m.mtime(), 1_000_000_000);
    // No temp files are left behind.
    assert_eq!(
        std::fs::read_dir(d.path().join("sub/dir")).unwrap().count(),
        1
    );

    let r = call(
        "ssh://u@h",
        "upload",
        &[("source", &s(&local)), ("dest", "sub/dir/app.conf")],
    );
    assert_eq!(r.code(), 1);
    assert_eq!(r.err(), "ssh.upload_dest_exists");
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source_mode", "inline"),
            ("source", "aGk="),
            ("source_encoding", "base64"),
            ("dest", "sub/dir/app.conf"),
            ("overwrite", "true"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "hi");
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source_mode", "inline"),
            ("source", "x"),
            ("dest", "missing/f"),
            ("mkdir_parents", "false"),
        ],
    );
    assert_eq!(r.err(), "ssh.upload_remote_dir_missing");
    let r = call(
        "ssh://u@h",
        "upload",
        &[("source_mode", "inline"), ("source", "x"), ("dest", "sub")],
    );
    assert_eq!(r.err(), "ssh.upload_dest_is_directory");
    // A symlink at dest is replaced, not written through.
    let target = d.path().join("target.txt");
    std::fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, d.path().join("link")).unwrap();
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source_mode", "inline"),
            ("source", "new"),
            ("dest", "link"),
            ("overwrite", "true"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    assert_eq!(
        std::fs::read_to_string(d.path().join("link")).unwrap(),
        "new"
    );
    for atomic in ["true", "false"] {
        let r = call(
            "ssh://u@h",
            "upload",
            &[
                ("source_mode", "inline"),
                ("source", "abc"),
                ("dest", &format!("na-{atomic}")),
                ("atomic", atomic),
            ],
        );
        assert_eq!(r.code(), 0, "{}", r.stdout);
    }
}

#[test]
fn upload_validation_and_local_errors() {
    let d = tmp();
    let calls = mock(|_, _| panic!("no ssh"));
    for (pairs, code, exit) in [
        (vec![("dest", "x")], "ssh.upload_source_missing", 2),
        (vec![("source", "a")], "ssh.upload_dest_missing", 2),
        (
            vec![("source", "/nonexistent/f"), ("dest", "x")],
            "ssh.upload_source_not_found",
            1,
        ),
        (
            vec![
                ("source_mode", "inline"),
                ("source", "!!"),
                ("source_encoding", "base64"),
                ("dest", "x"),
            ],
            "ssh.upload_invalid_source_encoding",
            2,
        ),
        (
            vec![
                ("source_mode", "inline"),
                ("source", "abcdef"),
                ("dest", "x"),
                ("max_size_bytes", "3"),
            ],
            "ssh.upload_too_large",
            1,
        ),
        (
            vec![("source", "a"), ("dest", "x"), ("file_mode", "644")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("source", "a"), ("dest", "-x")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("source", "a"), ("dest", "x/")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![
                ("source", "a"),
                ("dest", "x"),
                ("source_encoding", "base64"),
            ],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![
                ("source_mode", "inline"),
                ("source", "a"),
                ("dest", "x"),
                ("preserve_times", "true"),
            ],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![
                ("source", "a"),
                ("dest", "x"),
                ("checksum_algorithm", "crc"),
            ],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("source", &s(d.path())), ("dest", "x")],
            "ssh.upload_source_read_error",
            1,
        ),
    ] {
        let r = call("ssh://u@h", "upload", &pairs);
        assert_eq!((r.code(), r.err()), (exit, code), "{pairs:?}");
    }
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source_mode", "inline"),
            ("source", "abc"),
            ("dest", "x"),
            ("dry_run", "true"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["result"]["planned"], true);
    assert_eq!(r.json["source"]["size_bytes"], 3);
    assert!(calls.borrow().is_empty());
    mock(|_, _| Err(RunError::Timeout));
    let r = call(
        "ssh://u@h",
        "upload",
        &[("source_mode", "inline"), ("source", "abc"), ("dest", "x")],
    );
    assert_eq!((r.code(), r.err()), (124, "ssh.upload_timeout"));
    mock(|_, _| Ok(out(255, b"", "Host key verification failed.")));
    let r = call(
        "ssh://u@h",
        "upload",
        &[("source_mode", "inline"), ("source", "abc"), ("dest", "x")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.hostkey_verification_failed"));
    mock(|_, _| Ok(out(1, b"", "cat: x: Permission denied")));
    let r = call(
        "ssh://u@h",
        "upload",
        &[("source_mode", "inline"), ("source", "abc"), ("dest", "x")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.upload_remote_write_failed"));
}

#[test]
fn upload_checksum_mismatch_installs_nothing() {
    let d = tmp();
    let dir = d.path().to_path_buf();
    // The "remote" side corrupts the data on its way in.
    mock(move |cmd, spec| {
        let sh = SshCommandLine {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("cd '{}' && {}", dir.display(), cmd.remote()),
            ],
            env: vec![],
        };
        let spec = RunSpec {
            stdin: Some(b"abX"),
            ..*spec
        };
        run_real_process(&sh, &spec)
    });
    let r = call(
        "ssh://u@h",
        "upload",
        &[
            ("source_mode", "inline"),
            ("source", "abc"),
            ("dest", "f"),
            ("verify_checksum", "true"),
        ],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.upload_checksum_mismatch"));
    assert!(!d.path().join("f").exists());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn download_writes_dest_and_returns_content() {
    let d = tmp();
    local_remote(d.path());
    std::fs::write(d.path().join("remote.txt"), "remote data\n").unwrap();
    let dest = d.path().join("out/copy.txt");
    let r = call(
        "ssh://u@h",
        "download",
        &[
            ("source", "remote.txt"),
            ("dest", &s(&dest)),
            ("verify_checksum", "true"),
            ("checksum_algorithm", "md5"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["content"], "remote data\n");
    assert_eq!(r.json["result"]["checksum_verified"], true);
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "remote data\n");
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "remote.txt"), ("dest", &s(&dest))],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.download_dest_exists"));
    let r = call(
        "ssh://u@h",
        "download",
        &[
            ("source", "remote.txt"),
            ("dest_mode", "none"),
            ("return_encoding", "base64"),
        ],
    );
    assert_eq!(r.json["result"]["content"], "cmVtb3RlIGRhdGEK");
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "nope"), ("dest_mode", "none")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.download_source_not_found"));
    std::fs::create_dir(d.path().join("adir")).unwrap();
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "adir"), ("dest_mode", "none")],
    );
    assert_eq!(r.err(), "ssh.download_source_is_directory");
    let r = call(
        "ssh://u@h",
        "download",
        &[
            ("source", "remote.txt"),
            ("dest", &s(&dest)),
            ("overwrite", "true"),
            ("max_size_bytes", "4"),
        ],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.download_too_large"));
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "remote data\n");
    std::fs::write(d.path().join("bin"), [0xff, 0xfe]).unwrap();
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "bin"), ("dest_mode", "none")],
    );
    assert_eq!(r.err(), "ssh.download_invalid_utf8");
    // A symlink at dest is replaced, never written through.
    let target = d.path().join("keep.txt");
    std::fs::write(&target, "keep").unwrap();
    let link = d.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let r = call(
        "ssh://u@h",
        "download",
        &[
            ("source", "remote.txt"),
            ("dest", &s(&link)),
            ("overwrite", "true"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    assert!(
        !std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn download_validation_and_failures() {
    let d = tmp();
    mock(|_, _| panic!("no ssh"));
    std::fs::write(d.path().join("exists"), "x").unwrap();
    for (pairs, code, exit) in [
        (vec![("dest", "x")], "ssh.download_source_missing", 2),
        (
            vec![("source", "/etc/hosts")],
            "ssh.download_dest_missing",
            2,
        ),
        (
            vec![("source", "a"), ("dest_mode", "none"), ("dest", "x")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![
                ("source", "a"),
                ("dest_mode", "none"),
                ("overwrite", "true"),
            ],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("source", "a"), ("dest", &s(&d.path().join("exists")))],
            "ssh.download_dest_exists",
            1,
        ),
        (
            vec![
                ("source", "a"),
                ("dest", &s(&d.path().join("no/x"))),
                ("mkdir_parents", "false"),
            ],
            "ssh.download_local_dir_missing",
            1,
        ),
        (
            vec![
                ("source", "a"),
                ("dest", &s(d.path())),
                ("overwrite", "true"),
            ],
            "ssh.download_local_write_failed",
            1,
        ),
    ] {
        let r = call("ssh://u@h", "download", &pairs);
        assert_eq!((r.code(), r.err()), (exit, code), "{pairs:?}");
    }
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "a"), ("dest", "b"), ("dry_run", "true")],
    );
    assert_eq!(r.code(), 0);
    mock(|_, _| Err(RunError::Timeout));
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "a"), ("dest_mode", "none")],
    );
    assert_eq!((r.code(), r.err()), (124, "ssh.download_timeout"));
    mock(|_, _| Ok(out(255, b"", "u@h: Permission denied (publickey).")));
    let r = call(
        "ssh://u@h",
        "download",
        &[("source", "a"), ("dest_mode", "none")],
    );
    assert_eq!(r.err(), "ssh.auth_failed");
    mock(|_, _| Ok(out(0, b"data", "RESH-SUM:0000\n")));
    let r = call(
        "ssh://u@h",
        "download",
        &[
            ("source", "a"),
            ("dest_mode", "none"),
            ("verify_checksum", "true"),
        ],
    );
    assert_eq!(r.err(), "ssh.download_checksum_mismatch");
}

// ------------------------------------------------------------------ keys --

#[test]
fn keys_list_reads_and_reports_keys() {
    let d = tmp();
    local_remote(d.path());
    let ssh = d.path().join(format!("~{NOUSER}/.ssh"));
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(
        ssh.join("authorized_keys"),
        format!("# c\nfrom=\"10.0.0.1\" {ED}\n{RSA}\ngarbage line\n"),
    )
    .unwrap();
    let r = call(&format!("ssh://{NOUSER}@h"), "keys.list", &[]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    let f = &r.json["files"][0];
    assert_eq!(f["exists"], true);
    assert_eq!(f["keys"][0]["fingerprint"], ED_FP);
    assert_eq!(f["keys"][0]["options"][0], "from=\"10.0.0.1\"");
    assert_eq!(f["keys"][1]["bits"], 2048);
    assert_eq!(
        f["parse_errors"][0].as_str().unwrap().split(':').next(),
        Some("line 4")
    );
    assert_eq!(r.json["files"][1]["exists"], false);
    assert_eq!(r.json["summary"]["total_keys"], 2);

    let r = call(
        &format!("ssh://{NOUSER}@h"),
        "keys.list",
        &[
            ("key_types", "rsa"),
            ("include_raw_key", "false"),
            ("include_options", "false"),
            ("fingerprint_algorithm", "md5"),
        ],
    );
    assert_eq!(r.json["summary"]["matched_keys"], 1);
    assert!(r.json["files"][0]["keys"][0].get("raw_key").is_none());
    assert!(
        r.json["files"][0]["keys"][0]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("MD5:")
    );
    let r = call(
        &format!("ssh://{NOUSER}@h"),
        "keys.list",
        &[("max_keys", "1")],
    );
    assert_eq!(r.json["summary"]["truncated"], true);
    let r = call(
        &format!("ssh://{NOUSER}@h"),
        "keys.list",
        &[("max_bytes", "10")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.keys_list_too_large"));
    std::fs::write(d.path().join("pub"), ED).unwrap();
    let r = call(
        "ssh://u@h",
        "keys.list",
        &[("scope", "custom"), ("custom_paths", "pub,nothere")],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["files"][0]["keys"][0]["comment"], "bob@laptop");
    let r = call(
        "ssh://u@h",
        "keys.list",
        &[("scope", "custom"), ("custom_paths", &s(d.path()))],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.keys_list_remote_read_failed"));
}

#[test]
fn keys_list_validation_dry_run_and_timeouts() {
    let calls = mock(|_, _| panic!("no ssh"));
    for (pairs, code) in [
        (
            vec![("scope", "custom")],
            "ssh.keys_list_custom_paths_required",
        ),
        (vec![("scope", "everything")], "ssh.invalid_argument"),
        (
            vec![("scope", "host"), ("custom_paths", "/a")],
            "ssh.invalid_argument",
        ),
        (
            vec![("authorized_user", "a"), ("authorized_paths", "/x")],
            "ssh.invalid_argument",
        ),
        (vec![("key_types", "rsa,foo")], "ssh.invalid_argument"),
        (vec![("authorized_user", "-x")], "ssh.invalid_argument"),
    ] {
        let r = call("ssh://u@h", "keys.list", &pairs);
        assert_eq!((r.code(), r.err()), (2, code), "{pairs:?}");
    }
    let r = call("ssh://h", "keys.list", &[]);
    assert_eq!(r.err(), "ssh.username_required");
    let r = call("ssh://alice@h", "keys.list", &[("dry_run", "true")]);
    assert_eq!(r.json["planned_files"][0], "~alice/.ssh/authorized_keys");
    let r = call(
        "ssh://alice@h",
        "keys.list",
        &[("dry_run", "true"), ("scope", "host")],
    );
    assert_eq!(r.json["planned_files"][0], "/etc/ssh/ssh_host_rsa_key.pub");
    assert!(calls.borrow().is_empty());
    mock(|_, _| Err(RunError::Timeout));
    let r = call("ssh://u@h", "keys.list", &[]);
    assert_eq!((r.code(), r.err()), (124, "ssh.keys_list_timeout"));
    mock(|_, _| Ok(out(255, b"", "connect to host h port 22: No route to host")));
    let r = call("ssh://u@h", "keys.list", &[]);
    assert_eq!(r.err(), "ssh.connect_failed");
}

fn key_add(d: &Path, pairs: &[(&str, &str)]) -> Run {
    let mut all = vec![("public_key", ED), ("scope", "custom")];
    let path = s(&d.join("home/.ssh/authorized_keys"));
    if !pairs.iter().any(|(k, _)| *k == "custom_paths") {
        all.push(("custom_paths", &path));
    }
    all.extend_from_slice(pairs);
    let all: Vec<(&str, &str)> = all.into_iter().collect();
    call("ssh://u@h", "key.add", &all)
}

#[test]
fn key_add_creates_appends_skips_and_replaces() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp();
    local_remote(d.path());
    let file = d.path().join("home/.ssh/authorized_keys");
    let r = key_add(d.path(), &[]);
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["operation"]["status"], "added");
    assert_eq!(r.json["operation"]["created_file"], true);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{ED}\n"));
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let r = key_add(d.path(), &[]);
    assert_eq!(r.json["operation"]["status"], "already_present");
    assert_eq!(r.json["operation"]["duplicates_found"], 1);
    let r = key_add(d.path(), &[("on_duplicate", "error")]);
    assert_eq!((r.code(), r.err()), (1, "ssh.key_add_duplicate"));
    let r = key_add(d.path(), &[("public_key", RSA)]);
    assert_eq!(r.json["operation"]["status"], "added");
    assert_eq!(r.json["operation"]["backup_created"], true);
    assert_eq!(
        std::fs::read_to_string(format!("{}.bak", file.display())).unwrap(),
        format!("{ED}\n")
    );
    let commented = format!("{} new-comment", &ED[..ED.rfind(' ').unwrap()]);
    let r = key_add(
        d.path(),
        &[
            ("public_key", &commented),
            ("on_duplicate", "replace"),
            ("backup_suffix", ".old"),
        ],
    );
    assert_eq!(r.json["operation"]["status"], "replaced");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{RSA}\n{commented}\n")
    );
    assert!(PathBuf::from(format!("{}.old", file.display())).exists());
    // No temp files left in the directory.
    let names: Vec<String> = std::fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.starts_with(".resh")), "{names:?}");
    // ensure_permissions=false keeps an existing mode.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let r = key_add(
        d.path(),
        &[
            ("public_key", ED),
            ("on_duplicate", "replace"),
            ("ensure_permissions", "false"),
            ("backup_existing", "false"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn key_add_refusals() {
    let d = tmp();
    local_remote(d.path());
    let r = key_add(d.path(), &[("create_if_missing", "false")]);
    assert_eq!((r.code(), r.err()), (1, "ssh.key_add_target_missing"));
    std::fs::write(d.path().join("real"), "").unwrap();
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("link")).unwrap();
    let r = key_add(d.path(), &[("custom_paths", &s(&d.path().join("link")))]);
    assert_eq!((r.code(), r.err()), (1, "ssh.key_add_target_is_symlink"));
    assert_eq!(std::fs::read_to_string(d.path().join("real")).unwrap(), "");
    std::fs::write(d.path().join("big"), "x".repeat(100)).unwrap();
    let r = key_add(
        d.path(),
        &[
            ("custom_paths", &s(&d.path().join("big"))),
            ("max_file_bytes", "10"),
        ],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.key_add_file_too_large"));

    let pubfile = d.path().join("id.pub");
    std::fs::write(&pubfile, format!("{ED}\n")).unwrap();
    let path = s(&d.path().join("x"));
    for (pairs, code, exit) in [
        (
            vec![("scope", "custom"), ("custom_paths", path.as_str())],
            "ssh.key_add_missing_public_key",
            2,
        ),
        (
            vec![
                ("public_key", "ssh-ed25519 AAAA"),
                ("scope", "custom"),
                ("custom_paths", path.as_str()),
            ],
            "ssh.key_add_invalid_public_key",
            2,
        ),
        (
            vec![("public_key", ED), ("scope", "custom")],
            "ssh.key_add_custom_paths_required",
            2,
        ),
        (
            vec![
                ("public_key", ED),
                ("scope", "custom"),
                ("custom_paths", "a,b"),
            ],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("public_key", ED), ("public_key_path", "x")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("public_key", ED), ("public_key_source", "file")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("public_key_path", "/nonexistent/id.pub")],
            "ssh.key_add_public_key_file_not_found",
            1,
        ),
        (
            vec![("public_key", ED), ("file_mode", "600")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("public_key", ED), ("backup_suffix", "/x")],
            "ssh.invalid_argument",
            2,
        ),
        (
            vec![("public_key", "-----BEGIN OPENSSH PRIVATE KEY-----")],
            "ssh.key_add_invalid_public_key",
            2,
        ),
    ] {
        let r = call("ssh://u@h", "key.add", &pairs);
        assert_eq!((r.code(), r.err()), (exit, code), "{pairs:?}");
    }
    let r = call(
        "ssh://u@h",
        "key.add",
        &[("public_key_path", &s(&pubfile)), ("dry_run", "true")],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["target_file"], "~u/.ssh/authorized_keys");
    assert_eq!(r.json["key"]["fingerprint"], ED_FP);
    assert_eq!(r.json["operation"]["status"], "dry_run");
}

#[test]
fn key_add_concurrent_change_and_timeouts() {
    let d = tmp();
    let file = d.path().join("ak");
    std::fs::write(&file, format!("{RSA}\n")).unwrap();
    let dir = d.path().to_path_buf();
    let f2 = file.clone();
    // Someone changes the file between the read and the write.
    mock(move |cmd, spec| {
        if spec.stdin.is_some() {
            std::fs::write(&f2, "changed\n").unwrap();
        }
        let sh = SshCommandLine {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!("cd '{}' && {}", dir.display(), cmd.remote()),
            ],
            env: vec![],
        };
        run_real_process(&sh, spec)
    });
    let r = key_add(d.path(), &[("custom_paths", &s(&file))]);
    assert_eq!((r.code(), r.err()), (1, "ssh.key_add_concurrent_change"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "changed\n");
    mock(|_, _| Err(RunError::Timeout));
    let r = key_add(d.path(), &[]);
    assert_eq!((r.code(), r.err()), (124, "ssh.key_add_timeout"));
}

// ---------------------------------------------------------------- tunnel --

#[test]
fn tunnel_validation_and_dry_run() {
    let calls = mock(|_, _| panic!("no ssh"));
    for (pairs, code) in [
        (vec![], "ssh.tunnel_mode_required"),
        (vec![("mode", "sideways")], "ssh.invalid_argument"),
        (vec![("mode", "local")], "ssh.tunnel_missing_remote_dest"),
        (vec![("mode", "remote")], "ssh.tunnel_missing_local_dest"),
        (
            vec![("mode", "dynamic"), ("local_bind_host", "0.0.0.0")],
            "ssh.tunnel_wildcard_bind_forbidden",
        ),
        (
            vec![("mode", "dynamic"), ("allow_wildcard_binds", "true")],
            "ssh.invalid_argument",
        ),
        (
            vec![("mode", "dynamic"), ("remote_dest_host", "x")],
            "ssh.invalid_argument",
        ),
        (
            vec![
                ("mode", "local"),
                ("remote_dest_host", "db"),
                ("remote_dest_port", "5432"),
                ("socks_version", "socks4"),
            ],
            "ssh.invalid_argument",
        ),
        (
            vec![("mode", "dynamic"), ("max_connections", "0")],
            "ssh.invalid_argument",
        ),
        (
            vec![("mode", "dynamic"), ("local_bind_port", "70000")],
            "ssh.invalid_argument",
        ),
    ] {
        let r = call("ssh://u@h", "tunnel", &pairs);
        assert_eq!((r.code(), r.err()), (2, code), "{pairs:?}");
    }
    let r = call("ssh://h", "tunnel", &[("mode", "dynamic")]);
    assert_eq!(r.err(), "ssh.username_required");
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "dynamic"),
            ("local_bind_host", "0.0.0.0"),
            ("allow_wildcard_binds", "true"),
            ("dry_run", "true"),
            ("max_bytes_in", "5"),
        ],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["tunnel"]["socks_version"], "socks5");
    assert_eq!(r.json["lifetime"]["max_bytes_in"], 5);
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("all network interfaces")
    );
    assert!(calls.borrow().is_empty());
}

#[test]
fn tunnel_forward_args() {
    let a = Args::from([
        ("mode".to_string(), "remote".to_string()),
        ("remote_bind_host".to_string(), "::1".to_string()),
        ("remote_bind_port".to_string(), "8080".to_string()),
        ("local_dest_host".to_string(), "127.0.0.1".to_string()),
        ("local_dest_port".to_string(), "80".to_string()),
    ]);
    let t = SshTarget::from_url(&Url::parse("ssh://u@h").unwrap());
    let o = tunnel::parse(&args::ArgReader::new(&a), &t).unwrap();
    let f = tunnel::forward_args(&o, Path::new("/d/s"), 0);
    assert_eq!(
        f.join(" "),
        "-N -o ExitOnForwardFailure=yes -v -R [::1]:8080:/d/s"
    );
    assert_eq!(
        tunnel::allocated_port("Allocated port 41234 for remote forward to /d/s"),
        Some(41234)
    );
}

fn have(tool: &str) -> bool {
    which::which(tool).is_ok()
}

/// A local echo server; returns its port.
fn echo_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = c.try_clone().unwrap();
                let mut w = c;
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    port
}

/// Stands in for `ssh -L <sock>:host:port` with socat.
fn socat_for_local_forward() {
    MOCK_SPAWN.with(|m| {
        *m.borrow_mut() = Some(Box::new(|cmd: &SshCommandLine| {
            let spec = cmd
                .args
                .iter()
                .position(|a| a == "-L")
                .map(|i| cmd.args[i + 1].clone())
                .unwrap();
            let (sock, dest) = spec.split_once(':').unwrap();
            SshCommandLine {
                program: "socat".into(),
                args: vec![format!("UNIX-LISTEN:{sock},fork"), format!("TCP:{dest}")],
                env: vec![],
            }
        }))
    });
}

#[test]
fn tunnel_local_forward_relays_and_enforces_limits() {
    use std::io::{Read, Write};
    if !have("socat") {
        eprintln!("skipped: socat is not installed");
        return;
    }
    socat_for_local_forward();
    let dest = echo_server();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut c = loop {
            if let Ok(c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                break c;
            }
            assert!(start.elapsed().as_secs() < 10, "tunnel never came up");
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        c.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    });
    let destp = dest.to_string();
    let portp = port.to_string();
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "local"),
            ("local_bind_port", &portp),
            ("remote_dest_host", "127.0.0.1"),
            ("remote_dest_port", &destp),
            ("max_connections", "1"),
            ("tunnel_timeout_ms", "15000"),
        ],
    );
    client.join().unwrap();
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert!(r.stdout.starts_with("{\"event\":\"ready\""), "{}", r.stdout);
    assert_eq!(r.json["lifetime"]["closed_reason"], "max_connections");
    assert_eq!(r.json["stats"]["connections_accepted"], 1);
    assert_eq!(r.json["stats"]["bytes_in"], 5);
    assert_eq!(r.json["stats"]["bytes_out"], 5);
    assert_eq!(r.json["tunnel"]["local_bind_port"], port);
}

#[test]
fn tunnel_closes_on_idle_and_byte_limits() {
    use std::io::Write;
    if !have("socat") {
        eprintln!("skipped: socat is not installed");
        return;
    }
    socat_for_local_forward();
    let dest = echo_server().to_string();
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "local"),
            ("remote_dest_host", "127.0.0.1"),
            ("remote_dest_port", &dest),
            ("idle_timeout_ms", "300"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["lifetime"]["closed_reason"], "idle_timeout");
    let ready: Value = serde_json::from_str(r.stdout.lines().next().unwrap()).unwrap();
    assert!(ready["listen"].as_str().unwrap().starts_with("127.0.0.1:"));

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut c = loop {
            if let Ok(c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                break c;
            }
            assert!(start.elapsed().as_secs() < 10);
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let _ = c.write_all(&[b'x'; 100]);
        std::thread::sleep(std::time::Duration::from_millis(500));
    });
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "local"),
            ("local_bind_port", &port.to_string()),
            ("remote_dest_host", "127.0.0.1"),
            ("remote_dest_port", &dest),
            ("max_bytes_in", "10"),
            ("timeout_ms", "10000"),
        ],
    );
    client.join().unwrap();
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["lifetime"]["closed_reason"], "max_bytes_in");
    assert_eq!(r.json["stats"]["bytes_in"], 10);
}

#[test]
fn tunnel_ssh_failures_and_timeout() {
    // ssh exits at once: the forward never came up.
    MOCK_SPAWN.with(|m| {
        *m.borrow_mut() = Some(Box::new(|_: &SshCommandLine| SshCommandLine {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                "echo 'Error: remote port forwarding failed for listen port 80' >&2; exit 255"
                    .into(),
            ],
            env: vec![],
        }))
    });
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "remote"),
            ("remote_bind_port", "80"),
            ("local_dest_host", "127.0.0.1"),
            ("local_dest_port", "1"),
        ],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.tunnel_forward_failed"));
    // ssh hangs without setting anything up: timeout_ms ends it.
    MOCK_SPAWN.with(|m| {
        *m.borrow_mut() = Some(Box::new(|_: &SshCommandLine| SshCommandLine {
            program: "sleep".into(),
            args: vec!["30".into()],
            env: vec![],
        }))
    });
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[
            ("mode", "local"),
            ("remote_dest_host", "db"),
            ("remote_dest_port", "1"),
            ("timeout_ms", "300"),
        ],
    );
    assert_eq!((r.code(), r.err()), (124, "ssh.tunnel_timeout"));
    // A busy local port fails before ssh starts.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port().to_string();
    let r = call(
        "ssh://u@h",
        "tunnel",
        &[("mode", "dynamic"), ("local_bind_port", &port)],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.tunnel_bind_failed"));
}

// ------------------------------------------------------------------ test --

#[test]
fn test_verb_runs_each_check() {
    let d = tmp();
    local_remote(d.path());
    let r = call(
        "ssh://u@h",
        "test",
        &[
            ("tests", "connect,auth,exec,sftp,hostkey"),
            ("exec_command", "true"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["summary"]["tests_passed"], 5);
    assert_eq!(r.json["security"]["hostkey_fingerprint"], "SHA256:abc");
    assert_eq!(r.json["tests"][3]["details"]["protocol_version"], 3);
    // exec alone runs without connect/auth.
    let r = call(
        "ssh://u@h",
        "test",
        &[("tests", "exec"), ("exec_command", "exit 4")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.test_failed"));
    assert_eq!(r.json["tests"][0]["error"]["code"], "ssh.test_exec_failed");
}

#[test]
fn test_verb_failures_dependencies_and_timeouts() {
    mock(|_, _| {
        Ok(out(
            255,
            b"",
            "ssh: connect to host h port 22: Connection refused",
        ))
    });
    let r = call(
        "ssh://u@h",
        "test",
        &[("tests", "connect,auth,exec"), ("exec_command", "x")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.test_failed"));
    assert_eq!(
        r.json["tests"][0]["error"]["code"],
        "ssh.test_connect_failed"
    );
    assert_eq!(r.json["tests"][1]["status"], "skipped");
    assert_eq!(
        r.json["tests"][2]["error"]["code"],
        "ssh.test_dependency_failed"
    );
    mock(|_, _| Ok(out(255, b"", "u@h: Permission denied (publickey).")));
    let r = call("ssh://u@h", "test", &[]);
    assert_eq!(r.json["tests"][0]["status"], "passed");
    assert_eq!(r.json["tests"][1]["error"]["code"], "ssh.test_auth_failed");
    mock(|_, _| Ok(out(255, b"", "Host key verification failed.")));
    let r = call("ssh://u@h", "test", &[("tests", "hostkey")]);
    assert_eq!(
        r.json["tests"][0]["error"]["code"],
        "ssh.test_hostkey_failed"
    );
    mock(|_, _| Ok(out(1, b"", "subsystem request failed")));
    let r = call("ssh://u@h", "test", &[("tests", "sftp")]);
    assert_eq!(r.json["tests"][0]["error"]["code"], "ssh.test_sftp_failed");
    mock(|_, _| Err(RunError::Timeout));
    let r = call("ssh://u@h", "test", &[("tests", "connect")]);
    assert_eq!(
        r.json["tests"][0]["error"]["code"],
        "ssh.test_check_timeout"
    );
    let d = tmp();
    local_remote(d.path());
    let r = call(
        "ssh://u@h",
        "test",
        &[
            ("tests", "exec,auth"),
            ("exec_command", "sleep 5"),
            ("overall_timeout_ms", "300"),
        ],
    );
    assert_eq!((r.code(), r.err()), (124, "ssh.test_overall_timeout"));
    assert_eq!(r.json["tests"][1]["status"], "skipped");
}

#[test]
fn test_verb_validation() {
    mock(|_, _| panic!("no ssh"));
    for (pairs, code) in [
        (
            vec![("tests", "connect,ping")],
            "ssh.test_invalid_test_name",
        ),
        (
            vec![("known_hosts_mode", "insecure")],
            "ssh.test_insecure_hostkey_forbidden",
        ),
        (
            vec![("allow_insecure_hostkey", "true")],
            "ssh.invalid_argument",
        ),
        (vec![("exec_command", "x")], "ssh.invalid_argument"),
        (vec![("tests", "")], "ssh.invalid_argument"),
    ] {
        let r = call("ssh://u@h", "test", &pairs);
        assert_eq!((r.code(), r.err()), (2, code), "{pairs:?}");
    }
    let r = call(
        "ssh://u@h",
        "test",
        &[("dry_run", "true"), ("tests", "connect,connect,sftp")],
    );
    assert_eq!(r.code(), 0);
    assert_eq!(r.json["tests"].as_array().unwrap().len(), 2);
    assert_eq!(r.json["tests"][0]["status"], "planned");
}

// ------------------------------------------------------------ config.get --

#[test]
fn config_get_uses_the_url_host_and_reads_files() {
    let d = tmp();
    let cfg = d.path().join("cfg");
    std::fs::write(
        &cfg,
        "Host web01\n  HostName 192.0.2.10\n  User alice\nHost *\n  User nobody\n",
    )
    .unwrap();
    let r = call(
        "ssh://web01",
        "config.get",
        &[
            ("user_config_path", &s(&cfg)),
            ("system_config_path", "/dev/null"),
        ],
    );
    assert_eq!(r.code(), 0, "{}", r.stdout);
    assert_eq!(r.json["host"], "web01");
    assert_eq!(r.json["effective"]["User"]["value"], "alice");
    assert_eq!(r.json["raw_entries"].as_array().unwrap().len(), 3);
    let r = call(
        "ssh://web01",
        "config.get",
        &[
            ("user_config_path", &s(&cfg)),
            ("system_config_path", "/dev/null"),
            ("include_raw_entries", "false"),
            ("include_origin", "false"),
            ("format", "text"),
        ],
    );
    assert!(
        r.stdout.contains("User                 = alice"),
        "{}",
        r.stdout
    );
    for (url, pairs, code) in [
        (
            "ssh://web01",
            vec![("host", "web02")],
            "ssh.target_conflict",
        ),
        ("ssh://web01:22", vec![], "ssh.invalid_argument"),
        (
            "ssh://web01",
            vec![("max_hosts", "x")],
            "ssh.invalid_argument",
        ),
    ] {
        let r = call(url, "config.get", &pairs);
        assert_eq!((r.code(), r.err()), (2, code), "{pairs:?}");
    }
    let r = call(
        "ssh://web01",
        "config.get",
        &[("user_config_path", "/nonexistent/cfg")],
    );
    assert_eq!((r.code(), r.err()), (1, "ssh.config_get_read_failed"));
    let r = call("ssh://web01", "config.get", &[("dry_run", "true")]);
    assert_eq!(r.code(), 0);
    assert!(r.json.get("effective").is_none());
}
