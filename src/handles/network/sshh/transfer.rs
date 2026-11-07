//! `upload` and `download`: file transfer through a remote POSIX shell
//! (`cat`) over the system ssh client.

use super::args::{ArgReader, check_known};
use super::conn::{
    ConnOptions, SshTarget, UserRule, check_remote_path, connection_error, parse_checksum_output,
    parse_conn, quote_remote_path, run_error,
};
use super::runner::{Deadline, RunError, RunSpec, run_ssh_process};
use super::types::*;
use super::{Out, coded, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use base64::prelude::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;

pub const DEFAULT_MAX_SIZE_BYTES: u64 = 104_857_600;
pub const DEFAULT_TRANSFER_TIMEOUT_MS: u64 = 600_000;

/// Exit codes of the remote upload/download scripts.
const EXIT_DEST_EXISTS: i32 = 17;
const EXIT_DIR_MISSING: i32 = 18;
const EXIT_WRITE_FAILED: i32 = 19;
const EXIT_IS_DIRECTORY: i32 = 20;
const EXIT_INCOMPLETE: i32 = 21;
const EXIT_CHECKSUM: i32 = 22;

/// Marker of the checksum line a download prints on stderr.
const SUM_MARKER: &str = "RESH-SUM:";

/// Text describing which limit stopped a transfer.
fn timeout_text(deadline: &Deadline, step: &str, step_ms: u64, timeout_ms: Option<u64>) -> String {
    if deadline.expired() {
        format!("timeout_ms={} passed", timeout_ms.unwrap_or(0))
    } else {
        format!("{step}={step_ms} passed")
    }
}

// ---------------------------------------------------------------- upload --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    File,
    Inline,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub conn: ConnOptions,
    pub source: String,
    pub source_mode: SourceMode,
    pub source_encoding: Encoding,
    pub dest: String,
    pub overwrite: bool,
    pub atomic: bool,
    pub mkdir_parents: bool,
    pub file_mode: Option<String>,
    pub preserve_times: bool,
    pub mtime_epoch_ms: Option<i64>,
    pub max_size_bytes: u64,
    pub verify_checksum: bool,
    pub checksum_algorithm: ChecksumAlgorithm,
    pub transfer_timeout_ms: u64,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

pub fn parse_upload(r: &ArgReader, target: &SshTarget) -> Result<UploadOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::DefaultToLocal)?;
    let source_mode = r
        .choice(
            "source_mode",
            &[("file", SourceMode::File), ("inline", SourceMode::Inline)],
        )?
        .unwrap_or(SourceMode::File);
    let source = match source_mode {
        SourceMode::Inline => r.data("source", true)?,
        SourceMode::File => r.text("source")?,
    }
    .ok_or(SshError::UploadSourceMissing)?;
    let source_encoding = r.choice("source_encoding", Encoding::VALUES)?;
    if source_encoding.is_some() && source_mode == SourceMode::File {
        return Err(SshError::InvalidArgument(
            "source_encoding applies only to source_mode=inline".into(),
        ));
    }
    let dest = r.text("dest")?.ok_or(SshError::UploadDestMissing)?;
    check_remote_path("dest", &dest)?;
    if dest.ends_with('/') {
        return Err(SshError::InvalidArgument(
            "dest must name a file, not a directory".into(),
        ));
    }
    let file_mode = r.text("file_mode")?;
    if let Some(m) = &file_mode {
        let ok =
            m.len() == 4 && m.starts_with('0') && m.bytes().all(|b| (b'0'..=b'7').contains(&b));
        if !ok {
            return Err(SshError::InvalidArgument(format!(
                "invalid value for file_mode: {m:?} (expected four octal digits such as 0644)"
            )));
        }
    }
    let preserve_times = r.bool("preserve_times", false)?;
    let mtime_epoch_ms = r.i64("mtime_epoch_ms")?;
    if preserve_times && source_mode == SourceMode::Inline {
        return Err(SshError::InvalidArgument(
            "preserve_times needs source_mode=file".into(),
        ));
    }
    if preserve_times && mtime_epoch_ms.is_some() {
        return Err(SshError::InvalidArgument(
            "give preserve_times or mtime_epoch_ms, not both".into(),
        ));
    }
    Ok(UploadOptions {
        conn,
        source,
        source_mode,
        source_encoding: source_encoding.unwrap_or_default(),
        dest,
        overwrite: r.bool("overwrite", false)?,
        atomic: r.bool("atomic", true)?,
        mkdir_parents: r.bool("mkdir_parents", true)?,
        file_mode,
        preserve_times,
        mtime_epoch_ms,
        max_size_bytes: r.u64_or("max_size_bytes", DEFAULT_MAX_SIZE_BYTES)?,
        verify_checksum: r.bool("verify_checksum", false)?,
        checksum_algorithm: r
            .choice("checksum_algorithm", ChecksumAlgorithm::VALUES)?
            .unwrap_or_default(),
        transfer_timeout_ms: r.u64_or("transfer_timeout_ms", DEFAULT_TRANSFER_TIMEOUT_MS)?,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// The bytes to upload and the local path they came from.
pub fn read_source(o: &UploadOptions) -> Result<(Vec<u8>, Option<String>), SshError> {
    match o.source_mode {
        SourceMode::File => {
            let path = o.source.strip_prefix("file://").unwrap_or(&o.source);
            let meta = std::fs::metadata(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    SshError::UploadSourceNotFound(path.to_string())
                } else {
                    SshError::UploadSourceReadError(format!("{path}: {e}"))
                }
            })?;
            if meta.is_dir() {
                return Err(SshError::UploadSourceReadError(format!(
                    "{path} is a directory"
                )));
            }
            if meta.len() > o.max_size_bytes {
                return Err(SshError::UploadTooLarge(meta.len(), o.max_size_bytes));
            }
            let data = std::fs::read(path)
                .map_err(|e| SshError::UploadSourceReadError(format!("{path}: {e}")))?;
            if data.len() as u64 > o.max_size_bytes {
                return Err(SshError::UploadTooLarge(
                    data.len() as u64,
                    o.max_size_bytes,
                ));
            }
            Ok((data, Some(path.to_string())))
        }
        SourceMode::Inline => {
            let data = match o.source_encoding {
                Encoding::Utf8 => o.source.as_bytes().to_vec(),
                Encoding::Base64 => BASE64_STANDARD
                    .decode(o.source.trim())
                    .map_err(|e| SshError::UploadInvalidSourceEncoding(e.to_string()))?,
            };
            if data.len() as u64 > o.max_size_bytes {
                return Err(SshError::UploadTooLarge(
                    data.len() as u64,
                    o.max_size_bytes,
                ));
            }
            Ok((data, None))
        }
    }
}

/// Modification time (whole seconds) to set on the uploaded file.
fn upload_mtime_secs(o: &UploadOptions, source_path: Option<&str>) -> Option<i64> {
    if let Some(ms) = o.mtime_epoch_ms {
        return Some(ms.div_euclid(1000));
    }
    if o.preserve_times {
        let modified = std::fs::metadata(source_path?).ok()?.modified().ok()?;
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        return i64::try_from(secs).ok();
    }
    None
}

/// The remote shell script that stores stdin (exactly `size` bytes) at
/// `dest`. With atomic=true the data goes to a fresh temporary file in the
/// same directory (created with noclobber), is checked for size and
/// checksum, and only then renamed over dest; a symlink at dest is replaced,
/// never written through. Without overwrite the final step is a hard link,
/// which fails if dest appeared meanwhile.
pub fn build_upload_script(
    o: &UploadOptions,
    size: u64,
    local_sum: Option<&str>,
    temp_suffix: u32,
    mtime_secs: Option<i64>,
) -> String {
    let mut s: Vec<String> = Vec::new();
    s.push(format!("d={}", quote_remote_path(&o.dest)));
    if let Some(parent) = Path::new(&o.dest)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
    {
        s.push(format!("p={}", quote_remote_path(&parent)));
        if o.mkdir_parents {
            s.push(format!("mkdir -p -- \"$p\" || exit {EXIT_WRITE_FAILED}"));
        } else {
            s.push(format!(
                "[ -d \"$p\" ] || {{ echo 'resh: remote directory missing' >&2; exit {EXIT_DIR_MISSING}; }}"
            ));
        }
    }
    s.push(format!(
        "if [ ! -L \"$d\" ] && [ -d \"$d\" ]; then echo 'resh: remote dest is a directory' >&2; exit {EXIT_IS_DIRECTORY}; fi"
    ));
    let exists = format!("{{ echo 'resh: remote file exists' >&2; exit {EXIT_DEST_EXISTS}; }}");
    if !o.overwrite {
        s.push(format!(
            "if [ -e \"$d\" ] || [ -L \"$d\" ]; then {exists}; fi"
        ));
    }
    let target = if o.atomic {
        let tmp = format!("{}.resh.tmp.{temp_suffix}", o.dest);
        s.push(format!("t={}", quote_remote_path(&tmp)));
        "$t"
    } else {
        "$d"
    };
    let cleanup = if o.atomic { "rm -f -- \"$t\"; " } else { "" };
    let fail = format!("{{ {cleanup}exit {EXIT_WRITE_FAILED}; }}");
    if !o.atomic && o.overwrite {
        s.push("if [ -L \"$d\" ]; then rm -f -- \"$d\" || exit 19; fi".to_string());
    }
    if o.atomic || !o.overwrite {
        // noclobber: never write into a file someone else created first.
        let on_fail = if o.atomic {
            fail.clone()
        } else {
            format!(
                "{{ if [ -e \"$d\" ] || [ -L \"$d\" ]; then {exists}; fi; exit {EXIT_WRITE_FAILED}; }}"
            )
        };
        s.push(format!("(set -C; cat > \"{target}\") || {on_fail}"));
    } else {
        s.push(format!("cat > \"{target}\" || {fail}"));
    }
    s.push(format!(
        "[ $(wc -c < \"{target}\") -eq {size} ] || {{ {cleanup}echo 'resh: incomplete transfer' >&2; exit {EXIT_INCOMPLETE}; }}"
    ));
    if let Some(sum) = local_sum {
        let tool = o.checksum_algorithm.remote_tool();
        s.push(format!(
            "s=$({tool} -- \"{target}\") || {fail}; set -- $s; printf '%s\\n' \"$1\"; [ \"$1\" = {sum} ] || {{ {cleanup}echo 'resh: checksum mismatch' >&2; exit {EXIT_CHECKSUM}; }}"
        ));
    }
    if let Some(mode) = &o.file_mode {
        s.push(format!("chmod {mode} -- \"{target}\" || {fail}"));
    }
    if let Some(secs) = mtime_secs {
        s.push(format!("touch -d @{secs} -- \"{target}\" || {fail}"));
    }
    if o.atomic {
        if o.overwrite {
            s.push(format!(
                "if [ -L \"$d\" ]; then rm -f -- \"$d\" || {fail}; fi"
            ));
            s.push(format!("mv -f -- \"$t\" \"$d\" || {fail}"));
        } else {
            s.push(format!(
                "ln -- \"$t\" \"$d\" 2>/dev/null || {{ rm -f -- \"$t\"; if [ -e \"$d\" ] || [ -L \"$d\" ]; then {exists}; fi; exit {EXIT_WRITE_FAILED}; }}"
            ));
            s.push("rm -f -- \"$t\"".to_string());
        }
    }
    s.join("\n")
}

fn upload_error(o: &UploadOptions, out: &super::runner::ProcessOutput) -> SshError {
    let parent = Path::new(&o.dest)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    match out.exit_code {
        Some(EXIT_DEST_EXISTS) => SshError::UploadDestExists(o.dest.clone()),
        Some(EXIT_DIR_MISSING) => SshError::UploadRemoteDirMissing(parent),
        Some(EXIT_IS_DIRECTORY) => SshError::UploadDestIsDirectory(o.dest.clone()),
        Some(EXIT_INCOMPLETE) => SshError::UploadRemoteWriteFailed(
            "the remote side received fewer bytes than were sent".into(),
        ),
        Some(EXIT_CHECKSUM) => {
            let remote = parse_checksum_output(&out.stdout).unwrap_or_default();
            SshError::UploadChecksumMismatch(String::new(), remote)
        }
        _ => {
            let stderr = out.stderr_text();
            SshError::UploadRemoteWriteFailed(if stderr.is_empty() {
                format!("remote exit code {:?}", out.exit_code)
            } else {
                stderr
            })
        }
    }
}

pub fn run_upload(
    target: &SshTarget,
    args: &Args,
    out: &Out,
    io: &mut IoStreams,
) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshUploadResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: SshConnectionInfo::new(
            target.host.as_deref().unwrap_or("unknown"),
            target.port.unwrap_or(22),
            target.username.as_deref().unwrap_or("unknown"),
        ),
        source: None,
        dest: None,
        result: None,
        timing: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshUploadResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_upload_text).map(|_| status)
    };
    let o = match check_known("upload", args).and_then(|_| parse_upload(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.connection = SshConnectionInfo::new(&o.conn.host, o.conn.port, &o.conn.username);
    let mode = if o.source_mode == SourceMode::File {
        "file"
    } else {
        "inline"
    };
    let (data, source_path) = match read_source(&o) {
        Ok(v) => v,
        Err(e) => {
            response.source = Some(SshUploadSourceInfo {
                mode: mode.into(),
                path: None,
                size_bytes: None,
            });
            return fail(&mut response, io, e);
        }
    };
    let size = data.len() as u64;
    response.source = Some(SshUploadSourceInfo {
        mode: mode.into(),
        path: source_path.clone(),
        size_bytes: Some(size),
    });
    response.dest = Some(SshUploadDestInfo {
        path: o.dest.clone(),
        overwrite: o.overwrite,
        atomic: o.atomic,
        mkdir_parents: o.mkdir_parents,
        file_mode: o.file_mode.clone(),
        size_bytes: Some(size),
    });
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    let algorithm = o.checksum_algorithm.as_str().to_string();
    if o.dry_run {
        response.ok = true;
        response.result = Some(SshUploadResult {
            uploaded: false,
            planned: true,
            verify_checksum: o.verify_checksum,
            checksum_algorithm: algorithm,
            checksum_verified: None,
        });
        response
            .warnings
            .push("Dry run: no SSH connection was made and no file was uploaded.".into());
        write_response(io, out.format, &response, format_upload_text)?;
        return Ok(Status::ok());
    }

    let local_sum = o
        .verify_checksum
        .then(|| o.checksum_algorithm.digest(&data));
    let script = build_upload_script(
        &o,
        size,
        local_sum.as_deref(),
        rand::random::<u32>(),
        upload_mtime_secs(&o, source_path.as_deref()),
    );
    let deadline = Deadline::new(o.timeout_ms);
    let cmd = o.conn.command_line(&prep, &[], Some(&script), false);
    let spec = RunSpec {
        stdin: Some(&data),
        max_stdout: 64 * 1024,
        timeout: deadline.bound(o.transfer_timeout_ms),
        ..Default::default()
    };
    let start = Instant::now();
    let output = match run_ssh_process(&cmd, &spec) {
        Ok(output) => output,
        Err(e) => {
            let state = if o.atomic {
                "nothing was installed at dest (the remote side removes its temporary file \
                 when the connection drops)"
            } else {
                "dest may hold a partial file (atomic=false)"
            };
            let timeout = SshError::UploadTimeout(format!(
                "{}; {state}",
                timeout_text(
                    &deadline,
                    "transfer_timeout_ms",
                    o.transfer_timeout_ms,
                    o.timeout_ms
                )
            ));
            return fail(&mut response, io, run_error(e, timeout));
        }
    };
    let transfer_ms = start.elapsed().as_millis() as u64;
    if !output.success() {
        let e = connection_error(&cmd, &output).unwrap_or_else(|| {
            let mut e = upload_error(&o, &output);
            if let (SshError::UploadChecksumMismatch(local, _), Some(sum)) = (&mut e, &local_sum) {
                *local = sum.clone();
            }
            e
        });
        return fail(&mut response, io, e);
    }
    let checksum_verified = match &local_sum {
        Some(local) => match parse_checksum_output(&output.stdout) {
            Some(remote) if &remote == local => Some(true),
            other => {
                return fail(
                    &mut response,
                    io,
                    SshError::UploadChecksumMismatch(local.clone(), other.unwrap_or_default()),
                );
            }
        },
        None => None,
    };
    response.ok = true;
    response.result = Some(SshUploadResult {
        uploaded: true,
        planned: false,
        verify_checksum: o.verify_checksum,
        checksum_algorithm: algorithm,
        checksum_verified,
    });
    response.timing = Some(SshTimingInfo {
        connect_ms: None,
        command_ms: Some(transfer_ms),
    });
    write_response(io, out.format, &response, format_upload_text)?;
    Ok(Status::ok())
}

pub fn format_upload_text(response: &SshUploadResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Upload\n==========\n\n");
    output.push_str(&format!("Host    : {}\n", response.connection.host));
    output.push_str(&format!("Port    : {}\n", response.connection.port));
    output.push_str(&format!("User    : {}\n", response.connection.username));
    output.push_str(&format!("Dry Run : {}\n\n", response.dry_run));
    if let Some(source) = &response.source {
        output.push_str("Source  :\n");
        output.push_str(&format!("  Mode       : {}\n", source.mode));
        if let Some(path) = &source.path {
            output.push_str(&format!("  Path       : {path}\n"));
        }
        if let Some(size) = source.size_bytes {
            output.push_str(&format!("  Size       : {size} bytes\n"));
        }
        output.push('\n');
    }
    if let Some(dest) = &response.dest {
        output.push_str("Dest    :\n");
        output.push_str(&format!("  Path       : {}\n", dest.path));
        output.push_str(&format!("  Overwrite  : {}\n", dest.overwrite));
        output.push_str(&format!("  Atomic     : {}\n", dest.atomic));
        output.push_str(&format!("  MkdirParents: {}\n", dest.mkdir_parents));
        if let Some(mode) = &dest.file_mode {
            output.push_str(&format!("  Mode       : {mode}\n"));
        }
        output.push('\n');
    }
    if let Some(result) = &response.result {
        output.push_str("Result  :\n");
        output.push_str(&format!(
            "  Uploaded   : {}\n",
            if result.uploaded { "yes" } else { "no" }
        ));
        if result.planned {
            output.push_str("  Planned    : yes\n");
        }
        if result.verify_checksum {
            let state = match result.checksum_verified {
                Some(true) => "verified",
                Some(false) => "failed",
                None => "not checked",
            };
            output.push_str(&format!(
                "  Checksum   : {state} ({})\n",
                result.checksum_algorithm
            ));
        } else {
            output.push_str("  Checksum   : disabled\n");
        }
        output.push('\n');
    }
    if let Some(timing) = &response.timing {
        output.push_str("Timing  :\n");
        if let Some(ms) = timing.command_ms {
            output.push_str(&format!("  Transfer   : {ms} ms\n"));
        }
        output.push('\n');
    }
    push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}

pub(super) fn push_error_and_warnings(
    output: &mut String,
    error: &Option<SshErrorDetails>,
    warnings: &[String],
) {
    if let Some(error) = error {
        output.push_str("Error:\n");
        output.push_str(&format!("  Code   : {}\n", error.code));
        output.push_str(&format!("  Message: {}\n", error.message));
        output.push('\n');
    }
    output.push_str("Warnings:\n");
    if warnings.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for warning in warnings {
            output.push_str(&format!("  - {warning}\n"));
        }
    }
}

// -------------------------------------------------------------- download --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestMode {
    File,
    None,
}

#[derive(Debug, Clone)]
pub struct DownloadOptions {
    pub conn: ConnOptions,
    pub source: String,
    pub dest: Option<String>,
    pub dest_mode: DestMode,
    pub return_content: bool,
    pub return_encoding: Encoding,
    pub overwrite: bool,
    pub mkdir_parents: bool,
    pub max_size_bytes: u64,
    pub verify_checksum: bool,
    pub checksum_algorithm: ChecksumAlgorithm,
    pub transfer_timeout_ms: u64,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

pub fn parse_download(r: &ArgReader, target: &SshTarget) -> Result<DownloadOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::DefaultToLocal)?;
    let source = r.text("source")?.ok_or(SshError::DownloadSourceMissing)?;
    check_remote_path("source", &source)?;
    let dest_mode = r
        .choice(
            "dest_mode",
            &[("file", DestMode::File), ("none", DestMode::None)],
        )?
        .unwrap_or(DestMode::File);
    let dest = r.text("dest")?;
    match dest_mode {
        DestMode::File if dest.is_none() => return Err(SshError::DownloadDestMissing),
        DestMode::None => {
            for key in ["dest", "overwrite", "mkdir_parents"] {
                if r.has(key) {
                    return Err(SshError::InvalidArgument(format!(
                        "{key} is not used with dest_mode=none"
                    )));
                }
            }
        }
        DestMode::File => {}
    }
    Ok(DownloadOptions {
        conn,
        source,
        dest,
        dest_mode,
        return_content: r.bool("return_content", true)?,
        return_encoding: r
            .choice("return_encoding", Encoding::VALUES)?
            .unwrap_or_default(),
        overwrite: r.bool("overwrite", false)?,
        mkdir_parents: r.bool("mkdir_parents", true)?,
        max_size_bytes: r.u64_or("max_size_bytes", DEFAULT_MAX_SIZE_BYTES)?,
        verify_checksum: r.bool("verify_checksum", false)?,
        checksum_algorithm: r
            .choice("checksum_algorithm", ChecksumAlgorithm::VALUES)?
            .unwrap_or_default(),
        transfer_timeout_ms: r.u64_or("transfer_timeout_ms", DEFAULT_TRANSFER_TIMEOUT_MS)?,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// Checks the local dest before connecting.
pub fn check_local_dest(o: &DownloadOptions) -> Result<(), SshError> {
    let Some(dest) = &o.dest else {
        return Ok(());
    };
    let path = Path::new(dest);
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.is_dir() {
            return Err(SshError::DownloadLocalWriteFailed(format!(
                "{dest} is a directory"
            )));
        }
        if !o.overwrite {
            return Err(SshError::DownloadDestExists(dest.clone()));
        }
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        match std::fs::metadata(parent) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(SshError::DownloadLocalWriteFailed(format!(
                    "{} is not a directory",
                    parent.display()
                )));
            }
            Err(_) if !o.mkdir_parents => {
                return Err(SshError::DownloadLocalDirMissing(
                    parent.display().to_string(),
                ));
            }
            Err(_) => {}
        }
    }
    Ok(())
}

/// The remote script: refuse a directory, `cat` the file, then print its
/// checksum on stderr after a marker when asked.
pub fn build_download_script(o: &DownloadOptions) -> String {
    let mut s = format!(
        "f={}\nif [ -d \"$f\" ]; then echo 'resh: remote source is a directory' >&2; exit {EXIT_IS_DIRECTORY}; fi\ncat -- \"$f\" || exit $?",
        quote_remote_path(&o.source)
    );
    if o.verify_checksum {
        s.push_str(&format!(
            "\ns=$({} -- \"$f\") || exit 1\nset -- $s\nprintf '{SUM_MARKER}%s\\n' \"$1\" >&2",
            o.checksum_algorithm.remote_tool()
        ));
    }
    s
}

/// The checksum line the download script printed on stderr.
fn remote_sum(stderr: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stderr)
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix(SUM_MARKER).map(|s| s.trim().to_lowercase()))
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()))
}

fn download_error(o: &DownloadOptions, out: &super::runner::ProcessOutput) -> SshError {
    let stderr = out.stderr_text();
    if out.exit_code == Some(EXIT_IS_DIRECTORY) {
        SshError::DownloadSourceIsDirectory(o.source.clone())
    } else if stderr.contains("No such file or directory") {
        SshError::DownloadSourceNotFound(o.source.clone())
    } else if stderr.is_empty() {
        SshError::DownloadRemoteReadFailed(format!("remote exit code {:?}", out.exit_code))
    } else {
        SshError::DownloadRemoteReadFailed(stderr)
    }
}

/// Writes `data` to a fresh 0600 temp file next to dest and renames it over
/// dest (an existing regular file's permission bits are kept). A symlink at
/// dest is replaced, never written through; without overwrite the final
/// step is a hard link, which fails if dest appeared meanwhile.
pub fn write_download_dest(dest: &str, data: &[u8], o: &DownloadOptions) -> Result<(), SshError> {
    let path = Path::new(dest);
    let werr = |e: std::io::Error| SshError::DownloadLocalWriteFailed(format!("{dest}: {e}"));
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            if !o.mkdir_parents {
                return Err(SshError::DownloadLocalDirMissing(
                    parent.display().to_string(),
                ));
            }
            std::fs::create_dir_all(parent).map_err(werr)?;
        }
    }
    let keep_mode = std::fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.permissions().mode() & 0o777);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(
        ".{name}.resh.tmp.{}.{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(data)?;
        if let Some(mode) = keep_mode {
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.sync_all()?;
        if o.overwrite {
            std::fs::rename(&tmp, path)
        } else {
            std::fs::hard_link(&tmp, path)?;
            std::fs::remove_file(&tmp)
        }
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        if e.kind() == std::io::ErrorKind::AlreadyExists && !o.overwrite {
            return Err(SshError::DownloadDestExists(dest.to_string()));
        }
        return Err(werr(e));
    }
    Ok(())
}

pub fn run_download(
    target: &SshTarget,
    args: &Args,
    out: &Out,
    io: &mut IoStreams,
) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshDownloadResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: SshConnectionInfo::new(
            target.host.as_deref().unwrap_or("unknown"),
            target.port.unwrap_or(22),
            target.username.as_deref().unwrap_or("unknown"),
        ),
        source: None,
        dest: None,
        result: None,
        timing: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshDownloadResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_download_text).map(|_| status)
    };
    let o = match check_known("download", args).and_then(|_| parse_download(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.connection = SshConnectionInfo::new(&o.conn.host, o.conn.port, &o.conn.username);
    response.source = Some(SshDownloadSourceInfo {
        path: o.source.clone(),
        size_bytes: None,
    });
    response.dest = Some(SshDownloadDestInfo {
        mode: if o.dest_mode == DestMode::File {
            "file"
        } else {
            "none"
        }
        .into(),
        path: o.dest.clone(),
        overwrite: o.overwrite,
        mkdir_parents: o.mkdir_parents,
        size_bytes: None,
    });
    if let Err(e) = check_local_dest(&o) {
        return fail(&mut response, io, e);
    }
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    let mut result = SshDownloadResult {
        downloaded: false,
        planned: o.dry_run,
        return_content: o.return_content,
        return_encoding: o.return_encoding.as_str().into(),
        content: None,
        verify_checksum: o.verify_checksum,
        checksum_algorithm: o.checksum_algorithm.as_str().into(),
        checksum_verified: None,
    };
    if o.dest_mode == DestMode::None && !o.return_content {
        response
            .warnings
            .push("dest_mode=none with return_content=false: the content is not kept".into());
    }
    if o.dry_run {
        response.ok = true;
        response.result = Some(result);
        response
            .warnings
            .push("Dry run: no SSH connection was made and no file was downloaded.".into());
        write_response(io, out.format, &response, format_download_text)?;
        return Ok(Status::ok());
    }

    let deadline = Deadline::new(o.timeout_ms);
    let cmd = o
        .conn
        .command_line(&prep, &[], Some(&build_download_script(&o)), false);
    let spec = RunSpec {
        max_stdout: o.max_size_bytes,
        kill_on_overflow: true,
        timeout: deadline.bound(o.transfer_timeout_ms),
        ..Default::default()
    };
    let start = Instant::now();
    let output = match run_ssh_process(&cmd, &spec) {
        Ok(output) => output,
        Err(RunError::TooLarge) => {
            return fail(
                &mut response,
                io,
                SshError::DownloadTooLarge(o.max_size_bytes),
            );
        }
        Err(e) => {
            let timeout = SshError::DownloadTimeout(timeout_text(
                &deadline,
                "transfer_timeout_ms",
                o.transfer_timeout_ms,
                o.timeout_ms,
            ));
            return fail(&mut response, io, run_error(e, timeout));
        }
    };
    if !output.success() {
        let e = connection_error(&cmd, &output).unwrap_or_else(|| download_error(&o, &output));
        return fail(&mut response, io, e);
    }
    let content = output.stdout;
    if let Some(src) = response.source.as_mut() {
        src.size_bytes = Some(content.len() as u64);
    }
    if o.verify_checksum {
        let local = o.checksum_algorithm.digest(&content);
        match remote_sum(&output.stderr) {
            Some(remote) if remote == local => result.checksum_verified = Some(true),
            remote => {
                return fail(
                    &mut response,
                    io,
                    SshError::DownloadChecksumMismatch(remote.unwrap_or_default(), local),
                );
            }
        }
    }
    if o.return_content {
        result.content = Some(match o.return_encoding {
            Encoding::Utf8 => match std::str::from_utf8(&content) {
                Ok(s) => s.to_string(),
                Err(_) => return fail(&mut response, io, SshError::DownloadInvalidUtf8),
            },
            Encoding::Base64 => BASE64_STANDARD.encode(&content),
        });
    }
    if let Some(dest) = &o.dest {
        if let Err(e) = write_download_dest(dest, &content, &o) {
            return fail(&mut response, io, e);
        }
        if let Some(d) = response.dest.as_mut() {
            d.size_bytes = Some(content.len() as u64);
        }
    }
    result.downloaded = true;
    response.ok = true;
    response.result = Some(result);
    response.timing = Some(SshDownloadTimingInfo {
        connect_ms: None,
        transfer_ms: Some(start.elapsed().as_millis() as u64),
    });
    write_response(io, out.format, &response, format_download_text)?;
    Ok(Status::ok())
}

pub fn format_download_text(response: &SshDownloadResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Download\n============\n\n");
    output.push_str(&format!("Host    : {}\n", response.connection.host));
    output.push_str(&format!("Port    : {}\n", response.connection.port));
    output.push_str(&format!("User    : {}\n", response.connection.username));
    output.push_str(&format!("Dry Run : {}\n\n", response.dry_run));
    if let Some(source) = &response.source {
        output.push_str("Source  :\n");
        output.push_str(&format!("  Path       : {}\n", source.path));
        if let Some(size) = source.size_bytes {
            output.push_str(&format!("  Size       : {size} bytes\n"));
        }
        output.push('\n');
    }
    if let Some(dest) = &response.dest {
        output.push_str("Dest    :\n");
        output.push_str(&format!("  Mode       : {}\n", dest.mode));
        if let Some(path) = &dest.path {
            output.push_str(&format!("  Path       : {path}\n"));
        }
        output.push_str(&format!("  Overwrite  : {}\n", dest.overwrite));
        output.push_str(&format!("  MkdirParents: {}\n", dest.mkdir_parents));
        if let Some(size) = dest.size_bytes {
            output.push_str(&format!("  Size       : {size} bytes\n"));
        }
        output.push('\n');
    }
    if let Some(result) = &response.result {
        output.push_str("Result  :\n");
        output.push_str(&format!(
            "  Downloaded : {}\n",
            if result.downloaded { "yes" } else { "no" }
        ));
        if result.planned {
            output.push_str("  Planned    : yes\n");
        }
        output.push_str(&format!(
            "  Returned   : {} ({})\n",
            if result.return_content { "yes" } else { "no" },
            result.return_encoding
        ));
        if result.verify_checksum {
            let state = match result.checksum_verified {
                Some(true) => "verified",
                Some(false) => "failed",
                None => "not checked",
            };
            output.push_str(&format!(
                "  Checksum   : {state} ({})\n",
                result.checksum_algorithm
            ));
        } else {
            output.push_str("  Checksum   : disabled\n");
        }
        if let Some(content) = &result.content {
            output.push_str("  Content    :\n");
            for line in content.lines() {
                output.push_str(&format!("    {line}\n"));
            }
        }
        output.push('\n');
    }
    if let Some(timing) = &response.timing {
        output.push_str("Timing  :\n");
        if let Some(ms) = timing.transfer_ms {
            output.push_str(&format!("  Transfer   : {ms} ms\n"));
        }
        output.push('\n');
    }
    push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}
