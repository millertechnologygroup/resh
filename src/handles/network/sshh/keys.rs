//! `keys.list` and `key.add`: public key files on the remote host, read and
//! changed through a remote POSIX shell over the system ssh client.

use super::args::{ArgReader, check_known};
use super::conn::{
    ConnOptions, SshTarget, UserRule, check_remote_path, check_user, connection_error, parse_conn,
    quote_remote_path, run_error,
};
use super::runner::{Deadline, ProcessOutput, RunError, RunSpec, run_ssh_process};
use super::types::*;
use super::{Out, coded, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use base64::prelude::*;

pub const DEFAULT_MAX_KEYS: u64 = 1024;
pub const DEFAULT_MAX_BYTES: u64 = 1_048_576;
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 10_000;
pub const KEY_TYPES: &[&str] = &["rsa", "ecdsa", "ed25519", "dsa"];

// ------------------------------------------------------------ key lines --

/// One parsed public key line (`[options] type base64 [comment]`).
#[derive(Debug, Clone, PartialEq)]
pub struct KeyLine {
    pub options: Vec<String>,
    pub type_raw: String,
    pub blob: Vec<u8>,
    pub blob_b64: String,
    pub comment: Option<String>,
}

fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-")
}

/// Splits the leading authorized_keys options field (comma-separated,
/// double quotes protect spaces and commas).
fn split_options(line: &str) -> Result<(Vec<String>, &str), String> {
    let mut options = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                cur.push(c);
                quoted = !quoted;
            }
            ',' if !quoted => options.push(std::mem::take(&mut cur)),
            c if c.is_whitespace() && !quoted => {
                options.push(cur);
                return Ok((options, &line[i..]));
            }
            c => cur.push(c),
        }
    }
    Err(if quoted {
        "unterminated quote in the options".into()
    } else {
        "options without a key".into()
    })
}

/// Reads the length-prefixed string at `pos` of an SSH wire-format blob.
fn wire_string(blob: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len_bytes = blob.get(*pos..*pos + 4)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let start = *pos + 4;
    let data = blob.get(start..start.checked_add(len)?)?.to_vec();
    *pos = start + len;
    Some(data)
}

fn mpint_bits(v: &[u8]) -> u32 {
    let v: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
    match v.first() {
        None => 0,
        Some(first) => (v.len() as u32 - 1) * 8 + (8 - first.leading_zeros()),
    }
}

/// Parses and checks one key line: the blob must be valid base64 whose
/// embedded type matches the type field.
pub fn parse_key_line(line: &str) -> Result<KeyLine, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err("empty or comment line".into());
    }
    let first = line.split_whitespace().next().unwrap_or("");
    let (options, rest) = if is_key_type(first) {
        (Vec::new(), line)
    } else {
        split_options(line)?
    };
    let mut parts = rest.split_whitespace();
    let type_raw = parts.next().ok_or("missing key type")?.to_string();
    if !is_key_type(&type_raw) {
        return Err(format!("unknown key type {type_raw:?}"));
    }
    let blob_b64 = parts.next().ok_or("missing key data")?.to_string();
    let blob = BASE64_STANDARD
        .decode(&blob_b64)
        .map_err(|_| "key data is not valid base64".to_string())?;
    let mut pos = 0;
    let embedded = wire_string(&blob, &mut pos).ok_or("key data is truncated")?;
    if embedded != type_raw.as_bytes() {
        return Err(format!(
            "key data is a {} key, not {type_raw}",
            String::from_utf8_lossy(&embedded)
        ));
    }
    let comment: Vec<&str> = parts.collect();
    Ok(KeyLine {
        options,
        type_raw,
        blob,
        blob_b64,
        comment: (!comment.is_empty()).then(|| comment.join(" ")),
    })
}

/// `ssh-rsa` -> `rsa`, `ecdsa-sha2-nistp256` -> `ecdsa`, and so on.
pub fn normalize_key_type(type_raw: &str) -> String {
    let t = type_raw.trim_start_matches("sk-");
    if t.starts_with("ssh-rsa") || t.starts_with("rsa-") {
        "rsa".into()
    } else if t.starts_with("ssh-dss") {
        "dsa".into()
    } else if t.starts_with("ecdsa-") {
        "ecdsa".into()
    } else if t.starts_with("ssh-ed25519") {
        "ed25519".into()
    } else {
        type_raw.to_string()
    }
}

/// Key size in bits, from the curve name or the RSA/DSA modulus.
pub fn key_bits(k: &KeyLine) -> Option<u32> {
    let t = k.type_raw.as_str();
    if t.contains("nistp256") {
        return Some(256);
    }
    if t.contains("nistp384") {
        return Some(384);
    }
    if t.contains("nistp521") {
        return Some(521);
    }
    if t.contains("ed25519") {
        return Some(256);
    }
    let mut pos = 0;
    wire_string(&k.blob, &mut pos)?;
    match normalize_key_type(t).as_str() {
        "rsa" => {
            wire_string(&k.blob, &mut pos)?; // e
            Some(mpint_bits(&wire_string(&k.blob, &mut pos)?))
        }
        "dsa" => Some(mpint_bits(&wire_string(&k.blob, &mut pos)?)),
        _ => None,
    }
}

/// OpenSSH-style fingerprint: `SHA256:<base64>` or `MD5:<hex:pairs>`.
pub fn fingerprint(blob: &[u8], algorithm: &str) -> String {
    if algorithm == "md5" {
        let digest = md5::compute(blob);
        let hex: Vec<String> = digest.0.iter().map(|b| format!("{b:02x}")).collect();
        format!("MD5:{}", hex.join(":"))
    } else {
        use sha2::{Digest, Sha256};
        format!(
            "SHA256:{}",
            BASE64_STANDARD_NO_PAD.encode(Sha256::digest(blob))
        )
    }
}

/// A random marker that cannot appear in file content by accident.
fn nonce() -> String {
    format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}

fn timeout_text(deadline: &Deadline, step: &str, step_ms: u64, timeout_ms: Option<u64>) -> String {
    if deadline.expired() {
        format!("timeout_ms={} passed", timeout_ms.unwrap_or(0))
    } else {
        format!("{step}={step_ms} passed")
    }
}

fn check_paths(key: &str, paths: &[String]) -> Result<(), SshError> {
    for p in paths {
        check_remote_path(key, p)?;
    }
    Ok(())
}

fn default_authorized(user: &str) -> String {
    format!("~{user}/.ssh/authorized_keys")
}

// ------------------------------------------------------------ keys.list --

#[derive(Debug, Clone)]
pub struct KeysListOptions {
    pub conn: ConnOptions,
    pub scope: KeysScope,
    pub paths: Vec<String>,
    pub key_types: Vec<String>,
    pub fingerprint_algorithm: String,
    pub include_options: bool,
    pub include_raw_key: bool,
    pub max_keys: u64,
    pub max_bytes: u64,
    pub read_timeout_ms: u64,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

/// Refuses the scope options that do not belong to `scope`.
fn refuse_other_scopes(r: &ArgReader, scope: &str, keys: &[&str]) -> Result<(), SshError> {
    for key in keys {
        if r.has(key) {
            return Err(SshError::InvalidArgument(format!(
                "{key} is not used with scope={scope}"
            )));
        }
    }
    Ok(())
}

pub fn parse_list(r: &ArgReader, target: &SshTarget) -> Result<KeysListOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::Required)?;
    let scope = r.choice("scope", KeysScope::VALUES)?.unwrap_or_default();
    let paths = match scope {
        KeysScope::Authorized => {
            refuse_other_scopes(r, "authorized", &["host_key_paths", "custom_paths"])?;
            match (r.text("authorized_user")?, r.list("authorized_paths")?) {
                (Some(_), Some(_)) => {
                    return Err(SshError::InvalidArgument(
                        "give authorized_user or authorized_paths, not both".into(),
                    ));
                }
                (_, Some(paths)) => paths,
                (user, None) => {
                    let user = user.unwrap_or_else(|| conn.username.clone());
                    check_user("authorized_user", &user)?;
                    vec![
                        default_authorized(&user),
                        format!("~{user}/.ssh/authorized_keys2"),
                    ]
                }
            }
        }
        KeysScope::Host => {
            refuse_other_scopes(
                r,
                "host",
                &["authorized_user", "authorized_paths", "custom_paths"],
            )?;
            r.list("host_key_paths")?.unwrap_or_else(|| {
                ["rsa", "ecdsa", "ed25519", "dsa"]
                    .iter()
                    .map(|t| format!("/etc/ssh/ssh_host_{t}_key.pub"))
                    .collect()
            })
        }
        KeysScope::Custom => {
            refuse_other_scopes(
                r,
                "custom",
                &["authorized_user", "authorized_paths", "host_key_paths"],
            )?;
            r.list("custom_paths")?
                .ok_or(SshError::KeysListCustomPathsRequired)?
        }
    };
    check_paths("path", &paths)?;
    let key_types = match r.list("key_types")? {
        Some(types) => {
            for t in &types {
                if !KEY_TYPES.contains(&t.as_str()) {
                    return Err(SshError::InvalidArgument(format!(
                        "invalid key type {t:?} in key_types (expected rsa, ecdsa, ed25519, dsa)"
                    )));
                }
            }
            types
        }
        None => KEY_TYPES.iter().map(|s| s.to_string()).collect(),
    };
    let fingerprint_algorithm = r
        .choice(
            "fingerprint_algorithm",
            &[("sha256", "sha256"), ("md5", "md5")],
        )?
        .unwrap_or("sha256")
        .to_string();
    Ok(KeysListOptions {
        conn,
        scope,
        paths,
        key_types,
        fingerprint_algorithm,
        include_options: r.bool("include_options", true)?,
        include_raw_key: r.bool("include_raw_key", true)?,
        max_keys: r.u64_or("max_keys", DEFAULT_MAX_KEYS)?,
        max_bytes: r.u64_or("max_bytes", DEFAULT_MAX_BYTES)?,
        read_timeout_ms: r.u64_or("read_timeout_ms", DEFAULT_READ_TIMEOUT_MS)?,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// The remote script that reports each file and prints its content between
/// markers. A file larger than `max_bytes` is reported without content.
pub fn build_list_script(paths: &[String], max_bytes: u64, n: &str) -> String {
    let list: Vec<String> = paths.iter().map(|p| quote_remote_path(p)).collect();
    format!(
        "n={n}\nfor f in {}; do\n\
         if [ -e \"$f\" ] || [ -L \"$f\" ]; then\n\
         if [ -f \"$f\" ] && [ -r \"$f\" ]; then\n\
         s=$(wc -c < \"$f\") || s=x\n\
         if [ \"$s\" -gt {max_bytes} ] 2>/dev/null; then printf 'RESH-FILE %s big %s %s\\n' \"$n\" $s \"$f\"\n\
         else printf 'RESH-FILE %s ok %s %s\\n' \"$n\" $s \"$f\"; cat -- \"$f\"; printf '\\nRESH-END %s\\n' \"$n\"; fi\n\
         else printf 'RESH-FILE %s unreadable 0 %s\\n' \"$n\" \"$f\"; fi\n\
         else printf 'RESH-FILE %s missing 0 %s\\n' \"$n\" \"$f\"; fi\n\
         done",
        list.join(" ")
    )
}

/// One file as reported by the list script.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteFile {
    pub path: String,
    pub state: String,
    pub size: u64,
    pub content: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parses the output of [`build_list_script`].
pub fn parse_list_output(stdout: &[u8], n: &str) -> Result<Vec<RemoteFile>, String> {
    let header = format!("RESH-FILE {n} ");
    let end_marker = format!("\nRESH-END {n}\n");
    let mut files = Vec::new();
    let mut rest = stdout;
    while !rest.is_empty() {
        let line_end = rest
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("unexpected output from the remote host")?;
        let line = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        rest = &rest[line_end + 1..];
        let Some(fields) = line.strip_prefix(&header) else {
            return Err(format!("unexpected output from the remote host: {line:?}"));
        };
        let mut it = fields.splitn(3, ' ');
        let state = it.next().unwrap_or("").to_string();
        let size = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let path = it.next().unwrap_or("").to_string();
        let mut content = Vec::new();
        if state == "ok" {
            let end = find(rest, end_marker.as_bytes()).ok_or("truncated output")?;
            content = rest[..end].to_vec();
            rest = &rest[end + end_marker.len()..];
        }
        files.push(RemoteFile {
            path,
            state,
            size,
            content,
        });
    }
    Ok(files)
}

/// Turns one file's content into a report.
pub fn report_file(
    f: &RemoteFile,
    o: &KeysListOptions,
    next_index: &mut usize,
    total: &mut usize,
    matched: &mut usize,
    truncated: &mut bool,
) -> SshKeysFileReport {
    let mut report = SshKeysFileReport {
        path: f.path.clone(),
        exists: f.state != "missing",
        readable: f.state == "ok",
        size_bytes: (f.state == "ok" || f.state == "big").then_some(f.size),
        parse_errors: vec![],
        keys: vec![],
    };
    let text = String::from_utf8_lossy(&f.content);
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let k = match parse_key_line(trimmed) {
            Ok(k) => k,
            Err(e) => {
                report.parse_errors.push(format!("line {}: {e}", i + 1));
                continue;
            }
        };
        *total += 1;
        let normalized = normalize_key_type(&k.type_raw);
        if !o.key_types.contains(&normalized) {
            continue;
        }
        *matched += 1;
        if *next_index as u64 >= o.max_keys {
            *truncated = true;
            continue;
        }
        report.keys.push(SshKeyInfo {
            index: *next_index,
            source_line: i + 1,
            bits: key_bits(&k),
            fingerprint: fingerprint(&k.blob, &o.fingerprint_algorithm),
            fingerprint_algorithm: o.fingerprint_algorithm.clone(),
            type_normalized: normalized,
            type_raw: k.type_raw.clone(),
            comment: k.comment.clone(),
            options: if o.include_options { k.options } else { vec![] },
            raw_key: o
                .include_raw_key
                .then(|| format!("{} {}", k.type_raw, k.blob_b64)),
        });
        *next_index += 1;
    }
    report
}

pub fn run_list(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshKeysListResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: None,
        scope: KeysScope::default(),
        files: None,
        planned_files: None,
        summary: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshKeysListResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_list_text).map(|_| status)
    };
    let o = match check_known("keys.list", args).and_then(|_| parse_list(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.scope = o.scope;
    response.connection = Some(SshConnectionInfo::new(
        &o.conn.host,
        o.conn.port,
        &o.conn.username,
    ));
    if o.conn.known_hosts_mode == KnownHostsMode::Insecure {
        response
            .warnings
            .push("known_hosts_mode=insecure: host key verification is disabled".into());
    }
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    if o.dry_run {
        response.ok = true;
        response.planned_files = Some(o.paths.clone());
        response.summary = Some(SshKeysListSummary {
            total_keys: 0,
            matched_keys: 0,
            truncated: false,
        });
        response
            .warnings
            .push("Dry run: no SSH connection was made and no keys were read.".into());
        write_response(io, out.format, &response, format_list_text)?;
        return Ok(Status::ok());
    }

    let n = nonce();
    let deadline = Deadline::new(o.timeout_ms);
    let cmd = o.conn.command_line(
        &prep,
        &[],
        Some(&build_list_script(&o.paths, o.max_bytes, &n)),
        false,
    );
    let spec = RunSpec {
        max_stdout: o
            .max_bytes
            .saturating_mul(o.paths.len() as u64 + 1)
            .saturating_add(64 * 1024),
        kill_on_overflow: true,
        timeout: deadline.bound(o.read_timeout_ms),
        ..Default::default()
    };
    let output = match run_ssh_process(&cmd, &spec) {
        Ok(output) => output,
        Err(RunError::TooLarge) => {
            return fail(
                &mut response,
                io,
                SshError::KeysListRemoteReadFailed("the remote output was too large".into()),
            );
        }
        Err(e) => {
            let t = SshError::KeysListTimeout(timeout_text(
                &deadline,
                "read_timeout_ms",
                o.read_timeout_ms,
                o.timeout_ms,
            ));
            return fail(&mut response, io, run_error(e, t));
        }
    };
    if !output.success() {
        let e = connection_error(&cmd, &output).unwrap_or_else(|| {
            SshError::KeysListRemoteReadFailed(format!(
                "remote exit code {:?}: {}",
                output.exit_code,
                output.stderr_text()
            ))
        });
        return fail(&mut response, io, e);
    }
    let files = match parse_list_output(&output.stdout, &n) {
        Ok(f) => f,
        Err(e) => return fail(&mut response, io, SshError::KeysListRemoteReadFailed(e)),
    };
    let (mut index, mut total, mut matched, mut truncated) = (0, 0, 0, false);
    let reports: Vec<SshKeysFileReport> = files
        .iter()
        .map(|f| report_file(f, &o, &mut index, &mut total, &mut matched, &mut truncated))
        .collect();
    response.files = Some(reports);
    response.summary = Some(SshKeysListSummary {
        total_keys: total,
        matched_keys: matched,
        truncated,
    });
    if let Some(big) = files.iter().find(|f| f.state == "big") {
        return fail(
            &mut response,
            io,
            SshError::KeysListTooLarge(big.path.clone(), o.max_bytes),
        );
    }
    let unreadable: Vec<&str> = files
        .iter()
        .filter(|f| f.state == "unreadable")
        .map(|f| f.path.as_str())
        .collect();
    if !unreadable.is_empty() {
        return fail(
            &mut response,
            io,
            SshError::KeysListRemoteReadFailed(format!(
                "cannot read {} (the other files are reported)",
                unreadable.join(", ")
            )),
        );
    }
    response.ok = true;
    write_response(io, out.format, &response, format_list_text)?;
    Ok(Status::ok())
}

pub fn format_list_text(response: &SshKeysListResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Keys List\n=============\n\n");
    output.push_str(&format!("OK       : {}\n", response.ok));
    output.push_str(&format!("Dry Run  : {}\n", response.dry_run));
    output.push_str(&format!("Scope    : {:?}\n\n", response.scope));
    if let Some(conn) = &response.connection {
        output.push_str("Connection:\n");
        output.push_str(&format!("  Host    : {}\n", conn.host));
        output.push_str(&format!("  Port    : {}\n", conn.port));
        output.push_str(&format!("  User    : {}\n\n", conn.username));
    }
    if let Some(planned) = &response.planned_files {
        output.push_str("Planned Files:\n");
        for path in planned {
            output.push_str(&format!("  - {path}\n"));
        }
        output.push('\n');
    }
    if let Some(files) = &response.files {
        output.push_str("Files:\n");
        for f in files {
            output.push_str(&format!("  Path: {}\n", f.path));
            output.push_str(&format!("    Exists   : {}\n", f.exists));
            output.push_str(&format!("    Readable : {}\n", f.readable));
            if let Some(size) = f.size_bytes {
                output.push_str(&format!("    Size     : {size} bytes\n"));
            }
            output.push_str(&format!("    Keys     : {}\n", f.keys.len()));
            for err in &f.parse_errors {
                output.push_str(&format!("    Parse error: {err}\n"));
            }
            for key in &f.keys {
                output.push_str(&format!(
                    "      [{}] {} ({}) - {}\n",
                    key.index, key.type_normalized, key.type_raw, key.fingerprint
                ));
                if let Some(comment) = &key.comment {
                    output.push_str(&format!("          Comment: {comment}\n"));
                }
                if !key.options.is_empty() {
                    output.push_str(&format!("          Options: {}\n", key.options.join(", ")));
                }
            }
            output.push('\n');
        }
    }
    if let Some(summary) = &response.summary {
        output.push_str("Summary:\n");
        output.push_str(&format!("  Total Keys   : {}\n", summary.total_keys));
        output.push_str(&format!("  Matched Keys : {}\n", summary.matched_keys));
        output.push_str(&format!("  Truncated    : {}\n\n", summary.truncated));
    }
    super::transfer::push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}

// -------------------------------------------------------------- key.add --

#[derive(Debug, Clone)]
pub struct KeyAddOptions {
    pub conn: ConnOptions,
    pub scope: KeyAddScope,
    /// The file to change, as given (may start with `~user/`).
    pub path: String,
    /// The user whose authorized_keys is changed (scope=authorized without
    /// authorized_paths), for ownership when connecting as root.
    pub owner: Option<String>,
    pub key_line: String,
    pub key: KeyLine,
    pub on_duplicate: OnDuplicate,
    pub create_if_missing: bool,
    pub backup_existing: bool,
    pub backup_suffix: String,
    pub ensure_permissions: bool,
    pub file_mode: String,
    pub dir_mode: String,
    pub max_file_bytes: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

fn octal_mode(r: &ArgReader, key: &str, default: &str) -> Result<String, SshError> {
    let m = r.text(key)?.unwrap_or_else(|| default.to_string());
    let ok = m.len() == 4 && m.starts_with('0') && m.bytes().all(|b| (b'0'..=b'7').contains(&b));
    if !ok {
        return Err(SshError::InvalidArgument(format!(
            "invalid value for {key}: {m:?} (expected four octal digits such as {default})"
        )));
    }
    Ok(m)
}

fn single(key: &str, paths: Vec<String>) -> Result<String, SshError> {
    match <[String; 1]>::try_from(paths) {
        Ok([p]) => Ok(p),
        Err(_) => Err(SshError::InvalidArgument(format!(
            "{key} must name exactly one file for key.add"
        ))),
    }
}

/// The key line from `public_key` or the local file `public_key_path`.
fn load_public_key(r: &ArgReader) -> Result<String, SshError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Src {
        Inline,
        File,
    }
    let given = r.choice(
        "public_key_source",
        &[("inline", Src::Inline), ("file", Src::File)],
    )?;
    let inline = r.data("public_key", false)?;
    let path = r.text("public_key_path")?;
    let source = match (given, &inline, &path) {
        (_, Some(_), Some(_)) => {
            return Err(SshError::InvalidArgument(
                "give public_key or public_key_path, not both".into(),
            ));
        }
        (Some(Src::Inline), None, Some(_)) => {
            return Err(SshError::InvalidArgument(
                "public_key_source=inline uses public_key, not public_key_path".into(),
            ));
        }
        (Some(Src::File), Some(_), None) => {
            return Err(SshError::InvalidArgument(
                "public_key_source=file uses public_key_path, not public_key".into(),
            ));
        }
        (_, None, None) => return Err(SshError::KeyAddMissingPublicKey),
        (_, Some(_), None) => Src::Inline,
        (_, None, Some(_)) => Src::File,
    };
    let text = if source == Src::Inline {
        inline.unwrap_or_default()
    } else {
        let path = path.unwrap_or_default();
        std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SshError::KeyAddPublicKeyFileNotFound(path.clone())
            } else {
                SshError::KeyAddPublicKeyFileReadFailed(format!("{path}: {e}"))
            }
        })?
    };
    if text.contains("PRIVATE KEY") {
        return Err(SshError::KeyAddInvalidPublicKey(
            "this is a private key; give the .pub file".into(),
        ));
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    match lines.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err(SshError::KeyAddInvalidPublicKey("no key line found".into())),
        _ => Err(SshError::KeyAddInvalidPublicKey(
            "more than one key line; give exactly one key".into(),
        )),
    }
}

pub fn parse_add(r: &ArgReader, target: &SshTarget) -> Result<KeyAddOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::Required)?;
    let scope = r.choice("scope", KeyAddScope::VALUES)?.unwrap_or_default();
    let (path, owner) = match scope {
        KeyAddScope::Authorized => {
            refuse_other_scopes(r, "authorized", &["custom_paths"])?;
            match (r.text("authorized_user")?, r.list("authorized_paths")?) {
                (Some(_), Some(_)) => {
                    return Err(SshError::InvalidArgument(
                        "give authorized_user or authorized_paths, not both".into(),
                    ));
                }
                (_, Some(paths)) => (single("authorized_paths", paths)?, None),
                (user, None) => {
                    let user = user.unwrap_or_else(|| conn.username.clone());
                    check_user("authorized_user", &user)?;
                    (default_authorized(&user), Some(user))
                }
            }
        }
        KeyAddScope::Custom => {
            refuse_other_scopes(r, "custom", &["authorized_user", "authorized_paths"])?;
            let paths = r
                .list("custom_paths")?
                .ok_or(SshError::KeyAddCustomPathsRequired)?;
            (single("custom_paths", paths)?, None)
        }
    };
    check_remote_path("path", &path)?;
    if path.ends_with('/') {
        return Err(SshError::InvalidArgument(
            "the target path must name a file".into(),
        ));
    }
    let key_line = load_public_key(r)?;
    let key = parse_key_line(&key_line).map_err(SshError::KeyAddInvalidPublicKey)?;
    let backup_suffix = r.text("backup_suffix")?.unwrap_or_else(|| ".bak".into());
    if backup_suffix.contains('/') {
        return Err(SshError::InvalidArgument(
            "backup_suffix must not contain '/'".into(),
        ));
    }
    Ok(KeyAddOptions {
        conn,
        scope,
        path,
        owner,
        key_line,
        key,
        on_duplicate: r
            .choice("on_duplicate", OnDuplicate::VALUES)?
            .unwrap_or_default(),
        create_if_missing: r.bool("create_if_missing", true)?,
        backup_existing: r.bool("backup_existing", true)?,
        backup_suffix,
        ensure_permissions: r.bool("ensure_permissions", true)?,
        file_mode: octal_mode(r, "file_mode", "0600")?,
        dir_mode: octal_mode(r, "dir_mode", "0700")?,
        max_file_bytes: r.u64_or("max_file_bytes", DEFAULT_MAX_BYTES)?,
        read_timeout_ms: r.u64_or("read_timeout_ms", DEFAULT_READ_TIMEOUT_MS)?,
        write_timeout_ms: r.u64_or("write_timeout_ms", DEFAULT_WRITE_TIMEOUT_MS)?,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// What the read step found.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TargetState {
    pub path: String,
    pub remote_uid: Option<u32>,
    /// `missing`, `file`, `symlink`, `notfile`, `unreadable`, `big`.
    pub state: String,
    pub dir_exists: bool,
    pub size: u64,
    /// `cksum` output, the concurrency guard for the write step.
    pub cksum: String,
    /// Permission string from `ls -ln` and numeric owner.
    pub perms: String,
    pub uid: String,
    pub gid: String,
    pub content: Vec<u8>,
}

pub fn build_read_script(o: &KeyAddOptions, n: &str) -> String {
    let parent = std::path::Path::new(&o.path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".into());
    format!(
        "n={n}\nf={}\nd={}\n\
         printf 'RESH-PATH %s %s\\n' \"$n\" \"$f\"\n\
         printf 'RESH-UID %s %s\\n' \"$n\" \"$(id -u)\"\n\
         if [ -d \"$d\" ]; then dd=1; else dd=0; fi\n\
         if [ -L \"$f\" ]; then printf 'RESH-STATE %s symlink %s\\n' \"$n\" $dd; exit 0; fi\n\
         if [ ! -e \"$f\" ]; then printf 'RESH-STATE %s missing %s\\n' \"$n\" $dd; exit 0; fi\n\
         if [ ! -f \"$f\" ]; then printf 'RESH-STATE %s notfile %s\\n' \"$n\" $dd; exit 0; fi\n\
         if [ ! -r \"$f\" ]; then printf 'RESH-STATE %s unreadable %s\\n' \"$n\" $dd; exit 0; fi\n\
         s=$(wc -c < \"$f\") || exit 1\n\
         c=$(cksum < \"$f\") || exit 1\n\
         set -- $(ls -ldn -- \"$f\") || exit 1\n\
         if [ $s -gt {} ]; then printf 'RESH-STATE %s big %s %s\\n' \"$n\" $dd $s; exit 0; fi\n\
         printf 'RESH-STATE %s file %s %s %s %s %s %s %s\\n' \"$n\" $dd $s \"$1\" \"$3\" \"$4\" $c\n\
         cat -- \"$f\" || exit 1\n\
         printf '\\nRESH-END %s\\n' \"$n\"",
        quote_remote_path(&o.path),
        quote_remote_path(&parent),
        o.max_file_bytes
    )
}

pub fn parse_read_output(stdout: &[u8], n: &str) -> Result<TargetState, String> {
    let mut st = TargetState::default();
    let mut rest = stdout;
    let bad = || "unexpected output from the remote host".to_string();
    while !rest.is_empty() {
        let line_end = rest.iter().position(|b| *b == b'\n').ok_or_else(bad)?;
        let line = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        rest = &rest[line_end + 1..];
        if let Some(p) = line.strip_prefix(&format!("RESH-PATH {n} ")) {
            st.path = p.to_string();
        } else if let Some(u) = line.strip_prefix(&format!("RESH-UID {n} ")) {
            st.remote_uid = u.trim().parse().ok();
        } else if let Some(s) = line.strip_prefix(&format!("RESH-STATE {n} ")) {
            let f: Vec<&str> = s.split_whitespace().collect();
            st.state = f.first().copied().ok_or_else(bad)?.to_string();
            st.dir_exists = f.get(1) == Some(&"1");
            if st.state == "big" {
                st.size = f.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            if st.state == "file" {
                if f.len() < 8 {
                    return Err(bad());
                }
                st.size = f[2].parse().map_err(|_| bad())?;
                st.perms = f[3].to_string();
                st.uid = f[4].to_string();
                st.gid = f[5].to_string();
                st.cksum = format!("{} {}", f[6], f[7]);
                let end_marker = format!("\nRESH-END {n}\n");
                let end = find(rest, end_marker.as_bytes()).ok_or_else(bad)?;
                st.content = rest[..end].to_vec();
                rest = &rest[end + end_marker.len()..];
            }
        } else {
            return Err(bad());
        }
    }
    if st.state.is_empty() || st.path.is_empty() {
        return Err(bad());
    }
    Ok(st)
}

/// Octal permission bits from an `ls -l` mode string (`-rw-------`).
pub fn perms_to_octal(perms: &str) -> Option<String> {
    let c: Vec<char> = perms.chars().collect();
    if c.len() < 10 {
        return None;
    }
    let mut mode = 0u32;
    let bits = [
        (1, 'r', 0o400),
        (2, 'w', 0o200),
        (4, 'r', 0o040),
        (5, 'w', 0o020),
        (7, 'r', 0o004),
        (8, 'w', 0o002),
    ];
    for (i, ch, bit) in bits {
        if c[i] == ch {
            mode |= bit;
        }
    }
    for (i, x, s, bit, special) in [
        (3, 'x', 's', 0o100, 0o4000),
        (6, 'x', 's', 0o010, 0o2000),
        (9, 'x', 't', 0o001, 0o1000),
    ] {
        match c[i] {
            v if v == x => mode |= bit,
            v if v == s => mode |= bit | special,
            v if v == s.to_ascii_uppercase() => mode |= special,
            _ => {}
        }
    }
    Some(format!("{mode:04o}"))
}

/// The new file content and what changed: (content, status, duplicates).
pub fn plan_content(
    existing: &[u8],
    o: &KeyAddOptions,
) -> Result<(Option<Vec<u8>>, &'static str, usize), SshError> {
    let text = String::from_utf8_lossy(existing);
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let dup: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| parse_key_line(l).is_ok_and(|k| k.blob == o.key.blob))
        .map(|(i, _)| i)
        .collect();
    if !dup.is_empty() {
        match o.on_duplicate {
            OnDuplicate::Skip => return Ok((None, "already_present", dup.len())),
            OnDuplicate::Error => return Err(SshError::KeyAddDuplicate),
            OnDuplicate::Replace => {}
        }
    }
    let mut out = String::new();
    for (i, l) in lines.iter().enumerate() {
        if !dup.contains(&i) {
            out.push_str(l);
        }
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&o.key_line);
    out.push('\n');
    let status = if dup.is_empty() { "added" } else { "replaced" };
    Ok((Some(out.into_bytes()), status, dup.len()))
}

const W_FAILED: i32 = 30;
const W_MKDIR: i32 = 31;
const W_BACKUP: i32 = 32;
const W_CHANGED: i32 = 33;
const W_SYMLINK: i32 = 34;
const W_INCOMPLETE: i32 = 35;
const W_PERMS: i32 = 36;

/// The write step: guards against a concurrent change (`cksum` must still
/// match, or the file must still be missing), backs up, writes a private
/// temp file in the same directory and renames it over the target. A
/// symlink at the target is refused, never followed.
pub fn build_write_script(o: &KeyAddOptions, st: &TargetState, size: u64, backup: bool) -> String {
    let path = &st.path;
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| ".".into());
    let q = super::conn::shell_escape;
    let mut s = vec![
        format!("f={}", q(path)),
        format!("d={}", q(&dir)),
        format!("t=\"$d/.resh-key-add.{}\"", rand::random::<u32>()),
    ];
    let root = st.remote_uid == Some(0);
    // Ownership to set when root creates or replaces another user's file.
    let owner: Option<String> = if st.state == "file" {
        root.then(|| format!("{}:{}", st.uid, st.gid))
    } else {
        o.owner
            .as_ref()
            .filter(|u| root && u.as_str() != "root")
            .map(|u| format!("{u}:$(id -g {u})"))
    };
    if st.state == "missing" && !st.dir_exists {
        let mut mk = format!("mkdir -p -- \"$d\" && chmod {} -- \"$d\"", o.dir_mode);
        if let Some(own) = &owner {
            mk.push_str(&format!(" && chown {own} -- \"$d\""));
        }
        s.push(format!(
            "if [ ! -d \"$d\" ]; then {{ {mk}; }} || exit {W_MKDIR}; fi"
        ));
    }
    s.push(format!("if [ -L \"$f\" ]; then exit {W_SYMLINK}; fi"));
    if st.state == "missing" {
        s.push(format!("if [ -e \"$f\" ]; then exit {W_CHANGED}; fi"));
    } else {
        s.push(format!(
            "c=$(cksum < \"$f\") || exit {W_FAILED}; [ \"$c\" = {} ] || exit {W_CHANGED}",
            q(&st.cksum)
        ));
    }
    if backup {
        let b = format!("\"$f\"{}", q(&o.backup_suffix));
        s.push(format!(
            "rm -f -- {b} && cp -p -- \"$f\" {b} || exit {W_BACKUP}"
        ));
    }
    s.push(format!(
        "(umask 077; set -C; cat > \"$t\") || {{ rm -f -- \"$t\"; exit {W_FAILED}; }}"
    ));
    s.push(format!(
        "[ $(wc -c < \"$t\") -eq {size} ] || {{ rm -f -- \"$t\"; exit {W_INCOMPLETE}; }}"
    ));
    let mode = if st.state == "file" && !o.ensure_permissions {
        perms_to_octal(&st.perms).unwrap_or_else(|| o.file_mode.clone())
    } else {
        o.file_mode.clone()
    };
    let mut perms = format!("chmod {mode} -- \"$t\"");
    if let Some(own) = &owner {
        perms.push_str(&format!(" && chown {own} -- \"$t\""));
    }
    if o.ensure_permissions && st.dir_exists {
        perms.push_str(&format!(" && chmod {} -- \"$d\"", o.dir_mode));
    }
    s.push(format!(
        "{{ {perms}; }} || {{ rm -f -- \"$t\"; exit {W_PERMS}; }}"
    ));
    s.push(format!(
        "mv -f -- \"$t\" \"$f\" || {{ rm -f -- \"$t\"; exit {W_FAILED}; }}"
    ));
    s.join("\n")
}

fn write_error(code: Option<i32>, st: &TargetState, stderr: String) -> SshError {
    match code {
        Some(W_MKDIR) => SshError::KeyAddRemoteWriteFailed(format!(
            "cannot create the directory of {}: {stderr}",
            st.path
        )),
        Some(W_BACKUP) => SshError::KeyAddBackupFailed(stderr),
        Some(W_CHANGED) => SshError::KeyAddConcurrentChange,
        Some(W_SYMLINK) => SshError::KeyAddTargetIsSymlink(st.path.clone()),
        Some(W_INCOMPLETE) => SshError::KeyAddRemoteWriteFailed(
            "the remote side received fewer bytes than were sent".into(),
        ),
        Some(W_PERMS) => SshError::KeyAddPermissionsFailed(stderr),
        _ => SshError::KeyAddRemoteWriteFailed(if stderr.is_empty() {
            format!("remote exit code {code:?}")
        } else {
            stderr
        }),
    }
}

fn key_summary(o: &KeyAddOptions) -> SshKeySummary {
    SshKeySummary {
        type_normalized: normalize_key_type(&o.key.type_raw),
        type_raw: o.key.type_raw.clone(),
        fingerprint: fingerprint(&o.key.blob, "sha256"),
        fingerprint_algorithm: "sha256".into(),
        comment: o.key.comment.clone(),
    }
}

pub fn run_add(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshKeyAddResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: None,
        scope: KeyAddScope::default(),
        target_file: None,
        operation: None,
        key: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshKeyAddResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_add_text).map(|_| status)
    };
    let o = match check_known("key.add", args).and_then(|_| parse_add(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.scope = o.scope;
    response.connection = Some(SshConnectionInfo::new(
        &o.conn.host,
        o.conn.port,
        &o.conn.username,
    ));
    response.key = Some(key_summary(&o));
    response.target_file = Some(o.path.clone());
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    let mut op = SshKeyAddOperation {
        status: "dry_run".into(),
        on_duplicate: o.on_duplicate,
        duplicates_found: 0,
        created_file: false,
        backup_created: false,
        backup_file: None,
    };
    if o.dry_run {
        response.ok = true;
        response.operation = Some(op);
        response
            .warnings
            .push("Dry run: no SSH connection was made and no file was changed.".into());
        write_response(io, out.format, &response, format_add_text)?;
        return Ok(Status::ok());
    }

    let deadline = Deadline::new(o.timeout_ms);
    let n = nonce();
    let cmd = o
        .conn
        .command_line(&prep, &[], Some(&build_read_script(&o, &n)), false);
    let spec = RunSpec {
        max_stdout: o.max_file_bytes.saturating_add(64 * 1024),
        kill_on_overflow: true,
        timeout: deadline.bound(o.read_timeout_ms),
        ..Default::default()
    };
    let read_err = |e: RunError| match e {
        RunError::TooLarge => {
            SshError::KeyAddRemoteReadFailed("the remote output was too large".into())
        }
        e => run_error(
            e,
            SshError::KeyAddTimeout(format!(
                "{} while reading; nothing was changed",
                timeout_text(
                    &deadline,
                    "read_timeout_ms",
                    o.read_timeout_ms,
                    o.timeout_ms
                )
            )),
        ),
    };
    let output: ProcessOutput = match run_ssh_process(&cmd, &spec) {
        Ok(output) => output,
        Err(e) => return fail(&mut response, io, read_err(e)),
    };
    if !output.success() {
        let e = connection_error(&cmd, &output).unwrap_or_else(|| {
            SshError::KeyAddRemoteReadFailed(format!(
                "remote exit code {:?}: {}",
                output.exit_code,
                output.stderr_text()
            ))
        });
        return fail(&mut response, io, e);
    }
    let st = match parse_read_output(&output.stdout, &n) {
        Ok(st) => st,
        Err(e) => return fail(&mut response, io, SshError::KeyAddRemoteReadFailed(e)),
    };
    response.target_file = Some(st.path.clone());
    let existing = match st.state.as_str() {
        "file" => st.content.clone(),
        "missing" if o.create_if_missing => Vec::new(),
        "missing" => {
            return fail(
                &mut response,
                io,
                SshError::KeyAddTargetMissing(st.path.clone()),
            );
        }
        "symlink" => {
            return fail(
                &mut response,
                io,
                SshError::KeyAddTargetIsSymlink(st.path.clone()),
            );
        }
        "big" => {
            return fail(
                &mut response,
                io,
                SshError::KeyAddFileTooLarge(st.path.clone(), st.size, o.max_file_bytes),
            );
        }
        "notfile" => {
            return fail(
                &mut response,
                io,
                SshError::KeyAddRemoteWriteFailed(format!("{} is not a regular file", st.path)),
            );
        }
        _ => {
            return fail(
                &mut response,
                io,
                SshError::KeyAddRemoteReadFailed(format!("cannot read {}", st.path)),
            );
        }
    };
    let (content, status, dups) = match plan_content(&existing, &o) {
        Ok(v) => v,
        Err(e) => {
            op.duplicates_found = 1;
            response.operation = Some(SshKeyAddOperation {
                status: "error".into(),
                ..op
            });
            return fail(&mut response, io, e);
        }
    };
    op.duplicates_found = dups;
    op.status = status.into();
    let Some(content) = content else {
        response.ok = true;
        response.operation = Some(op);
        write_response(io, out.format, &response, format_add_text)?;
        return Ok(Status::ok());
    };
    let backup = o.backup_existing && st.state == "file";
    let script = build_write_script(&o, &st, content.len() as u64, backup);
    let cmd = o.conn.command_line(&prep, &[], Some(&script), false);
    let spec = RunSpec {
        stdin: Some(&content),
        max_stdout: 64 * 1024,
        timeout: deadline.bound(o.write_timeout_ms),
        ..Default::default()
    };
    let output = match run_ssh_process(&cmd, &spec) {
        Ok(output) => output,
        Err(e) => {
            let t = SshError::KeyAddTimeout(format!(
                "{} while writing; the file is either unchanged or fully updated (the change \
                 is a single rename)",
                timeout_text(
                    &deadline,
                    "write_timeout_ms",
                    o.write_timeout_ms,
                    o.timeout_ms
                )
            ));
            return fail(&mut response, io, run_error(e, t));
        }
    };
    if !output.success() {
        let e = connection_error(&cmd, &output)
            .unwrap_or_else(|| write_error(output.exit_code, &st, output.stderr_text()));
        response.operation = Some(SshKeyAddOperation {
            status: "error".into(),
            ..op
        });
        return fail(&mut response, io, e);
    }
    op.created_file = st.state == "missing";
    op.backup_created = backup;
    op.backup_file = backup.then(|| format!("{}{}", st.path, o.backup_suffix));
    response.ok = true;
    response.operation = Some(op);
    write_response(io, out.format, &response, format_add_text)?;
    Ok(Status::ok())
}

pub fn format_add_text(response: &SshKeyAddResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Key Add\n===========\n\n");
    output.push_str(&format!("OK       : {}\n", response.ok));
    output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));
    if let Some(conn) = &response.connection {
        output.push_str("Connection:\n");
        output.push_str(&format!("  Host    : {}\n", conn.host));
        output.push_str(&format!("  Port    : {}\n", conn.port));
        output.push_str(&format!("  User    : {}\n\n", conn.username));
    }
    output.push_str(&format!("Scope    : {}\n", response.scope.as_str()));
    if let Some(file) = &response.target_file {
        output.push_str(&format!("File     : {file}\n\n"));
    }
    if let Some(key) = &response.key {
        output.push_str("Key:\n");
        output.push_str(&format!(
            "  Type       : {} ({})\n",
            key.type_normalized, key.type_raw
        ));
        output.push_str(&format!("  Fingerprint: {}\n", key.fingerprint));
        if let Some(comment) = &key.comment {
            output.push_str(&format!("  Comment    : {comment}\n"));
        }
        output.push('\n');
    }
    if let Some(op) = &response.operation {
        output.push_str("Operation:\n");
        output.push_str(&format!("  Status         : {}\n", op.status));
        output.push_str(&format!(
            "  On Duplicate   : {}\n",
            op.on_duplicate.as_str()
        ));
        output.push_str(&format!("  Duplicates     : {}\n", op.duplicates_found));
        output.push_str(&format!(
            "  File Created   : {}\n",
            if op.created_file { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Backup Created : {}\n\n",
            if op.backup_created { "yes" } else { "no" }
        ));
    }
    super::transfer::push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEP31YpA0Imm4x6v+o1r0O2XM9fZkMEDQUNAn9WtLLqt bob@laptop";
    pub const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCUEhpO2JPXdV4Gm1Ftc0FS71xXGhAYaEboX5hxFOziEDKcWAOO/gGGB5nRy+FSBhIEiS+z2LwTyj/6NNg/nrM2owMGGDXJlbIBDEMHhMXRB0+VSTBPZR8rGv+r4xNTnB7aoGjg6uR8CFpTIbs7myfdlD9p58QqvrkFjUAYuhc3iKz8s6Q0299w292PyoIZVgdJyNSte1MZOhtgSLyTsaqItpNe379Z/lWFx7veYI0pypZuExA/xSKruzBJzePKYOtMbHx7u543B5Dw3WdI7yQfEshZj4iddbAwyQMs/mCDKKLtYhxSj9LjHo4lvnS4t/IKBDhbwk1iBEbkVhJKHJW3 rsa@x";

    #[test]
    fn key_lines_are_parsed_and_checked() {
        let k = parse_key_line(ED).unwrap();
        assert_eq!(k.type_raw, "ssh-ed25519");
        assert_eq!(k.comment.as_deref(), Some("bob@laptop"));
        assert_eq!(key_bits(&k), Some(256));
        assert_eq!(
            fingerprint(&k.blob, "sha256"),
            "SHA256:3xDjK+bg/gX0dncBKmABpUGbcOI6xx9mMC3MDjssIBU"
        );
        assert_eq!(
            fingerprint(&k.blob, "md5"),
            "MD5:86:20:e2:23:44:98:4f:41:67:02:65:97:9a:d2:2e:0b"
        );
        let r = parse_key_line(RSA).unwrap();
        assert_eq!(key_bits(&r), Some(2048));
        assert_eq!(
            fingerprint(&r.blob, "sha256"),
            "SHA256:M1nolz6tn2NXR7U1Fhtsx3aVyZf94/C4Oe2N9wuDQQo"
        );
        let with_opts = format!("from=\"10.0.0.1,10.0.0.2\",command=\"echo a b\" {ED}");
        let k2 = parse_key_line(&with_opts).unwrap();
        assert_eq!(
            k2.options,
            vec!["from=\"10.0.0.1,10.0.0.2\"", "command=\"echo a b\""]
        );
        assert_eq!(k2.blob, k.blob);
        assert!(
            parse_key_line(&ED.replace("ssh-ed25519 ", "ssh-rsa "))
                .unwrap_err()
                .contains("not ssh-rsa")
        );
        assert!(parse_key_line("ssh-ed25519 !!!").is_err());
        assert!(parse_key_line("hello world").is_err());
        assert!(parse_key_line("# comment").is_err());
        assert_eq!(normalize_key_type("ecdsa-sha2-nistp384"), "ecdsa");
        assert_eq!(normalize_key_type("sk-ssh-ed25519@openssh.com"), "ed25519");
        assert_eq!(normalize_key_type("rsa-sha2-512"), "rsa");
    }

    #[test]
    fn list_output_round_trip() {
        let out = b"RESH-FILE n1 ok 5 /home/a/.ssh/authorized_keys\nabcd\n\nRESH-END n1\nRESH-FILE n1 missing 0 /home/a/.ssh/authorized_keys2\nRESH-FILE n1 unreadable 0 /x y\n";
        let files = parse_list_output(out, "n1").unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].content, b"abcd\n");
        assert_eq!(files[1].state, "missing");
        assert_eq!(files[2].path, "/x y");
        assert!(parse_list_output(b"garbage\n", "n1").is_err());
        assert!(parse_list_output(b"RESH-FILE n1 ok 5 /a\nabc", "n1").is_err());
    }

    #[test]
    fn modes_from_ls() {
        assert_eq!(perms_to_octal("-rw-------").as_deref(), Some("0600"));
        assert_eq!(perms_to_octal("-rwsr-xr-t").as_deref(), Some("5755"));
        assert_eq!(perms_to_octal("-rw-r--r--.").as_deref(), Some("0644"));
        assert_eq!(perms_to_octal("short"), None);
    }
}
