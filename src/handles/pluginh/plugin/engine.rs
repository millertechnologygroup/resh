//! `install`, `update` and `remove`.
//!
//! Integrity rules (plugin.md, section 2): registry artifacts are checked
//! against the registry's SHA-256 before anything is unpacked; `source=url`
//! needs an explicit `verify=none`; a local `source=file` artifact has no
//! checksum. Every step runs against the verb's `timeout_ms` deadline; a
//! timeout before the new version is activated leaves the installed plugin
//! as it was.

use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use chrono::Utc;
use serde_json::json;

use super::registry::{resolve, sha256_hex};
use super::store::{
    PluginStore, artifact_relative_path, create_dirs_no_follow, create_new_no_follow, find_binary,
    sanitized_mode,
};
use super::types::{
    Actions, ArtifactCandidate, Envelope, InstalledPlugin, Mode, PlanDecision, PluginOpArgs,
    SourceSpec, TargetInfo, VerifyMode,
};
use crate::handles::pluginh::common::{
    DOWNGRADE_REFUSED, Deadline, EXTRACT_FAILED, IN_USE, INSTALL_FAILED, NO_UPDATE_AVAILABLE,
    NOT_INSTALLED, PResult, PluginError, REMOVE_FAILED, VERIFY_FAILED, compare_versions, io_error,
};
use crate::handles::pluginh::net::Fetcher;
use crate::handles::pluginh::paths;

/// Largest artifact downloaded or read (512 MiB).
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
/// Largest total size of the files unpacked from one artifact (2 GiB).
pub const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Most entries in one `.tar.gz` artifact.
pub const MAX_ENTRIES: u64 = 100_000;

/// The finished envelope and, on failure, the error it reports.
pub struct Outcome {
    pub envelope: Envelope,
    pub error: Option<PluginError>,
}

struct Ctx {
    actions: Actions,
    warnings: Vec<String>,
    target: TargetInfo,
    result: serde_json::Value,
}

/// Runs install, update or remove and builds its envelope.
pub fn run(args: &PluginOpArgs) -> Outcome {
    let deadline = Deadline::after_ms(args.timeout_ms);
    let install_root = PluginStore::default_root()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut ctx = Ctx {
        actions: Actions::default(),
        warnings: Vec::new(),
        target: TargetInfo {
            name: args.plugin_id.clone(),
            requested_name: args.plugin_id.clone(),
            version: None,
            install_root,
            bin_path: None,
        },
        result: json!({}),
    };
    let res = match args.mode {
        Mode::Install | Mode::Update => install_or_update(args, &deadline, &mut ctx),
        Mode::Remove => remove(args, &deadline, &mut ctx),
    };
    let (op, verb_args) = match args.mode {
        Mode::Install => ("plugin.install", install_args(args)),
        Mode::Update => ("plugin.update", update_args(args)),
        Mode::Remove => (
            "plugin.remove",
            json!({
                "force": args.force,
                "purge": args.purge,
                "dry_run": args.dry_run,
                "timeout_ms": args.timeout_ms,
            }),
        ),
    };
    let error = res.err();
    Outcome {
        envelope: Envelope {
            op: op.to_string(),
            ok: error.is_none(),
            code: error.as_ref().map_or(0, |e| e.exit),
            target: ctx.target,
            args: verb_args,
            actions: ctx.actions.0,
            result: ctx.result,
            warnings: ctx.warnings,
            error: error.as_ref().map(PluginError::json),
            ts: Utc::now().to_rfc3339(),
        },
        error,
    }
}

fn source_args(args: &PluginOpArgs, v: &mut serde_json::Value) {
    match &args.source {
        SourceSpec::Registry { url } => v["registry"] = json!(url.as_str()),
        SourceSpec::Url { url } => v["url"] = json!(url.as_str()),
        SourceSpec::File { path } => v["path"] = json!(path),
    }
    if let Some(ca) = &args.ca_file {
        v["ca_file"] = json!(ca.path);
    }
}

fn install_args(args: &PluginOpArgs) -> serde_json::Value {
    let mut v = json!({
        "source": args.source.kind(),
        "version": match &args.requested_version {
            super::types::RequestedVersion::Latest => "latest",
            super::types::RequestedVersion::Specific(v) => v.as_str(),
        },
        "verify": args.verify.as_str(),
        "force": args.force,
        "allow_downgrade": args.allow_downgrade,
        "dry_run": args.dry_run,
        "timeout_ms": args.timeout_ms,
    });
    source_args(args, &mut v);
    v
}

fn update_args(args: &PluginOpArgs) -> serde_json::Value {
    let mut v = json!({
        "verify": args.verify.as_str(),
        "strict": args.strict,
        "dry_run": args.dry_run,
        "timeout_ms": args.timeout_ms,
    });
    source_args(args, &mut v);
    v
}

fn not_installed(id: &str) -> PluginError {
    PluginError::failed(NOT_INSTALLED, format!("plugin {id} is not installed"))
}

fn installed_now(id: &str) -> PResult<Option<InstalledPlugin>> {
    match PluginStore::open(false)? {
        Some(store) => store.installed(id),
        None => Ok(None),
    }
}

/// What install or update does for `installed` and the resolved candidate.
fn plan(
    args: &PluginOpArgs,
    installed: Option<&InstalledPlugin>,
    cand: &ArtifactCandidate,
) -> PResult<PlanDecision> {
    let id = &args.plugin_id;
    let Some(inst) = installed else {
        return match args.mode {
            Mode::Update => Err(not_installed(id)),
            _ => Ok(PlanDecision::Install { from: None }),
        };
    };
    let from = Some(inst.version.clone());
    let order = compare_versions(&inst.version, &cand.version);
    if args.mode == Mode::Install {
        if inst.version == cand.version {
            return Ok(if args.force {
                PlanDecision::Install { from }
            } else {
                PlanDecision::NoOp {
                    reason: format!("plugin {id} {} is already installed", inst.version),
                }
            });
        }
        if order == Some(std::cmp::Ordering::Greater) && !(args.allow_downgrade || args.force) {
            return Err(PluginError::failed(
                DOWNGRADE_REFUSED,
                format!(
                    "plugin {id} {} is installed, which is newer than {}; pass \
                     allow_downgrade=true to install the older version",
                    inst.version, cand.version
                ),
            ));
        }
        return Ok(PlanDecision::Install { from });
    }
    // Update. A url artifact has no version to compare: it is always installed.
    if matches!(args.source, SourceSpec::Url { .. }) {
        return Ok(PlanDecision::Install { from });
    }
    let current = inst.version == cand.version
        || matches!(
            order,
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        );
    if !current {
        return Ok(PlanDecision::Install { from });
    }
    let reason = if inst.version == cand.version || order == Some(std::cmp::Ordering::Equal) {
        format!("plugin {id} {} is the newest version", inst.version)
    } else {
        format!(
            "plugin {id} {} is newer than the registry's newest version {}",
            inst.version, cand.version
        )
    };
    if args.strict {
        Err(PluginError::failed(NO_UPDATE_AVAILABLE, reason))
    } else {
        Ok(PlanDecision::NoOp { reason })
    }
}

fn install_or_update(args: &PluginOpArgs, deadline: &Deadline, ctx: &mut Ctx) -> PResult<()> {
    let id = args.plugin_id.as_str();
    let installed = installed_now(id).inspect_err(|e| {
        ctx.actions.push(
            "check_installed",
            format!("cannot read the plugin store: {}", e.message),
            false,
            None,
        )
    })?;
    match &installed {
        Some(m) => ctx.actions.push(
            "check_installed",
            format!("Plugin installed: version {}", m.version),
            true,
            Some(json!({ "version": m.version })),
        ),
        None => ctx
            .actions
            .push("check_installed", "Plugin not installed", true, None),
    }
    if args.mode == Mode::Update && installed.is_none() {
        return Err(not_installed(id));
    }
    if let Some(m) = &installed {
        ctx.target.version = Some(m.version.clone());
        ctx.target.bin_path = m.bin_path.clone();
    }

    let fetcher = match args.source {
        SourceSpec::File { .. } => None,
        _ => Some(Fetcher::new(args.ca_file.as_ref(), *deadline)?),
    };
    let cand = resolve(
        id,
        &args.source,
        &args.requested_version,
        args.verify,
        fetcher.as_ref(),
    )
    .inspect_err(|e| {
        ctx.actions.push(
            "resolve",
            format!("Failed to resolve plugin: {}", e.message),
            false,
            None,
        )
    })?;
    ctx.actions.push(
        "resolve",
        format!("Resolved plugin version: {}", cand.version),
        true,
        Some(json!({ "version": cand.version })),
    );

    let from = match plan(args, installed.as_ref(), &cand)? {
        PlanDecision::NoOp { reason } => {
            ctx.actions
                .push("install", "noop", true, Some(json!({ "reason": reason })));
            ctx.result = json!({
                "installed": installed.is_some(),
                "changed": false,
                "version": installed.as_ref().map(|m| m.version.clone()),
            });
            return Ok(());
        }
        PlanDecision::Install { from } => from,
    };
    if args.dry_run {
        ctx.actions.push(
            "install",
            "Dry run: no changes made",
            true,
            Some(json!({
                "dry_run": true,
                "from_version": from,
                "to_version": cand.version,
                "artifact_kind": cand.kind,
                "artifact_url": cand.url.as_ref().map(|u| u.as_str()),
                "artifact_path": cand.path,
                "sha256": cand.sha256,
            })),
        );
        ctx.result = json!({
            "installed": installed.is_some(),
            "changed": false,
            "version": cand.version,
            "previous_version": from,
        });
        return Ok(());
    }

    let store = PluginStore::open(true)?.ok_or_else(|| {
        PluginError::failed(INSTALL_FAILED, "the plugin store could not be created")
    })?;
    let _lock = store.lock(id, deadline)?;
    // Another process may have changed the plugin while we resolved it.
    let installed = store.installed(id)?;
    let from = match plan(args, installed.as_ref(), &cand)? {
        PlanDecision::NoOp { reason } => {
            ctx.actions
                .push("install", "noop", true, Some(json!({ "reason": reason })));
            ctx.result = json!({
                "installed": true,
                "changed": false,
                "version": installed.as_ref().map(|m| m.version.clone()),
            });
            return Ok(());
        }
        PlanDecision::Install { from: f } => f.or(from),
    };

    let data = obtain(&cand, fetcher.as_ref(), deadline, ctx)?;
    verify(args, &cand, &data, ctx)?;
    let artifact_sha256 = sha256_hex(&data);

    let staging = store.staging()?;
    let payload = staging.payload();
    let what = "before the plugin was installed; nothing was installed";
    let extracted = if cand.kind == "tar.gz" {
        extract_tar_gz(&data, &payload, deadline)
    } else {
        write_binary(&data, &payload, id)
    };
    drop(data);
    match extracted {
        Ok(stats) => ctx.actions.push(
            "extract",
            format!("Unpacked {} file(s), {} bytes", stats.files, stats.bytes),
            true,
            Some(json!({ "files": stats.files, "bytes": stats.bytes })),
        ),
        Err(e) => {
            ctx.actions.push(
                "extract",
                format!("Extraction failed: {}", e.message),
                false,
                None,
            );
            return Err(if deadline.expired() {
                deadline.error(what)
            } else {
                e
            });
        }
    }

    let vdir = store.version_dir(id, &cand.version);
    let bin_path = find_binary(&payload, id)
        .and_then(|p| p.strip_prefix(&payload).ok().map(|rel| vdir.join(rel)))
        .map(|p| p.to_string_lossy().into_owned());
    let now = Utc::now().to_rfc3339();
    let meta = InstalledPlugin {
        plugin_id: id.to_string(),
        version: cand.version.clone(),
        install_path: vdir.to_string_lossy().into_owned(),
        bin_path: bin_path.clone(),
        installed_at: installed
            .as_ref()
            .map(|m| m.installed_at.clone())
            .unwrap_or_else(|| now.clone()),
        updated_at: Some(now),
        source: args.source.kind().to_string(),
        sha256: Some(artifact_sha256),
    };
    write_metadata(&payload, &meta)?;
    deadline.check(what)?;
    let warnings = store.commit(id, &cand.version, &staging)?;
    ctx.actions
        .push("install", "Plugin installed successfully", true, None);
    ctx.actions.push(
        "activate",
        "Plugin activated successfully",
        true,
        Some(json!({ "version": cand.version })),
    );
    drop(staging);
    ctx.actions
        .push("cleanup", "Staging cleanup completed", true, None);
    ctx.warnings.extend(warnings);
    ctx.target.version = Some(cand.version.clone());
    ctx.target.bin_path = bin_path;
    ctx.result = json!({
        "installed": true,
        "changed": true,
        "version": cand.version,
        "previous_version": from,
    });
    Ok(())
}

fn write_metadata(payload: &Path, meta: &InstalledPlugin) -> PResult<()> {
    let data = serde_json::to_vec_pretty(meta).map_err(|e| {
        PluginError::failed(INSTALL_FAILED, format!("cannot encode metadata.json: {e}"))
    })?;
    let path = payload.join("metadata.json");
    // A metadata.json shipped in the artifact is replaced by resh's own.
    if fs::symlink_metadata(&path).is_ok() {
        fs::remove_file(&path).map_err(|e| {
            PluginError::failed(INSTALL_FAILED, format!("cannot write metadata.json: {e}"))
        })?;
    }
    let mut f = create_new_no_follow(&path, 0o644).map_err(|e| {
        PluginError::failed(INSTALL_FAILED, format!("cannot write metadata.json: {e}"))
    })?;
    std::io::Write::write_all(&mut f, &data).map_err(|e| {
        PluginError::failed(INSTALL_FAILED, format!("cannot write metadata.json: {e}"))
    })
}

/// Downloads or reads the artifact.
fn obtain(
    cand: &ArtifactCandidate,
    fetcher: Option<&Fetcher>,
    deadline: &Deadline,
    ctx: &mut Ctx,
) -> PResult<Vec<u8>> {
    if let (Some(url), Some(fetcher)) = (&cand.url, fetcher) {
        let res = fetcher.get(url, MAX_ARTIFACT_BYTES, "the plugin artifact");
        match &res {
            Ok(d) => ctx.actions.push(
                "download",
                format!("Downloaded artifact ({} bytes)", d.len()),
                true,
                Some(json!({ "url": url.as_str(), "bytes": d.len() })),
            ),
            Err(e) => ctx.actions.push(
                "download",
                format!("Download failed: {}", e.message),
                false,
                Some(json!({ "url": url.as_str() })),
            ),
        }
        return res.map_err(|e| {
            if e.exit == crate::core::status::exit::TIMEOUT {
                deadline.error("while downloading the artifact; nothing was installed")
            } else {
                e
            }
        });
    }
    let path = cand.path.as_deref().unwrap_or_default();
    let read = || -> PResult<Vec<u8>> {
        let f = fs::File::open(path).map_err(|e| io_error(&format!("cannot read {path}"), &e))?;
        let mut data = Vec::new();
        let mut f = DeadlineReader {
            inner: f.take(MAX_ARTIFACT_BYTES + 1),
            deadline: *deadline,
        };
        f.read_to_end(&mut data).map_err(|e| {
            if deadline.expired() {
                deadline.error("while reading the artifact; nothing was installed")
            } else {
                io_error(&format!("cannot read {path}"), &e)
            }
        })?;
        if data.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(PluginError::failed(
                EXTRACT_FAILED,
                format!("{path} is larger than the {MAX_ARTIFACT_BYTES}-byte artifact limit"),
            ));
        }
        Ok(data)
    };
    let res = read();
    match &res {
        Ok(d) => ctx.actions.push(
            "download",
            format!("Read artifact file ({} bytes)", d.len()),
            true,
            Some(json!({ "path": path, "bytes": d.len() })),
        ),
        Err(e) => ctx.actions.push(
            "download",
            format!("File read failed: {}", e.message),
            false,
            Some(json!({ "path": path })),
        ),
    }
    res
}

/// Checks the artifact against its trusted SHA-256 before it is unpacked.
fn verify(
    args: &PluginOpArgs,
    cand: &ArtifactCandidate,
    data: &[u8],
    ctx: &mut Ctx,
) -> PResult<()> {
    if args.verify == VerifyMode::None {
        ctx.actions.push(
            "verify",
            "Checksum not checked (verify=none): the artifact is installed unverified",
            true,
            None,
        );
        ctx.warnings.push(
            "verify=none: the artifact was not checked against a trusted checksum".to_string(),
        );
        return Ok(());
    }
    match (&args.source, &cand.sha256) {
        (SourceSpec::File { .. }, _) => {
            ctx.actions.push(
                "verify",
                "Local file source: no checksum to verify",
                true,
                None,
            );
            Ok(())
        }
        (_, Some(expected)) => {
            let actual = sha256_hex(data);
            if &actual == expected {
                ctx.actions.push(
                    "verify",
                    "Checksum verified successfully",
                    true,
                    Some(json!({ "sha256": expected })),
                );
                Ok(())
            } else {
                ctx.actions.push(
                    "verify",
                    "Checksum verification failed",
                    false,
                    Some(json!({ "expected_sha256": expected, "actual_sha256": actual })),
                );
                Err(PluginError::failed(
                    VERIFY_FAILED,
                    format!(
                        "the artifact's SHA-256 is {actual}, but the registry gives {expected}; \
                         nothing was installed"
                    ),
                ))
            }
        }
        (_, None) => {
            ctx.actions
                .push("verify", "No trusted checksum available", false, None);
            Err(PluginError::failed(
                VERIFY_FAILED,
                "no trusted SHA-256 for a remote artifact; refusing to install",
            ))
        }
    }
}

/// Fails reads once the deadline has passed.
struct DeadlineReader<R> {
    inner: R,
    deadline: Deadline,
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.deadline.expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the deadline passed",
            ));
        }
        self.inner.read(buf)
    }
}

pub(crate) struct ExtractStats {
    files: u64,
    bytes: u64,
}

fn extract_failed(msg: impl Into<String>) -> PluginError {
    PluginError::failed(EXTRACT_FAILED, msg)
}

/// Unpacks a `.tar.gz` artifact into the empty directory `dest`.
///
/// Plugin artifacts are untrusted. Only regular files and directories with
/// plain relative paths are accepted; symbolic links, hard links, device
/// nodes and FIFOs fail the whole extraction. Files are created with
/// `create_new` and `O_NOFOLLOW`, and their mode is reduced to 0644 or 0755.
/// Header data per member is limited as for the archive handle (1 MiB), and
/// the artifact may hold at most [`MAX_ENTRIES`] entries and
/// [`MAX_EXTRACTED_BYTES`] of file data.
pub(crate) fn extract_tar_gz(
    data: &[u8],
    dest: &Path,
    deadline: &Deadline,
) -> PResult<ExtractStats> {
    use crate::handles::filesystem::tar_limit::limited_archive;
    use flate2::read::GzDecoder;
    use tar::EntryType;

    let reader = DeadlineReader {
        inner: GzDecoder::new(Cursor::new(data)),
        deadline: *deadline,
    };
    let mut archive = limited_archive(reader);
    let entries = archive
        .entries()
        .map_err(|e| extract_failed(format!("cannot read the tar.gz artifact: {e}")))?;
    let mut stats = ExtractStats { files: 0, bytes: 0 };
    let mut count = 0u64;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| extract_failed(format!("cannot read the tar.gz artifact: {e}")))?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(extract_failed(format!(
                "the artifact has more than {MAX_ENTRIES} entries"
            )));
        }
        let raw_path = entry
            .path()
            .map_err(|e| extract_failed(format!("invalid entry path in the artifact: {e}")))?
            .into_owned();
        let Some(rel) = artifact_relative_path(&raw_path).map_err(extract_failed)? else {
            continue; // "." / "./": the destination itself
        };
        match entry.header().entry_type() {
            EntryType::Directory => {
                create_dirs_no_follow(dest, &rel)
                    .map_err(|e| extract_failed(format!("cannot create {rel:?}: {e}")))?;
            }
            EntryType::Regular | EntryType::Continuous => {
                if let Some(parent) = rel.parent() {
                    create_dirs_no_follow(dest, parent)
                        .map_err(|e| extract_failed(format!("cannot create {parent:?}: {e}")))?;
                }
                let mode = entry.header().mode().unwrap_or(0o644);
                let mut out = create_new_no_follow(&dest.join(&rel), sanitized_mode(mode))
                    .map_err(|e| {
                        extract_failed(format!("cannot create plugin file {rel:?}: {e}"))
                    })?;
                let budget = MAX_EXTRACTED_BYTES - stats.bytes;
                let n =
                    std::io::copy(&mut (&mut entry).take(budget + 1), &mut out).map_err(|e| {
                        extract_failed(format!("cannot write plugin file {rel:?}: {e}"))
                    })?;
                if n > budget {
                    return Err(extract_failed(format!(
                        "the artifact unpacks to more than {MAX_EXTRACTED_BYTES} bytes"
                    )));
                }
                stats.bytes += n;
                stats.files += 1;
            }
            EntryType::Symlink | EntryType::Link => {
                return Err(extract_failed(format!(
                    "refusing artifact entry {raw_path:?}: symbolic and hard links are not allowed in plugin artifacts"
                )));
            }
            other => {
                return Err(extract_failed(format!(
                    "refusing artifact entry {raw_path:?}: unsupported entry type {other:?}"
                )));
            }
        }
    }
    Ok(stats)
}

/// Installs a single-file artifact as `<dest>/<id>` with mode 0755.
fn write_binary(data: &[u8], dest: &Path, id: &str) -> PResult<ExtractStats> {
    let path = dest.join(id);
    let mut f = create_new_no_follow(&path, 0o755)
        .map_err(|e| extract_failed(format!("cannot write {}: {e}", path.display())))?;
    std::io::Write::write_all(&mut f, data)
        .map_err(|e| extract_failed(format!("cannot write {}: {e}", path.display())))?;
    Ok(ExtractStats {
        files: 1,
        bytes: data.len() as u64,
    })
}

fn remove(args: &PluginOpArgs, deadline: &Deadline, ctx: &mut Ctx) -> PResult<()> {
    let id = args.plugin_id.as_str();
    let Some(store) = PluginStore::open(false)? else {
        ctx.actions
            .push("check", "resolve_installation", false, None);
        return Err(not_installed(id));
    };
    let present = fs::symlink_metadata(store.plugin_dir(id)).is_ok();
    let installed = match store.installed(id) {
        Ok(m) => m,
        Err(e) if present && e.code == crate::handles::pluginh::common::IO_ERROR => {
            ctx.warnings
                .push(format!("removing a damaged plugin: {}", e.message));
            None
        }
        Err(e) => return Err(e),
    };
    if !present {
        ctx.actions
            .push("check", "resolve_installation", false, None);
        return Err(not_installed(id));
    }
    let version = installed.as_ref().map(|m| m.version.clone());
    ctx.target.version = version.clone();
    ctx.target.bin_path = installed.as_ref().and_then(|m| m.bin_path.clone());
    ctx.actions.push(
        "check",
        "resolve_installation",
        true,
        Some(json!({
            "version": version,
            "install_path": store.plugin_dir(id).to_string_lossy(),
        })),
    );

    let pids = store.running_processes(id, deadline)?;
    if pids.is_empty() {
        ctx.actions.push("check", "check_in_use", true, None);
    } else if args.force {
        ctx.actions.push(
            "check",
            "check_in_use",
            true,
            Some(json!({ "pids": pids, "forced": true })),
        );
    } else {
        ctx.actions.push(
            "check",
            "check_in_use",
            false,
            Some(json!({ "pids": pids })),
        );
        return Err(PluginError::failed(
            IN_USE,
            format!(
                "plugin {id} is in use by process(es) {pids:?}; pass force=true to remove it anyway"
            ),
        ));
    }

    let purge_dirs = if args.purge {
        purge_targets(id)?
    } else {
        Vec::new()
    };
    if args.dry_run {
        ctx.actions.push(
            "fs",
            "remove_plugin",
            true,
            Some(json!({ "dry_run": true, "path": store.plugin_dir(id).to_string_lossy() })),
        );
        if args.purge {
            ctx.actions.push(
                "fs",
                "purge_state",
                true,
                Some(json!({ "dry_run": true, "paths": purge_dirs })),
            );
        }
        ctx.result = json!({
            "removed": false,
            "purged": false,
            "installed": true,
            "previous_version": version,
        });
        return Ok(());
    }

    let _lock = store.lock(id, deadline)?;
    deadline.check("before the plugin was removed; nothing was removed")?;
    let warnings = store.remove(id).inspect_err(|e| {
        ctx.actions
            .push("fs", format!("remove_plugin: {}", e.message), false, None)
    })?;
    ctx.warnings.extend(warnings);
    ctx.actions.push(
        "fs",
        "remove_plugin",
        true,
        Some(json!({ "path": store.plugin_dir(id).to_string_lossy() })),
    );
    ctx.result = json!({
        "removed": true,
        "purged": false,
        "installed": false,
        "previous_version": version,
    });
    if args.purge {
        let mut purged = Vec::new();
        for p in &purge_dirs {
            fs::remove_dir_all(p).map_err(|e| {
                PluginError::failed(
                    REMOVE_FAILED,
                    format!("the plugin was removed, but purging {p} failed: {e}"),
                )
            })?;
            purged.push(p.clone());
        }
        let forgot = crate::handles::pluginh::state::forget_user_entry(id)?;
        ctx.actions.push(
            "fs",
            "purge_state",
            true,
            Some(json!({ "paths": purged, "state_entry_removed": forgot })),
        );
        ctx.result["purged"] = json!(true);
    }
    Ok(())
}

/// The plugin's own data directories that `purge=true` deletes:
/// `resh/plugins/<id>` under the XDG state, cache and config directories.
/// Each must be a real directory owned by the user; a symlink anywhere on
/// the way is refused.
fn purge_targets(id: &str) -> PResult<Vec<String>> {
    let loc = paths::locations()?;
    let mut out = Vec::new();
    for base in [&loc.state, &loc.cache, &loc.config] {
        let Some(parent) = paths::existing_dir(base, &["resh", "plugins"])? else {
            continue;
        };
        let p = parent.join(id);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {
                paths::existing_dir(&parent, &[id])?;
                out.push(p.to_string_lossy().into_owned());
            }
            Ok(m) if m.file_type().is_symlink() => {
                return Err(PluginError::failed(
                    crate::handles::pluginh::common::UNSAFE_PATH,
                    format!("refusing to purge {}: it is a symbolic link", p.display()),
                ));
            }
            // A file of the same name (state.json) is not plugin data.
            _ => {}
        }
    }
    Ok(out)
}
