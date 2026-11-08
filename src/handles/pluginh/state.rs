//! `enable` and `disable`: the plugin enable state.
//!
//! The state of one scope is a `state.json`:
//!
//! ```json
//! {"enabled_plugins": {"aws": true},
//!  "changes": {"aws": {"enabled": true, "reason": "...", "changed_at": "..."}}}
//! ```
//!
//! User scope: `$XDG_STATE_HOME/resh/plugins/state.json` (directory 0700,
//! file 0600). System scope: `/var/lib/resh/plugins/state.json` (directory
//! 0755, file 0644, so that every user's `installed.list` can read it).
//! `installed.list` reports a plugin enabled from the user entry, or from
//! the system entry when the user scope has none. Other keys in the file
//! are kept as they are.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::common::{IN_USE, IO_ERROR, LOCKED, NOT_INSTALLED, PResult, PluginError};
use super::paths;
use super::plugin::store::PluginStore;
use super::plugin::types::{Actions, Envelope, TargetInfo};

/// Largest state file read.
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
/// How long enable/disable wait for another process's state update.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Enable state scope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scope {
    User,
    System,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scope::User => "user",
            Scope::System => "system",
        })
    }
}

/// Parsed arguments of enable and disable.
#[derive(Debug, Clone)]
pub struct SetEnabledOptions {
    pub scope: Scope,
    pub force: bool,
    pub dry_run: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Change {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub changed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginState {
    #[serde(default)]
    pub enabled_plugins: BTreeMap<String, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub changes: BTreeMap<String, Change>,
    /// Keys written by other versions, kept unchanged.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// The state directory of `scope`: (base, parts below it, directory mode,
/// file mode).
fn scope_dir(scope: Scope) -> PResult<(PathBuf, Vec<&'static str>, u32, u32)> {
    let loc = paths::locations()?;
    Ok(match scope {
        Scope::User => (loc.state, vec!["resh", "plugins"], 0o700, 0o600),
        Scope::System => (loc.system_state, vec!["resh", "plugins"], 0o755, 0o644),
    })
}

/// The `state.json` path of `scope`, whether or not it exists.
pub fn state_path(scope: Scope) -> PResult<PathBuf> {
    let (base, rel, _, _) = scope_dir(scope)?;
    Ok(rel.iter().fold(base, |p, c| p.join(c)).join("state.json"))
}

/// Reads the state of `scope`; empty when there is none yet.
pub fn load(scope: Scope) -> PResult<PluginState> {
    let (base, rel, _, _) = scope_dir(scope)?;
    let Some(dir) = paths::existing_dir(&base, &rel)? else {
        return Ok(PluginState::default());
    };
    match paths::read_file(&dir, "state.json", MAX_STATE_BYTES)? {
        None => Ok(PluginState::default()),
        Some(d) if d.iter().all(u8::is_ascii_whitespace) => Ok(PluginState::default()),
        Some(d) => serde_json::from_slice(&d).map_err(|e| {
            PluginError::failed(
                IO_ERROR,
                format!("{} is not valid: {e}", dir.join("state.json").display()),
            )
        }),
    }
}

/// Changes the state of `scope` under its lock: `f` gets the current state
/// and returns whether it changed it.
fn update(scope: Scope, f: impl FnOnce(&mut PluginState) -> bool) -> PResult<bool> {
    let (base, rel, dmode, fmode) = scope_dir(scope)?;
    let dir = paths::ensure_dir(&base, &rel, dmode)?;
    let _lock = paths::lock(&dir, "state.lock", Instant::now() + LOCK_WAIT)?.ok_or_else(|| {
        PluginError::failed(
            LOCKED,
            format!(
                "another process is changing {}; try again",
                dir.join("state.json").display()
            ),
        )
    })?;
    let mut state = load(scope)?;
    if !f(&mut state) {
        return Ok(false);
    }
    let data = serde_json::to_vec_pretty(&state)
        .map_err(|e| PluginError::failed(IO_ERROR, format!("cannot encode the state: {e}")))?;
    paths::write_file_atomic(&dir, "state.json", &data, fmode)?;
    Ok(true)
}

/// Whether each plugin is enabled: the user entry, else the system entry.
pub fn effective_enabled() -> (BTreeMap<String, bool>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut out = BTreeMap::new();
    for scope in [Scope::System, Scope::User] {
        match load(scope) {
            Ok(s) => out.extend(s.enabled_plugins),
            Err(e) => warnings.push(format!(
                "cannot read the {scope} enable state: {}",
                e.message
            )),
        }
    }
    (out, warnings)
}

/// Removes the user-scope entry of `id` (`remove purge=true`). True when
/// there was one.
pub fn forget_user_entry(id: &str) -> PResult<bool> {
    let (base, rel, _, _) = scope_dir(Scope::User)?;
    if paths::existing_dir(&base, &rel)?.is_none() {
        return Ok(false);
    }
    update(Scope::User, |s| {
        let a = s.enabled_plugins.remove(id).is_some();
        let b = s.changes.remove(id).is_some();
        a || b
    })
}

/// The finished envelope and, on failure, the error it reports.
pub struct Outcome {
    pub envelope: Envelope,
    pub error: Option<PluginError>,
}

/// Runs enable (`enabled` true) or disable for plugin `id`.
pub fn set_enabled(id: &str, enabled: bool, opts: &SetEnabledOptions) -> Outcome {
    let op = if enabled {
        "plugin.enable"
    } else {
        "plugin.disable"
    };
    let mut actions = Actions::default();
    let mut target = TargetInfo {
        name: id.to_string(),
        requested_name: id.to_string(),
        install_root: PluginStore::default_root()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ..Default::default()
    };
    let mut result =
        json!({ "installed": false, "enabled": null, "scope": opts.scope.to_string() });
    let res = run(id, enabled, opts, &mut actions, &mut target, &mut result);
    let mut args = json!({
        "scope": opts.scope.to_string(),
        "force": opts.force,
        "dry_run": opts.dry_run,
    });
    if let Some(r) = &opts.reason {
        args["reason"] = json!(r);
    }
    let error = res.err();
    Outcome {
        envelope: Envelope {
            op: op.to_string(),
            ok: error.is_none(),
            code: error.as_ref().map_or(0, |e| e.exit),
            target,
            args,
            actions: actions.0,
            result,
            warnings: vec![],
            error: error.as_ref().map(PluginError::json),
            ts: Utc::now().to_rfc3339(),
        },
        error,
    }
}

fn run(
    id: &str,
    enabled: bool,
    opts: &SetEnabledOptions,
    actions: &mut Actions,
    target: &mut TargetInfo,
    result: &mut serde_json::Value,
) -> PResult<()> {
    let verb = if enabled { "enable" } else { "disable" };
    // 1. The plugin must be installed.
    let store = PluginStore::open(false)?;
    let installed = match &store {
        Some(s) => s.installed(id)?,
        None => None,
    };
    let Some(meta) = installed else {
        actions.push("check", "verify plugin installation", false, None);
        return Err(PluginError::failed(
            NOT_INSTALLED,
            format!("plugin {id} is not installed"),
        ));
    };
    let store = store.expect("installed implies a store");
    actions.push(
        "check",
        "verify plugin installation",
        true,
        Some(json!({ "version": meta.version, "path": meta.install_path })),
    );
    target.version = Some(meta.version.clone());
    target.bin_path = meta.bin_path.clone();
    result["installed"] = json!(true);
    result["version"] = json!(meta.version);

    // 2. The current state of the scope.
    let path = state_path(opts.scope)?;
    let state = load(opts.scope).inspect_err(|e| {
        actions.push(
            "fs.read",
            "load plugin state",
            false,
            Some(json!({ "path": path.to_string_lossy(), "error": e.message })),
        )
    })?;
    actions.push(
        "fs.read",
        "load plugin state",
        true,
        Some(json!({ "path": path.to_string_lossy() })),
    );
    let was_enabled = state.enabled_plugins.get(id).copied().unwrap_or(false);
    result["was_enabled"] = json!(was_enabled);
    result["enabled"] = json!(was_enabled);
    result["changed"] = json!(false);
    // No entry counts as disabled.
    if was_enabled == enabled && !opts.force {
        actions.push(
            "state.change",
            format!("plugin already {verb}d"),
            true,
            Some(json!({ "change": "none" })),
        );
        return Ok(());
    }

    // 3. A running plugin is not disabled without force=true.
    if !enabled {
        let pids = store.running_processes(id, &super::common::Deadline::after_ms(10_000))?;
        if !pids.is_empty() {
            if !opts.force {
                actions.push(
                    "check",
                    "check if plugin is in use",
                    false,
                    Some(json!({ "pids": pids })),
                );
                return Err(PluginError::failed(
                    IN_USE,
                    format!(
                        "plugin {id} is running (process(es) {pids:?}); pass force=true to disable it anyway"
                    ),
                ));
            }
            actions.push(
                "check",
                "plugin in use but forced",
                true,
                Some(json!({ "pids": pids, "forced": true })),
            );
        } else {
            actions.push("check", "plugin not in use", true, None);
        }
    }

    // 4. Write the new state.
    if opts.dry_run {
        actions.push(
            "fs.write",
            format!("would {verb} plugin"),
            true,
            Some(json!({ "dry_run": true, "path": path.to_string_lossy() })),
        );
        return Ok(());
    }
    let change = Change {
        enabled,
        reason: opts.reason.clone(),
        changed_at: Utc::now().to_rfc3339(),
    };
    let written = update(opts.scope, |s| {
        s.enabled_plugins.insert(id.to_string(), enabled);
        s.changes.insert(id.to_string(), change);
        true
    })
    .inspect_err(|e| {
        actions.push(
            "fs.write",
            "save plugin state",
            false,
            Some(json!({ "path": path.to_string_lossy(), "error": e.message })),
        )
    })?;
    actions.push(
        "fs.write",
        format!("{verb}d plugin in {} scope", opts.scope),
        written,
        Some(json!({ "path": path.to_string_lossy(), "enabled": enabled, "was_enabled": was_enabled })),
    );
    result["enabled"] = json!(enabled);
    result["changed"] = json!(true);
    if let Some(r) = &opts.reason {
        result["reason"] = json!(r);
    }
    Ok(())
}
