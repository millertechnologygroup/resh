//! The local plugin store: `<XDG_DATA_HOME>/resh/plugins`.
//!
//! ```text
//! <store>/<id>/versions/<version>/   the installed files and metadata.json
//! <store>/<id>/current -> versions/<version>
//! <store>/.staging/<uuid>/           work area of one install (removed after)
//! <store>/.locks/<id>.lock           flock taken by install, update and remove
//! ```
//!
//! Only one version is kept: install and update build the new version in
//! staging, move it into place and switch `current` in one rename, then
//! delete the old version. A failure before the switch leaves the installed
//! version as it was.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use super::types::InstalledPlugin;
use crate::handles::pluginh::common::{
    Deadline, INSTALL_FAILED, IO_ERROR, PResult, PluginError, REMOVE_FAILED, UNSAFE_PATH, io_error,
};
use crate::handles::pluginh::paths;

/// Longest plugin id or version accepted as a store path component.
const MAX_COMPONENT_LEN: usize = 128;

/// Names that are not plugin ids.
const RESERVED_PLUGIN_IDS: &[&str] = &["locks"];

/// Largest metadata.json read.
const MAX_METADATA_BYTES: u64 = 1024 * 1024;

/// True if `value` is safe as exactly one store path component: 1-128 ASCII
/// characters from `[A-Za-z0-9._+-]`, starting with a letter or digit.
pub fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMPONENT_LEN
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Why `value` is not a safe component, for messages.
pub fn component_problem(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        Some("must not be empty")
    } else if value.len() > MAX_COMPONENT_LEN {
        Some("is longer than 128 characters")
    } else if !value.as_bytes()[0].is_ascii_alphanumeric() {
        Some("must start with a letter or digit")
    } else if !is_safe_component(value) {
        Some("may contain only letters, digits and . _ + -")
    } else {
        None
    }
}

/// Checks a plugin id (`plugin://<id>.<verb>`).
pub fn validate_plugin_id(id: &str) -> Result<(), String> {
    if let Some(p) = component_problem(id) {
        return Err(format!("invalid plugin id {id:?}: it {p}"));
    }
    if RESERVED_PLUGIN_IDS.contains(&id) {
        return Err(format!("invalid plugin id {id:?}: the name is reserved"));
    }
    Ok(())
}

/// Map a path taken from a plugin artifact to a relative path made only of
/// normal components. `.` components are dropped; an empty result (the
/// artifact root itself) is `None`. Absolute paths, `..` and prefixes are
/// rejected, never rewritten.
pub(crate) fn artifact_relative_path(path: &Path) -> Result<Option<PathBuf>, String> {
    let mut rel = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => rel.push(c),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "refusing artifact path {path:?}: it must stay inside the artifact"
                ));
            }
        }
    }
    Ok(if rel.as_os_str().is_empty() {
        None
    } else {
        Some(rel)
    })
}

/// Create `root/rel` one directory at a time. An existing component must be
/// a real directory; a symlink or any other file type is refused.
pub(crate) fn create_dirs_no_follow(root: &Path, rel: &Path) -> std::io::Result<()> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => cur.push(c),
            _ => return Err(std::io::Error::other(format!("unsafe path {rel:?}"))),
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "{cur:?} is a non-directory or a symlink"
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o755).create(&cur)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Create a new file without following a symlink at its final component.
pub(crate) fn create_new_no_follow(path: &Path, mode: u32) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
}

/// File mode for plugin files: 0755 if any execute bit is set, else 0644.
/// setuid, setgid, sticky and group/other write bits are never kept.
pub(crate) fn sanitized_mode(mode: u32) -> u32 {
    if mode & 0o111 != 0 { 0o755 } else { 0o644 }
}

fn install_failed(what: &str, e: &std::io::Error) -> PluginError {
    PluginError::failed(INSTALL_FAILED, format!("{what}: {e}"))
}

/// The work area of one install; removed when dropped.
pub struct Staging {
    pub dir: PathBuf,
}

impl Staging {
    /// Where the artifact is unpacked.
    pub fn payload(&self) -> PathBuf {
        self.dir.join("payload")
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The plugin store.
pub struct PluginStore {
    root: PathBuf,
}

impl PluginStore {
    /// The store, created when `create` is true; `None` when it does not
    /// exist and `create` is false.
    pub fn open(create: bool) -> PResult<Option<Self>> {
        let loc = paths::locations()?;
        let (base, rel) = loc.store();
        let root = if create {
            Some(paths::ensure_dir(&base, &rel, 0o755)?)
        } else {
            paths::existing_dir(&base, &rel)?
        };
        Ok(root.map(|root| Self { root }))
    }

    /// The store path, whether or not it exists.
    pub fn default_root() -> PResult<PathBuf> {
        let loc = paths::locations()?;
        let (base, rel) = loc.store();
        Ok(rel.iter().fold(base, |p, c| p.join(c)))
    }

    #[cfg(test)]
    pub fn at(root: &Path) -> Self {
        fs::create_dir_all(root).unwrap();
        Self {
            root: root.to_path_buf(),
        }
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn plugin_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn version_dir(&self, id: &str, version: &str) -> PathBuf {
        self.root.join(id).join("versions").join(version)
    }

    /// The ids of every plugin directory in the store, sorted.
    pub fn plugin_ids(&self) -> PResult<Vec<String>> {
        let entries = fs::read_dir(&self.root).map_err(|e| {
            io_error(
                &format!("cannot read the plugin store {}", self.root.display()),
                &e,
            )
        })?;
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error("cannot read the plugin store", &e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir && validate_plugin_id(&name).is_ok() {
                ids.push(name);
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// The installed version of `id`: `current` must be a link to
    /// `versions/<version>`. `None` when the plugin is not installed.
    pub fn current_version(&self, id: &str) -> PResult<Option<String>> {
        self.link_version(id, "current")
    }

    /// The previous version kept for `rollback`, when there is a valid one
    /// whose directory exists.
    pub fn previous_version(&self, id: &str) -> Option<String> {
        self.link_version(id, "previous")
            .ok()
            .flatten()
            .filter(|v| self.version_dir(id, v).is_dir())
    }

    /// Switches `current` to the previous version and records the replaced
    /// version as the new previous one. Returns (new current, new previous).
    pub fn rollback(&self, id: &str) -> PResult<(String, String)> {
        let pdir = paths::ensure_dir(&self.root, &[id], 0o755)?;
        let cur = self.current_version(id)?.ok_or_else(|| {
            PluginError::failed(
                crate::handles::pluginh::common::NOT_INSTALLED,
                format!("plugin {id} is not installed"),
            )
        })?;
        let prev = self.previous_version(id).ok_or_else(|| {
            PluginError::failed(
                crate::handles::pluginh::common::NO_PREVIOUS_VERSION,
                format!("plugin {id} has no previous version to roll back to"),
            )
        })?;
        set_link(&pdir, "previous", &cur)
            .map_err(|e| install_failed("cannot record the previous version", &e))?;
        set_link(&pdir, "current", &prev)
            .map_err(|e| install_failed("cannot activate the previous version", &e))?;
        Ok((prev, cur))
    }

    fn link_version(&self, id: &str, link_name: &str) -> PResult<Option<String>> {
        let dir = self.plugin_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
                return Err(PluginError::failed(
                    UNSAFE_PATH,
                    format!(
                        "{} is not a plugin directory (a symlink or a file)",
                        dir.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(&format!("cannot inspect {}", dir.display()), &e)),
        }
        let link = dir.join(link_name);
        let target = match fs::read_link(&link) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(PluginError::failed(
                    IO_ERROR,
                    format!("the plugin store entry {} is damaged: {e}", link.display()),
                ));
            }
        };
        let mut comps = target.components();
        let version = match (comps.next(), comps.next(), comps.next()) {
            (Some(Component::Normal(v)), Some(Component::Normal(ver)), None) if v == "versions" => {
                ver.to_string_lossy().into_owned()
            }
            _ => {
                return Err(PluginError::failed(
                    IO_ERROR,
                    format!(
                        "the plugin store entry {} is damaged: it points to {target:?}",
                        link.display()
                    ),
                ));
            }
        };
        if !is_safe_component(&version) {
            return Err(PluginError::failed(
                IO_ERROR,
                format!(
                    "the plugin store entry {} names an unsafe version",
                    link.display()
                ),
            ));
        }
        Ok(Some(version))
    }

    /// The metadata of the installed version of `id`. Paths are taken from
    /// the store, never trusted from the file.
    pub fn installed(&self, id: &str) -> PResult<Option<InstalledPlugin>> {
        let Some(version) = self.current_version(id)? else {
            return Ok(None);
        };
        let vdir = self.version_dir(id, &version);
        let damaged = |why: String| {
            PluginError::failed(
                IO_ERROR,
                format!("installed plugin {id} {version} is damaged: {why}"),
            )
        };
        match fs::symlink_metadata(&vdir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(damaged(format!("{} is not a directory", vdir.display()))),
            Err(e) => return Err(damaged(format!("{}: {e}", vdir.display()))),
        }
        let data = paths::read_file(&vdir, "metadata.json", MAX_METADATA_BYTES)?
            .ok_or_else(|| damaged("metadata.json is missing".into()))?;
        let mut meta: InstalledPlugin = serde_json::from_slice(&data)
            .map_err(|e| damaged(format!("metadata.json is not valid: {e}")))?;
        if meta.plugin_id != id || meta.version != version {
            return Err(damaged(format!(
                "metadata.json names {} {}",
                meta.plugin_id, meta.version
            )));
        }
        meta.install_path = vdir.to_string_lossy().into_owned();
        meta.bin_path = meta.bin_path.filter(|b| inside(Path::new(b), &vdir));
        Ok(Some(meta))
    }

    /// Takes the store lock of `id`, waiting until the deadline.
    pub fn lock(&self, id: &str, deadline: &Deadline) -> PResult<paths::FileLock> {
        let dir = paths::ensure_dir(&self.root, &[".locks"], 0o700)?;
        paths::lock(&dir, &format!("{id}.lock"), deadline.at)?
            .ok_or_else(|| deadline.error(&format!("waiting for another operation on plugin {id}")))
    }

    /// A new, empty staging directory.
    pub fn staging(&self) -> PResult<Staging> {
        let base = paths::ensure_dir(&self.root, &[".staging"], 0o700)?;
        let dir = base.join(uuid::Uuid::new_v4().simple().to_string());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| install_failed("cannot create the staging directory", &e))?;
        let staging = Staging { dir };
        fs::DirBuilder::new()
            .mode(0o755)
            .create(staging.payload())
            .map_err(|e| install_failed("cannot create the staging directory", &e))?;
        Ok(staging)
    }

    /// Moves the staged payload into `versions/<version>` and makes it the
    /// current version. Until `current` is switched, the old version stays
    /// installed; any failure before that restores it. Returns warnings for
    /// old versions that could not be deleted afterwards.
    pub fn commit(&self, id: &str, version: &str, staging: &Staging) -> PResult<Vec<String>> {
        let pdir = paths::ensure_dir(&self.root, &[id], 0o755)?;
        let versions = paths::ensure_dir(&self.root, &[id, "versions"], 0o755)?;
        let old_current = self.current_version(id).ok().flatten();
        let old_previous = self.previous_version(id);
        let target = versions.join(version);
        let parked = staging.dir.join("previous");
        let had_old = match fs::symlink_metadata(&target) {
            Ok(_) => {
                fs::rename(&target, &parked)
                    .map_err(|e| install_failed("cannot move the old version aside", &e))?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(install_failed("cannot inspect the version directory", &e)),
        };
        let restore = || {
            let _ = fs::remove_dir_all(&target);
            if had_old {
                let _ = fs::rename(&parked, &target);
            }
        };
        if let Err(e) = fs::rename(staging.payload(), &target) {
            restore();
            return Err(install_failed("cannot move the new version into place", &e));
        }
        // Switch `current` atomically: a new link renamed over the old one.
        if let Err(e) = set_link(&pdir, "current", version) {
            restore();
            return Err(install_failed("cannot activate the new version", &e));
        }
        // Keep exactly one previous version: the one that was current, or
        // (when the same version was reinstalled) the previous one.
        let mut warnings = Vec::new();
        let previous = match old_current {
            Some(o) if o != version => Some(o),
            _ => old_previous.filter(|p| p != version),
        };
        let linked = match &previous {
            Some(p) => set_link(&pdir, "previous", p),
            None => match fs::remove_file(pdir.join("previous")) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        };
        if let Err(e) = linked {
            warnings.push(format!("could not record the previous version: {e}"));
        }
        if let Ok(entries) = fs::read_dir(&versions) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name == version || previous.as_deref().is_some_and(|p| name == p) {
                    continue;
                }
                if let Err(e) = fs::remove_dir_all(entry.path()) {
                    warnings.push(format!(
                        "could not delete the old version {}: {e}",
                        entry.path().display()
                    ));
                }
            }
        }
        Ok(warnings)
    }

    /// Removes the whole plugin directory: it is first renamed into staging
    /// (so the plugin is gone at once), then deleted. Returns a warning when
    /// the renamed copy could not be deleted completely.
    pub fn remove(&self, id: &str) -> PResult<Vec<String>> {
        let dir = self.plugin_dir(id);
        let base = paths::ensure_dir(&self.root, &[".staging"], 0o700)?;
        let trash = base.join(format!("removed-{}", uuid::Uuid::new_v4().simple()));
        fs::rename(&dir, &trash).map_err(|e| {
            PluginError::failed(
                REMOVE_FAILED,
                format!("cannot remove {}: {e}", dir.display()),
            )
        })?;
        match fs::remove_dir_all(&trash) {
            Ok(()) => Ok(vec![]),
            Err(e) => Ok(vec![format!(
                "the plugin is removed, but deleting its files at {} failed: {e}",
                trash.display()
            )]),
        }
    }

    /// The ids of running processes that execute a file of plugin `id`.
    pub fn running_processes(&self, id: &str, deadline: &Deadline) -> PResult<Vec<u32>> {
        let dir = self.plugin_dir(id);
        // /proc/<pid>/exe holds the canonical path.
        let dir = fs::canonicalize(&dir).unwrap_or(dir);
        let mut pids = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return Ok(pids);
        };
        for entry in entries.flatten() {
            deadline.check("while checking for running plugin processes; nothing was removed")?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if let Ok(exe) = fs::read_link(entry.path().join("exe")) {
                let exe = exe.to_string_lossy();
                let exe = exe.trim_end_matches(" (deleted)");
                if Path::new(exe).starts_with(&dir) {
                    pids.push(pid);
                }
            }
        }
        Ok(pids)
    }
}

/// True if `path` is lexically inside `dir` (no `..`, no other root).
fn inside(path: &Path, dir: &Path) -> bool {
    path.strip_prefix(dir)
        .map(|rel| {
            rel.components().all(|c| matches!(c, Component::Normal(_)))
                && !rel.as_os_str().is_empty()
        })
        .unwrap_or(false)
}

/// Points `<dir>/<name>` at `versions/<version>` atomically (a new link
/// renamed over the old one).
fn set_link(dir: &Path, name: &str, version: &str) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}-{}", uuid::Uuid::new_v4().simple()));
    let r = std::os::unix::fs::symlink(Path::new("versions").join(version), &tmp)
        .and_then(|()| fs::rename(&tmp, dir.join(name)));
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

/// The plugin executable inside an installed version directory: the first
/// regular file of `bin/plugin`, `plugin`, `bin/<os>-<arch>/plugin`, a file
/// named like the plugin, then any executable regular file at the top level
/// (in name order).
pub fn find_binary(dir: &Path, id: &str) -> Option<PathBuf> {
    let regular = |p: &Path| {
        fs::symlink_metadata(p)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
    };
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    for p in [
        dir.join("bin").join("plugin"),
        dir.join("plugin"),
        dir.join("bin").join(&platform).join("plugin"),
        dir.join(id),
    ] {
        if regular(&p) {
            return Some(p);
        }
    }
    let mut names: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            fs::symlink_metadata(p)
                .map(|m| m.file_type().is_file() && m.mode() & 0o111 != 0)
                .unwrap_or(false)
        })
        .collect();
    names.sort();
    names.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn valid_components_are_accepted() {
        for id in [
            "aws",
            "my-helper",
            "security-scanner",
            "demo",
            "Plugin_2",
            "a",
        ] {
            validate_plugin_id(id).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        for v in [
            "1.0.0",
            "0.1.0",
            "local",
            "unknown",
            "v2.0.0-rc.1",
            "1.0.0+build.5",
            "2024.10.16",
            "1.2.3-beta_1",
        ] {
            assert!(is_safe_component(v), "{v}");
        }
    }

    #[test]
    fn unsafe_components_are_rejected() {
        let long = "a".repeat(MAX_COMPONENT_LEN + 1);
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "../../../../.ssh",
            "/etc",
            "/",
            "a/b",
            "a\\b",
            "..\\x",
            ".staging",
            ".hidden",
            "-rf",
            "+x",
            "%2e%2e",
            "%2fetc",
            "a\0b",
            "C:x",
            "a b",
            "a\nb",
            "~",
            "~root",
            "é",
            "a@1.0",
            long.as_str(),
        ] {
            assert!(!is_safe_component(bad), "{bad:?} accepted");
            assert!(component_problem(bad).is_some(), "{bad:?}");
            assert!(validate_plugin_id(bad).is_err(), "{bad:?} accepted as id");
        }
        assert!(validate_plugin_id("locks").is_err());
    }

    fn staged(store: &PluginStore, file: &str) -> Staging {
        let s = store.staging().unwrap();
        fs::write(s.payload().join(file), b"#!/bin/sh\n").unwrap();
        s
    }

    #[test]
    fn commit_switches_versions_and_keeps_only_the_current_one() {
        let t = TempDir::new().unwrap();
        let store = PluginStore::at(&t.path().join("plugins"));
        assert_eq!(store.current_version("demo").unwrap(), None);
        let s = staged(&store, "one");
        store.commit("demo", "1.0.0", &s).unwrap();
        drop(s);
        assert_eq!(
            store.current_version("demo").unwrap().as_deref(),
            Some("1.0.0")
        );
        let s = staged(&store, "two");
        store.commit("demo", "1.1.0", &s).unwrap();
        drop(s);
        assert_eq!(
            store.current_version("demo").unwrap().as_deref(),
            Some("1.1.0")
        );
        let versions: Vec<_> = fs::read_dir(store.plugin_dir("demo").join("versions"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        let mut versions = versions;
        versions.sort();
        assert_eq!(
            versions,
            vec!["1.0.0", "1.1.0"],
            "one previous version is kept"
        );
        assert_eq!(store.previous_version("demo").as_deref(), Some("1.0.0"));
        assert!(store.version_dir("demo", "1.1.0").join("two").is_file());
        // Reinstalling the same version replaces it in place.
        let s = staged(&store, "three");
        store.commit("demo", "1.1.0", &s).unwrap();
        drop(s);
        assert!(store.version_dir("demo", "1.1.0").join("three").is_file());
        assert!(!store.version_dir("demo", "1.1.0").join("two").exists());
        // Staging is cleaned up.
        assert_eq!(
            fs::read_dir(store.root().join(".staging")).unwrap().count(),
            0
        );
        assert_eq!(store.plugin_ids().unwrap(), vec!["demo"]);
        store.remove("demo").unwrap();
        assert!(!store.plugin_dir("demo").exists());
        assert_eq!(store.current_version("demo").unwrap(), None);
    }

    #[test]
    fn damaged_or_planted_entries_are_refused() {
        let t = TempDir::new().unwrap();
        let store = PluginStore::at(&t.path().join("plugins"));
        let victim = t.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep"), b"x").unwrap();
        // A symlinked plugin directory is never followed.
        symlink(&victim, store.plugin_dir("demo")).unwrap();
        assert_eq!(store.current_version("demo").unwrap_err().code, UNSAFE_PATH);
        assert!(store.commit("demo", "1.0.0", &staged(&store, "p")).is_err());
        assert!(victim.join("keep").exists());
        assert_eq!(fs::read_dir(&victim).unwrap().count(), 1);
        fs::remove_file(store.plugin_dir("demo")).unwrap();
        // A current link that escapes versions/ is damage, not a version.
        fs::create_dir(store.plugin_dir("demo")).unwrap();
        symlink("../../victim", store.plugin_dir("demo").join("current")).unwrap();
        assert_eq!(store.current_version("demo").unwrap_err().code, IO_ERROR);
        fs::remove_file(store.plugin_dir("demo").join("current")).unwrap();
        symlink("versions/..", store.plugin_dir("demo").join("current")).unwrap();
        assert!(store.current_version("demo").is_err());
    }

    #[test]
    fn metadata_paths_are_not_trusted() {
        let t = TempDir::new().unwrap();
        let store = PluginStore::at(&t.path().join("plugins"));
        let s = store.staging().unwrap();
        let meta = InstalledPlugin {
            plugin_id: "demo".into(),
            version: "1.0.0".into(),
            install_path: "/etc".into(),
            bin_path: Some("/etc/passwd".into()),
            installed_at: "x".into(),
            updated_at: None,
            source: "file".into(),
            sha256: None,
        };
        fs::write(
            s.payload().join("metadata.json"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        store.commit("demo", "1.0.0", &s).unwrap();
        let m = store.installed("demo").unwrap().unwrap();
        assert_eq!(m.bin_path, None);
        assert_eq!(
            Path::new(&m.install_path),
            store.version_dir("demo", "1.0.0")
        );
    }

    #[test]
    fn binary_is_found_in_the_documented_order() {
        let t = TempDir::new().unwrap();
        let d = t.path();
        assert_eq!(find_binary(d, "x"), None);
        fs::write(d.join("README"), b"x").unwrap();
        assert_eq!(find_binary(d, "x"), None);
        fs::write(d.join("x"), b"x").unwrap();
        assert_eq!(find_binary(d, "x"), Some(d.join("x")));
        fs::write(d.join("plugin"), b"x").unwrap();
        assert_eq!(find_binary(d, "x"), Some(d.join("plugin")));
        fs::create_dir(d.join("bin")).unwrap();
        fs::write(d.join("bin").join("plugin"), b"x").unwrap();
        assert_eq!(find_binary(d, "x"), Some(d.join("bin").join("plugin")));
    }

    #[test]
    fn inside_is_lexical_and_strict() {
        let d = Path::new("/s/demo/versions/1");
        assert!(inside(Path::new("/s/demo/versions/1/bin/plugin"), d));
        assert!(!inside(Path::new("/s/demo/versions/1"), d));
        assert!(!inside(Path::new("/s/demo/versions/1/../../x"), d));
        assert!(!inside(Path::new("/etc/passwd"), d));
    }
}
