use crate::core::process::AsyncBoundedOutput as _;
use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command as AsyncCommand;
use tokio::time::timeout;
use url::Url;
use which::which;

#[path = "pkg_args.rs"]
mod pkg_args;
#[path = "pkg_version.rs"]
mod version_cmp;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// Metadata for `resh pkg --help` and `resh pkg <verb> --help`.
static PKG_HELP: HandleHelp = HandleHelp {
    description: "The pkg handle installs, removes, updates, queries, and snapshots system \
        packages through the host's package manager, supporting apt, dnf, yum, pacman, apk, \
        and brew. Every verb requires an input argument holding one JSON object, whose \
        manager key names the backend or is auto to detect it. The URL host is a \
        free-form alias, such as pkg://system, that is echoed in the output.",
    usage: "resh pkg://<alias>.<verb> input=<json>",
    verbs: &[
        VerbHelp {
            name: "info",
            definition: "Reports details for named packages, such as installed and candidate \
                versions, summary, homepage, and repository.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.info input=<json>\n  \
                    <json> keys: manager, packages (both required; package names),\n  \
                    include_dependencies, include_reverse_deps, include_files,\n  \
                    include_repo (default true; false sets repository to null),\n  \
                    timeout_ms (default 5000), env\n  \
                    An unknown package is reported with found false and exit 1",
                example: "resh pkg://system.info 'input={\"manager\":\"apt\",\"packages\":[\"nginx\"]}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "backend": "pkg",
  "manager": "apt",
  "packages": [
    {
      "architecture": "amd64",
      "candidate_version": "1.24.0-2ubuntu7",
      "description": "Nginx is a web server and reverse proxy.",
      "found": true,
      "homepage": "https://nginx.org",
      "installed": true,
      "installed_version": "1.24.0-2ubuntu7",
      "license": null,
      "repository": "noble/main",
      "repository_url": "http://archive.ubuntu.com/ubuntu",
      "summary": "small, powerful, scalable web/proxy server"
    }
  ]
}

Shown for apt. Other managers fill different subsets of these fields."#,
                ),
            }),
        },
        VerbHelp {
            name: "search",
            definition: "Searches the package index by name or description and returns \
                paginated matches with versions and installed state.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.search input=<json>\n  \
                    <json> keys: manager, query (both required), search_in\n  \
                    (name|description|all), exact, case_sensitive, limit (default 50),\n  \
                    offset, include_installed, include_versions, include_repo,\n  \
                    timeout_ms (default 5000), extra_args, env",
                example: "resh pkg://system.search 'input={\"manager\":\"apt\",\"query\":\"nginx\",\"limit\":1}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "backend": "pkg",
  "case_sensitive": false,
  "exact": false,
  "limit": 1,
  "manager": "apt",
  "offset": 0,
  "query": "nginx",
  "results": [
    {
      "description": null,
      "homepage": "https://nginx.org",
      "installed": true,
      "name": "nginx",
      "repository": "noble/main",
      "repository_url": "http://archive.ubuntu.com/ubuntu",
      "score": 1.0,
      "summary": "small, powerful, scalable web/proxy server",
      "version": "1.24.0-2ubuntu7"
    }
  ],
  "search_in": [
    "name",
    "description"
  ],
  "total_matches": 12
}

Shown for apt."#,
                ),
            }),
        },
        VerbHelp {
            name: "list_installed",
            definition: "Lists installed packages with their versions, optionally filtered \
                by name prefix or substring and paginated.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.list_installed input=<json>\n  \
                    <json> keys: manager (required), filter, prefix, include_versions\n  \
                    (default true; false sets version to null), include_repo,\n  \
                    include_size, include_install_reason, limit (default 500), offset,\n  \
                    timeout_ms (default 600000), env",
                example: "resh pkg://system.list_installed 'input={\"manager\":\"apt\",\"prefix\":\"nginx\"}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "backend": "pkg",
  "limit": 500,
  "manager": "apt",
  "offset": 0,
  "results": [
    {
      "architecture": "amd64",
      "install_reason": null,
      "installed_size_bytes": null,
      "manager_specific": null,
      "name": "nginx",
      "repository": null,
      "version": "1.24.0-2ubuntu7"
    }
  ],
  "total_installed": 1
}

Shown for apt."#,
                ),
            }),
        },
        VerbHelp {
            name: "snapshot",
            definition: "Captures the installed package set as a pkg-lock/v1 lockfile in \
                JSON, YAML, or text form, along with parsed metadata.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.snapshot input=<json>\n  \
                    <json> keys: manager (required), scope (all|manual|dependency),\n  \
                    include_versions (exact|minimal|none; minimal records the\n  \
                    upstream version only), include_repo, include_arch,\n  \
                    include_install_reason, include_os_metadata, exclude_patterns\n  \
                    (shell-style globs), format (json|yaml|text), timeout_ms\n  \
                    (default 15000), env",
                example: "resh pkg://system.snapshot 'input={\"manager\":\"apt\",\"scope\":\"manual\"}'",
                example_output: Some(
                    r#"{
  "action": "snapshot",
  "alias": "system",
  "backend": "pkg",
  "format": "json",
  "lockfile": "{\n  \"lockfile_version\": \"pkg-lock/v1\",\n  ...\n}",
  "manager": "apt",
  "parsed": {
    "lockfile_version": "pkg-lock/v1",
    "manager": {
      "alias": "system",
      "name": "apt",
      "version": "apt 2.7.14 (amd64)"
    },
    "packages_count": 214,
    "platform": {
      "architecture": "x86_64",
      "kernel": "Linux 6.8.0-45-generic",
      "os_family": "debian",
      "os_name": "Ubuntu",
      "os_version": "24.04"
    },
    "scope": "manual"
  }
}

Shown for apt with the lockfile string shortened."#,
                ),
            }),
        },
        VerbHelp {
            name: "install",
            definition: "Installs packages, refreshing the package index first and skipping \
                packages that are already installed by default.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.install input=<json>\n  \
                    <json> keys: manager, packages (both required; each package is\n  \
                    {name, version}), update_cache, assume_yes, only_if_missing,\n  \
                    reinstall, upgrade, allow_downgrade (default false; a version older\n  \
                    than the installed one is refused without it), dry_run,\n  \
                    timeout_ms (default 600000), arch,\n  \
                    extra_args, env\n  \
                    version: apt, dnf, yum, apk; arch: apt, dnf, yum; elsewhere refused\n  \
                    A package source is not supported; a package with source is refused",
                example: "resh pkg://system.install 'input={\"manager\":\"apt\",\"packages\":[{\"name\":\"jq\"}]}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "backend": "pkg",
  "dry_run": false,
  "manager": "apt",
  "packages": [
    {
      "action": "installed",
      "from_cache": false,
      "installed_version": "1.7.1-3build1",
      "name": "jq",
      "requested_version": null
    }
  ],
  "summary": {
    "failed": 0,
    "installed": 1,
    "reinstalled": 0,
    "unchanged": 0,
    "upgraded": 0
  },
  "update_cache": true
}

Shown for apt. With dry_run true, the output lists commands and planned
actions instead."#,
                ),
            }),
        },
        VerbHelp {
            name: "remove",
            definition: "Removes packages, optionally purging configuration and removing \
                unused dependencies.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.remove input=<json>\n  \
                    <json> keys: manager, packages (both required), purge, recursive,\n  \
                    assume_yes, only_if_installed, fail_if_missing, dry_run,\n  \
                    timeout_ms (default 600000), arch, extra_args, env\n  \
                    Each package is {name, version}; a package with source is refused\n  \
                    purge: apt, apk, pacman; version and arch: apt, dnf, yum",
                example: "resh pkg://system.remove 'input={\"manager\":\"apt\",\"packages\":[{\"name\":\"jq\"}]}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "backend": "pkg",
  "dry_run": false,
  "manager": "apt",
  "packages": [
    {
      "action": "removed",
      "from_cache": false,
      "installed_version": "1.7.1-3build1",
      "name": "jq",
      "requested_version": null
    }
  ],
  "purge": false,
  "recursive": false,
  "summary": {
    "autoremove_run": false,
    "failed": 0,
    "not_installed": 0,
    "purged": 0,
    "removed": 1,
    "skipped": 0
  }
}

Shown for apt."#,
                ),
            }),
        },
        VerbHelp {
            name: "update",
            definition: "Refreshes the package index and, by default, upgrades all or the \
                listed packages, or only reports available updates when check_only is set.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.update input=<json>\n  \
                    <json> keys: manager (required), packages, refresh_index, upgrade,\n  \
                    assume_yes, security_only, check_only, dry_run, timeout_ms\n  \
                    (default 900000), extra_args, env\n  \
                    security_only works with dnf and yum only; elsewhere it is refused",
                example: "resh pkg://system.update 'input={\"manager\":\"apt\",\"check_only\":true}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "available_updates": [
    {
      "candidate_version": "1.24.0-2ubuntu7.1",
      "current_version": "1.24.0-2ubuntu7",
      "name": "nginx",
      "security": true
    }
  ],
  "backend": "pkg",
  "check_only": true,
  "commands": [
    "apt-get update"
  ],
  "dry_run": false,
  "manager": "apt",
  "packages_scope": "all",
  "refresh_index": true,
  "upgrade": true
}

Shown for apt with check_only. A real update reports packages and summary
instead of available_updates and commands."#,
                ),
            }),
        },
        VerbHelp {
            name: "upgrade",
            definition: "Upgrades all or the listed packages to their latest available \
                versions, or only reports available upgrades when check_only is set.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.upgrade input=<json>\n  \
                    <json> keys: manager (required), packages, refresh_index,\n  \
                    assume_yes, security_only, check_only, dry_run, timeout_ms\n  \
                    (default 900000), extra_args, env\n  \
                    security_only works with dnf only; elsewhere it is refused",
                example: "resh pkg://system.upgrade 'input={\"manager\":\"apt\",\"check_only\":true}'",
                example_output: Some(
                    r#"{
  "alias": "system",
  "available_upgrades": [
    {
      "candidate_version": "1.24.0-2ubuntu7.1",
      "current_version": "1.24.0-2ubuntu7",
      "name": "nginx",
      "security": true
    }
  ],
  "backend": "pkg",
  "check_only": true,
  "commands": [
    "apt-get update"
  ],
  "dry_run": false,
  "manager": "apt",
  "packages_scope": "all",
  "refresh_index": true
}

Shown for apt with check_only. A real upgrade reports packages and summary
instead of available_upgrades and commands."#,
                ),
            }),
        },
        VerbHelp {
            name: "restore",
            definition: "Installs, upgrades, downgrades, or removes packages so the host \
                matches a lockfile produced by snapshot.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.restore input=<json>\n  \
                    <json> keys: manager, lockfile (both required; lockfile is the\n  \
                    lockfile content as a string), format (auto|json|yaml|text),\n  \
                    mode (exact|best_effort, default exact), allow_downgrades,\n  \
                    allow_removals, allow_newer, on_missing_package, on_repo_mismatch,\n  \
                    on_platform_mismatch, include_dependencies, dry_run, timeout_ms\n  \
                    (default 180000), extra_args, env\n  \
                    mode exact installs the locked versions (pacman: only the\n  \
                    repository version; brew: refused) and fails a package left at\n  \
                    another version; best_effort falls back to the repository version\n  \
                    on_repo_mismatch (fail|warn|ignore, default warn) compares each\n  \
                    locked repository with the installed package's repository;\n  \
                    include_dependencies (default true) false leaves packages the\n  \
                    lockfile records as dependencies out of the plan",
                example: "resh pkg://system.restore \"input=$(cat restore.json)\"",
                example_output: Some(
                    r#"{
  "action": "restore",
  "alias": "system",
  "backend": "pkg",
  "commands": [
    "DEBIAN_FRONTEND=noninteractive apt-get install -y jq=1.7.1-3build1"
  ],
  "dry_run": true,
  "manager": "apt",
  "mode": "exact",
  "plan": {
    "downgrade": [],
    "extra": [],
    "install": [
      "jq"
    ],
    "keep": [
      "nginx"
    ],
    "remove": [],
    "unresolved": [],
    "upgrade": []
  },
  "warnings": []
}

Shown for apt with dry_run true in restore.json. Without dry_run, the
output adds results and summary and omits commands."#,
                ),
            }),
        },
        VerbHelp {
            name: "apply_lock",
            definition: "Alias for restore.",
            detail: Some(VerbDetail {
                usage: "resh pkg://<alias>.apply_lock input=<json>\n  \
                    <json> keys: the same as restore",
                example: "resh pkg://system.apply_lock \"input=$(cat restore.json)\"",
                example_output: None,
            }),
        },
    ],
};

/// A package-manager command line, run directly with no shell.
///
/// Fixed words come from string literals in this file (`lit`); every value
/// from the caller (package names, versions, arch, extra args) is added with
/// `arg` and always stays exactly one argv element, so shell syntax in it is
/// never interpreted. Leading `NAME=value` words of a literal are set in the
/// child's environment. `Display` renders the same text the handle has
/// always reported in dry-run `commands`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CmdLine {
    env: Vec<(String, String)>,
    argv: Vec<String>,
}

impl CmdLine {
    fn lit(words: &str) -> Self {
        let mut c = Self::default();
        c.push_lit(words);
        c
    }

    /// Append fixed words from a literal, e.g. `" -y"`.
    fn push_lit(&mut self, words: &str) {
        for w in words.split_whitespace() {
            match w.split_once('=') {
                Some((k, v)) if self.argv.is_empty() && !k.is_empty() => {
                    self.env.push((k.to_string(), v.to_string()))
                }
                _ => self.argv.push(w.to_string()),
            }
        }
    }

    /// Append one caller-supplied value as a single argument.
    fn arg(&mut self, value: &str) {
        self.argv.push(value.to_string());
    }

    #[cfg(test)]
    fn argv(&self) -> &[String] {
        &self.argv
    }

    /// A `tokio` command for this line; nothing is spawned yet.
    fn command(&self) -> AsyncCommand {
        let mut c = pkg_cmd(&self.argv[0]);
        c.args(&self.argv[1..]);
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }
}

impl std::fmt::Display for CmdLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let words: Vec<String> = self
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .chain(self.argv.iter().cloned())
            .collect();
        f.write_str(&words.join(" "))
    }
}

/// Check a package name, version or architecture before it reaches a
/// package manager. Names must start with a letter or digit (so they can
/// never be read as an option) and use only `[A-Za-z0-9._+:~@/=-]`; no
/// whitespace, quotes or shell syntax. Returns the reason on failure.
fn check_pkg_token(kind: &str, value: &str) -> std::result::Result<(), String> {
    if value.is_empty() || value.len() > 256 {
        return Err(format!("{} must be 1-256 characters", kind));
    }
    if !value.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(format!(
            "{} {:?} must start with a letter or digit",
            kind, value
        ));
    }
    if let Some(c) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "._+:~@/=-".contains(*c)))
    {
        return Err(format!(
            "{} {:?} contains invalid character {:?}",
            kind, value, c
        ));
    }
    Ok(())
}

/// Package-file suffixes that make dnf, yum, apt, apk or pacman install a
/// local file instead of a repository package.
const PKG_FILE_SUFFIXES: &[&str] = &[
    ".rpm",
    ".deb",
    ".apk",
    ".pkg.tar",
    ".pkg.tar.zst",
    ".pkg.tar.xz",
    ".pkg.tar.gz",
];

/// A package name read from a restore lockfile, which is untrusted data.
/// On top of `check_pkg_token`, it must name a repository package: no URL
/// (`dnf install https://...` fetches and installs it), no `..` path
/// segment, and no package-file suffix (which makes the manager install a
/// local file).
fn check_lockfile_pkg_name(value: &str) -> std::result::Result<(), String> {
    check_pkg_token("package name", value)?;
    if value.contains("://") {
        return Err(format!("package name {:?} looks like a URL", value));
    }
    if value.split('/').any(|seg| seg == "..") {
        return Err(format!(
            "package name {:?} contains a '..' path segment",
            value
        ));
    }
    let lower = value.to_ascii_lowercase();
    if let Some(suffix) = PKG_FILE_SUFFIXES.iter().find(|s| lower.ends_with(*s)) {
        return Err(format!(
            "package name {:?} names a package file ({})",
            value, suffix
        ));
    }
    Ok(())
}

/// Package manager error types
#[derive(Error, Debug, Clone)]
pub enum PkgError {
    #[error("Invalid install configuration: {0}")]
    InvalidInstallConfig(String),
    #[error("Manager not available: {0}")]
    ManagerNotAvailable(String),
    #[error("Update cache failed: {0}")]
    UpdateCacheFailed(String),
    #[error("Package not found: {0}")]
    InstallNotFound(String),
    #[error("Dependency failure: {0}")]
    InstallDependencyFailure(String),
    #[error("Install conflict: {0}")]
    InstallConflict(String),
    #[error("Permission denied: {0}")]
    InstallPermissionDenied(String),
    #[error("Invalid version: {0}")]
    InstallInvalidVersion(String),
    #[error("Install failed: {0}")]
    InstallFailed(String),
    // Remove errors
    #[error("Invalid remove configuration: {0}")]
    InvalidRemoveConfig(String),
    #[error("Package not found for removal: {0}")]
    RemoveNotFound(String),
    #[error("Package not installed: {0}")]
    RemoveNotInstalled(String),
    #[error("Remove dependency failure: {0}")]
    RemoveDependencyFailure(String),
    #[error("Remove permission denied: {0}")]
    RemovePermissionDenied(String),
    #[error("Remove failed: {0}")]
    RemoveFailed(String),
    // Update errors
    #[error("Invalid update configuration: {0}")]
    InvalidUpdateConfig(String),
    #[error("Update index failed: {0}")]
    UpdateIndexFailed(String),
    #[error("Update check failed: {0}")]
    UpdateCheckFailed(String),
    #[error("Update permission denied: {0}")]
    UpdatePermissionDenied(String),
    #[error("Update timeout")]
    UpdateTimeout,
    #[error("Update failed: {0}")]
    UpdateFailed(String),
    // Upgrade errors
    #[error("Invalid upgrade configuration: {0}")]
    InvalidUpgradeConfig(String),
    #[error("Upgrade index failed: {0}")]
    UpgradeIndexFailed(String),
    #[error("Upgrade check failed: {0}")]
    UpgradeCheckFailed(String),
    #[error("Upgrade timeout")]
    UpgradeTimeout,
    #[error("Upgrade failed: {0}")]
    UpgradeFailed(String),
    // Info errors
    #[error("Invalid info configuration: {0}")]
    InvalidInfoConfig(String),
    #[error("Info timeout")]
    InfoTimeout,
    #[error("Info query failed: {0}")]
    InfoQueryFailed(String),
    // Search errors
    #[error("Invalid search configuration: {0}")]
    InvalidSearchConfig(String),
    #[error("Search timeout")]
    SearchTimeout,
    #[error("Search failed: {0}")]
    SearchFailed(String),
    // List installed errors
    #[error("Invalid list installed configuration: {0}")]
    InvalidListInstalledConfig(String),
    #[error("List installed timeout")]
    ListInstalledTimeout,
    #[error("List installed failed: {0}")]
    ListInstalledFailed(String),
    // Snapshot errors
    #[error("Invalid snapshot configuration: {0}")]
    InvalidSnapshotConfig(String),
    #[error("Snapshot timeout")]
    SnapshotTimeout,
    #[error("Snapshot failed: {0}")]
    SnapshotFailed(String),
    // Restore errors
    #[error("Invalid restore configuration: {0}")]
    InvalidRestoreConfig(String),
    #[error("Invalid lockfile: {0}")]
    RestoreInvalidLockfile(String),
    #[error("Manager mismatch: {0}")]
    RestoreManagerMismatch(String),
    #[error("Platform incompatible: {0}")]
    RestorePlatformIncompatible(String),
    #[error("Restore timeout")]
    RestoreTimeout,
    #[error("Restore apply failed: {0}")]
    RestoreApplyFailed(String),
    #[error("Repository mismatch: {0}")]
    RestoreRepoMismatch(String),
    /// A request that this manager cannot honor; refused before anything ran.
    #[error("{0}")]
    Unsupported(String),
    /// Restore `on_missing_package: fail` with packages the plan cannot bring
    /// to the locked state; refused before anything ran.
    #[error("Unresolved packages: {0}")]
    RestoreUnresolved(String),
    /// A requested version older than the installed one without
    /// `allow_downgrade`; refused before anything ran.
    #[error("Downgrade refused: {0}")]
    DowngradeRefused(String),
}

impl PkgError {
    /// True for the errors that report a passed deadline.
    fn is_timeout(&self) -> bool {
        self.code().1 == "pkg.timeout"
    }

    /// The exit status and `pkg.*` error code of this error (see
    /// `pkg_args::ERROR_CODES` and `pkg.md` 3.6).
    fn code(&self) -> (i32, &'static str) {
        use crate::core::status::exit::{FAILED, TIMEOUT, USAGE};
        match self {
            PkgError::InvalidInstallConfig(_)
            | PkgError::InvalidRemoveConfig(_)
            | PkgError::InvalidUpdateConfig(_)
            | PkgError::InvalidUpgradeConfig(_)
            | PkgError::InvalidInfoConfig(_)
            | PkgError::InvalidSearchConfig(_)
            | PkgError::InvalidListInstalledConfig(_)
            | PkgError::InvalidSnapshotConfig(_)
            | PkgError::InvalidRestoreConfig(_) => (USAGE, "pkg.invalid_argument"),
            PkgError::Unsupported(_) => (USAGE, "pkg.unsupported_option"),
            PkgError::RestoreInvalidLockfile(_) => (USAGE, "pkg.invalid_lockfile"),
            PkgError::RestoreManagerMismatch(_) => (USAGE, "pkg.manager_mismatch"),
            PkgError::ManagerNotAvailable(_) => (FAILED, "pkg.manager_not_found"),
            PkgError::InstallNotFound(_)
            | PkgError::InstallInvalidVersion(_)
            | PkgError::RemoveNotFound(_)
            | PkgError::RemoveNotInstalled(_) => (FAILED, "pkg.not_found"),
            PkgError::InstallPermissionDenied(_)
            | PkgError::RemovePermissionDenied(_)
            | PkgError::UpdatePermissionDenied(_) => (FAILED, "pkg.permission_denied"),
            PkgError::InstallDependencyFailure(_) | PkgError::RemoveDependencyFailure(_) => {
                (FAILED, "pkg.dependency_failure")
            }
            PkgError::InstallConflict(_) => (FAILED, "pkg.conflict"),
            PkgError::UpdateCacheFailed(_)
            | PkgError::UpdateIndexFailed(_)
            | PkgError::UpgradeIndexFailed(_) => (FAILED, "pkg.index_failed"),
            PkgError::RestorePlatformIncompatible(_) => (FAILED, "pkg.platform_mismatch"),
            PkgError::RestoreRepoMismatch(_) => (FAILED, "pkg.repo_mismatch"),
            PkgError::RestoreUnresolved(_) => (FAILED, "pkg.unresolved"),
            PkgError::DowngradeRefused(_) => (FAILED, "pkg.downgrade_refused"),
            PkgError::UpdateTimeout
            | PkgError::UpgradeTimeout
            | PkgError::InfoTimeout
            | PkgError::SearchTimeout
            | PkgError::ListInstalledTimeout
            | PkgError::SnapshotTimeout
            | PkgError::RestoreTimeout => (TIMEOUT, "pkg.timeout"),
            PkgError::InstallFailed(_)
            | PkgError::RemoveFailed(_)
            | PkgError::UpdateCheckFailed(_)
            | PkgError::UpdateFailed(_)
            | PkgError::UpgradeCheckFailed(_)
            | PkgError::UpgradeFailed(_)
            | PkgError::InfoQueryFailed(_)
            | PkgError::SearchFailed(_)
            | PkgError::ListInstalledFailed(_)
            | PkgError::SnapshotFailed(_)
            | PkgError::RestoreApplyFailed(_) => (FAILED, "pkg.command_failed"),
        }
    }
}

/// The error of a failed package-manager command, by its standard error.
/// Used for per-package failures recorded in a result.
fn error_value(e: &PkgError) -> Value {
    crate::core::status::error_json(e.code().1, &e.to_string())
}

/// The manager's name as it appears in output and lockfiles.
fn manager_name(manager: &ManagerKind) -> &'static str {
    match manager {
        ManagerKind::Auto => "auto",
        ManagerKind::Apt => "apt",
        ManagerKind::Dnf => "dnf",
        ManagerKind::Yum => "yum",
        ManagerKind::Pacman => "pacman",
        ManagerKind::Apk => "apk",
        ManagerKind::Brew => "brew",
    }
}

/// Whether `manager` can install a given version of a package (`name=1.2`
/// for apt and apk, `name-1.2` for dnf and yum). pacman installs only the
/// version its repositories carry, and brew only the current formula.
fn supports_version_pin(manager: &ManagerKind) -> bool {
    matches!(
        manager,
        ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Yum | ManagerKind::Apk
    )
}

/// Whether `manager` can select a package architecture (`name:arch` for apt,
/// `name.arch` for dnf and yum).
fn supports_arch(manager: &ManagerKind) -> bool {
    matches!(
        manager,
        ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Yum
    )
}

/// Whether `assume_yes: false` means something: apt, dnf, yum and pacman
/// then ask for confirmation, which fails without a terminal (resh gives
/// the manager none), so nothing changes when a confirmation is needed. apk
/// and brew do not ask, so `false` cannot be honored.
fn supports_confirmation(manager: &ManagerKind) -> bool {
    matches!(
        manager,
        ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Yum | ManagerKind::Pacman
    )
}

/// The package argument for `manager`: the name with a version and an
/// architecture in the manager's syntax.
fn package_argument(
    manager: &ManagerKind,
    name: &str,
    version: Option<&str>,
    arch: Option<&str>,
) -> String {
    let mut arg = name.to_string();
    if let Some(arch) = arch {
        match manager {
            ManagerKind::Apt => arg = format!("{arg}:{arch}"),
            ManagerKind::Dnf | ManagerKind::Yum => {}
            _ => {}
        }
    }
    if let Some(version) = version {
        match manager {
            ManagerKind::Apt | ManagerKind::Apk => arg = format!("{arg}={version}"),
            ManagerKind::Dnf | ManagerKind::Yum => arg = format!("{arg}-{version}"),
            _ => {}
        }
    }
    if let Some(arch) = arch {
        if matches!(manager, ManagerKind::Dnf | ManagerKind::Yum) {
            arg = format!("{arg}.{arch}");
        }
    }
    arg
}

/// Refuses the install options that `manager` cannot honor, before anything
/// runs.
fn check_install_support(config: &InstallConfig, manager: &ManagerKind) -> Result<(), PkgError> {
    let name = manager_name(manager);
    if !supports_version_pin(manager) {
        if let Some(pkg) = config.packages.iter().find(|p| p.version.is_some()) {
            return Err(PkgError::Unsupported(format!(
                "a package version (package {:?}) is not supported by pkg install for {name}: \
                 it installs only the version its repositories carry; remove version; \
                 nothing was run",
                pkg.name
            )));
        }
    }
    if config.arch.is_some() && !supports_arch(manager) {
        return Err(PkgError::Unsupported(format!(
            "arch is not supported by pkg install for {name} (only apt, dnf and yum); \
             nothing was run"
        )));
    }
    if !config.assume_yes && !supports_confirmation(manager) {
        return Err(PkgError::Unsupported(format!(
            "assume_yes=false is not supported for {name}: it does not ask for \
             confirmation, so the install would go ahead anyway; nothing was run"
        )));
    }
    Ok(())
}

/// What `install` does with one package, given its installed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallStep {
    /// Already installed (at the requested version): nothing to do.
    Skip,
    /// Install it (or install the requested version).
    Install,
    /// Upgrade the installed package to the latest version.
    Upgrade,
    /// Reinstall the installed package.
    Reinstall,
    /// Install the requested version, older than the installed one
    /// (`allow_downgrade`).
    Downgrade,
}

fn install_step(
    config: &InstallConfig,
    pkg: &PackageSpec,
    installed: Option<&str>,
    manager: &ManagerKind,
) -> InstallStep {
    let Some(installed) = installed else {
        return InstallStep::Install;
    };
    if let Some(wanted) = pkg.version.as_deref() {
        return match compare_package_versions(manager, wanted, installed) {
            std::cmp::Ordering::Equal if config.reinstall => InstallStep::Reinstall,
            std::cmp::Ordering::Equal => InstallStep::Skip,
            std::cmp::Ordering::Less => InstallStep::Downgrade,
            std::cmp::Ordering::Greater => InstallStep::Install,
        };
    }
    if config.reinstall {
        return InstallStep::Reinstall;
    }
    if config.upgrade {
        InstallStep::Upgrade
    } else if config.only_if_missing {
        InstallStep::Skip
    } else {
        InstallStep::Install
    }
}

/// Refuses the remove options that `manager` cannot honor, before anything
/// runs.
fn check_remove_support(config: &RemoveConfig, manager: &ManagerKind) -> Result<(), PkgError> {
    let name = manager_name(manager);
    let version_ok = matches!(
        manager,
        ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Yum
    );
    if !version_ok {
        if let Some(pkg) = config.packages.iter().find(|p| p.version.is_some()) {
            return Err(PkgError::Unsupported(format!(
                "a package version (package {:?}) is not supported by pkg remove for {name} \
                 (only apt, dnf and yum); remove version; nothing was run",
                pkg.name
            )));
        }
    }
    if config.arch.is_some() && !supports_arch(manager) {
        return Err(PkgError::Unsupported(format!(
            "arch is not supported by pkg remove for {name} (only apt, dnf and yum); \
             nothing was run"
        )));
    }
    if config.purge
        && !matches!(
            manager,
            ManagerKind::Apt | ManagerKind::Apk | ManagerKind::Pacman
        )
    {
        return Err(PkgError::Unsupported(format!(
            "purge is not supported by pkg remove for {name} (only apt, apk and pacman); \
             nothing was run"
        )));
    }
    if !config.assume_yes && !supports_confirmation(manager) {
        return Err(PkgError::Unsupported(format!(
            "assume_yes=false is not supported for {name}: it does not ask for \
             confirmation, so the removal would go ahead anyway; nothing was run"
        )));
    }
    Ok(())
}

/// The command that upgrades every package (`packages` empty) or only the
/// listed installed packages, for `update` and `upgrade`. A listed package
/// that is not installed is not installed by it (`--only-upgrade` for apt,
/// `--needed` without `-u` for pacman).
fn upgrade_command(
    manager: &ManagerKind,
    packages: &[String],
    assume_yes: bool,
    security_only: bool,
    extra_args: Option<&[String]>,
) -> Result<CmdLine, PkgError> {
    let mut cmd = match manager {
        ManagerKind::Apt => {
            let mut cmd = CmdLine::lit(if packages.is_empty() {
                "DEBIAN_FRONTEND=noninteractive apt-get upgrade"
            } else {
                "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade"
            });
            if assume_yes {
                cmd.push_lit(" -y");
            }
            cmd
        }
        ManagerKind::Dnf | ManagerKind::Yum => {
            let mut cmd = CmdLine::lit(if *manager == ManagerKind::Dnf {
                "dnf upgrade"
            } else {
                "yum update"
            });
            if assume_yes {
                cmd.push_lit(" -y");
            }
            if security_only {
                cmd.push_lit(" --security");
            }
            cmd
        }
        ManagerKind::Pacman => {
            let mut cmd = CmdLine::lit(if packages.is_empty() {
                "pacman -Su"
            } else {
                "pacman -S --needed"
            });
            if assume_yes {
                cmd.push_lit(" --noconfirm");
            }
            cmd
        }
        ManagerKind::Apk => CmdLine::lit("apk upgrade --no-interactive"),
        ManagerKind::Brew => CmdLine::lit("brew upgrade"),
        ManagerKind::Auto => {
            return Err(PkgError::ManagerNotAvailable(
                "manager auto was not resolved".to_string(),
            ));
        }
    };
    for package in packages {
        cmd.arg(package);
    }
    for arg in extra_args.unwrap_or_default() {
        cmd.arg(arg);
    }
    Ok(cmd)
}

/// Refuses `assume_yes: false` where the manager never asks (apk, brew), for
/// `update` and `upgrade`.
fn check_confirmation_support(
    verb: &str,
    assume_yes: bool,
    manager: &ManagerKind,
) -> Result<(), PkgError> {
    if !assume_yes && !supports_confirmation(manager) {
        return Err(PkgError::Unsupported(format!(
            "assume_yes=false is not supported by pkg {verb} for {}: it does not ask for \
             confirmation, so the upgrade would go ahead anyway; nothing was run",
            manager_name(manager)
        )));
    }
    Ok(())
}

/// Compiles `exclude_patterns` as shell-style globs (`*` and `?` never
/// cross `/`). An invalid pattern is refused.
fn exclude_matchers(patterns: &[String]) -> Result<Vec<globset::GlobMatcher>, PkgError> {
    patterns
        .iter()
        .map(|p| {
            globset::GlobBuilder::new(p)
                .literal_separator(true)
                .build()
                .map(|g| g.compile_matcher())
                .map_err(|e| {
                    PkgError::InvalidSnapshotConfig(format!(
                        "exclude_patterns: invalid pattern {p:?}: {e}"
                    ))
                })
        })
        .collect()
}

/// Whether a lockfile records upstream versions (`include_versions:
/// minimal`).
fn lockfile_is_minimal(lockfile: &Lockfile) -> bool {
    lockfile
        .manager
        .config
        .as_ref()
        .and_then(|c| c.get("include_versions"))
        .and_then(Value::as_str)
        == Some("minimal")
}

/// The upstream part of a version, without the packaging revision and
/// epoch: dpkg `[epoch:]upstream[-revision]`, rpm and pacman
/// `[epoch:]version[-release]`, apk `version[-rN]`, brew `version[_N]`.
fn upstream_version(manager: &ManagerKind, version: &str) -> String {
    match manager {
        ManagerKind::Apk => match version.rsplit_once("-r") {
            Some((v, r)) if !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()) => v,
            _ => version,
        }
        .to_string(),
        ManagerKind::Brew => match version.rsplit_once('_') {
            Some((v, r)) if !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()) => v,
            _ => version,
        }
        .to_string(),
        _ => {
            let without_epoch = match version.split_once(':') {
                Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => rest,
                _ => version,
            };
            without_epoch
                .rsplit_once('-')
                .map_or(without_epoch, |(v, _)| v)
                .to_string()
        }
    }
}

/// The versions a manager's listing of available builds shows (apt
/// `madison`, dnf/yum `list --showduplicates --available`, apk `policy`).
fn available_versions(manager: &ManagerKind, name: &str, listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line| match manager {
            ManagerKind::Apt => {
                let mut cols = line.split('|').map(str::trim);
                (cols.next() == Some(name)).then(|| cols.next()).flatten()
            }
            ManagerKind::Dnf | ManagerKind::Yum => {
                let mut words = line.split_whitespace();
                let first = words.next()?;
                (first.rsplit_once('.').map(|(n, _)| n) == Some(name))
                    .then(|| words.next())
                    .flatten()
            }
            _ => {
                let t = line.trim();
                (line.starts_with("  ") && !line.starts_with("    ") && t.ends_with(':'))
                    .then(|| t.trim_end_matches(':'))
            }
        })
        .map(str::to_string)
        .collect()
}

/// The kind of one restore operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreKind {
    Install,
    Upgrade,
    Downgrade,
    Remove,
}

/// One restore operation: a package, the locked version to install (when
/// the lockfile records one) and the installed version before.
#[derive(Debug, Clone)]
struct RestoreOp {
    kind: RestoreKind,
    name: String,
    version: Option<String>,
    from: Option<String>,
    /// The lockfile records upstream versions (`include_versions:
    /// minimal`): any build of `locked` satisfies it.
    locked: Option<String>,
}

/// The operations for `plan`, in execution order (see
/// `restore_operations_with`), for tests.
#[cfg(test)]
fn restore_operations(
    plan: &mut RestorePlan,
    lockfile: &Lockfile,
    current: &[InstalledPackage],
    config: &RestoreConfig,
    manager: &ManagerKind,
) -> Result<Vec<RestoreOp>, PkgError> {
    restore_operations_with(
        plan,
        lockfile,
        current,
        config,
        manager,
        &HashSet::new(),
        &HashMap::new(),
    )
}

/// The operations for `plan`, in execution order. With `mode: exact`, a
/// manager that cannot install a given version (pacman, brew) refuses a
/// plan that needs one, except for the packages in `at_repo_version`, whose
/// locked version is the one the repositories carry; with `best_effort` it
/// installs by name and a downgrade, which it cannot do, becomes
/// unresolved. For a lockfile of upstream versions (`include_versions:
/// minimal`), `builds` holds the newest available build of each locked
/// upstream version, which is what gets installed.
fn restore_operations_with(
    plan: &mut RestorePlan,
    lockfile: &Lockfile,
    current: &[InstalledPackage],
    config: &RestoreConfig,
    manager: &ManagerKind,
    at_repo_version: &HashSet<String>,
    builds: &HashMap<String, String>,
) -> Result<Vec<RestoreOp>, PkgError> {
    let minimal = lockfile_is_minimal(lockfile);
    let locked: HashMap<&str, &LockfilePackage> = lockfile
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();
    let installed: HashMap<&str, &str> = current
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str()))
        .collect();
    let op = |kind: RestoreKind, name: &String| {
        let locked_version = if kind == RestoreKind::Remove {
            None
        } else {
            locked
                .get(name.as_str())
                .and_then(|p| p.version.as_deref())
                .map(|v| normalize_version(manager, v))
        };
        RestoreOp {
            kind,
            name: name.clone(),
            version: builds.get(name).cloned().or(locked_version.clone()),
            from: installed.get(name.as_str()).map(|v| v.to_string()),
            locked: locked_version.filter(|_| minimal),
        }
    };

    if !supports_version_pin(manager) {
        let needs_pin: Vec<String> = plan
            .install
            .iter()
            .chain(&plan.upgrade)
            .chain(&plan.downgrade)
            .filter(|n| op(RestoreKind::Install, n).version.is_some())
            .filter(|n| !at_repo_version.contains(*n))
            .cloned()
            .collect();
        if config.mode == RestoreMode::Exact && !needs_pin.is_empty() {
            return Err(PkgError::Unsupported(format!(
                "mode=exact needs the locked versions of {} package(s), but {} cannot install \
                 a given version: {}; use mode=best_effort to install the repository \
                 versions; nothing was changed",
                needs_pin.len(),
                manager_name(manager),
                name_list(&needs_pin)
            )));
        }
        for name in std::mem::take(&mut plan.downgrade) {
            plan.unresolved.push(UnresolvedPackage {
                name,
                reason: format!("downgrade_not_supported_by_{}", manager_name(manager)),
            });
        }
    }

    let mut ops = Vec::new();
    ops.extend(plan.install.iter().map(|n| op(RestoreKind::Install, n)));
    ops.extend(plan.upgrade.iter().map(|n| op(RestoreKind::Upgrade, n)));
    ops.extend(plan.downgrade.iter().map(|n| op(RestoreKind::Downgrade, n)));
    ops.extend(plan.remove.iter().map(|n| op(RestoreKind::Remove, n)));
    Ok(ops)
}

/// The command for one restore operation. `pin` passes the locked version
/// where the manager can take one; `extra_args` is added to every command.
fn restore_command(
    op: &RestoreOp,
    manager: &ManagerKind,
    config: &RestoreConfig,
    pin: bool,
) -> Result<CmdLine, PkgError> {
    let version = op
        .version
        .as_deref()
        .filter(|_| pin && supports_version_pin(manager));
    let target = package_argument(manager, &op.name, version, None);
    let kind = op.kind;
    let mut cmd = match (manager, kind) {
        (ManagerKind::Apt, RestoreKind::Remove) => {
            CmdLine::lit("DEBIAN_FRONTEND=noninteractive apt-get remove -y")
        }
        (ManagerKind::Apt, RestoreKind::Downgrade) => {
            CmdLine::lit("DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades")
        }
        (ManagerKind::Apt, _) => CmdLine::lit("DEBIAN_FRONTEND=noninteractive apt-get install -y"),
        (ManagerKind::Dnf | ManagerKind::Yum, _) => {
            let mut cmd = CmdLine::lit(manager_name(manager));
            cmd.push_lit(match kind {
                RestoreKind::Install => "install -y",
                RestoreKind::Upgrade if *manager == ManagerKind::Yum => "update -y",
                RestoreKind::Upgrade => "upgrade -y",
                RestoreKind::Downgrade => "downgrade -y",
                RestoreKind::Remove => "remove -y",
            });
            cmd
        }
        (ManagerKind::Pacman, RestoreKind::Remove) => CmdLine::lit("pacman -R --noconfirm"),
        (ManagerKind::Pacman, _) => CmdLine::lit("pacman -S --noconfirm --needed"),
        (ManagerKind::Apk, RestoreKind::Remove) => CmdLine::lit("apk del --no-interactive"),
        (ManagerKind::Apk, RestoreKind::Upgrade) if version.is_none() => {
            CmdLine::lit("apk add --no-interactive --upgrade")
        }
        (ManagerKind::Apk, _) => CmdLine::lit("apk add --no-interactive"),
        (ManagerKind::Brew, RestoreKind::Remove) => CmdLine::lit("brew uninstall"),
        (ManagerKind::Brew, RestoreKind::Upgrade) => CmdLine::lit("brew upgrade"),
        (ManagerKind::Brew, _) => CmdLine::lit("brew install"),
        (ManagerKind::Auto, _) => {
            return Err(PkgError::ManagerNotAvailable(
                "manager auto was not resolved".to_string(),
            ));
        }
    };
    cmd.arg(&target);
    for arg in config.extra_args.iter().flatten() {
        cmd.arg(arg);
    }
    Ok(cmd)
}

/// Warnings about versions `mode` will not reproduce.
fn restore_mode_warnings(
    ops: &[RestoreOp],
    config: &RestoreConfig,
    manager: &ManagerKind,
) -> Vec<String> {
    let unpinned: Vec<String> = ops
        .iter()
        .filter(|op| op.kind != RestoreKind::Remove && op.version.is_some())
        .map(|op| op.name.clone())
        .collect();
    if config.mode == RestoreMode::BestEffort
        && !supports_version_pin(manager)
        && !unpinned.is_empty()
    {
        vec![format!(
            "best_effort: {} cannot install a given version, so {} package(s) get the \
             repository version instead of the locked one: {}",
            manager_name(manager),
            unpinned.len(),
            name_list(&unpinned)
        )]
    } else {
        Vec::new()
    }
}

/// Checks the version an operation left: a removed package must be gone,
/// any other installed; with `mode: exact` at the locked version.
fn verify_restore_op(
    op: &RestoreOp,
    now: Option<&str>,
    config: &RestoreConfig,
    manager: &ManagerKind,
) -> Result<(), PkgError> {
    match (op.kind, now) {
        (RestoreKind::Remove, None) => Ok(()),
        (RestoreKind::Remove, Some(v)) => Err(PkgError::RestoreApplyFailed(format!(
            "{} is still installed ({v})",
            op.name
        ))),
        (_, None) => Err(PkgError::RestoreApplyFailed(format!(
            "{} is not installed after the command",
            op.name
        ))),
        (_, Some(v)) if op.locked.is_some() => {
            let locked = op.locked.as_deref().unwrap_or_default();
            if config.mode == RestoreMode::Exact
                && upstream_version(manager, v) != upstream_version(manager, locked)
            {
                Err(PkgError::RestoreApplyFailed(format!(
                    "{} is at {v}, not a build of the locked upstream version {locked} \
                     (mode=exact)",
                    op.name
                )))
            } else {
                Ok(())
            }
        }
        (_, Some(v)) => match op.version.as_deref() {
            Some(locked)
                if config.mode == RestoreMode::Exact
                    && normalize_version(manager, v) != normalize_version(manager, locked) =>
            {
                Err(PkgError::RestoreApplyFailed(format!(
                    "{} is at {v}, not the locked version {locked} (mode=exact)",
                    op.name
                )))
            }
            _ => Ok(()),
        },
    }
}

/// What `remove` does with one package, given its installed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoveStep {
    /// Installed (at the requested version, when one is given): remove it.
    Remove,
    /// Not installed: reported as `not_installed`.
    NotInstalled,
    /// Not installed with `fail_if_missing`: a failure.
    Missing,
    /// Installed, but not at the requested version: a failure.
    OtherVersion,
}

fn remove_step(config: &RemoveConfig, pkg: &PackageSpec, installed: Option<&str>) -> RemoveStep {
    match installed {
        None if config.fail_if_missing => RemoveStep::Missing,
        // only_if_installed=false hands the package to the manager anyway,
        // which decides what a missing package means.
        None if !config.only_if_installed => RemoveStep::Remove,
        None => RemoveStep::NotInstalled,
        Some(v) if pkg.version.as_deref().is_some_and(|want| want != v) => RemoveStep::OtherVersion,
        Some(_) => RemoveStep::Remove,
    }
}

/// Whether a manager's (lowercased) error says a package does not exist:
/// apt "unable to locate package", dnf "no match for argument", pacman
/// "target not found", apk "no such package", brew "no available formula".
fn is_not_found_message(lower: &str) -> bool {
    lower.contains("unable to locate package")
        || lower.contains("no match for argument")
        || lower.contains("target not found")
        || lower.contains("no such package")
        || lower.contains("no available formula")
        || (lower.contains("package") && lower.contains("not found"))
        || (lower.contains("version") && lower.contains("was not found"))
}

/// Whether a manager's (lowercased) error is about privileges: apt "are you
/// root?", dnf "this command has to be run with superuser privileges",
/// pacman "you cannot perform this operation unless you are root", apk
/// "permission denied".
fn is_permission_message(lower: &str) -> bool {
    lower.contains("permission denied")
        || lower.contains("not allowed")
        || lower.contains("are you root")
        || lower.contains("superuser privileges")
        || lower.contains("unless you are root")
        || lower.contains("operation not permitted")
}

/// The package name in apk's `<name>-<version>-r<release>` (such as
/// `tree-sitter-c-0.24.1-r0`): the part before the version.
fn apk_package_name(name_version: &str) -> &str {
    let without_release = match name_version.rsplit_once("-r") {
        Some((rest, rel)) if !rel.is_empty() && rel.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => name_version,
    };
    match without_release.rfind('-') {
        Some(i)
            if without_release[i + 1..]
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_digit()) =>
        {
            &name_version[..i]
        }
        _ => name_version,
    }
}

/// The last `n` non-empty lines of a tool's output, for an error message.
fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Reads the installed version from the per-package query of
/// `installed_version_of`.
fn parse_installed_version(manager: &ManagerKind, name: &str, stdout: &str) -> Option<String> {
    let lines = || stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    let version = match manager {
        // `<dpkg status>\t<version>`; only state `installed` counts.
        ManagerKind::Apt => lines().find_map(|l| {
            let (status, version) = l.split_once('\t')?;
            (status == "installed").then(|| version.to_string())
        }),
        // One line per installed instance (several for kernels): the last.
        ManagerKind::Dnf | ManagerKind::Yum => lines().next_back().map(str::to_string),
        // `<name> <version>`
        ManagerKind::Pacman | ManagerKind::Brew => lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .map(str::to_string),
        // `<name>-<version>`
        ManagerKind::Apk => lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('-'))
            .map(str::to_string),
        ManagerKind::Auto => None,
    };
    version.filter(|v| !v.is_empty())
}

/// A version as compared by restore: rpm's epoch 0 is the same as none.
fn normalize_version(manager: &ManagerKind, version: &str) -> String {
    match manager {
        ManagerKind::Dnf | ManagerKind::Yum | ManagerKind::Pacman => {
            version.strip_prefix("0:").unwrap_or(version).to_string()
        }
        _ => version.to_string(),
    }
}

/// Compares two versions the way `manager` does: dpkg's algorithm for apt,
/// rpm's for dnf, yum and pacman (`vercmp` uses it), apk's for apk; brew
/// (no defined order) compares the strings.
fn compare_package_versions(manager: &ManagerKind, a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (normalize_version(manager, a), normalize_version(manager, b));
    match manager {
        ManagerKind::Apt => version_cmp::dpkg(&a, &b),
        ManagerKind::Dnf | ManagerKind::Yum => version_cmp::rpm_evr(&a, &b),
        ManagerKind::Pacman => version_cmp::pacman(&a, &b),
        ManagerKind::Apk => version_cmp::apk(&a, &b),
        _ => a.cmp(&b),
    }
}

/// Whether `verb` restricts its upgrade to security fixes on `manager` when
/// `security_only` is set: `update` passes `--security` to dnf and yum,
/// `upgrade` to dnf. The other managers' commands have no such filter, so
/// the flag would be dropped and every package upgraded; the request is
/// refused instead.
fn security_only_supported(verb: &str, manager: &ManagerKind) -> bool {
    match verb {
        "update" => matches!(manager, ManagerKind::Dnf | ManagerKind::Yum),
        "upgrade" => matches!(manager, ManagerKind::Dnf),
        _ => false,
    }
}

fn security_only_refusal(verb: &str, manager: &ManagerKind) -> String {
    let manager = format!("{manager:?}").to_lowercase();
    let supported = if verb == "update" {
        "dnf and yum"
    } else {
        "dnf"
    };
    format!(
        "security_only is not supported by pkg {verb} for {manager} (only {supported}); \
         nothing was run. Without it, every listed or available package would be upgraded."
    )
}

/// Supported package managers
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum ManagerKind {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "apt")]
    Apt,
    #[serde(rename = "yum")]
    Yum,
    #[serde(rename = "dnf")]
    Dnf,
    #[serde(rename = "pacman")]
    Pacman,
    #[serde(rename = "apk")]
    Apk,
    #[serde(rename = "brew")]
    Brew,
}

/// Package specification
#[derive(Debug, Clone, Deserialize)]
pub struct PackageSpec {
    pub name: String,
    pub version: Option<String>,
    /// Never defined for any manager; a request that sets it is refused (see
    /// `check_no_package_source`) instead of being silently ignored.
    pub source: Option<String>,
}

/// `source` in a package entry has no defined meaning for any manager: no
/// backend can choose a repository, URL or file from it. A request that sets
/// it is refused before anything runs (dry run included), so it is never
/// silently dropped.
fn check_no_package_source(pkg: &PackageSpec) -> std::result::Result<(), String> {
    match &pkg.source {
        None => Ok(()),
        Some(source) => Err(format!(
            "package {:?}: source={:?} is not supported by pkg for any manager \
             (the package is always taken from the manager's configured repositories); \
             remove source from the request; nothing was run",
            pkg.name, source
        )),
    }
}

/// Install configuration
#[derive(Debug, Clone, Deserialize)]
pub struct InstallConfig {
    pub manager: ManagerKind,
    pub packages: Vec<PackageSpec>,
    #[serde(default = "default_true")]
    pub update_cache: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default = "default_true")]
    pub only_if_missing: bool,
    #[serde(default)]
    pub reinstall: bool,
    #[serde(default)]
    pub upgrade: bool,
    /// Allows installing a requested version older than the installed one.
    #[serde(default)]
    pub allow_downgrade: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub arch: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    600000
} // 10 minutes

/// Remove configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RemoveConfig {
    pub manager: ManagerKind,
    pub packages: Vec<PackageSpec>,
    #[serde(default)]
    pub purge: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default = "default_true")]
    pub only_if_installed: bool,
    #[serde(default)]
    pub fail_if_missing: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub arch: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Update configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateConfig {
    pub manager: ManagerKind,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default = "default_true")]
    pub refresh_index: bool,
    #[serde(default = "default_true")]
    pub upgrade: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default)]
    pub security_only: bool,
    #[serde(default)]
    pub check_only: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_long_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_long_timeout() -> u64 {
    900000
} // 15 minutes

/// Upgrade configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpgradeConfig {
    pub manager: ManagerKind,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default = "default_true")]
    pub refresh_index: bool,
    #[serde(default = "default_true")]
    pub assume_yes: bool,
    #[serde(default)]
    pub security_only: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub check_only: bool,
    #[serde(default = "default_long_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Info configuration
#[derive(Debug, Clone, Deserialize)]
pub struct InfoConfig {
    pub manager: ManagerKind,
    pub packages: Vec<String>,
    #[serde(default)]
    pub include_dependencies: bool,
    #[serde(default)]
    pub include_reverse_deps: bool,
    #[serde(default)]
    pub include_files: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_info_timeout")]
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

fn default_info_timeout() -> u64 {
    5000
} // 5 seconds

/// Search field enum for specifying what fields to search in
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum SearchField {
    #[serde(rename = "name")]
    Name,
    #[serde(rename = "description")]
    Description,
    #[serde(rename = "all")]
    All,
}

/// Search configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SearchConfig {
    pub manager: ManagerKind,
    pub query: String,
    #[serde(default = "default_search_in")]
    pub search_in: Vec<SearchField>,
    #[serde(default)]
    pub exact: bool,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default = "default_search_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_true")]
    pub include_installed: bool,
    #[serde(default = "default_true")]
    pub include_versions: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_info_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

fn default_search_in() -> Vec<SearchField> {
    vec![SearchField::Name, SearchField::Description]
}

fn default_search_limit() -> u32 {
    50
}

/// Individual search result
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub name: String,
    pub version: Option<String>,
    pub installed: bool,
    pub summary: Option<String>,
    pub description: Option<String>,
    /// The suite/component (apt) or repository name the package comes from.
    pub repository: Option<String>,
    /// The source URL of that repository, where the manager reports one.
    pub repository_url: Option<String>,
    pub homepage: Option<String>,
    pub score: f64,
}

/// Search results container
#[derive(Debug, Clone, Serialize)]
pub struct SearchResults {
    pub backend: String,
    pub manager: String,
    pub alias: String,
    pub query: String,
    pub search_in: Vec<SearchField>,
    pub exact: bool,
    pub case_sensitive: bool,
    pub limit: u32,
    pub offset: u32,
    pub total_matches: u32,
    pub results: Vec<SearchResult>,
}

/// Package dependencies structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDependencies {
    #[serde(default)]
    pub runtime: Vec<String>,
    #[serde(default)]
    pub build: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
}

/// Individual package info result
#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub found: bool,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub candidate_version: Option<String>,
    pub architecture: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    /// The suite/component (apt, as in snapshot) or repository name of the
    /// installed version, or of the candidate when not installed.
    pub repository: Option<String>,
    /// The source URL of that repository, where the manager reports one.
    pub repository_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<PackageDependencies>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dependencies: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

/// Command output structure for internal use
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Available update information
#[derive(Debug, Clone, Serialize)]
pub struct AvailableUpdate {
    pub name: String,
    pub current_version: Option<String>,
    pub candidate_version: String,
    #[serde(default)]
    pub security: bool,
}

/// Update result for a package
#[derive(Debug, Clone, Serialize)]
pub struct UpdateResult {
    pub name: String,
    pub previous_version: Option<String>,
    pub new_version: Option<String>,
    pub action: String, // "upgraded", "unchanged"
}

/// Update summary
#[derive(Debug, Clone, Serialize)]
pub struct UpdateSummary {
    pub upgraded: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Upgrade result for a package
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeResult {
    pub name: String,
    pub previous_version: Option<String>,
    pub new_version: Option<String>,
    pub action: String, // "upgraded", "unchanged"
}

/// Upgrade summary
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeSummary {
    pub upgraded: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Package action result
#[derive(Debug, Clone, Serialize)]
pub struct PackageResult {
    pub name: String,
    pub requested_version: Option<String>,
    pub installed_version: Option<String>,
    pub action: String, // "installed", "upgraded", "reinstalled", "unchanged", "failed", ...
    #[serde(default)]
    pub from_cache: bool,
    /// Why the operation failed (`action: "failed"` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Install result summary
#[derive(Debug, Clone, Serialize)]
pub struct InstallSummary {
    pub installed: u32,
    pub upgraded: u32,
    pub reinstalled: u32,
    pub downgraded: u32,
    pub unchanged: u32,
    pub failed: u32,
}

/// Remove result summary
#[derive(Debug, Clone, Serialize)]
pub struct RemoveSummary {
    pub removed: u32,
    pub purged: u32,
    pub not_installed: u32,
    pub skipped: u32,
    pub failed: u32,
    pub autoremove_run: bool,
}

/// List installed configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ListInstalledConfig {
    pub manager: ManagerKind,
    pub filter: Option<String>,
    pub prefix: Option<String>,
    #[serde(default = "default_true")]
    pub include_versions: bool,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default)]
    pub include_size: bool,
    #[serde(default)]
    pub include_install_reason: bool,
    #[serde(default = "default_list_installed_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

fn default_list_installed_limit() -> u32 {
    500
}

/// Snapshot configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotConfig {
    pub manager: ManagerKind,
    #[serde(default = "default_snapshot_scope")]
    pub scope: SnapshotScope,
    #[serde(default = "default_version_mode")]
    pub include_versions: SnapshotVersionMode,
    #[serde(default = "default_true")]
    pub include_repo: bool,
    #[serde(default = "default_true")]
    pub include_arch: bool,
    #[serde(default = "default_true")]
    pub include_install_reason: bool,
    #[serde(default = "default_true")]
    pub include_os_metadata: bool,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default = "default_snapshot_format")]
    pub format: SnapshotFormat,
    #[serde(default = "default_snapshot_timeout")]
    pub timeout_ms: u64,
    pub env: Option<HashMap<String, String>>,
}

/// Snapshot scope enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotScope {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "dependency")]
    Dependency,
}

/// Snapshot version mode
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotVersionMode {
    #[serde(rename = "exact")]
    Exact,
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "none")]
    None,
}

/// Snapshot format enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum SnapshotFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "yaml")]
    Yaml,
    #[serde(rename = "text")]
    Text,
}

fn default_snapshot_scope() -> SnapshotScope {
    SnapshotScope::All
}
fn default_version_mode() -> SnapshotVersionMode {
    SnapshotVersionMode::Exact
}
fn default_snapshot_format() -> SnapshotFormat {
    SnapshotFormat::Json
}
fn default_snapshot_timeout() -> u64 {
    15000
} // 15 seconds

/// Restore configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreConfig {
    pub manager: ManagerKind,
    pub lockfile: String,
    #[serde(default = "default_restore_format")]
    pub format: LockfileFormat,
    #[serde(default = "default_restore_mode")]
    pub mode: RestoreMode,
    #[serde(default)]
    pub allow_downgrades: bool,
    #[serde(default)]
    pub allow_removals: bool,
    #[serde(default = "default_true")]
    pub allow_newer: bool,
    #[serde(default = "default_missing_policy")]
    pub on_missing_package: MissingPolicy,
    #[serde(default = "default_repo_policy")]
    pub on_repo_mismatch: RepoPolicy,
    #[serde(default = "default_platform_policy")]
    pub on_platform_mismatch: PlatformPolicy,
    #[serde(default = "default_true")]
    pub include_dependencies: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_restore_timeout")]
    pub timeout_ms: u64,
    pub extra_args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

/// Restore mode enumeration
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum RestoreMode {
    #[serde(rename = "exact")]
    Exact,
    #[serde(rename = "best_effort")]
    BestEffort,
}

/// Lockfile format enumeration (for parsing lockfiles)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum LockfileFormat {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "yaml")]
    Yaml,
    #[serde(rename = "text")]
    Text,
}

/// Policy for handling missing packages
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum MissingPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

/// Policy for handling repository mismatches
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum RepoPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

/// Policy for handling platform mismatches
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum PlatformPolicy {
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "ignore")]
    Ignore,
}

fn default_restore_format() -> LockfileFormat {
    LockfileFormat::Auto
}
fn default_restore_mode() -> RestoreMode {
    RestoreMode::Exact
}
fn default_missing_policy() -> MissingPolicy {
    MissingPolicy::Fail
}
fn default_repo_policy() -> RepoPolicy {
    RepoPolicy::Warn
}
fn default_platform_policy() -> PlatformPolicy {
    PlatformPolicy::Warn
}
fn default_restore_timeout() -> u64 {
    180000
} // 3 minutes

/// Lockfile schema structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub lockfile_version: String,
    pub generated_at: String,
    pub manager: ManagerInfo,
    pub platform: PlatformInfo,
    pub scope: String,
    pub packages: Vec<LockfilePackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerInfo {
    pub name: String,
    pub alias: String,
    pub version: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os_family: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel: Option<String>,
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfilePackage {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_spec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_reason: Option<String>,
    #[serde(default)]
    pub pinned: bool,
}

/// Individual installed package result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub repository: Option<String>,
    pub installed_size_bytes: Option<u64>,
    pub install_reason: Option<String>, // "manual" | "dependency" | null
    pub manager_specific: Option<serde_json::Value>,
}

/// List installed results container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInstalledResults {
    pub backend: String,
    pub manager: String,
    pub alias: String,
    pub limit: u32,
    pub offset: u32,
    pub total_installed: u32,
    pub results: Vec<InstalledPackage>,
}

/// Restore plan structure for dry runs and execution planning
#[derive(Debug, Clone, Serialize)]
pub struct RestorePlan {
    pub install: Vec<String>,
    pub upgrade: Vec<String>,
    pub downgrade: Vec<String>,
    pub remove: Vec<String>,
    pub keep: Vec<String>,
    pub extra: Vec<String>,
    pub unresolved: Vec<UnresolvedPackage>,
    /// Locked packages left out of the plan by `include_dependencies: false`
    /// (recorded as installed as a dependency); neither installed nor removed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_dependencies: Vec<String>,
}

/// Unresolved package with reason
#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedPackage {
    pub name: String,
    pub reason: String,
}

/// Package operation result
#[derive(Debug, Clone, Serialize)]
pub struct PackageOpResult {
    pub name: String,
    pub status: String, // "success" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_version: Option<String>,
    /// The version the lockfile asks for, when it records one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_version: Option<String>,
    /// `{code, message}` of a failed operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Restore operation results
#[derive(Debug, Clone, Serialize)]
pub struct RestoreResults {
    pub install: Vec<PackageOpResult>,
    pub upgrade: Vec<PackageOpResult>,
    pub downgrade: Vec<PackageOpResult>,
    pub remove: Vec<PackageOpResult>,
}

/// Restore summary information
#[derive(Debug, Clone, Serialize)]
pub struct RestoreSummary {
    pub installed: u32,
    pub upgraded: u32,
    pub downgraded: u32,
    pub removed: u32,
    pub kept: u32,
    pub extra: u32,
    pub unresolved: u32,
    pub failed: u32,
    pub mode: String,
    pub success: bool,
}

/// Verbs registered by the pkg handle (shared by `Handle::verbs` and the
/// in-URL help forms).
const PKG_VERBS: &[&str] = &[
    "install",
    "remove",
    "update",
    "upgrade",
    "info",
    "search",
    "list_installed",
    "snapshot",
    "restore",
    "apply_lock",
];

/// True for the in-URL help forms `pkg://--help`, `pkg://-h` and `pkg://help`.
fn is_pkg_help_word(s: &str) -> bool {
    crate::core::help::is_help_flag(s) || s == "help"
}

/// Renders the approved pkg help, for one verb when `verb` names a registered verb.
fn pkg_help_text(verb: Option<&str>) -> String {
    crate::core::help::render_legacy("pkg", &PKG_HELP, PKG_VERBS, verb)
}

/// Package handle for managing system packages
#[derive(Debug)]
pub struct PkgHandle {
    pub alias: String,
}

impl PkgHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        // For pkg:// URLs, the alias can be in the host or path
        let alias = if let Some(host) = url.host_str() {
            // Check if host is a help request
            if is_pkg_help_word(host) {
                print!("{}", pkg_help_text(None));
                std::process::exit(0);
            }
            // If we have a host, that's our alias (pkg://system)
            host.to_string()
        } else if url.path() == "/" || url.path().is_empty() {
            // No host and empty path means default
            "default".to_string()
        } else {
            // Path-based alias (pkg:///system)
            let path_alias = url.path().trim_start_matches('/').to_string();
            if is_pkg_help_word(&path_alias) {
                print!("{}", pkg_help_text(None));
                std::process::exit(0);
            }
            path_alias
        };

        if alias.is_empty() {
            return Err(anyhow::anyhow!("pkg:// URLs must specify an alias"));
        }

        Ok(PkgHandle { alias })
    }
}

/// Register the pkg handle with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("pkg", |u| Ok(Box::new(PkgHandle::from_url(u)?)));
}

impl Handle for PkgHandle {
    fn verbs(&self) -> &'static [&'static str] {
        PKG_VERBS
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&PKG_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help forms: help=<verb>, --help[=<verb>], -h, or a help verb.
        let help_arg = ["help", "--help", "-h"].iter().find_map(|k| args.get(*k));
        if help_arg.is_some() || is_pkg_help_word(verb) {
            let wanted = help_arg.map(|v| v.as_str()).filter(|v| !v.is_empty());
            write!(io.stdout, "{}", pkg_help_text(wanted))?;
            return Ok(Status::success());
        }

        if !PKG_VERBS.contains(&verb) {
            return Ok(Status::coded(
                crate::core::status::exit::USAGE,
                "pkg.unknown_verb",
                format!(
                    "unknown verb for pkg://: {verb} (verbs: {}); nothing was done",
                    PKG_VERBS.join(", ")
                ),
            ));
        }
        self.call_verb(verb, args, io)
    }
}

impl PkgHandle {
    /// Runs one verb: checks the arguments and the input keys (exit 2,
    /// nothing run), applies `timeout_ms` as the deadline of every
    /// package-manager process (stopped at the deadline: exit 124), and maps
    /// every failure to a `pkg.*` code and exit status.
    fn call_verb(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let text = match pkg_args::check_args(verb, args) {
            Ok(text) => text,
            Err(reason) => return Ok(usage_error(reason)),
        };
        let input = match pkg_args::check_input(verb, text) {
            Ok(input) => input,
            Err(reason) => return Ok(usage_error(reason)),
        };
        let config = match VerbConfig::parse(verb, input) {
            Ok(config) => config,
            Err(reason) => return Ok(usage_error(reason)),
        };
        let (timeout_ms, env) = config.common();
        if timeout_ms == 0 {
            return Ok(usage_error(format!(
                "timeout_ms must be greater than 0 for pkg {verb}"
            )));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _env = VerbEnv::set(env);
        crate::core::process::limit(Duration::from_millis(timeout_ms));
        let outcome = runtime.block_on(async {
            match config {
                VerbConfig::Install(c) => self.install_async(c).await,
                VerbConfig::Remove(c) => self.remove_async(c).await,
                VerbConfig::Update(c) => self.update_async(c).await,
                VerbConfig::Upgrade(c) => self.upgrade_async(c).await,
                VerbConfig::Info(c) => self.info_async(c).await,
                VerbConfig::Search(c) => self.search_async(c).await,
                VerbConfig::ListInstalled(c) => self.list_installed_async(c).await,
                VerbConfig::Snapshot(c) => self.snapshot_async(c).await,
                VerbConfig::Restore(c) => self.restore_async(c).await,
            }
        });
        crate::core::process::clear_limit();
        let lost = crate::core::process::has_lost();
        match outcome {
            Ok(result) => {
                writeln!(io.stdout, "{}", serde_json::to_string_pretty(&result)?)?;
                io.stdout.flush()?;
                if lost {
                    return Ok(timeout_status(verb, timeout_ms));
                }
                Ok(result_status(verb, &result))
            }
            Err(e) if lost || e.is_timeout() => Ok(timeout_status(verb, timeout_ms)),
            Err(e) => {
                let (exit, code) = e.code();
                Ok(Status::coded(exit, code, e.to_string()))
            }
        }
    }
}

/// A refused request: exit 2, `pkg.invalid_argument`, nothing was run.
fn usage_error(reason: String) -> Status {
    Status::coded(
        crate::core::status::exit::USAGE,
        "pkg.invalid_argument",
        reason,
    )
}

/// The deadline passed: a package-manager process was stopped (or never
/// started), so the outcome is unknown.
fn timeout_status(verb: &str, timeout_ms: u64) -> Status {
    Status::coded(
        crate::core::status::exit::TIMEOUT,
        "pkg.timeout",
        format!(
            "pkg {verb} did not finish within timeout_ms={timeout_ms}; the package manager \
             was stopped and may have left work half done; check its state before retrying"
        ),
    )
}

/// One verb's parsed input.
enum VerbConfig {
    Install(InstallConfig),
    Remove(RemoveConfig),
    Update(UpdateConfig),
    Upgrade(UpgradeConfig),
    Info(InfoConfig),
    Search(SearchConfig),
    ListInstalled(ListInstalledConfig),
    Snapshot(SnapshotConfig),
    Restore(RestoreConfig),
}

impl VerbConfig {
    fn parse(verb: &str, input: Value) -> std::result::Result<Self, String> {
        Ok(match verb {
            "install" => Self::Install(parse_config(verb, input)?),
            "remove" => Self::Remove(parse_config(verb, input)?),
            "update" => Self::Update(parse_config(verb, input)?),
            "upgrade" => Self::Upgrade(parse_config(verb, input)?),
            "info" => Self::Info(parse_config(verb, input)?),
            "search" => Self::Search(parse_config(verb, input)?),
            "list_installed" => Self::ListInstalled(parse_config(verb, input)?),
            "snapshot" => Self::Snapshot(parse_config(verb, input)?),
            "restore" | "apply_lock" => Self::Restore(parse_config(verb, input)?),
            other => return Err(format!("unknown verb for pkg://: {other}")),
        })
    }

    /// `timeout_ms` and `env`, which every verb has.
    fn common(&self) -> (u64, Vec<(String, String)>) {
        let (timeout_ms, env) = match self {
            Self::Install(c) => (c.timeout_ms, &c.env),
            Self::Remove(c) => (c.timeout_ms, &c.env),
            Self::Update(c) => (c.timeout_ms, &c.env),
            Self::Upgrade(c) => (c.timeout_ms, &c.env),
            Self::Info(c) => (c.timeout_ms, &c.env),
            Self::Search(c) => (c.timeout_ms, &c.env),
            Self::ListInstalled(c) => (c.timeout_ms, &c.env),
            Self::Snapshot(c) => (c.timeout_ms, &c.env),
            Self::Restore(c) => (c.timeout_ms, &c.env),
        };
        let mut env: Vec<(String, String)> = env
            .iter()
            .flatten()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        env.sort();
        (timeout_ms, env)
    }
}

/// Deserializes a verb's input. A value of the wrong type or outside its
/// accepted set is refused with the key named.
fn parse_config<T: serde::de::DeserializeOwned>(
    verb: &str,
    input: Value,
) -> std::result::Result<T, String> {
    let err = match serde_json::from_value::<T>(input.clone()) {
        Ok(config) => return Ok(config),
        Err(e) => e,
    };
    // The key whose removal makes the input parse is the one at fault.
    let culprit = input.as_object().and_then(|object| {
        let mut keys: Vec<&String> = object.keys().collect();
        keys.sort();
        keys.into_iter()
            .find(|key| {
                let mut rest = object.clone();
                rest.remove(*key);
                serde_json::from_value::<T>(Value::Object(rest)).is_ok()
            })
            .cloned()
            // A required key cannot be removed: find it by the value the
            // error quotes (such as an unknown manager name).
            .or_else(|| {
                let text = err.to_string();
                let mut keys: Vec<&String> = object.keys().collect();
                keys.sort();
                keys.into_iter()
                    .find(|key| {
                        object[*key].as_str().is_some_and(|v| {
                            text.contains(&format!("`{v}`")) || text.contains(&format!("\"{v}\""))
                        })
                    })
                    .cloned()
            })
    });
    Err(match culprit {
        Some(key) => format!("invalid value for `{key}` in pkg {verb} input: {err}"),
        None => format!("invalid input for pkg {verb}: {err}"),
    })
}

thread_local! {
    /// The `env` of the verb being run, set in every package-manager process
    /// it starts (after `LC_ALL=C`, so the caller can override that).
    static VERB_ENV: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Holds the verb's `env` while it runs.
struct VerbEnv;

impl VerbEnv {
    fn set(env: Vec<(String, String)>) -> Self {
        VERB_ENV.with(|e| *e.borrow_mut() = env);
        VerbEnv
    }
}

impl Drop for VerbEnv {
    fn drop(&mut self) {
        VERB_ENV.with(|e| e.borrow_mut().clear());
    }
}

/// A package-manager command: `LC_ALL=C` so its output is parsed in the
/// language the parsers read, then the verb's `env`.
fn pkg_cmd(program: &str) -> AsyncCommand {
    let mut command = AsyncCommand::new(program);
    command.env("LC_ALL", "C");
    VERB_ENV.with(|env| {
        for (name, value) in env.borrow().iter() {
            command.env(name, value);
        }
    });
    command
}

impl PkgHandle {
    async fn install_async(&self, config: InstallConfig) -> Result<Value, PkgError> {
        self.validate_config(&config)?;
        let manager = self.resolve_manager(&config.manager).await?;
        check_install_support(&config, &manager)?;
        self.check_downgrades(&config, &manager).await?;
        if config.dry_run {
            return self.dry_run_install(&config, &manager).await;
        }
        self.perform_install(&config, &manager).await
    }

    /// Validate install configuration
    fn validate_config(&self, config: &InstallConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidInstallConfig(
                "packages cannot be empty".to_string(),
            ));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.name.trim().is_empty() {
                return Err(PkgError::InvalidInstallConfig(
                    "package name cannot be empty".to_string(),
                ));
            }
            check_pkg_token("package name", &pkg.name).map_err(PkgError::InvalidInstallConfig)?;
            if let Some(ref v) = pkg.version {
                check_pkg_token("version", v).map_err(PkgError::InvalidInstallConfig)?;
            }
            check_no_package_source(pkg).map_err(PkgError::InvalidInstallConfig)?;
        }
        if let Some(ref arch) = config.arch {
            check_pkg_token("arch", arch).map_err(PkgError::InvalidInstallConfig)?;
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidInstallConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidInstallConfig(
                    "extra_args cannot contain empty strings".to_string(),
                ));
            }
        }

        // Check contradictory flags
        if config.only_if_missing && config.reinstall {
            return Err(PkgError::InvalidInstallConfig(
                "only_if_missing and reinstall are contradictory".to_string(),
            ));
        }

        if config.only_if_missing && config.upgrade {
            return Err(PkgError::InvalidInstallConfig(
                "only_if_missing and upgrade are contradictory".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate info configuration
    fn validate_info_config(&self, config: &InfoConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidInfoConfig(
                "packages cannot be empty".to_string(),
            ));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.trim().is_empty() {
                return Err(PkgError::InvalidInfoConfig(
                    "package name cannot be empty".to_string(),
                ));
            }
            check_pkg_token("package name", pkg).map_err(PkgError::InvalidInfoConfig)?;
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidInfoConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        // Check env if present
        if let Some(ref env) = config.env {
            for (key, value) in env {
                if key.is_empty() || value.is_empty() {
                    return Err(PkgError::InvalidInfoConfig(
                        "env keys and values cannot be empty".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Resolve manager from config or auto-detect
    async fn resolve_manager(&self, manager: &ManagerKind) -> Result<ManagerKind, PkgError> {
        match manager {
            ManagerKind::Auto => self.detect_manager().await,
            _ => {
                // Check if specified manager is available
                if self.is_manager_available(manager).await? {
                    Ok(manager.clone())
                } else {
                    Err(PkgError::ManagerNotAvailable(format!("{:?}", manager)))
                }
            }
        }
    }

    /// Auto-detect available package manager
    async fn detect_manager(&self) -> Result<ManagerKind, PkgError> {
        // Detection order: apt, dnf/yum, pacman, apk, brew
        let managers = [
            (ManagerKind::Apt, "apt-get"),
            (ManagerKind::Dnf, "dnf"),
            (ManagerKind::Yum, "yum"),
            (ManagerKind::Pacman, "pacman"),
            (ManagerKind::Apk, "apk"),
            (ManagerKind::Brew, "brew"),
        ];

        for (manager, binary) in &managers {
            if which(binary).is_ok() {
                return Ok(manager.clone());
            }
        }

        Err(PkgError::ManagerNotAvailable(
            "No supported package manager found".to_string(),
        ))
    }

    /// Check if manager is available on system
    async fn is_manager_available(&self, manager: &ManagerKind) -> Result<bool, PkgError> {
        let binary = match manager {
            ManagerKind::Auto => {
                return Err(PkgError::InvalidInstallConfig(
                    "Auto should be resolved first".to_string(),
                ));
            }
            ManagerKind::Apt => "apt-get",
            ManagerKind::Dnf => "dnf",
            ManagerKind::Yum => "yum",
            ManagerKind::Pacman => "pacman",
            ManagerKind::Apk => "apk",
            ManagerKind::Brew => "brew",
        };

        Ok(which(binary).is_ok())
    }

    /// Perform dry run installation
    async fn dry_run_install(
        &self,
        config: &InstallConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut packages = Vec::new();

        if config.update_cache {
            commands.push(self.build_update_cache_command(manager)?.to_string());
        }

        // The same per-package decision and command as a real install.
        for pkg in &config.packages {
            let installed = self.installed_version_of(&pkg.name, manager).await;
            let action = match install_step(config, pkg, installed.as_deref(), manager) {
                InstallStep::Skip => "already_installed",
                InstallStep::Reinstall => "would_reinstall",
                InstallStep::Upgrade => "would_upgrade",
                InstallStep::Downgrade => "would_downgrade",
                InstallStep::Install if installed.is_some() => "would_change_version",
                InstallStep::Install => "would_install",
            };
            if action != "already_installed" {
                let step = install_step(config, pkg, installed.as_deref(), manager);
                commands.push(
                    self.build_install_command(config, pkg, manager, step)?
                        .to_string(),
                );
            }
            packages.push(json!({
                "name": pkg.name,
                "action": action,
                "installed_version": installed,
                "requested_version": pkg.version,
            }));
        }

        Ok(json!({
            "backend": "pkg",
            "manager": manager_name(manager),
            "alias": self.alias,
            "dry_run": true,
            "commands": commands,
            "packages": packages
        }))
    }

    /// Perform actual installation
    async fn perform_install(
        &self,
        config: &InstallConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = InstallSummary {
            installed: 0,
            upgraded: 0,
            reinstalled: 0,
            downgraded: 0,
            unchanged: 0,
            failed: 0,
        };

        if config.update_cache {
            self.update_package_cache(manager).await?;
        }

        for pkg in &config.packages {
            let result = match self.install_single_package(pkg, config, manager).await {
                Ok(result) => result,
                Err(e) => PackageResult {
                    name: pkg.name.clone(),
                    requested_version: pkg.version.clone(),
                    installed_version: self.installed_version_of(&pkg.name, manager).await,
                    action: "failed".to_string(),
                    from_cache: false,
                    error: Some(error_value(&e)),
                },
            };
            match result.action.as_str() {
                "installed" => summary.installed += 1,
                "upgraded" => summary.upgraded += 1,
                "reinstalled" => summary.reinstalled += 1,
                "downgraded" => summary.downgraded += 1,
                "unchanged" => summary.unchanged += 1,
                _ => summary.failed += 1,
            }
            results.push(result);
            if crate::core::process::has_lost() {
                // The deadline passed: nothing more is started.
                break;
            }
        }

        Ok(json!({
            "backend": "pkg",
            "manager": manager_name(manager),
            "alias": self.alias,
            "update_cache": config.update_cache,
            "dry_run": false,
            "packages": results,
            "summary": summary
        }))
    }

    /// Build cache update command for manager
    fn build_update_cache_command(&self, manager: &ManagerKind) -> Result<CmdLine, PkgError> {
        match manager {
            ManagerKind::Apt => Ok(CmdLine::lit("apt-get update")),
            ManagerKind::Dnf => Ok(CmdLine::lit("dnf makecache")),
            ManagerKind::Yum => Ok(CmdLine::lit("yum makecache")),
            ManagerKind::Pacman => Ok(CmdLine::lit("pacman -Sy")),
            ManagerKind::Apk => Ok(CmdLine::lit("apk update")),
            ManagerKind::Brew => Ok(CmdLine::lit("brew update")),
            _ => Err(PkgError::ManagerNotAvailable(
                "Unsupported manager".to_string(),
            )),
        }
    }

    /// Build install command for manager and packages
    /// Refuses a requested version older than the installed one unless
    /// `allow_downgrade` is set, before anything runs (dry run included).
    async fn check_downgrades(
        &self,
        config: &InstallConfig,
        manager: &ManagerKind,
    ) -> Result<(), PkgError> {
        let mut older = Vec::new();
        for pkg in config.packages.iter().filter(|p| p.version.is_some()) {
            let installed = self.installed_version_of(&pkg.name, manager).await;
            if install_step(config, pkg, installed.as_deref(), manager) == InstallStep::Downgrade {
                older.push(format!(
                    "{} {} (installed: {})",
                    pkg.name,
                    pkg.version.as_deref().unwrap_or_default(),
                    installed.unwrap_or_default()
                ));
            }
        }
        if older.is_empty() || config.allow_downgrade {
            return Ok(());
        }
        Err(PkgError::DowngradeRefused(format!(
            "{} requested version(s) are older than the installed one: {}; set \
             allow_downgrade to install them; nothing was run",
            older.len(),
            name_list(&older)
        )))
    }

    /// The command that installs (or upgrades, or reinstalls) one package.
    fn build_install_command(
        &self,
        config: &InstallConfig,
        pkg: &PackageSpec,
        manager: &ManagerKind,
        step: InstallStep,
    ) -> Result<CmdLine, PkgError> {
        let upgrade = step == InstallStep::Upgrade;
        let reinstall = step == InstallStep::Reinstall;
        let downgrade = step == InstallStep::Downgrade;
        let mut cmd = match manager {
            ManagerKind::Apt => {
                let mut base = CmdLine::lit("DEBIAN_FRONTEND=noninteractive apt-get install");
                if config.assume_yes {
                    base.push_lit(" -y");
                }
                if reinstall {
                    base.push_lit(" --reinstall");
                }
                if upgrade {
                    base.push_lit(" --only-upgrade");
                }
                if downgrade {
                    base.push_lit(" --allow-downgrades");
                }
                base
            }
            ManagerKind::Dnf | ManagerKind::Yum => {
                let tool = if *manager == ManagerKind::Dnf {
                    "dnf"
                } else {
                    "yum"
                };
                let verb = if reinstall {
                    "reinstall"
                } else if upgrade {
                    "upgrade"
                } else if downgrade {
                    "downgrade"
                } else {
                    "install"
                };
                let mut base = CmdLine::lit(tool);
                base.push_lit(verb);
                if config.assume_yes {
                    base.push_lit(" -y");
                }
                base
            }
            ManagerKind::Pacman => {
                let mut base = CmdLine::lit("pacman -S");
                if config.assume_yes {
                    base.push_lit(" --noconfirm");
                }
                // Without reinstall, a package that is up to date is left
                // alone (and an outdated one is upgraded).
                if !reinstall {
                    base.push_lit(" --needed");
                }
                base
            }
            ManagerKind::Apk => {
                // `apk fix` reinstalls an installed package.
                let mut base = CmdLine::lit(if reinstall {
                    "apk fix --no-interactive"
                } else {
                    "apk add --no-interactive"
                });
                if upgrade {
                    base.push_lit(" --upgrade");
                }
                base
            }
            ManagerKind::Brew => CmdLine::lit(if reinstall {
                "brew reinstall"
            } else if upgrade {
                "brew upgrade"
            } else {
                "brew install"
            }),
            ManagerKind::Auto => {
                return Err(PkgError::ManagerNotAvailable(
                    "manager auto was not resolved".to_string(),
                ));
            }
        };

        cmd.arg(&self.format_package_name(pkg, manager, config)?);
        if let Some(ref extra_args) = config.extra_args {
            for arg in extra_args {
                cmd.arg(arg);
            }
        }
        Ok(cmd)
    }

    /// Format package name for specific manager
    /// The package argument: `name`, with the requested version and `arch`
    /// in the manager's syntax (`check_install_support` has refused the
    /// managers that have none).
    fn format_package_name(
        &self,
        pkg: &PackageSpec,
        manager: &ManagerKind,
        config: &InstallConfig,
    ) -> Result<String, PkgError> {
        Ok(package_argument(
            manager,
            &pkg.name,
            pkg.version.as_deref(),
            config.arch.as_deref(),
        ))
    }

    /// The installed version of a package, or None when it is not installed.
    /// apt counts only packages in dpkg state `installed` (a removed package
    /// whose configuration files remain is not installed).
    async fn installed_version_of(
        &self,
        package_name: &str,
        manager: &ManagerKind,
    ) -> Option<String> {
        let mut cmd = match manager {
            ManagerKind::Apt => {
                CmdLine::lit("dpkg-query -W -f=${db:Status-Status}\\t${Version}\\n")
            }
            ManagerKind::Dnf | ManagerKind::Yum => {
                CmdLine::lit("rpm -q --qf %|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n")
            }
            ManagerKind::Pacman => CmdLine::lit("pacman -Q"),
            ManagerKind::Apk => CmdLine::lit("apk info -e -v"),
            ManagerKind::Brew => CmdLine::lit("brew list --versions"),
            ManagerKind::Auto => return None,
        };
        cmd.arg(package_name);
        let output = cmd.command().bounded_output().await.ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_installed_version(manager, package_name, &stdout)
    }

    /// Update package cache
    async fn update_package_cache(&self, manager: &ManagerKind) -> Result<(), PkgError> {
        let cmd = self.build_update_cache_command(manager)?;

        let output = cmd
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .bounded_output()
            .await
            .map_err(|e| PkgError::UpdateCacheFailed(format!("Failed to update cache: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::UpdateCacheFailed(format!(
                "Cache update failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Install single package
    /// Installs one package: skipped when `only_if_missing` finds it
    /// installed (at the requested version, when one is given), upgraded in
    /// place with `upgrade`, reinstalled with `reinstall`. The action is
    /// decided from the installed version before and after.
    async fn install_single_package(
        &self,
        pkg: &PackageSpec,
        config: &InstallConfig,
        manager: &ManagerKind,
    ) -> Result<PackageResult, PkgError> {
        let before = self.installed_version_of(&pkg.name, manager).await;
        let step = install_step(config, pkg, before.as_deref(), manager);
        if step == InstallStep::Skip {
            return Ok(PackageResult {
                name: pkg.name.clone(),
                requested_version: pkg.version.clone(),
                installed_version: before,
                action: "unchanged".to_string(),
                from_cache: false,
                error: None,
            });
        }

        let cmd = self.build_install_command(config, pkg, manager, step)?;
        let output = cmd
            .command()
            .bounded_output()
            .await
            .map_err(|e| PkgError::InstallFailed(format!("could not run {cmd}: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(self.map_install_error(
                &format!("{}{}", stderr, tail_lines(&stdout, 5)),
                &output.status.code(),
            ));
        }

        let after = self.installed_version_of(&pkg.name, manager).await;
        let action = if after.is_none() {
            // The manager reported success but the package is not installed.
            return Err(PkgError::InstallFailed(format!(
                "{cmd} succeeded but {} is not installed afterwards",
                pkg.name
            )));
        } else if before.is_none() {
            "installed"
        } else if step == InstallStep::Reinstall {
            "reinstalled"
        } else if step == InstallStep::Downgrade {
            "downgraded"
        } else if before != after {
            "upgraded"
        } else {
            "unchanged"
        };

        Ok(PackageResult {
            name: pkg.name.clone(),
            requested_version: pkg.version.clone(),
            installed_version: after,
            action: action.to_string(),
            from_cache: false,
            error: None,
        })
    }

    /// Map install error from stderr and exit code
    fn map_install_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();

        // Check for specific error patterns
        if is_not_found_message(&stderr_lower) {
            PkgError::InstallNotFound(stderr.to_string())
        } else if is_permission_message(&stderr_lower) || exit_code == &Some(13) {
            PkgError::InstallPermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("dependency")
            || stderr_lower.contains("broken")
            || stderr_lower.contains("unresolved")
        {
            PkgError::InstallDependencyFailure(stderr.to_string())
        } else if stderr_lower.contains("conflict")
            || stderr_lower.contains("already installed") && stderr_lower.contains("error")
        {
            PkgError::InstallConflict(stderr.to_string())
        } else if stderr_lower.contains("version") && stderr_lower.contains("invalid") {
            PkgError::InstallInvalidVersion(stderr.to_string())
        } else {
            PkgError::InstallFailed(stderr.to_string())
        }
    }

    // ===== REMOVE METHODS =====

    async fn remove_async(&self, config: RemoveConfig) -> Result<Value, PkgError> {
        self.validate_remove_config(&config)?;
        let manager = self.resolve_manager(&config.manager).await?;
        check_remove_support(&config, &manager)?;
        if config.dry_run {
            return self.dry_run_remove(&config, &manager).await;
        }
        self.perform_remove(&config, &manager).await
    }

    /// Validate remove configuration
    pub fn validate_remove_config(&self, config: &RemoveConfig) -> Result<(), PkgError> {
        // Check packages is not empty
        if config.packages.is_empty() {
            return Err(PkgError::InvalidRemoveConfig(
                "packages cannot be empty".to_string(),
            ));
        }

        // Check package names are not empty
        for pkg in &config.packages {
            if pkg.name.trim().is_empty() {
                return Err(PkgError::InvalidRemoveConfig(
                    "package name cannot be empty".to_string(),
                ));
            }
            check_pkg_token("package name", &pkg.name).map_err(PkgError::InvalidRemoveConfig)?;
            if let Some(ref v) = pkg.version {
                check_pkg_token("version", v).map_err(PkgError::InvalidRemoveConfig)?;
            }
            check_no_package_source(pkg).map_err(PkgError::InvalidRemoveConfig)?;
        }
        if let Some(ref arch) = config.arch {
            check_pkg_token("arch", arch).map_err(PkgError::InvalidRemoveConfig)?;
        }

        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidRemoveConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidRemoveConfig(
                    "extra_args cannot contain empty strings".to_string(),
                ));
            }
        }

        // Check contradictory flags
        if config.only_if_installed && config.fail_if_missing {
            return Err(PkgError::InvalidRemoveConfig(
                "only_if_installed and fail_if_missing are contradictory".to_string(),
            ));
        }

        Ok(())
    }

    /// Reports the packages a removal would act on and the commands it
    /// would run, without running them.
    async fn dry_run_remove(
        &self,
        config: &RemoveConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut packages = Vec::new();
        let mut to_remove = Vec::new();
        for pkg in &config.packages {
            let installed = self.installed_version_of(&pkg.name, manager).await;
            let action = match remove_step(config, pkg, installed.as_deref()) {
                RemoveStep::Remove => {
                    to_remove.push(pkg);
                    if config.purge {
                        "would_purge"
                    } else {
                        "would_remove"
                    }
                }
                RemoveStep::NotInstalled => "not_installed",
                RemoveStep::Missing => "would_fail_not_installed",
                RemoveStep::OtherVersion => "would_fail_other_version",
            };
            packages.push(json!({
                "name": pkg.name,
                "action": action,
                "installed_version": installed,
            }));
        }
        if !to_remove.is_empty() {
            commands.push(
                self.build_remove_command(&to_remove, config, manager)
                    .await?
                    .to_string(),
            );
            if config.recursive {
                if let Some(cmd) = self.build_autoremove_command(manager)? {
                    commands.push(cmd.to_string());
                }
            }
        }
        Ok(json!({
            "backend": "pkg",
            "manager": manager_name(manager),
            "alias": self.alias,
            "dry_run": true,
            "purge": config.purge,
            "recursive": config.recursive,
            "commands": commands,
            "packages": packages
        }))
    }

    /// Removes the packages in one manager command, then checks that each
    /// one is gone. Packages that are not installed are reported (or fail
    /// with `fail_if_missing`); with `recursive`, unused dependencies are
    /// removed afterwards.
    async fn perform_remove(
        &self,
        config: &RemoveConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = RemoveSummary {
            removed: 0,
            purged: 0,
            not_installed: 0,
            skipped: 0,
            failed: 0,
            autoremove_run: false,
        };
        let failed = |pkg: &PackageSpec, installed: Option<String>, e: PkgError| PackageResult {
            name: pkg.name.clone(),
            requested_version: pkg.version.clone(),
            installed_version: installed,
            action: "failed".to_string(),
            from_cache: false,
            error: Some(error_value(&e)),
        };

        let mut to_remove = Vec::new();
        let mut before = HashMap::new();
        for pkg in &config.packages {
            let installed = self.installed_version_of(&pkg.name, manager).await;
            match remove_step(config, pkg, installed.as_deref()) {
                RemoveStep::Remove => {
                    before.insert(pkg.name.clone(), installed);
                    to_remove.push(pkg);
                }
                RemoveStep::NotInstalled => {
                    summary.not_installed += 1;
                    results.push(PackageResult {
                        name: pkg.name.clone(),
                        requested_version: pkg.version.clone(),
                        installed_version: None,
                        action: "not_installed".to_string(),
                        from_cache: false,
                        error: None,
                    });
                }
                RemoveStep::Missing => {
                    summary.failed += 1;
                    results.push(failed(
                        pkg,
                        None,
                        PkgError::RemoveNotInstalled(format!(
                            "{} is not installed (fail_if_missing)",
                            pkg.name
                        )),
                    ));
                }
                RemoveStep::OtherVersion => {
                    summary.failed += 1;
                    let e = PkgError::RemoveNotInstalled(format!(
                        "{} {} is not installed (installed: {})",
                        pkg.name,
                        pkg.version.as_deref().unwrap_or(""),
                        installed.as_deref().unwrap_or("none")
                    ));
                    results.push(failed(pkg, installed, e));
                }
            }
        }

        let mut autoremove_error = None;
        if !to_remove.is_empty() {
            match self
                .remove_packages_batch(&to_remove, config, manager)
                .await
            {
                Ok(()) => {
                    for pkg in &to_remove {
                        let previous = before.get(&pkg.name).cloned().flatten();
                        match self.installed_version_of(&pkg.name, manager).await {
                            None => {
                                let action = if config.purge {
                                    summary.purged += 1;
                                    "purged"
                                } else {
                                    "removed"
                                };
                                summary.removed += 1;
                                results.push(PackageResult {
                                    name: pkg.name.clone(),
                                    requested_version: pkg.version.clone(),
                                    installed_version: previous,
                                    action: action.to_string(),
                                    from_cache: false,
                                    error: None,
                                });
                            }
                            // Previously absent and still absent is handled
                            // above; here the package is still installed.
                            Some(still) => {
                                summary.failed += 1;
                                let e = PkgError::RemoveFailed(format!(
                                    "{} is still installed ({still}) after the remove command",
                                    pkg.name
                                ));
                                results.push(failed(pkg, Some(still), e));
                            }
                        }
                    }
                }
                Err(e) => {
                    summary.failed += to_remove.len() as u32;
                    for pkg in &to_remove {
                        let previous = before.get(&pkg.name).cloned().flatten();
                        results.push(failed(pkg, previous, e.clone()));
                    }
                }
            }

            if config.recursive && summary.removed > 0 && !crate::core::process::has_lost() {
                match self.run_autoremove(manager, config).await {
                    Ok(ran) => summary.autoremove_run = ran,
                    Err(e) => autoremove_error = Some(error_value(&e)),
                }
            }
        }

        let mut result = json!({
            "backend": "pkg",
            "manager": manager_name(manager),
            "alias": self.alias,
            "dry_run": false,
            "purge": config.purge,
            "recursive": config.recursive,
            "packages": results,
            "summary": summary
        });
        if let Some(e) = autoremove_error {
            result["autoremove_error"] = e;
        }
        Ok(result)
    }

    /// Runs one remove command for `packages`.
    async fn remove_packages_batch(
        &self,
        packages: &[&PackageSpec],
        config: &RemoveConfig,
        manager: &ManagerKind,
    ) -> Result<(), PkgError> {
        let cmd = self.build_remove_command(packages, config, manager).await?;
        let output = cmd
            .command()
            .bounded_output()
            .await
            .map_err(|e| PkgError::RemoveFailed(format!("could not run {cmd}: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(self.map_remove_error(
                &format!("{}{}", stderr, tail_lines(&stdout, 5)),
                &output.status.code(),
            ));
        }
        Ok(())
    }

    /// The command that removes `packages` (refused options were checked by
    /// `check_remove_support`).
    pub async fn build_remove_command(
        &self,
        packages: &[&PackageSpec],
        config: &RemoveConfig,
        manager: &ManagerKind,
    ) -> Result<CmdLine, PkgError> {
        let mut cmd = match manager {
            ManagerKind::Apt => {
                let mut cmd = CmdLine::lit(if config.purge {
                    "DEBIAN_FRONTEND=noninteractive apt-get purge"
                } else {
                    "DEBIAN_FRONTEND=noninteractive apt-get remove"
                });
                if config.assume_yes {
                    cmd.push_lit(" -y");
                }
                cmd
            }
            ManagerKind::Dnf | ManagerKind::Yum => {
                let mut cmd = CmdLine::lit(manager_name(manager));
                cmd.push_lit("remove");
                if config.assume_yes {
                    cmd.push_lit(" -y");
                }
                cmd
            }
            ManagerKind::Pacman => {
                // -s: also dependencies nothing else needs; -n: configuration
                // files are deleted instead of kept as .pacsave.
                let mut flags = String::from("-R");
                if config.recursive {
                    flags.push('s');
                }
                if config.purge {
                    flags.push('n');
                }
                let mut cmd = CmdLine::lit("pacman");
                cmd.push_lit(&flags);
                if config.assume_yes {
                    cmd.push_lit(" --noconfirm");
                }
                cmd
            }
            ManagerKind::Apk => {
                let mut cmd = CmdLine::lit("apk del --no-interactive");
                if config.purge {
                    cmd.push_lit(" --purge");
                }
                cmd
            }
            ManagerKind::Brew => CmdLine::lit("brew uninstall"),
            ManagerKind::Auto => {
                return Err(PkgError::ManagerNotAvailable(
                    "manager auto was not resolved".to_string(),
                ));
            }
        };
        for pkg in packages {
            cmd.arg(&self.format_remove_package_name(pkg, manager, config)?);
        }
        if let Some(ref extra_args) = config.extra_args {
            for arg in extra_args {
                cmd.arg(arg);
            }
        }
        Ok(cmd)
    }

    /// The command that removes dependencies nothing needs any more, for
    /// `recursive`. pacman does it in the remove command itself (`-Rs`) and
    /// apk on every removal, so they have none.
    pub fn build_autoremove_command(
        &self,
        manager: &ManagerKind,
    ) -> Result<Option<CmdLine>, PkgError> {
        Ok(match manager {
            ManagerKind::Apt => Some(CmdLine::lit(
                "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y",
            )),
            ManagerKind::Dnf => Some(CmdLine::lit("dnf autoremove -y")),
            ManagerKind::Yum => Some(CmdLine::lit("yum autoremove -y")),
            ManagerKind::Brew => Some(CmdLine::lit("brew autoremove")),
            ManagerKind::Pacman | ManagerKind::Apk => None,
            ManagerKind::Auto => {
                return Err(PkgError::ManagerNotAvailable(
                    "manager auto was not resolved".to_string(),
                ));
            }
        })
    }

    /// Removes unused dependencies after a removal (`recursive`). Returns
    /// whether dependencies were taken care of: by the autoremove command, or
    /// by the removal itself for pacman (`-Rs`) and apk.
    async fn run_autoremove(
        &self,
        manager: &ManagerKind,
        _config: &RemoveConfig,
    ) -> Result<bool, PkgError> {
        let Some(cmd) = self.build_autoremove_command(manager)? else {
            return Ok(true);
        };
        let output = cmd
            .command()
            .bounded_output()
            .await
            .map_err(|e| PkgError::RemoveFailed(format!("could not run {cmd}: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::RemoveFailed(format!(
                "{cmd} failed: {}",
                stderr.trim()
            )));
        }
        Ok(true)
    }

    /// The package argument for a removal: the name, with the version and
    /// `arch` in the manager's syntax.
    pub fn format_remove_package_name(
        &self,
        pkg: &PackageSpec,
        manager: &ManagerKind,
        config: &RemoveConfig,
    ) -> Result<String, PkgError> {
        Ok(package_argument(
            manager,
            &pkg.name,
            pkg.version.as_deref(),
            config.arch.as_deref(),
        ))
    }

    /// Map remove error from stderr and exit code
    pub fn map_remove_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();

        // Check for specific error patterns
        if is_not_found_message(&stderr_lower)
            || (stderr_lower.contains("package") && stderr_lower.contains("not installed"))
        {
            PkgError::RemoveNotFound(stderr.to_string())
        } else if is_permission_message(&stderr_lower) || exit_code == &Some(13) {
            PkgError::RemovePermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("dependency")
            || stderr_lower.contains("required by")
            || stderr_lower.contains("needed by")
        {
            PkgError::RemoveDependencyFailure(stderr.to_string())
        } else {
            PkgError::RemoveFailed(stderr.to_string())
        }
    }

    // ===== UPDATE METHODS =====

    async fn update_async(&self, config: UpdateConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_update_config(&config)?;

        // Refuse an unhonorable security_only before touching the host: for
        // an explicit manager here, for `auto` once it is detected.
        if config.security_only
            && config.manager != ManagerKind::Auto
            && !security_only_supported("update", &config.manager)
        {
            return Err(PkgError::Unsupported(security_only_refusal(
                "update",
                &config.manager,
            )));
        }

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        if config.security_only && !security_only_supported("update", &manager) {
            return Err(PkgError::Unsupported(security_only_refusal(
                "update", &manager,
            )));
        }
        check_confirmation_support("update", config.assume_yes, &manager)?;

        // Check for check-only or dry-run modes
        if config.check_only || config.dry_run {
            return self.check_or_dry_run_update(&config, &manager).await;
        }

        // Perform actual update with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_update(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::UpdateTimeout)?;

        result
    }

    /// Validate update configuration
    fn validate_update_config(&self, config: &UpdateConfig) -> Result<(), PkgError> {
        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidUpdateConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidUpdateConfig(
                    "extra_args cannot contain empty strings".to_string(),
                ));
            }
        }

        for pkg in &config.packages {
            check_pkg_token("package name", pkg).map_err(PkgError::InvalidUpdateConfig)?;
        }

        // Check that there's something to do
        if !config.refresh_index && !config.upgrade && !config.check_only {
            return Err(PkgError::InvalidUpdateConfig(
                "Nothing to do: refresh_index, upgrade, and check_only are all false".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate upgrade configuration
    fn validate_upgrade_config(&self, config: &UpgradeConfig) -> Result<(), PkgError> {
        // Check timeout
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidUpgradeConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        // Check extra_args if present
        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.is_empty()) {
                return Err(PkgError::InvalidUpgradeConfig(
                    "extra_args cannot contain empty strings".to_string(),
                ));
            }
        }

        // Check packages if present
        if config.packages.iter().any(|pkg| pkg.trim().is_empty()) {
            return Err(PkgError::InvalidUpgradeConfig(
                "package names cannot be empty".to_string(),
            ));
        }
        for pkg in &config.packages {
            check_pkg_token("package name", pkg).map_err(PkgError::InvalidUpgradeConfig)?;
        }

        // Check for meaningless combination
        if config.dry_run
            && config.check_only
            && !config.refresh_index
            && config.packages.is_empty()
        {
            return Err(PkgError::InvalidUpgradeConfig("Nothing meaningful to do: dry_run and check_only are both true, no refresh_index, and no packages specified".to_string()));
        }

        Ok(())
    }

    /// Handle check-only or dry-run update modes
    async fn check_or_dry_run_update(
        &self,
        config: &UpdateConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut commands = Vec::new();
        let mut available_updates = Vec::new();

        // Add refresh index command if requested
        if config.refresh_index {
            commands.push(self.build_update_cache_command(manager)?.to_string());
        }

        // Get available updates
        if config.upgrade || config.check_only {
            available_updates = self.get_available_updates(config, manager).await?;

            if config.upgrade && config.dry_run {
                // Add upgrade commands for dry-run
                let upgrade_cmd = self
                    .build_upgrade_command(config, manager, &available_updates)
                    .await?;
                commands.push(upgrade_cmd.to_string());
            }
        }

        let packages_scope = if config.packages.is_empty() {
            "all"
        } else {
            "subset"
        };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "upgrade": config.upgrade,
            "check_only": config.check_only,
            "dry_run": config.dry_run,
            "packages_scope": packages_scope,
            "commands": commands,
            "available_updates": available_updates
        }))
    }

    /// Handle check-only or dry-run upgrade modes
    async fn check_or_dry_run_upgrade(
        &self,
        config: &UpgradeConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut commands = Vec::new();

        // Add refresh index command if requested
        if config.refresh_index {
            commands.push(self.build_update_cache_command(manager)?.to_string());
        }

        // Get available upgrades
        let available_updates = self.get_available_upgrades(config, manager).await?;

        if !config.check_only && config.dry_run {
            // Add upgrade commands for dry-run
            let upgrade_cmd = self
                .build_upgrade_command_for_execution(config, manager, &available_updates)
                .await?;
            commands.push(upgrade_cmd.to_string());
        }

        let packages_scope = if config.packages.is_empty() {
            "all"
        } else {
            "subset"
        };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "dry_run": config.dry_run,
            "check_only": config.check_only,
            "packages_scope": packages_scope,
            "commands": commands,
            "available_upgrades": available_updates
        }))
    }

    async fn upgrade_async(&self, config: UpgradeConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_upgrade_config(&config)?;

        // Refuse an unhonorable security_only before touching the host: for
        // an explicit manager here, for `auto` once it is detected.
        if config.security_only
            && config.manager != ManagerKind::Auto
            && !security_only_supported("upgrade", &config.manager)
        {
            return Err(PkgError::Unsupported(security_only_refusal(
                "upgrade",
                &config.manager,
            )));
        }

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;
        if config.security_only && !security_only_supported("upgrade", &manager) {
            return Err(PkgError::Unsupported(security_only_refusal(
                "upgrade", &manager,
            )));
        }
        check_confirmation_support("upgrade", config.assume_yes, &manager)?;

        // Check for check-only or dry-run modes
        if config.check_only || config.dry_run {
            return self.check_or_dry_run_upgrade(&config, &manager).await;
        }

        // Perform actual upgrade with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_upgrade(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::UpgradeTimeout)?;

        result
    }

    /// Perform actual update operation
    async fn perform_update(
        &self,
        config: &UpdateConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = UpdateSummary {
            upgraded: 0,
            unchanged: 0,
            failed: 0,
        };

        // Step 1: Refresh index if requested
        if config.refresh_index {
            self.update_package_cache(manager)
                .await
                .map_err(|e| PkgError::UpdateIndexFailed(e.to_string()))?;
        }

        // Step 2: Get available updates if needed
        let available_updates = if config.upgrade {
            self.get_available_updates(config, manager)
                .await
                .map_err(|e| PkgError::UpdateCheckFailed(e.to_string()))?
        } else {
            Vec::new()
        };

        // Step 3: Apply upgrades if requested
        if config.upgrade && !available_updates.is_empty() {
            match self
                .apply_updates(config, manager, &available_updates)
                .await
            {
                Ok(update_results) => {
                    for result in update_results {
                        match result.action.as_str() {
                            "upgraded" => summary.upgraded += 1,
                            "unchanged" => summary.unchanged += 1,
                            _ => summary.failed += 1,
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    for update in &available_updates {
                        results.push(UpdateResult {
                            name: update.name.clone(),
                            previous_version: update.current_version.clone(),
                            new_version: None,
                            action: "failed".to_string(),
                        });
                    }
                    return Err(PkgError::UpdateFailed(e.to_string()));
                }
            }
        }

        let packages_scope = if config.packages.is_empty() {
            "all"
        } else {
            "subset"
        };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "upgrade": config.upgrade,
            "check_only": config.check_only,
            "dry_run": config.dry_run,
            "packages_scope": packages_scope,
            "packages": results,
            "summary": summary
        }))
    }

    /// Perform actual upgrade operation
    async fn perform_upgrade(
        &self,
        config: &UpgradeConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut results = Vec::new();
        let mut summary = UpgradeSummary {
            upgraded: 0,
            unchanged: 0,
            failed: 0,
        };

        // Step 1: Refresh index if requested
        if config.refresh_index {
            self.update_package_cache(manager)
                .await
                .map_err(|e| PkgError::UpgradeIndexFailed(e.to_string()))?;
        }

        // Step 2: Get available upgrades
        let available_upgrades = self
            .get_available_upgrades(config, manager)
            .await
            .map_err(|e| PkgError::UpgradeCheckFailed(e.to_string()))?;

        // Step 3: Apply upgrades if there are any
        if !available_upgrades.is_empty() {
            match self
                .apply_upgrades(config, manager, &available_upgrades)
                .await
            {
                Ok(upgrade_results) => {
                    for result in upgrade_results {
                        match result.action.as_str() {
                            "upgraded" => summary.upgraded += 1,
                            "unchanged" => summary.unchanged += 1,
                            _ => summary.failed += 1,
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    for upgrade in &available_upgrades {
                        results.push(UpgradeResult {
                            name: upgrade.name.clone(),
                            previous_version: upgrade.current_version.clone(),
                            new_version: None,
                            action: "failed".to_string(),
                        });
                    }
                    return Err(PkgError::UpgradeFailed(e.to_string()));
                }
            }
        }

        let packages_scope = if config.packages.is_empty() {
            "all"
        } else {
            "subset"
        };

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "refresh_index": config.refresh_index,
            "dry_run": config.dry_run,
            "check_only": config.check_only,
            "packages_scope": packages_scope,
            "packages": results,
            "summary": summary
        }))
    }

    /// The pending updates (for `update`).
    async fn get_available_updates(
        &self,
        config: &UpdateConfig,
        manager: &ManagerKind,
    ) -> Result<Vec<AvailableUpdate>, PkgError> {
        let stdout = self
            .pending_updates_output(&config.packages, manager)
            .await
            .map_err(PkgError::UpdateCheckFailed)?;
        self.parse_available_updates(&stdout, manager)
    }

    /// Runs the manager's list of pending updates and returns its output.
    /// dnf and yum `check-update` exit 100 when updates are pending, and
    /// pacman `-Qu` exits 1 with no output when there are none; any other
    /// failure is an error.
    async fn pending_updates_output(
        &self,
        packages: &[String],
        manager: &ManagerKind,
    ) -> Result<String, String> {
        let (cmd, _, skip_header) = self
            .list_updates_command(packages, manager)
            .map_err(|e| e.to_string())?;
        let output = cmd
            .command()
            .bounded_output()
            .await
            .map_err(|e| format!("could not run {cmd}: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let code = output.status.code();
        let ok = output.status.success()
            || (matches!(manager, ManagerKind::Dnf | ManagerKind::Yum) && code == Some(100))
            || (*manager == ManagerKind::Pacman && code == Some(1) && stdout.trim().is_empty());
        if !ok {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "{cmd} failed (exit {}): {}",
                code.map_or("signal".to_string(), |c| c.to_string()),
                stderr.trim()
            ));
        }
        Ok(if skip_header {
            stdout.lines().skip(1).map(|l| format!("{}\n", l)).collect()
        } else {
            stdout
        })
    }

    /// Parse available updates from command output
    fn parse_available_updates(
        &self,
        output: &str,
        manager: &ManagerKind,
    ) -> Result<Vec<AvailableUpdate>, PkgError> {
        let mut updates = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let update = match manager {
                ManagerKind::Apt => self.parse_apt_update_line(line),
                ManagerKind::Dnf | ManagerKind::Yum => self.parse_dnf_yum_update_line(line),
                ManagerKind::Pacman => self.parse_pacman_update_line(line),
                ManagerKind::Apk => self.parse_apk_update_line(line),
                ManagerKind::Brew => self.parse_brew_update_line(line),
                _ => continue,
            };

            if let Some(update) = update {
                updates.push(update);
            }
        }

        Ok(updates)
    }

    /// Parse APT update line
    fn parse_apt_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package/source version arch [upgradable from: current_version]"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && line.contains("[upgradable from:") {
            let package_name = parts[0].split('/').next()?.to_string();
            let new_version = parts[1].to_string();
            let current_version = line
                .split("[upgradable from: ")
                .nth(1)?
                .split(']')
                .next()?
                .to_string();

            Some(AvailableUpdate {
                name: package_name,
                current_version: Some(current_version),
                candidate_version: new_version,
                security: line.contains("security"),
            })
        } else {
            None
        }
    }

    /// Parse DNF/YUM update line
    fn parse_dnf_yum_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package.arch version repo"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let package_name = parts[0].split('.').next()?.to_string();
            let new_version = parts[1].to_string();

            Some(AvailableUpdate {
                name: package_name,
                current_version: None, // DNF check-update doesn't show current version
                candidate_version: new_version,
                security: parts.len() > 3 && parts[2].contains("security"),
            })
        } else {
            None
        }
    }

    /// Parse Pacman update line
    fn parse_pacman_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package current_version -> new_version"
        let parts: Vec<&str> = line.split(" -> ").collect();
        if parts.len() == 2 {
            let left_part = parts[0].trim();
            let new_version = parts[1].trim().to_string();

            let left_parts: Vec<&str> = left_part.split_whitespace().collect();
            if left_parts.len() >= 2 {
                let package_name = left_parts[0].to_string();
                let current_version = left_parts[1].to_string();

                Some(AvailableUpdate {
                    name: package_name,
                    current_version: Some(current_version),
                    candidate_version: new_version,
                    security: false, // Pacman doesn't typically indicate security updates in this output
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Parse APK update line  
    fn parse_apk_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format varies, but typically: "package-version [available: new-version]"
        if line.contains("[available:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let package_part = parts.get(0)?;
            let package_name = package_part.split('-').next()?.to_string();

            if let Some(avail_part) = line.split("[available: ").nth(1) {
                let new_version = avail_part.split(']').next()?.to_string();

                Some(AvailableUpdate {
                    name: package_name,
                    current_version: None, // APK output parsing is complex for current version
                    candidate_version: new_version,
                    security: false,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Parse Brew update line
    fn parse_brew_update_line(&self, line: &str) -> Option<AvailableUpdate> {
        // Format: "package (current_version) < new_version"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let package_name = parts[0].to_string();
            let current_version = parts[1]
                .trim_start_matches('(')
                .trim_end_matches(')')
                .to_string();
            let new_version = parts[3].to_string();

            Some(AvailableUpdate {
                name: package_name,
                current_version: Some(current_version),
                candidate_version: new_version,
                security: false,
            })
        } else {
            None
        }
    }

    /// The upgrade command of `update` (the same as `upgrade`'s).
    async fn build_upgrade_command(
        &self,
        config: &UpdateConfig,
        manager: &ManagerKind,
        _available_updates: &[AvailableUpdate],
    ) -> Result<CmdLine, PkgError> {
        upgrade_command(
            manager,
            &config.packages,
            config.assume_yes,
            config.security_only,
            config.extra_args.as_deref(),
        )
    }

    /// The pending upgrades (for `upgrade`).
    async fn get_available_upgrades(
        &self,
        config: &UpgradeConfig,
        manager: &ManagerKind,
    ) -> Result<Vec<AvailableUpdate>, PkgError> {
        let stdout = self
            .pending_updates_output(&config.packages, manager)
            .await
            .map_err(PkgError::UpgradeCheckFailed)?;
        self.parse_available_upgrades(&stdout, manager)
    }

    /// Command that lists pending updates, run without a shell. Returns the
    /// command plus what the former shell form did around it: whether its
    /// exit status was discarded (`apt list ... | tail`, `check-update ||
    /// true`) and whether the first output line was dropped (`tail -n +2`).
    /// Standard error, formerly sent to /dev/null, is captured and unused.
    fn list_updates_command(
        &self,
        packages: &[String],
        manager: &ManagerKind,
    ) -> Result<(CmdLine, bool, bool), PkgError> {
        let (mut cmd, ignore_status, skip_header) = match manager {
            ManagerKind::Apt => (CmdLine::lit("apt list --upgradable"), true, true),
            ManagerKind::Dnf => (CmdLine::lit("dnf check-update"), true, false),
            ManagerKind::Yum => (CmdLine::lit("yum check-update"), true, false),
            ManagerKind::Pacman => (CmdLine::lit("pacman -Qu"), false, false),
            ManagerKind::Apk => (CmdLine::lit("apk list -u"), false, false),
            ManagerKind::Brew => (CmdLine::lit("brew outdated"), false, false),
            _ => {
                return Err(PkgError::ManagerNotAvailable(
                    "Unsupported manager".to_string(),
                ));
            }
        };
        for package in packages {
            cmd.arg(package);
        }
        Ok((cmd, ignore_status, skip_header))
    }

    /// Parse available upgrades from command output
    fn parse_available_upgrades(
        &self,
        output: &str,
        manager: &ManagerKind,
    ) -> Result<Vec<AvailableUpdate>, PkgError> {
        let mut upgrades = Vec::new();

        match manager {
            ManagerKind::Apt => {
                for line in output.lines() {
                    if let Some(update) = self.parse_apt_update_line(line) {
                        upgrades.push(update);
                    }
                }
            }
            ManagerKind::Dnf | ManagerKind::Yum => {
                for line in output.lines() {
                    if let Some(update) = self.parse_dnf_yum_update_line(line) {
                        upgrades.push(update);
                    }
                }
            }
            ManagerKind::Pacman => {
                for line in output.lines() {
                    if let Some(update) = self.parse_pacman_update_line(line) {
                        upgrades.push(update);
                    }
                }
            }
            ManagerKind::Apk => {
                for line in output.lines() {
                    if let Some(update) = self.parse_apk_update_line(line) {
                        upgrades.push(update);
                    }
                }
            }
            ManagerKind::Brew => {
                for line in output.lines() {
                    if let Some(update) = self.parse_brew_update_line(line) {
                        upgrades.push(update);
                    }
                }
            }
            _ => {
                return Err(PkgError::ManagerNotAvailable(
                    "Unsupported manager".to_string(),
                ));
            }
        }

        Ok(upgrades)
    }

    /// Apply upgrades
    async fn apply_upgrades(
        &self,
        config: &UpgradeConfig,
        manager: &ManagerKind,
        available_upgrades: &[AvailableUpdate],
    ) -> Result<Vec<UpgradeResult>, PkgError> {
        let mut results = Vec::new();

        // Get current versions before upgrade
        let mut current_versions = HashMap::new();
        for upgrade in available_upgrades {
            current_versions.insert(upgrade.name.clone(), upgrade.current_version.clone());
        }

        // Build and execute upgrade command
        let cmd = self
            .build_upgrade_command_for_execution(config, manager, available_upgrades)
            .await?;

        let mut command = cmd.command();
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // Set environment if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command.bounded_output().await.map_err(|e| {
            PkgError::UpgradeFailed(format!("Failed to execute upgrade command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::UpgradeFailed(format!(
                "Upgrade command failed: {}",
                stderr
            )));
        }

        // Create results for each attempted upgrade
        for upgrade in available_upgrades {
            let result = UpgradeResult {
                name: upgrade.name.clone(),
                previous_version: upgrade.current_version.clone(),
                new_version: Some(upgrade.candidate_version.clone()),
                action: "upgraded".to_string(),
            };
            results.push(result);
        }

        Ok(results)
    }

    /// The upgrade command of `upgrade`, shown by a dry run and run for real.
    async fn build_upgrade_command_for_execution(
        &self,
        config: &UpgradeConfig,
        manager: &ManagerKind,
        _available_upgrades: &[AvailableUpdate],
    ) -> Result<CmdLine, PkgError> {
        upgrade_command(
            manager,
            &config.packages,
            config.assume_yes,
            config.security_only,
            config.extra_args.as_deref(),
        )
    }

    /// Apply updates
    async fn apply_updates(
        &self,
        config: &UpdateConfig,
        manager: &ManagerKind,
        available_updates: &[AvailableUpdate],
    ) -> Result<Vec<UpdateResult>, PkgError> {
        let mut results = Vec::new();

        // Get current versions before upgrade
        let mut current_versions = HashMap::new();
        for update in available_updates {
            current_versions.insert(update.name.clone(), update.current_version.clone());
        }

        // Build and execute upgrade command
        let cmd = self
            .build_upgrade_command(config, manager, available_updates)
            .await?;

        let mut command = cmd.command();

        // Set environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                command.env(key, value);
            }
        }

        let output = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .bounded_output()
            .await
            .map_err(|e| PkgError::UpdateFailed(format!("Failed to execute upgrade: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.map_update_error(&stderr, &output.status.code()));
        }

        // Create results for packages
        for update in available_updates {
            // Check if package should be included based on config.packages filter
            if !config.packages.is_empty() && !config.packages.contains(&update.name) {
                continue;
            }

            // For simplicity, assume all available updates were applied successfully
            // In production, you might want to check actual final versions
            let action = "upgraded".to_string();

            results.push(UpdateResult {
                name: update.name.clone(),
                previous_version: update.current_version.clone(),
                new_version: Some(update.candidate_version.clone()),
                action,
            });
        }

        Ok(results)
    }

    /// Map update error from stderr and exit code
    fn map_update_error(&self, stderr: &str, exit_code: &Option<i32>) -> PkgError {
        let stderr_lower = stderr.to_lowercase();

        // Check for specific error patterns
        if stderr_lower.contains("permission denied")
            || stderr_lower.contains("not allowed")
            || exit_code == &Some(13)
        {
            PkgError::UpdatePermissionDenied(stderr.to_string())
        } else if stderr_lower.contains("index")
            || stderr_lower.contains("cache")
            || stderr_lower.contains("metadata")
        {
            PkgError::UpdateIndexFailed(stderr.to_string())
        } else if stderr_lower.contains("check") || stderr_lower.contains("available") {
            PkgError::UpdateCheckFailed(stderr.to_string())
        } else {
            PkgError::UpdateFailed(stderr.to_string())
        }
    }

    async fn info_async(&self, config: InfoConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_info_config(&config)?;

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;

        // Perform info query with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_info_query(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::InfoTimeout)?;

        result
    }

    async fn perform_info_query(
        &self,
        config: &InfoConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        let mut packages = Vec::new();
        let mut partial_failures = 0;

        for package_name in &config.packages {
            match self
                .query_single_package(package_name, config, manager)
                .await
            {
                Ok(mut package_info) => {
                    // The repository is looked up together with the candidate
                    // version, so it is dropped here rather than not queried.
                    if !config.include_repo {
                        package_info.repository = None;
                        package_info.repository_url = None;
                    }
                    packages.push(package_info)
                }
                Err(e) => {
                    if crate::core::process::has_lost() {
                        return Err(PkgError::InfoTimeout);
                    }
                    partial_failures += 1;
                    // Add a failed package result
                    packages.push(PackageInfo {
                        name: package_name.clone(),
                        found: false,
                        installed: false,
                        installed_version: None,
                        candidate_version: None,
                        architecture: None,
                        summary: None,
                        description: None,
                        homepage: None,
                        license: None,
                        repository: None,
                        repository_url: None,
                        dependencies: None,
                        reverse_dependencies: None,
                        files: None,
                        raw: Some(json!({ "error": error_value(&e) })),
                    });
                }
            }
        }

        // Every query failed: an error. Some failed: the result says which
        // (`raw.error`) and the exit status is a partial failure.
        if partial_failures == config.packages.len() {
            return Err(PkgError::InfoQueryFailed(format!(
                "every package query failed; first: {}",
                packages
                    .first()
                    .and_then(|p| p.raw.as_ref())
                    .map(|r| r["error"]["message"].to_string())
                    .unwrap_or_default()
            )));
        }

        Ok(json!({
            "backend": "pkg",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "packages": packages
        }))
    }

    async fn query_single_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
        manager: &ManagerKind,
    ) -> Result<PackageInfo, PkgError> {
        match manager {
            ManagerKind::Apt => self.query_apt_package(package_name, config).await,
            ManagerKind::Yum | ManagerKind::Dnf => {
                self.query_yum_dnf_package(package_name, config, manager)
                    .await
            }
            ManagerKind::Pacman => self.query_pacman_package(package_name, config).await,
            ManagerKind::Apk => self.query_apk_package(package_name, config).await,
            ManagerKind::Brew => self.query_brew_package(package_name, config).await,
            ManagerKind::Auto => unreachable!("Auto should have been resolved by now"),
        }
    }

    async fn query_apt_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
    ) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            repository_url: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status with dpkg
        let dpkg_output = self
            .run_command("dpkg", &["-s", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = dpkg_output {
            if output.status.success() {
                package_info.installed = true;
                // Parse dpkg output for version and architecture
                for line in output.stdout.lines() {
                    if line.starts_with("Version: ") {
                        package_info.installed_version = Some(line[9..].to_string());
                    } else if line.starts_with("Architecture: ") {
                        package_info.architecture = Some(line[14..].to_string());
                    }
                }
            }
        }

        // Get package information from apt-cache
        let show_output = self
            .run_command("apt-cache", &["show", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = show_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;

                // Parse apt-cache show output
                let mut current_description = String::new();
                let mut in_description = false;

                for line in output.stdout.lines() {
                    if line.starts_with("Package: ") {
                        // Confirm package name
                    } else if line.starts_with("Version: ")
                        && package_info.candidate_version.is_none()
                    {
                        package_info.candidate_version = Some(line[9..].to_string());
                    } else if line.starts_with("Architecture: ")
                        && package_info.architecture.is_none()
                    {
                        package_info.architecture = Some(line[14..].to_string());
                    } else if line.starts_with("Maintainer: ") {
                        // Could be used for additional metadata
                    } else if line.starts_with("Homepage: ") {
                        package_info.homepage = Some(line[10..].to_string());
                    } else if line.starts_with("Section: ") {
                        // Could be used for categorization
                    } else if line.starts_with("Description: ") {
                        package_info.summary = Some(line[13..].to_string());
                        in_description = true;
                    } else if line.starts_with("Description-md5: ") {
                        in_description = false;
                    } else if in_description && line.starts_with(" ") {
                        if !current_description.is_empty() {
                            current_description.push('\n');
                        }
                        current_description.push_str(line.trim());
                    } else if line.starts_with("Depends: ") && config.include_dependencies {
                        let deps = self.parse_apt_dependencies(line);
                        package_info.dependencies = Some(PackageDependencies {
                            runtime: deps,
                            build: Vec::new(),
                            optional: Vec::new(),
                        });
                    }
                }

                if !current_description.is_empty() {
                    package_info.description = Some(current_description);
                }
            }
        }

        // Get candidate version and repository information
        let policy_output = self
            .run_command("apt-cache", &["policy", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = policy_output {
            if output.status.success() {
                for line in output.stdout.lines() {
                    if line.trim().starts_with("Candidate: ") {
                        let candidate = line.trim()[11..].trim();
                        if candidate != "(none)" {
                            package_info.candidate_version = Some(candidate.to_string());
                        }
                    }
                }
                if let Some((url, suite)) = apt_policy_source(&output.stdout) {
                    package_info.repository = Some(suite);
                    package_info.repository_url = Some(url);
                }
            }
        }

        // Handle dependencies if requested
        if config.include_dependencies && package_info.dependencies.is_none() {
            if let Ok(deps_output) = self
                .run_command("apt-cache", &["depends", package_name], config.env.as_ref())
                .await
            {
                if deps_output.status.success() {
                    let deps = self.parse_apt_depends_output(&deps_output.stdout);
                    package_info.dependencies = Some(deps);
                }
            }
        }

        // Handle reverse dependencies if requested
        if config.include_reverse_deps {
            if let Ok(rdeps_output) = self
                .run_command(
                    "apt-cache",
                    &["rdepends", package_name],
                    config.env.as_ref(),
                )
                .await
            {
                if rdeps_output.status.success() {
                    let rdeps = self.parse_apt_rdepends_output(&rdeps_output.stdout);
                    package_info.reverse_dependencies = Some(rdeps);
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self
                .run_command("dpkg", &["-L", package_name], config.env.as_ref())
                .await
            {
                if files_output.status.success() {
                    let files: Vec<String> =
                        files_output.stdout.lines().map(|s| s.to_string()).collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_yum_dnf_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
        manager: &ManagerKind,
    ) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            repository_url: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        let cmd = if manager == &ManagerKind::Dnf {
            "dnf"
        } else {
            "yum"
        };

        // Check installed status with rpm
        let rpm_output = self
            .run_command("rpm", &["-q", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = rpm_output {
            if output.status.success() {
                package_info.installed = true;
                // Parse version from rpm output like "package-1.2.3-1.el8.x86_64"
                if let Some(version_part) = output
                    .stdout
                    .trim()
                    .strip_prefix(&format!("{}-", package_name))
                {
                    if let Some(version_end) = version_part.rfind('.') {
                        let version_arch = &version_part[..version_end];
                        if let Some(arch_start) = version_arch.rfind('.') {
                            package_info.installed_version =
                                Some(version_arch[..arch_start].to_string());
                            package_info.architecture =
                                Some(version_arch[arch_start + 1..].to_string());
                        } else {
                            package_info.installed_version = Some(version_arch.to_string());
                        }
                    }
                }
            }
        }

        // Get package information
        let info_output = self
            .run_command(cmd, &["info", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = info_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;

                let mut in_description = false;
                let mut current_description = String::new();

                for line in output.stdout.lines() {
                    if line.starts_with("Name         : ") {
                        // Confirm package name
                    } else if line.starts_with("Version      : ")
                        && package_info.candidate_version.is_none()
                    {
                        package_info.candidate_version = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Architecture : ")
                        && package_info.architecture.is_none()
                    {
                        package_info.architecture = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Summary      : ") {
                        package_info.summary = Some(line[15..].trim().to_string());
                    } else if line.starts_with("URL          : ") {
                        package_info.homepage = Some(line[15..].trim().to_string());
                    } else if line.starts_with("License      : ") {
                        package_info.license = Some(line[15..].trim().to_string());
                    } else if line.starts_with("Repository   : ")
                        || line.starts_with("Repo         : ")
                    {
                        let repo = if line.starts_with("Repository   : ") {
                            line[15..].trim()
                        } else {
                            line[15..].trim()
                        };
                        package_info.repository = Some(repo.to_string());
                    } else if line.starts_with("Description  : ") {
                        current_description = line[15..].trim().to_string();
                        in_description = true;
                    } else if in_description && line.starts_with("           : ") {
                        if !current_description.is_empty() {
                            current_description.push('\n');
                        }
                        current_description.push_str(line[13..].trim());
                    } else if line.trim().is_empty()
                        || (!line.starts_with("           ") && in_description)
                    {
                        if in_description && !current_description.is_empty() {
                            package_info.description = Some(current_description.clone());
                        }
                        in_description = false;
                    }
                }

                if in_description && !current_description.is_empty() {
                    package_info.description = Some(current_description);
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self
                .run_command("rpm", &["-ql", package_name], config.env.as_ref())
                .await
            {
                if files_output.status.success() {
                    let files: Vec<String> =
                        files_output.stdout.lines().map(|s| s.to_string()).collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_pacman_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
    ) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            repository_url: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let qi_output = self
            .run_command("pacman", &["-Qi", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = qi_output {
            if output.status.success() {
                package_info.installed = true;
                package_info.found = true;

                // Parse pacman -Qi output
                for line in output.stdout.lines() {
                    if line.starts_with("Version         : ") {
                        package_info.installed_version = Some(line[18..].trim().to_string());
                        package_info.candidate_version = Some(line[18..].trim().to_string()); // Same as installed for local query
                    } else if line.starts_with("Architecture    : ") {
                        package_info.architecture = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Description     : ") {
                        package_info.summary = Some(line[18..].trim().to_string());
                        package_info.description = Some(line[18..].trim().to_string());
                    } else if line.starts_with("URL             : ") {
                        package_info.homepage = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Licenses        : ") {
                        package_info.license = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Repository      : ") {
                        package_info.repository = Some(line[18..].trim().to_string());
                    } else if line.starts_with("Depends On      : ") && config.include_dependencies
                    {
                        let deps = self.parse_pacman_dependencies(line[18..].trim());
                        package_info.dependencies = Some(PackageDependencies {
                            runtime: deps,
                            build: Vec::new(),
                            optional: Vec::new(),
                        });
                    }
                }
            }
        }

        // If not installed, check if available
        if !package_info.installed {
            let si_output = self
                .run_command("pacman", &["-Si", package_name], config.env.as_ref())
                .await;

            if let Ok(output) = si_output {
                if output.status.success() {
                    package_info.found = true;

                    // Parse pacman -Si output
                    for line in output.stdout.lines() {
                        if line.starts_with("Version         : ") {
                            package_info.candidate_version = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Architecture    : ") {
                            package_info.architecture = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Description     : ") {
                            package_info.summary = Some(line[18..].trim().to_string());
                            package_info.description = Some(line[18..].trim().to_string());
                        } else if line.starts_with("URL             : ") {
                            package_info.homepage = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Licenses        : ") {
                            package_info.license = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Repository      : ") {
                            package_info.repository = Some(line[18..].trim().to_string());
                        } else if line.starts_with("Depends On      : ")
                            && config.include_dependencies
                        {
                            let deps = self.parse_pacman_dependencies(line[18..].trim());
                            package_info.dependencies = Some(PackageDependencies {
                                runtime: deps,
                                build: Vec::new(),
                                optional: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self
                .run_command("pacman", &["-Ql", package_name], config.env.as_ref())
                .await
            {
                if files_output.status.success() {
                    let files: Vec<String> = files_output
                        .stdout
                        .lines()
                        .filter(|line| line.contains(' ')) // Filter out just the package name line
                        .map(|line| {
                            // pacman -Ql output format: "package_name /path/to/file"
                            if let Some(space_pos) = line.find(' ') {
                                line[space_pos + 1..].to_string()
                            } else {
                                line.to_string()
                            }
                        })
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_apk_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
    ) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            repository_url: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let installed_output = self
            .run_command("apk", &["info", "-e", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = installed_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.installed = true;
                package_info.found = true;
            }
        }

        // Get package information
        let info_output = self
            .run_command("apk", &["info", "-a", package_name], config.env.as_ref())
            .await;

        if let Ok(output) = info_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.found = true;

                // Parse apk info output
                for line in output.stdout.lines() {
                    if line.starts_with(&format!("{}-", package_name)) {
                        // Parse version from line like "package-1.2.3-r0"
                        if let Some(version_start) = line.find('-') {
                            let version_part = &line[version_start + 1..];
                            if let Some(release_start) = version_part.rfind('-') {
                                package_info.candidate_version =
                                    Some(version_part[..release_start].to_string());
                            } else {
                                package_info.candidate_version = Some(version_part.to_string());
                            }
                        }
                        if package_info.installed {
                            package_info.installed_version = package_info.candidate_version.clone();
                        }
                    } else if line.starts_with("description:") {
                        package_info.summary = Some(line[12..].trim().to_string());
                        package_info.description = Some(line[12..].trim().to_string());
                    } else if line.starts_with("webpage:") {
                        package_info.homepage = Some(line[8..].trim().to_string());
                    } else if line.starts_with("license:") {
                        package_info.license = Some(line[8..].trim().to_string());
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self
                .run_command("apk", &["info", "-L", package_name], config.env.as_ref())
                .await
            {
                if files_output.status.success() {
                    let files: Vec<String> = files_output
                        .stdout
                        .lines()
                        .skip(1) // Skip the first line which is usually the package name
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn query_brew_package(
        &self,
        package_name: &str,
        config: &InfoConfig,
    ) -> Result<PackageInfo, PkgError> {
        let mut package_info = PackageInfo {
            name: package_name.to_string(),
            found: false,
            installed: false,
            installed_version: None,
            candidate_version: None,
            architecture: None,
            summary: None,
            description: None,
            homepage: None,
            license: None,
            repository: None,
            repository_url: None,
            dependencies: None,
            reverse_dependencies: None,
            files: None,
            raw: None,
        };

        // Check installed status
        let list_output = self
            .run_command(
                "brew",
                &["list", "--versions", package_name],
                config.env.as_ref(),
            )
            .await;

        if let Ok(output) = list_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                package_info.installed = true;
                // Parse version from output like "package 1.2.3"
                if let Some(space_pos) = output.stdout.trim().find(' ') {
                    package_info.installed_version =
                        Some(output.stdout.trim()[space_pos + 1..].trim().to_string());
                }
            }
        }

        // Get package information using JSON output
        let json_output = self
            .run_command(
                "brew",
                &["info", "--json=v2", package_name],
                config.env.as_ref(),
            )
            .await;

        if let Ok(output) = json_output {
            if output.status.success() && !output.stdout.trim().is_empty() {
                if let Ok(json_data) = serde_json::from_str::<Value>(&output.stdout) {
                    if let Some(formulae) = json_data["formulae"].as_array() {
                        if let Some(formula) = formulae.first() {
                            package_info.found = true;

                            if let Some(name) = formula["name"].as_str() {
                                package_info.name = name.to_string();
                            }
                            if let Some(desc) = formula["desc"].as_str() {
                                package_info.summary = Some(desc.to_string());
                            }
                            if let Some(homepage) = formula["homepage"].as_str() {
                                package_info.homepage = Some(homepage.to_string());
                            }
                            if let Some(versions) = formula["versions"].as_object() {
                                if let Some(stable) = versions["stable"].as_str() {
                                    package_info.candidate_version = Some(stable.to_string());
                                }
                            }
                            if let Some(license) = formula["license"].as_str() {
                                package_info.license = Some(license.to_string());
                            }

                            // Handle dependencies
                            if config.include_dependencies {
                                let mut runtime_deps = Vec::new();
                                let mut build_deps = Vec::new();
                                let mut optional_deps = Vec::new();

                                if let Some(deps) = formula["dependencies"].as_array() {
                                    for dep in deps {
                                        if let Some(dep_str) = dep.as_str() {
                                            runtime_deps.push(dep_str.to_string());
                                        }
                                    }
                                }
                                if let Some(build_deps_array) =
                                    formula["build_dependencies"].as_array()
                                {
                                    for dep in build_deps_array {
                                        if let Some(dep_str) = dep.as_str() {
                                            build_deps.push(dep_str.to_string());
                                        }
                                    }
                                }
                                if let Some(optional_deps_array) =
                                    formula["optional_dependencies"].as_array()
                                {
                                    for dep in optional_deps_array {
                                        if let Some(dep_str) = dep.as_str() {
                                            optional_deps.push(dep_str.to_string());
                                        }
                                    }
                                }

                                package_info.dependencies = Some(PackageDependencies {
                                    runtime: runtime_deps,
                                    build: build_deps,
                                    optional: optional_deps,
                                });
                            }

                            // Store raw JSON for debugging
                            package_info.raw = Some(formula.clone());
                        }
                    }

                    // Also check casks
                    if !package_info.found {
                        if let Some(casks) = json_data["casks"].as_array() {
                            if let Some(cask) = casks.first() {
                                package_info.found = true;

                                if let Some(name) = cask["token"].as_str() {
                                    package_info.name = name.to_string();
                                }
                                if let Some(desc) = cask["desc"].as_str() {
                                    package_info.summary = Some(desc.to_string());
                                }
                                if let Some(homepage) = cask["homepage"].as_str() {
                                    package_info.homepage = Some(homepage.to_string());
                                }
                                if let Some(version) = cask["version"].as_str() {
                                    package_info.candidate_version = Some(version.to_string());
                                }

                                package_info.raw = Some(cask.clone());
                            }
                        }
                    }
                }
            }
        }

        // Handle reverse dependencies if requested
        if config.include_reverse_deps {
            if let Ok(rdeps_output) = self
                .run_command("brew", &["uses", package_name], config.env.as_ref())
                .await
            {
                if rdeps_output.status.success() {
                    let rdeps: Vec<String> = rdeps_output
                        .stdout
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    if !rdeps.is_empty() {
                        package_info.reverse_dependencies = Some(rdeps);
                    }
                }
            }
        }

        // Handle files listing if requested and package is installed
        if config.include_files && package_info.installed {
            if let Ok(files_output) = self
                .run_command("brew", &["list", package_name], config.env.as_ref())
                .await
            {
                if files_output.status.success() {
                    let files: Vec<String> = files_output
                        .stdout
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    package_info.files = Some(files);
                }
            }
        }

        Ok(package_info)
    }

    async fn search_async(&self, config: SearchConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_search_config(&config)?;

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;

        // Perform search query with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_search_query(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::SearchTimeout)?;

        result
    }

    fn validate_search_config(&self, config: &SearchConfig) -> Result<(), PkgError> {
        if config.query.trim().is_empty() {
            return Err(PkgError::InvalidSearchConfig(
                "Query cannot be empty".to_string(),
            ));
        }
        // The query is a manager argument: it must not read as an option.
        if config.query.starts_with('-')
            || config.query.len() > 256
            || config.query.chars().any(char::is_control)
        {
            return Err(PkgError::InvalidSearchConfig(format!(
                "query {:?} must be 1-256 characters, not start with '-', and have no \
                 control characters",
                config.query
            )));
        }
        if config.search_in.is_empty() {
            return Err(PkgError::InvalidSearchConfig(
                "search_in cannot be empty (use name, description or all)".to_string(),
            ));
        }

        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidSearchConfig(
                "Timeout must be greater than 0".to_string(),
            ));
        }

        if config.limit == 0 {
            return Err(PkgError::InvalidSearchConfig(
                "Limit must be greater than 0".to_string(),
            ));
        }

        // Validate search_in fields
        for field in &config.search_in {
            match field {
                SearchField::Name | SearchField::Description | SearchField::All => {}
            }
        }

        if let Some(extra_args) = &config.extra_args {
            for arg in extra_args {
                if arg.trim().is_empty() {
                    return Err(PkgError::InvalidSearchConfig(
                        "Extra args cannot contain empty strings".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    async fn perform_search_query(
        &self,
        config: &SearchConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        // The manager's matches (names and summaries only): the details
        // are looked up afterwards for the returned page, not every match.
        let listing = SearchConfig {
            include_installed: false,
            include_versions: false,
            include_repo: false,
            ..config.clone()
        };
        let raw_results = match manager {
            ManagerKind::Apt => self.search_apt(&config.query, &listing).await?,
            ManagerKind::Yum | ManagerKind::Dnf => {
                self.search_yum_dnf(&config.query, &listing, manager)
                    .await?
            }
            ManagerKind::Pacman => self.search_pacman(&config.query, &listing).await?,
            ManagerKind::Apk => self.search_apk(&config.query, &listing).await?,
            ManagerKind::Brew => self.search_brew(&config.query, &listing).await?,
            ManagerKind::Auto => unreachable!("Auto should have been resolved by now"),
        };

        // Apply filters and sorting
        let filtered_results = self.filter_and_sort_results(raw_results, config);

        // Apply pagination
        let total_matches = filtered_results.len() as u32;
        let start = config.offset as usize;
        let end = std::cmp::min(start + config.limit as usize, filtered_results.len());

        let mut paginated_results = if start < filtered_results.len() {
            filtered_results[start..end].to_vec()
        } else {
            vec![]
        };
        if config.include_installed || config.include_versions || config.include_repo {
            let info = InfoConfig {
                manager: manager.clone(),
                packages: Vec::new(),
                include_dependencies: false,
                include_reverse_deps: false,
                include_files: false,
                include_repo: config.include_repo,
                timeout_ms: config.timeout_ms,
                env: None,
            };
            for result in &mut paginated_results {
                let Ok(details) = self
                    .query_single_package(&result.name, &info, manager)
                    .await
                else {
                    continue;
                };
                if config.include_installed {
                    result.installed = details.installed;
                }
                if config.include_versions {
                    result.version = details.candidate_version.or(details.installed_version);
                }
                if config.include_repo {
                    result.repository = details.repository;
                    result.repository_url = details.repository_url;
                }
                if result.homepage.is_none() {
                    result.homepage = details.homepage;
                }
            }
        }

        Ok(json!(SearchResults {
            backend: "pkg".to_string(),
            manager: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            query: config.query.clone(),
            search_in: config.search_in.clone(),
            exact: config.exact,
            case_sensitive: config.case_sensitive,
            limit: config.limit,
            offset: config.offset,
            total_matches,
            results: paginated_results,
        }))
    }

    async fn search_apt(
        &self,
        query: &str,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        // apt-cache prints one "name - summary" line per package, which is
        // what the parser below reads. `apt search` (no stable CLI) prints a
        // "name/suite version arch" line plus an indented summary line, so
        // its summaries were being reported as package names.
        let output = self
            .run_command("apt-cache", &cmd_args, config.env.as_ref())
            .await
            .map_err(|e| PkgError::SearchFailed(format!("APT search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!(
                "APT search failed: {}",
                output.stderr
            )));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();

        for line in lines {
            if line.trim().is_empty() || line.starts_with("WARNING:") || line.starts_with("NOTE:") {
                continue;
            }

            // Parse APT search output: "package-name - description"
            if let Some(dash_pos) = line.find(" - ") {
                let name = line[..dash_pos].trim();
                let summary = line[dash_pos + 3..].trim();

                // Get additional metadata if requested
                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    repository_url: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(policy_output) = self
                        .run_command("apt-cache", &["policy", name], config.env.as_ref())
                        .await
                    {
                        if policy_output.status.success() {
                            for policy_line in policy_output.stdout.lines() {
                                if policy_line.trim().starts_with("Candidate:")
                                    && config.include_versions
                                {
                                    let version = policy_line
                                        .trim()
                                        .strip_prefix("Candidate:")
                                        .unwrap_or("")
                                        .trim();
                                    if version != "(none)" {
                                        search_result.version = Some(version.to_string());
                                    }
                                }
                                if policy_line.trim().starts_with("Installed:")
                                    && config.include_installed
                                {
                                    let installed_version = policy_line
                                        .trim()
                                        .strip_prefix("Installed:")
                                        .unwrap_or("")
                                        .trim();
                                    search_result.installed = installed_version != "(none)";
                                }
                            }
                        }
                    }
                }

                if config.include_repo {
                    if let Ok(show_output) = self
                        .run_command("apt-cache", &["show", name], config.env.as_ref())
                        .await
                    {
                        if show_output.status.success() {
                            for show_line in show_output.stdout.lines() {
                                if show_line.starts_with("Filename:") {
                                    if let Some(repo_part) = show_line.split('/').nth(1) {
                                        search_result.repository = Some(repo_part.to_string());
                                    }
                                } else if show_line.starts_with("Homepage:") {
                                    search_result.homepage =
                                        Some(show_line[9..].trim().to_string());
                                }
                            }
                        }
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_yum_dnf(
        &self,
        query: &str,
        config: &SearchConfig,
        manager: &ManagerKind,
    ) -> Result<Vec<SearchResult>, PkgError> {
        let cmd = match manager {
            ManagerKind::Dnf => "dnf",
            ManagerKind::Yum => "yum",
            _ => unreachable!(),
        };

        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self
            .run_command(cmd, &cmd_args, config.env.as_ref())
            .await
            .map_err(|e| PkgError::SearchFailed(format!("{} search command failed: {}", cmd, e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!(
                "{} search failed: {}",
                cmd, output.stderr
            )));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();

        for line in lines {
            if line.trim().is_empty() || line.contains("==") || line.starts_with("Last metadata") {
                continue;
            }

            // dnf 4 and yum print "package.arch : summary"; dnf 5 prints
            // " package.arch<TAB>summary" under "Matched fields:" headings.
            let split = line
                .find(" : ")
                .map(|i| (&line[..i], &line[i + 3..]))
                .or_else(|| {
                    line.starts_with(' ')
                        .then(|| line.trim_start().split_once('\t'))
                        .flatten()
                });
            if let Some((name_part, summary)) = split {
                let name_part = name_part.trim();
                let summary = summary.trim();

                // Extract just the package name (remove architecture)
                let name = if let Some(dot_pos) = name_part.find('.') {
                    &name_part[..dot_pos]
                } else {
                    name_part
                };

                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    repository_url: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(info_output) = self
                        .run_command(cmd, &["info", name], config.env.as_ref())
                        .await
                    {
                        if info_output.status.success() {
                            for info_line in info_output.stdout.lines() {
                                if info_line.starts_with("Version") && config.include_versions {
                                    if let Some(version) = info_line.split(':').nth(1) {
                                        search_result.version = Some(version.trim().to_string());
                                    }
                                }
                                if info_line.starts_with("Repository") && config.include_repo {
                                    if let Some(repo) = info_line.split(':').nth(1) {
                                        search_result.repository = Some(repo.trim().to_string());
                                    }
                                }
                                if info_line.starts_with("URL") {
                                    if let Some((_, url)) = info_line.split_once(':') {
                                        search_result.homepage = Some(url.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                if config.include_installed {
                    if let Ok(list_output) = self
                        .run_command(cmd, &["list", "installed", name], config.env.as_ref())
                        .await
                    {
                        search_result.installed =
                            list_output.status.success() && !list_output.stdout.is_empty();
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_pacman(
        &self,
        query: &str,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["-Ss", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self
            .run_command("pacman", &cmd_args, config.env.as_ref())
            .await
            .map_err(|e| PkgError::SearchFailed(format!("Pacman search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!(
                "Pacman search failed: {}",
                output.stderr
            )));
        }

        let mut results = Vec::new();
        let lines: Vec<&str> = output.stdout.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() {
                i += 1;
                continue;
            }

            // Parse pacman output: "repo/package version [group] (arch)"
            if let Some(space_pos) = line.find(' ') {
                let name_part = &line[..space_pos];
                let rest = &line[space_pos + 1..];

                // Extract repository and package name
                let (repository, name) = if let Some(slash_pos) = name_part.find('/') {
                    (
                        Some(name_part[..slash_pos].to_string()),
                        &name_part[slash_pos + 1..],
                    )
                } else {
                    (None, name_part)
                };

                // Extract version
                let version = rest.split_whitespace().next().map(|s| s.to_string());

                // Check for description on next line
                let summary = if i + 1 < lines.len() && lines[i + 1].trim().starts_with(' ') {
                    Some(lines[i + 1].trim().to_string())
                } else {
                    None
                };

                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version,
                    installed: false,
                    summary: summary.clone(),
                    description: None,
                    repository,
                    repository_url: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_installed {
                    if let Ok(query_output) = self
                        .run_command("pacman", &["-Qi", name], config.env.as_ref())
                        .await
                    {
                        search_result.installed = query_output.status.success();
                    }
                }

                results.push(search_result);

                // Skip description line if we processed it
                if summary.is_some() {
                    i += 2;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        Ok(results)
    }

    async fn search_apk(
        &self,
        query: &str,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", "-v", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self
            .run_command("apk", &cmd_args, config.env.as_ref())
            .await
            .map_err(|e| PkgError::SearchFailed(format!("APK search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!(
                "APK search failed: {}",
                output.stderr
            )));
        }

        let mut results = Vec::new();

        for line in output.stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Parse APK search output: "package-name-version - description"
            if let Some(dash_pos) = line.find(" - ") {
                let name_version = line[..dash_pos].trim();
                let summary = line[dash_pos + 3..].trim();

                let name = apk_package_name(name_version);

                let mut search_result = SearchResult {
                    name: name.to_string(),
                    version: None,
                    installed: false,
                    summary: Some(summary.to_string()),
                    description: None,
                    repository: None,
                    repository_url: None,
                    homepage: None,
                    score: 1.0,
                };

                if config.include_versions || config.include_installed {
                    if let Ok(info_output) = self
                        .run_command("apk", &["info", "-a", name], config.env.as_ref())
                        .await
                    {
                        if info_output.status.success() {
                            for info_line in info_output.stdout.lines() {
                                if info_line.starts_with(&format!("{}-", name))
                                    && config.include_versions
                                {
                                    if let Some(version_part) =
                                        info_line.strip_prefix(&format!("{}-", name))
                                    {
                                        search_result.version = Some(
                                            version_part
                                                .split_whitespace()
                                                .next()
                                                .unwrap_or(version_part)
                                                .to_string(),
                                        );
                                    }
                                }
                                if info_line.starts_with("webpage:") {
                                    search_result.homepage =
                                        Some(info_line[8..].trim().to_string());
                                }
                            }
                        }
                    }
                }

                if config.include_installed {
                    if let Ok(installed_output) = self
                        .run_command("apk", &["info", "-e", name], config.env.as_ref())
                        .await
                    {
                        search_result.installed = installed_output.status.success()
                            && !installed_output.stdout.is_empty();
                    }
                }

                results.push(search_result);
            }
        }

        Ok(results)
    }

    async fn search_brew(
        &self,
        query: &str,
        config: &SearchConfig,
    ) -> Result<Vec<SearchResult>, PkgError> {
        let mut cmd_args = vec!["search", query];
        if let Some(extra_args) = &config.extra_args {
            cmd_args.extend(extra_args.iter().map(|s| s.as_str()));
        }

        let output = self
            .run_command("brew", &cmd_args, config.env.as_ref())
            .await
            .map_err(|e| PkgError::SearchFailed(format!("Brew search command failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::SearchFailed(format!(
                "Brew search failed: {}",
                output.stderr
            )));
        }

        let mut results = Vec::new();

        for line in output.stdout.lines() {
            let name = line.trim();
            if name.is_empty() || name.starts_with("==>") {
                continue;
            }

            let mut search_result = SearchResult {
                name: name.to_string(),
                version: None,
                installed: false,
                summary: None,
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 1.0,
            };

            // Get detailed information if requested
            if config.include_versions || config.include_installed || config.include_repo {
                if let Ok(info_output) = self
                    .run_command("brew", &["info", "--json=v2", name], config.env.as_ref())
                    .await
                {
                    if info_output.status.success() {
                        if let Ok(json_value) = serde_json::from_str::<Value>(&info_output.stdout) {
                            if let Some(formulae) =
                                json_value.get("formulae").and_then(|f| f.as_array())
                            {
                                if let Some(formula) = formulae.first() {
                                    if config.include_versions {
                                        if let Some(versions) =
                                            formula.get("versions").and_then(|v| v.get("stable"))
                                        {
                                            if let Some(version_str) = versions.as_str() {
                                                search_result.version =
                                                    Some(version_str.to_string());
                                            }
                                        }
                                    }

                                    if config.include_installed {
                                        if let Some(installed) =
                                            formula.get("installed").and_then(|i| i.as_array())
                                        {
                                            search_result.installed = !installed.is_empty();
                                        }
                                    }

                                    if let Some(desc) = formula.get("desc").and_then(|d| d.as_str())
                                    {
                                        search_result.summary = Some(desc.to_string());
                                    }

                                    if let Some(homepage) =
                                        formula.get("homepage").and_then(|h| h.as_str())
                                    {
                                        search_result.homepage = Some(homepage.to_string());
                                    }

                                    if config.include_repo {
                                        if let Some(tap) =
                                            formula.get("tap").and_then(|t| t.as_str())
                                        {
                                            search_result.repository = Some(tap.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            results.push(search_result);
        }

        Ok(results)
    }

    fn filter_and_sort_results(
        &self,
        mut results: Vec<SearchResult>,
        config: &SearchConfig,
    ) -> Vec<SearchResult> {
        let query_lower = config.query.to_lowercase();

        // Apply search_in filters
        results.retain(|result| {
            if config.search_in.contains(&SearchField::All) {
                return true;
            }

            let mut matches = false;

            if config.search_in.contains(&SearchField::Name) {
                if config.case_sensitive {
                    matches = if config.exact {
                        result.name == config.query
                    } else {
                        result.name.contains(&config.query)
                    };
                } else {
                    let name_lower = result.name.to_lowercase();
                    matches = if config.exact {
                        name_lower == query_lower
                    } else {
                        name_lower.contains(&query_lower)
                    };
                }
            }

            if !matches && config.search_in.contains(&SearchField::Description) {
                if let Some(ref summary) = result.summary {
                    if config.case_sensitive {
                        matches = summary.contains(&config.query);
                    } else {
                        let summary_lower = summary.to_lowercase();
                        matches = summary_lower.contains(&query_lower);
                    }
                }

                if !matches {
                    if let Some(ref description) = result.description {
                        if config.case_sensitive {
                            matches = description.contains(&config.query);
                        } else {
                            let description_lower = description.to_lowercase();
                            matches = description_lower.contains(&query_lower);
                        }
                    }
                }
            }

            matches
        });

        // Calculate scores and sort
        for result in &mut results {
            result.score =
                self.calculate_search_score(result, &config.query, config.case_sensitive);
        }

        // Sort by score (descending), then by name (ascending)
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });

        results
    }

    fn calculate_search_score(
        &self,
        result: &SearchResult,
        query: &str,
        case_sensitive: bool,
    ) -> f64 {
        let query_to_use = if case_sensitive {
            query.to_string()
        } else {
            query.to_lowercase()
        };
        let name_to_use = if case_sensitive {
            result.name.clone()
        } else {
            result.name.to_lowercase()
        };

        // Exact name match gets highest score
        if name_to_use == query_to_use {
            return 1.0;
        }

        // Name starts with query gets high score
        if name_to_use.starts_with(&query_to_use) {
            return 0.9;
        }

        // Name contains query gets medium score
        if name_to_use.contains(&query_to_use) {
            return 0.7;
        }

        // Description/summary matches get lower score
        if let Some(ref summary) = result.summary {
            let summary_to_use = if case_sensitive {
                summary.clone()
            } else {
                summary.to_lowercase()
            };
            if summary_to_use.contains(&query_to_use) {
                return 0.5;
            }
        }

        if let Some(ref description) = result.description {
            let description_to_use = if case_sensitive {
                description.clone()
            } else {
                description.to_lowercase()
            };
            if description_to_use.contains(&query_to_use) {
                return 0.3;
            }
        }

        // Default score
        0.1
    }

    // Helper methods for parsing manager-specific output

    fn parse_apt_dependencies(&self, depends_line: &str) -> Vec<String> {
        let deps_str = if depends_line.starts_with("Depends: ") {
            &depends_line[9..]
        } else {
            depends_line
        };

        deps_str
            .split(',')
            .map(|dep| {
                // Remove version constraints like ">= 1.2.3" and alternatives
                let clean_dep = dep.trim().split_whitespace().next().unwrap_or(dep.trim());
                // Remove alternatives separated by |
                clean_dep
                    .split('|')
                    .next()
                    .unwrap_or(clean_dep)
                    .trim()
                    .to_string()
            })
            .filter(|dep| !dep.is_empty())
            .collect()
    }

    fn parse_apt_depends_output(&self, output: &str) -> PackageDependencies {
        let mut runtime_deps = Vec::new();

        for line in output.lines() {
            if line.trim().starts_with("Depends: ") {
                let dep = line.trim()[9..].trim();
                if !dep.is_empty() {
                    runtime_deps.push(dep.to_string());
                }
            }
        }

        PackageDependencies {
            runtime: runtime_deps,
            build: Vec::new(),
            optional: Vec::new(),
        }
    }

    fn parse_apt_rdepends_output(&self, output: &str) -> Vec<String> {
        output
            .lines()
            .skip(1) // Skip header line
            .filter(|line| !line.trim().is_empty() && !line.starts_with("Reverse Depends:"))
            .map(|line| line.trim().to_string())
            .collect()
    }

    fn parse_pacman_dependencies(&self, deps_line: &str) -> Vec<String> {
        if deps_line == "None" {
            return Vec::new();
        }

        deps_line
            .split_whitespace()
            .map(|dep| {
                // Remove version constraints
                let mut name = dep;
                if let Some((pkg_name, _)) = name.split_once('=') {
                    name = pkg_name;
                }
                if let Some((pkg_name, _)) = name.split_once('>') {
                    name = pkg_name;
                }
                if let Some((pkg_name, _)) = name.split_once('<') {
                    name = pkg_name;
                }
                name.trim().to_string()
            })
            .filter(|dep| !dep.is_empty())
            .collect()
    }

    async fn run_command(
        &self,
        cmd: &str,
        args: &[&str],
        env: Option<&HashMap<String, String>>,
    ) -> Result<CommandOutput, PkgError> {
        let mut command = pkg_cmd(cmd);
        command.args(args);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        if let Some(env_vars) = env {
            for (key, value) in env_vars {
                command.env(key, value);
            }
        }

        let output = command
            .bounded_output()
            .await
            .map_err(|e| PkgError::InfoQueryFailed(format!("Failed to run {}: {}", cmd, e)))?;

        Ok(CommandOutput {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    // List installed packages implementation
    async fn list_installed_async(&self, config: ListInstalledConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_list_installed_config(&config)?;

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;

        // Perform list installed operation with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_list_installed(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::ListInstalledTimeout)?;

        result
    }

    fn validate_list_installed_config(&self, config: &ListInstalledConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidListInstalledConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        if config.limit == 0 {
            return Err(PkgError::InvalidListInstalledConfig(
                "limit must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    async fn perform_list_installed(
        &self,
        config: &ListInstalledConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        // Get installed packages based on manager
        let mut packages = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => self.list_installed_apt(config).await?,
            ManagerKind::Dnf => self.list_installed_dnf(config).await?,
            ManagerKind::Yum => self.list_installed_yum(config).await?,
            ManagerKind::Pacman => self.list_installed_pacman(config).await?,
            ManagerKind::Apk => self.list_installed_apk(config).await?,
            ManagerKind::Brew => self.list_installed_brew(config).await?,
        };

        // Apply filtering
        self.filter_installed_packages(&mut packages, config);

        // Sort by name
        packages.sort_by(|a, b| a.name.cmp(&b.name));

        // Get total count after filtering but before pagination
        let total_installed = packages.len() as u32;

        // Apply pagination
        let start_idx = config.offset as usize;
        let end_idx = std::cmp::min(start_idx + config.limit as usize, packages.len());
        let paginated_packages = if start_idx < packages.len() {
            packages[start_idx..end_idx].to_vec()
        } else {
            vec![]
        };

        // Build result
        let results = ListInstalledResults {
            backend: "pkg".to_string(),
            manager: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            limit: config.limit,
            offset: config.offset,
            total_installed,
            results: paginated_packages,
        };

        let mut value = serde_json::to_value(results).map_err(|e| {
            PkgError::ListInstalledFailed(format!("Failed to serialize results: {}", e))
        })?;
        if !config.include_versions {
            omit_installed_versions(&mut value);
        }
        Ok(value)
    }

    fn filter_installed_packages(
        &self,
        packages: &mut Vec<InstalledPackage>,
        config: &ListInstalledConfig,
    ) {
        packages.retain(|pkg| {
            // Apply prefix filter if specified
            if let Some(prefix) = &config.prefix {
                if !pkg.name.to_lowercase().starts_with(&prefix.to_lowercase()) {
                    return false;
                }
            }

            // Apply name filter if specified
            if let Some(filter) = &config.filter {
                if !pkg.name.to_lowercase().contains(&filter.to_lowercase()) {
                    return false;
                }
            }

            true
        });
    }

    async fn list_installed_apt(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        self.apt_installed_packages(
            config.include_repo,
            config.include_install_reason,
            config.include_size,
        )
        .await
        .map_err(PkgError::ListInstalledFailed)
    }

    /// The installed packages from `dpkg-query` (state `installed` only: a
    /// removed package whose configuration files remain is not listed), with
    /// the repository of the installed version (one batched `apt-cache
    /// policy`), the install reason (one `apt-mark showmanual`) and the size.
    async fn apt_installed_packages(
        &self,
        with_repo: bool,
        with_reason: bool,
        with_size: bool,
    ) -> Result<Vec<InstalledPackage>, String> {
        let output = pkg_cmd("dpkg-query")
            .args([
                "-W",
                "-f",
                "${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\t${Installed-Size}\\n",
            ])
            .bounded_output()
            .await
            .map_err(|e| format!("could not run dpkg-query: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "dpkg-query failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages: Vec<InstalledPackage> = stdout
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 3 || parts.get(3).is_some_and(|s| *s != "installed") {
                    return None;
                }
                Some(InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: Some(parts[2].to_string()),
                    repository: None,
                    installed_size_bytes: if with_size {
                        parts
                            .get(4)
                            .and_then(|kib| kib.trim().parse::<u64>().ok())
                            .map(|kib| kib * 1024)
                    } else {
                        None
                    },
                    install_reason: None,
                    manager_specific: None,
                })
            })
            .collect();
        if with_reason {
            let manual = self.get_apt_manual_packages().await.unwrap_or_default();
            for pkg in &mut packages {
                pkg.install_reason = Some(
                    if manual.contains(&pkg.name) {
                        "manual"
                    } else {
                        "dependency"
                    }
                    .to_string(),
                );
            }
        }
        if with_repo {
            let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
            let repos = self.apt_policy_repositories(&names).await;
            for pkg in &mut packages {
                pkg.repository = repos.get(&pkg.name).cloned().flatten();
            }
        }
        Ok(packages)
    }

    /// The repository of the installed version of each package, from
    /// `apt-cache policy` run on many packages at once.
    async fn apt_policy_repositories(&self, names: &[String]) -> HashMap<String, Option<String>> {
        let mut repos = HashMap::new();
        for chunk in names.chunks(200) {
            let Ok(output) = pkg_cmd("apt-cache")
                .arg("policy")
                .args(chunk)
                .bounded_output()
                .await
            else {
                break;
            };
            if !output.status.success() {
                continue;
            }
            for (name, section) in apt_policy_sections(&String::from_utf8_lossy(&output.stdout)) {
                repos.insert(name, apt_policy_installed_repository(&section));
            }
        }
        repos
    }

    async fn list_installed_dnf(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        self.list_installed_rpm_based("dnf", config).await
    }

    async fn list_installed_yum(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        self.list_installed_rpm_based("yum", config).await
    }

    async fn list_installed_rpm_based(
        &self,
        manager_cmd: &str,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use rpm to get installed packages
        let mut cmd = pkg_cmd("rpm");
        cmd.arg("-qa")
            .arg("--qf")
            .arg("%{NAME}\\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\t%{ARCH}\\n");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("rpm command failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!(
                "rpm failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 && parts[0] != "gpg-pubkey" {
                let mut package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: Some(parts[2].to_string()),
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get repository info if requested
                if config.include_repo {
                    if let Ok(repo) = self.get_rpm_package_repo(&package.name, manager_cmd).await {
                        package.repository = repo;
                    }
                }

                // Get size info if requested
                if config.include_size {
                    if let Ok(size) = self.get_rpm_package_size(&package.name).await {
                        package.installed_size_bytes = size;
                    }
                }

                // Get install reason if requested (DNF only)
                if config.include_install_reason && manager_cmd == "dnf" {
                    if let Ok(reason) = self.get_dnf_install_reason(&package.name).await {
                        package.install_reason = reason;
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_rpm_package_repo(
        &self,
        package_name: &str,
        manager_cmd: &str,
    ) -> Result<Option<String>, PkgError> {
        let mut cmd = pkg_cmd(manager_cmd);
        cmd.arg("repoquery")
            .arg("--installed")
            .arg("--qf")
            .arg("%{repoid}")
            .arg(package_name);

        let output = cmd.bounded_output().await.map_err(|e| {
            PkgError::ListInstalledFailed(format!("{} repoquery failed: {}", manager_cmd, e))
        })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let repo = stdout.trim();
            if !repo.is_empty() {
                return Ok(Some(repo.to_string()));
            }
        }
        Ok(None)
    }

    async fn get_rpm_package_size(&self, package_name: &str) -> Result<Option<u64>, PkgError> {
        let mut cmd = pkg_cmd("rpm");
        cmd.arg("-qi").arg(package_name);

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("rpm -qi failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Size") {
                    if let Some(size_str) = line.split(':').nth(1) {
                        if let Ok(size) = size_str.trim().parse::<u64>() {
                            return Ok(Some(size));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    async fn get_dnf_install_reason(&self, package_name: &str) -> Result<Option<String>, PkgError> {
        let mut cmd = pkg_cmd("dnf");
        cmd.arg("repoquery")
            .arg("--installed")
            .arg("--qf")
            .arg("%{installreason}")
            .arg(package_name);

        let output = cmd.bounded_output().await.map_err(|e| {
            PkgError::ListInstalledFailed(format!("dnf repoquery installreason failed: {}", e))
        })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let reason = stdout.trim();
            match reason {
                "user" => Ok(Some("manual".to_string())),
                "dep" => Ok(Some("dependency".to_string())),
                _ if !reason.is_empty() => Ok(Some(reason.to_string())),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn list_installed_pacman(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use pacman -Q to get installed packages
        let mut cmd = pkg_cmd("pacman");
        cmd.arg("-Q");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("pacman -Q failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!(
                "pacman -Q failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mut package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    architecture: None,
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get detailed info if requested
                if config.include_repo || config.include_size || config.include_install_reason {
                    if let Ok(info) = self.get_pacman_package_info(&package.name).await {
                        if config.include_repo {
                            package.repository = info.repository;
                        }
                        if config.include_size {
                            package.installed_size_bytes = info.installed_size_bytes;
                        }
                        if config.include_install_reason {
                            package.install_reason = info.install_reason;
                        }
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    async fn get_pacman_package_info(
        &self,
        package_name: &str,
    ) -> Result<InstalledPackage, PkgError> {
        let mut cmd = pkg_cmd("pacman");
        cmd.arg("-Qi").arg(package_name);

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("pacman -Qi failed: {}", e)))?;

        if !output.status.success() {
            return Err(PkgError::ListInstalledFailed(format!(
                "pacman -Qi failed for {}",
                package_name
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut repository = None;
        let mut installed_size_bytes = None;
        let mut install_reason = None;

        for line in stdout.lines() {
            if line.starts_with("Repository") {
                if let Some(repo) = line.split(':').nth(1) {
                    repository = Some(repo.trim().to_string());
                }
            } else if line.starts_with("Installed Size") {
                if let Some(size_str) = line.split(':').nth(1) {
                    let size_str = size_str.trim();
                    // Parse sizes like "123.45 KiB", "1.23 MiB"
                    if let Some((num_str, unit)) = size_str.split_once(' ') {
                        if let Ok(size) = num_str.parse::<f64>() {
                            let bytes = match unit {
                                "KiB" => (size * 1024.0) as u64,
                                "MiB" => (size * 1024.0 * 1024.0) as u64,
                                "GiB" => (size * 1024.0 * 1024.0 * 1024.0) as u64,
                                "B" => size as u64,
                                _ => continue,
                            };
                            installed_size_bytes = Some(bytes);
                        }
                    }
                }
            } else if line.starts_with("Install Reason") {
                if let Some(reason_str) = line.split(':').nth(1) {
                    let reason = reason_str.trim();
                    install_reason = match reason {
                        "Explicitly installed" => Some("manual".to_string()),
                        "Installed as a dependency for another package" => {
                            Some("dependency".to_string())
                        }
                        _ => Some(reason.to_string()),
                    };
                }
            }
        }

        Ok(InstalledPackage {
            name: package_name.to_string(),
            version: "".to_string(), // Will be filled by caller
            architecture: None,
            repository,
            installed_size_bytes,
            install_reason,
            manager_specific: None,
        })
    }

    async fn list_installed_apk(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        // Use apk info -v to get installed packages
        let mut cmd = pkg_cmd("apk");
        cmd.arg("info").arg("-v");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apk info -v failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!(
                "apk info -v failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            // Parse lines like "busybox-1.35.0-r17"
            if let Some((name, version)) = Self::parse_apk_package_line(line) {
                let mut package = InstalledPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    architecture: None,
                    repository: None,
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };

                // Get size info if requested
                if config.include_size {
                    if let Ok(size) = self.get_apk_package_size(&package.name).await {
                        package.installed_size_bytes = size;
                    }
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }

    fn parse_apk_package_line(line: &str) -> Option<(&str, &str)> {
        // Parse lines like "busybox-1.35.0-r17"
        let line = line.trim();
        if let Some(dash_pos) = line.rfind('-') {
            if let Some(second_dash_pos) = line[..dash_pos].rfind('-') {
                let name = &line[..second_dash_pos];
                let version = &line[second_dash_pos + 1..];
                return Some((name, version));
            } else {
                // Single dash, split at first dash after excluding initial chars
                if let Some(version_start) = line.find('-') {
                    if version_start > 0 {
                        let name = &line[..version_start];
                        let version = &line[version_start + 1..];
                        return Some((name, version));
                    }
                }
            }
        }
        None
    }

    async fn get_apk_package_size(&self, package_name: &str) -> Result<Option<u64>, PkgError> {
        let mut cmd = pkg_cmd("apk");
        cmd.arg("info").arg("-s").arg(package_name);

        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::ListInstalledFailed(format!("apk info -s failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("installed size:") {
                    if let Some(size_str) = line.split(':').nth(1) {
                        let size_str = size_str.trim();
                        // Parse size (usually in bytes)
                        if let Ok(size) = size_str.parse::<u64>() {
                            return Ok(Some(size));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    async fn list_installed_brew(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        // Try to use JSON format first
        let json_output = self.get_brew_json_installed().await;

        match json_output {
            Ok(packages) => Ok(packages),
            Err(_) => {
                // Fallback to text format
                self.get_brew_text_installed(config).await
            }
        }
    }

    async fn get_brew_json_installed(&self) -> Result<Vec<InstalledPackage>, PkgError> {
        let mut cmd = pkg_cmd("brew");
        cmd.arg("info").arg("--json=v2").arg("--installed");

        let output = cmd.bounded_output().await.map_err(|e| {
            PkgError::ListInstalledFailed(format!("brew info --json failed: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!(
                "brew info --json failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).map_err(|e| {
            PkgError::ListInstalledFailed(format!("Failed to parse brew JSON: {}", e))
        })?;

        let mut packages = Vec::new();

        if let Some(formulae) = json["formulae"].as_array() {
            for formula in formulae {
                if let (Some(name), Some(installed)) =
                    (formula["name"].as_str(), formula["installed"].as_array())
                {
                    if let Some(version_obj) = installed.first() {
                        let version = version_obj["version"].as_str().unwrap_or("unknown");
                        let tap = formula["tap"].as_str();

                        let package = InstalledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            architecture: None,
                            repository: tap.map(|t| t.to_string()),
                            installed_size_bytes: None,
                            install_reason: version_obj["installed_on_request"]
                                .as_bool()
                                .map(|on_request| if on_request { "manual" } else { "dependency" })
                                .map(|s| s.to_string()),
                            manager_specific: Some(formula.clone()),
                        };
                        packages.push(package);
                    }
                }
            }
        }

        Ok(packages)
    }

    async fn get_brew_text_installed(
        &self,
        config: &ListInstalledConfig,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        let mut cmd = pkg_cmd("brew");
        cmd.arg("list").arg("--versions");

        // Add environment variables if specified
        if let Some(ref env) = config.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        let output = cmd.bounded_output().await.map_err(|e| {
            PkgError::ListInstalledFailed(format!("brew list --versions failed: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::ListInstalledFailed(format!(
                "brew list --versions failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let package = InstalledPackage {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(), // Take first version if multiple
                    architecture: None,
                    repository: Some("homebrew/core".to_string()), // Default tap
                    installed_size_bytes: None,
                    install_reason: None,
                    manager_specific: None,
                };
                packages.push(package);
            }
        }

        Ok(packages)
    }

    // ===============================
    // SNAPSHOT IMPLEMENTATION
    // ===============================
    // Restore (apply_lock) operations
    // ===============================

    async fn restore_async(&self, config: RestoreConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_restore_config(&config)?;

        // Parse and validate lockfile
        let lockfile = self.parse_lockfile(&config.lockfile, &config.format)?;

        // Validate lockfile against policies
        let platform_warnings = self.validate_lockfile(&lockfile, &config).await?;

        // Resolve manager (from config or lockfile). A text lockfile records no
        // manager ("auto"), so with manager=auto the system manager is detected.
        let detected = if config.manager == ManagerKind::Auto && lockfile.manager.name == "auto" {
            Some(self.detect_manager().await?)
        } else {
            None
        };
        let manager = self.resolve_restore_manager(&config.manager, &lockfile, detected)?;

        // Perform restore operation with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_restore(&config, &lockfile, &manager, platform_warnings),
        )
        .await
        .map_err(|_| PkgError::RestoreTimeout)?;

        result
    }

    fn validate_restore_config(&self, config: &RestoreConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidRestoreConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }

        if config.lockfile.trim().is_empty() {
            return Err(PkgError::InvalidRestoreConfig(
                "lockfile content cannot be empty".to_string(),
            ));
        }

        if let Some(ref extra_args) = config.extra_args {
            if extra_args.iter().any(|arg| arg.trim().is_empty()) {
                return Err(PkgError::InvalidRestoreConfig(
                    "extra_args cannot contain empty strings".to_string(),
                ));
            }
        }

        if let Some(ref env) = config.env {
            if env
                .iter()
                .any(|(k, v)| k.trim().is_empty() || v.trim().is_empty())
            {
                return Err(PkgError::InvalidRestoreConfig(
                    "env keys and values cannot be empty".to_string(),
                ));
            }
        }

        Ok(())
    }

    // ===============================
    // Snapshot operations
    // ===============================

    async fn snapshot_async(&self, config: SnapshotConfig) -> Result<Value, PkgError> {
        // Validate configuration
        self.validate_snapshot_config(&config)?;

        // Resolve manager
        let manager = self.resolve_manager(&config.manager).await?;

        // Perform snapshot operation with timeout
        let result = timeout(
            crate::core::process::limit(Duration::from_millis(config.timeout_ms)),
            self.perform_snapshot(&config, &manager),
        )
        .await
        .map_err(|_| PkgError::SnapshotTimeout)?;

        result
    }

    fn validate_snapshot_config(&self, config: &SnapshotConfig) -> Result<(), PkgError> {
        if config.timeout_ms == 0 {
            return Err(PkgError::InvalidSnapshotConfig(
                "timeout_ms must be greater than 0".to_string(),
            ));
        }
        exclude_matchers(&config.exclude_patterns)?;
        Ok(())
    }

    async fn perform_snapshot(
        &self,
        config: &SnapshotConfig,
        manager: &ManagerKind,
    ) -> Result<Value, PkgError> {
        // Collect OS metadata if requested
        let platform_info = if config.include_os_metadata {
            self.collect_platform_info().await
        } else {
            PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            }
        };

        // Collect manager metadata
        let manager_info = self.collect_manager_info(manager).await?;

        // Get installed packages
        let mut packages = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => self.snapshot_apt(config).await?,
            ManagerKind::Dnf => self.snapshot_dnf(config).await?,
            ManagerKind::Yum => self.snapshot_yum(config).await?,
            ManagerKind::Pacman => self.snapshot_pacman(config).await?,
            ManagerKind::Apk => self.snapshot_apk(config).await?,
            ManagerKind::Brew => self.snapshot_brew(config).await?,
        };

        // Apply filtering based on scope
        self.filter_snapshot_packages(&mut packages, config)?;

        // Apply exclude patterns
        self.apply_exclude_patterns(&mut packages, &config.exclude_patterns);

        // include_versions=minimal records the upstream version only.
        let minimal = config.include_versions == SnapshotVersionMode::Minimal;
        if minimal {
            for pkg in &mut packages {
                if let Some(v) = pkg.version.take() {
                    pkg.version = Some(upstream_version(manager, &v));
                }
            }
        }

        // Sort packages deterministically
        packages.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.architecture.cmp(&b.architecture))
                .then_with(|| a.version.cmp(&b.version))
        });

        // Build lockfile
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            manager: ManagerInfo {
                name: format!("{:?}", manager).to_lowercase(),
                alias: self.alias.clone(),
                version: manager_info.version,
                config: if minimal {
                    Some(json!({ "include_versions": "minimal" }))
                } else {
                    manager_info.config
                },
            },
            platform: platform_info,
            scope: format!("{:?}", config.scope).to_lowercase(),
            packages,
        };

        // Serialize lockfile in the requested format
        let lockfile_content = match config.format {
            SnapshotFormat::Json => serde_json::to_string_pretty(&lockfile).map_err(|e| {
                PkgError::SnapshotFailed(format!("JSON serialization failed: {}", e))
            })?,
            SnapshotFormat::Yaml => self.serialize_lockfile_yaml(&lockfile)?,
            SnapshotFormat::Text => self.serialize_lockfile_text(&lockfile)?,
        };

        // Build response
        let response = json!({
            "backend": "pkg",
            "action": "snapshot",
            "manager": format!("{:?}", manager).to_lowercase(),
            "alias": self.alias,
            "format": format!("{:?}", config.format).to_lowercase(),
            "lockfile": lockfile_content,
            "parsed": {
                "lockfile_version": lockfile.lockfile_version,
                "manager": {
                    "name": lockfile.manager.name,
                    "version": lockfile.manager.version,
                    "alias": lockfile.manager.alias
                },
                "platform": lockfile.platform,
                "scope": lockfile.scope,
                "packages_count": lockfile.packages.len()
            }
        });

        Ok(response)
    }

    async fn collect_platform_info(&self) -> PlatformInfo {
        let mut platform_info = PlatformInfo {
            os_family: None,
            os_name: None,
            os_version: None,
            kernel: None,
            architecture: None,
        };

        // Get OS info - try different methods
        if let Ok(output) = pkg_cmd("uname")
            .args(&["-s", "-r", "-m"])
            .bounded_output()
            .await
        {
            if output.status.success() {
                let info = String::from_utf8_lossy(&output.stdout);
                let parts: Vec<&str> = info.trim().split_whitespace().collect();
                if parts.len() >= 3 {
                    platform_info.kernel = Some(format!("{} {}", parts[0], parts[1]));
                    platform_info.architecture = Some(parts[2].to_string());
                }
            }
        }

        // Try to get distribution info
        if let Ok(output) = pkg_cmd("lsb_release")
            .args(&["-i", "-r"])
            .bounded_output()
            .await
        {
            if output.status.success() {
                let info = String::from_utf8_lossy(&output.stdout);
                for line in info.lines() {
                    if line.contains("Distributor ID:") {
                        platform_info.os_name =
                            line.split(':').nth(1).map(|s| s.trim().to_string());
                    } else if line.contains("Release:") {
                        platform_info.os_version =
                            line.split(':').nth(1).map(|s| s.trim().to_string());
                    }
                }
            }
        }

        // Fallback: try /etc/os-release
        if platform_info.os_name.is_none() {
            if let Ok(output) = tokio::fs::read_to_string("/etc/os-release").await {
                for line in output.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let value = value.trim_matches('"');
                        match key {
                            "NAME" => platform_info.os_name = Some(value.to_string()),
                            "VERSION" => platform_info.os_version = Some(value.to_string()),
                            _ => {}
                        }
                    }
                }
            }
        }

        // Determine OS family based on available package managers or OS name
        platform_info.os_family = self.determine_os_family(&platform_info.os_name).await;

        platform_info
    }

    async fn determine_os_family(&self, os_name: &Option<String>) -> Option<String> {
        if let Some(name) = os_name {
            let name_lower = name.to_lowercase();
            if name_lower.contains("ubuntu") || name_lower.contains("debian") {
                return Some("debian".to_string());
            } else if name_lower.contains("fedora")
                || name_lower.contains("rhel")
                || name_lower.contains("centos")
            {
                return Some("rhel".to_string());
            } else if name_lower.contains("arch") {
                return Some("arch".to_string());
            } else if name_lower.contains("alpine") {
                return Some("alpine".to_string());
            } else if name_lower.contains("darwin") || name_lower.contains("macos") {
                return Some("darwin".to_string());
            }
        }
        None
    }

    async fn collect_manager_info(&self, manager: &ManagerKind) -> Result<ManagerInfo, PkgError> {
        let (binary, version_arg) = match manager {
            ManagerKind::Auto => unreachable!("Auto should be resolved"),
            ManagerKind::Apt => ("apt", "--version"),
            ManagerKind::Dnf => ("dnf", "--version"),
            ManagerKind::Yum => ("yum", "--version"),
            ManagerKind::Pacman => ("pacman", "-V"),
            ManagerKind::Apk => ("apk", "--version"),
            ManagerKind::Brew => ("brew", "--version"),
        };

        let version = if let Ok(output) = pkg_cmd(binary).arg(version_arg).bounded_output().await {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                version_str.lines().next().map(|s| s.trim().to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(ManagerInfo {
            name: format!("{:?}", manager).to_lowercase(),
            alias: self.alias.clone(),
            version,
            config: None, // Could be extended to include repo config
        })
    }

    fn filter_snapshot_packages(
        &self,
        packages: &mut Vec<LockfilePackage>,
        config: &SnapshotConfig,
    ) -> Result<(), PkgError> {
        match config.scope {
            SnapshotScope::All => {
                // Keep all packages
            }
            SnapshotScope::Manual => {
                packages.retain(|pkg| pkg.install_reason.as_deref() == Some("manual"));
                // Note: If install_reason is not available, we could log a warning
                // but continue with all packages rather than error
            }
            SnapshotScope::Dependency => {
                packages.retain(|pkg| pkg.install_reason.as_deref() == Some("dependency"));
            }
        }
        Ok(())
    }

    /// Drops the packages whose name matches a shell-style pattern of
    /// `exclude_patterns` (`*`, `?`, `[...]`; checked by
    /// `validate_snapshot_config`).
    fn apply_exclude_patterns(&self, packages: &mut Vec<LockfilePackage>, patterns: &[String]) {
        let Ok(matchers) = exclude_matchers(patterns) else {
            return;
        };
        packages.retain(|pkg| !matchers.iter().any(|m| m.is_match(&pkg.name)));
    }

    fn serialize_lockfile_yaml(&self, lockfile: &Lockfile) -> Result<String, PkgError> {
        serde_yaml::to_string(lockfile)
            .map_err(|e| PkgError::SnapshotFailed(format!("YAML serialization failed: {}", e)))
    }

    /// The text lockfile: `#` header lines (lockfile version, manager, OS,
    /// scope), then one package per line, `name[=version] [arch] @repository
    /// (install reason) [pinned]`. `parse_text_lockfile` reads it back.
    fn serialize_lockfile_text(&self, lockfile: &Lockfile) -> Result<String, PkgError> {
        let mut output = String::new();
        output.push_str(&format!("# {}\n", lockfile.lockfile_version));
        output.push_str(&format!(
            "# manager: {} ({})\n",
            lockfile.manager.name,
            lockfile.manager.version.as_deref().unwrap_or("unknown")
        ));
        if let (Some(os_name), Some(os_version)) =
            (&lockfile.platform.os_name, &lockfile.platform.os_version)
        {
            output.push_str(&format!(
                "# os: {} {} ({})\n",
                os_name,
                os_version,
                lockfile
                    .platform
                    .architecture
                    .as_deref()
                    .unwrap_or("unknown")
            ));
        }
        if lockfile_is_minimal(lockfile) {
            output.push_str("# include_versions: minimal\n");
        }
        output.push_str(&format!("# scope: {}\n\n", lockfile.scope));
        for pkg in &lockfile.packages {
            let mut line = pkg.name.clone();
            if let Some(version) = &pkg.version {
                line.push_str(&format!("={}", version));
            }
            if let Some(arch) = &pkg.architecture {
                line.push_str(&format!(" [{}]", arch));
            }
            if let Some(repo) = &pkg.repository {
                line.push_str(&format!(" @{}", repo));
            }
            if let Some(reason) = &pkg.install_reason {
                line.push_str(&format!(" ({})", reason));
            }
            if pkg.pinned {
                line.push_str(" [pinned]");
            }
            output.push_str(&format!("{}\n", line));
        }
        Ok(output)
    }

    // Manager-specific snapshot implementations
    async fn snapshot_apt(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        let installed = self
            .apt_installed_packages(config.include_repo, config.include_install_reason, false)
            .await
            .map_err(PkgError::SnapshotFailed)?;
        let held_packages = self.get_apt_held_packages().await.unwrap_or_default();
        Ok(installed
            .into_iter()
            .map(|pkg| LockfilePackage {
                pinned: held_packages.contains(&pkg.name),
                version: (config.include_versions != SnapshotVersionMode::None)
                    .then_some(pkg.version),
                version_spec: None,
                architecture: pkg.architecture.filter(|_| config.include_arch),
                repository: pkg.repository,
                install_reason: pkg.install_reason,
                name: pkg.name,
            })
            .collect())
    }

    async fn get_apt_manual_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        let output = pkg_cmd("apt-mark")
            .arg("showmanual")
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("apt-mark showmanual failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.lines().map(|line| line.trim().to_string()).collect())
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_apt_held_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        let output = pkg_cmd("apt-mark")
            .arg("showhold")
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("apt-mark showhold failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.lines().map(|line| line.trim().to_string()).collect())
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_apt_package_repository(&self, package_name: &str) -> Option<String> {
        if let Ok(output) = pkg_cmd("apt-cache")
            .args(&["policy", package_name])
            .bounded_output()
            .await
        {
            if output.status.success() {
                return apt_policy_installed_repository(&String::from_utf8_lossy(&output.stdout));
            }
        }
        None
    }

    async fn snapshot_dnf(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        let locked = self.get_dnf_locked_packages().await.unwrap_or_default();
        self.snapshot_rpm("dnf", config, locked).await
    }

    /// The rpm-based snapshot (dnf, and yum, which is dnf on current
    /// systems): `rpm -qa` for the packages, one `repoquery --installed` for
    /// the repository each was installed from, one `repoquery
    /// --userinstalled` for the install reason.
    async fn snapshot_rpm(
        &self,
        tool: &str,
        config: &SnapshotConfig,
        locked_packages: HashSet<String>,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        let output = pkg_cmd("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\\n",
            ])
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("rpm query failed: {}", e)))?;
        if !output.status.success() {
            return Err(PkgError::SnapshotFailed(format!(
                "rpm -qa failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let user_packages = if config.include_install_reason {
            self.rpm_user_installed(tool).await?
        } else {
            HashSet::new()
        };
        let repos = if config.include_repo {
            self.rpm_from_repos(tool, None).await
        } else {
            HashMap::new()
        };
        let mut packages = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 3 {
                continue;
            }
            // gpg-pubkey entries are imported signing keys, not packages.
            if parts[0] == "gpg-pubkey" {
                continue;
            }
            let name = parts[0].to_string();
            let version = normalize_version(&ManagerKind::Dnf, parts[1]);
            packages.push(LockfilePackage {
                version: (config.include_versions != SnapshotVersionMode::None).then_some(version),
                version_spec: None,
                architecture: (config.include_arch && parts[2] != "(none)")
                    .then(|| parts[2].to_string()),
                repository: repos.get(&name).cloned().flatten(),
                install_reason: config.include_install_reason.then(|| {
                    if user_packages.contains(&name) {
                        "manual"
                    } else {
                        "dependency"
                    }
                    .to_string()
                }),
                pinned: locked_packages.contains(&name),
                name,
            });
        }
        Ok(packages)
    }

    /// The repository each installed package came from (`%{from_repo}`), for
    /// every package or one. A package installed from a file has none.
    async fn rpm_from_repos(
        &self,
        tool: &str,
        package: Option<&str>,
    ) -> HashMap<String, Option<String>> {
        let mut cmd = pkg_cmd(tool);
        cmd.args([
            "-q",
            "repoquery",
            "--installed",
            "--queryformat",
            "%{name} %{from_repo}\\n",
        ]);
        if let Some(name) = package {
            cmd.arg(name);
        }
        let mut repos = HashMap::new();
        let Ok(output) = cmd.bounded_output().await else {
            return repos;
        };
        if !output.status.success() {
            return repos;
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut words = line.split_whitespace();
            if let Some(name) = words.next() {
                let repo = words
                    .next()
                    .filter(|r| !matches!(*r, "(none)" | "@System" | "installed"))
                    .map(str::to_string);
                repos.insert(name.to_string(), repo);
            }
        }
        repos
    }

    /// The packages the user asked for (`repoquery --userinstalled`).
    async fn rpm_user_installed(&self, tool: &str) -> Result<HashSet<String>, PkgError> {
        let output = pkg_cmd(tool)
            .args([
                "-q",
                "repoquery",
                "--userinstalled",
                "--queryformat",
                "%{name}\\n",
            ])
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("{tool} repoquery failed: {e}")))?;
        if !output.status.success() {
            return Err(PkgError::SnapshotFailed(format!(
                "{tool} repoquery --userinstalled failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    async fn get_dnf_locked_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // Check for versionlock plugin configuration
        let versionlock_file = "/etc/dnf/plugins/versionlock.list";

        if let Ok(content) = tokio::fs::read_to_string(versionlock_file).await {
            let mut packages = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Versionlock format: "epoch:name-version-release.arch"
                // or just "name-*"
                // Extract package name
                if let Some(name_part) = line.split(':').last() {
                    if let Some(pkg_name) = name_part.split('-').next() {
                        packages.insert(pkg_name.to_string());
                    }
                }
            }
            Ok(packages)
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_dnf_package_repository(&self, package_name: &str) -> Option<String> {
        self.rpm_from_repos("dnf", Some(package_name))
            .await
            .remove(package_name)
            .flatten()
    }

    async fn snapshot_yum(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        let locked = self.get_yum_locked_packages().await.unwrap_or_default();
        self.snapshot_rpm("yum", config, locked).await
    }

    async fn get_yum_locked_packages(&self) -> Result<std::collections::HashSet<String>, PkgError> {
        // YUM uses versionlock plugin similar to DNF
        // Check for versionlock configuration
        let versionlock_file = "/etc/yum/pluginconf.d/versionlock.list";

        if let Ok(content) = tokio::fs::read_to_string(versionlock_file).await {
            let mut packages = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Versionlock format: "epoch:name-version-release.arch"
                // or just "name-*"
                // Extract package name
                if let Some(name_part) = line.split(':').last() {
                    if let Some(pkg_name) = name_part.split('-').next() {
                        packages.insert(pkg_name.to_string());
                    }
                }
            }
            Ok(packages)
        } else {
            Ok(std::collections::HashSet::new())
        }
    }

    async fn get_yum_package_repository(&self, package_name: &str) -> Option<String> {
        self.rpm_from_repos("yum", Some(package_name))
            .await
            .remove(package_name)
            .flatten()
    }

    pub async fn snapshot_pacman(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        // Pacman snapshot implementation for Arch Linux
        // Uses: pacman -Q (list packages), pacman -Qe (explicit packages), pacman -Qi (package info)

        // Get list of all installed packages
        let mut cmd = pkg_cmd("pacman");
        cmd.arg("-Q");

        if config.include_versions == SnapshotVersionMode::None {
            cmd.arg("-q"); // Quiet mode, names only
        }

        // Apply timeout
        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute pacman: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!(
                "pacman -Q failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get user-installed (explicit) packages
        let user_packages = if config.include_install_reason {
            self.get_pacman_explicit_packages()
                .await
                .unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages (HoldPkg from pacman.conf)
        let locked_packages = self.get_pacman_held_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (name, version) = if config.include_versions != SnapshotVersionMode::None {
                // Format: "package-name version"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    (parts[0].to_string(), Some(parts[1].to_string()))
                } else {
                    continue;
                }
            } else {
                // Quiet mode: just package name
                (line.to_string(), None)
            };

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get repository information if needed
            let repository = if config.include_repo {
                self.get_pacman_package_repository(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_pacman_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_pacman_explicit_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get explicitly installed packages using pacman -Qe
        let output = pkg_cmd("pacman")
            .args(&["-Qe", "-q"])
            .bounded_output()
            .await
            .map_err(|e| {
                PkgError::SnapshotFailed(format!("Failed to execute pacman -Qe: {}", e))
            })?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                packages.insert(line.to_string());
            }
        }

        Ok(packages)
    }

    pub async fn get_pacman_held_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Read HoldPkg entries from /etc/pacman.conf
        let config_path = "/etc/pacman.conf";
        let content = tokio::fs::read_to_string(config_path)
            .await
            .unwrap_or_default();

        let mut held_packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();

            // Look for HoldPkg directive
            if line.starts_with("HoldPkg") {
                if let Some(packages_part) = line.split('=').nth(1) {
                    for pkg in packages_part.split_whitespace() {
                        held_packages.insert(pkg.trim().to_string());
                    }
                }
            }
        }

        Ok(held_packages)
    }

    pub async fn get_pacman_package_repository(&self, package_name: &str) -> Option<String> {
        // Query package information using pacman -Qi
        let output = pkg_cmd("pacman")
            .args(&["-Qi", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for "Repository" field
        for line in stdout.lines() {
            if line.starts_with("Repository") {
                if let Some(repo) = line.split(':').nth(1) {
                    let repo = repo.trim();
                    if !repo.is_empty() && repo != "local" {
                        return Some(repo.to_string());
                    }
                }
            }
        }

        None
    }

    async fn get_pacman_package_architecture(&self, package_name: &str) -> Option<String> {
        // Query package architecture using pacman -Qi
        let output = pkg_cmd("pacman")
            .args(&["-Qi", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for "Architecture" field
        for line in stdout.lines() {
            if line.starts_with("Architecture") {
                if let Some(arch) = line.split(':').nth(1) {
                    let arch = arch.trim();
                    if !arch.is_empty() {
                        return Some(arch.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn snapshot_apk(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        // APK snapshot implementation for Alpine Linux
        // Uses: apk info (list packages), apk policy (repository info)

        // Get list of all installed packages
        let mut cmd = pkg_cmd("apk");
        cmd.arg("info");

        if config.include_versions == SnapshotVersionMode::None {
            // Just package names
        } else {
            cmd.arg("-v"); // Include version in output
        }

        // Apply timeout
        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute apk: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!(
                "apk info failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get explicitly installed (user) packages
        let user_packages = if config.include_install_reason {
            self.get_apk_explicit_packages().await.unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages
        let locked_packages = self.get_apk_pinned_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (name, version) = if config.include_versions != SnapshotVersionMode::None {
                // Format with -v: "package-name-version"
                // Version starts with first hyphen followed by digit
                let mut split_pos = None;
                let chars: Vec<char> = line.chars().collect();

                for i in 0..chars.len() {
                    if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                        split_pos = Some(i);
                        break;
                    }
                }

                if let Some(pos) = split_pos {
                    let name = line[..pos].to_string();
                    let version = line[pos + 1..].to_string();
                    (name, Some(version))
                } else {
                    (line.to_string(), None)
                }
            } else {
                // Without -v: just package name
                (line.to_string(), None)
            };

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get repository information if needed
            let repository = if config.include_repo {
                self.get_apk_package_repository(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_apk_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_apk_explicit_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get explicitly installed packages from /etc/apk/world
        let world_path = "/etc/apk/world";
        let content = tokio::fs::read_to_string(world_path)
            .await
            .unwrap_or_default();

        let mut packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse package name (may include version constraints)
            // Format can be: package, package=version, package>version, etc.
            let pkg_name =
                if let Some(pos) = line.find(|c| c == '=' || c == '>' || c == '<' || c == '~') {
                    &line[..pos]
                } else {
                    line
                };

            packages.insert(pkg_name.to_string());
        }

        Ok(packages)
    }

    pub async fn get_apk_pinned_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Read pinned packages from /etc/apk/world (packages with version pins)
        let world_path = "/etc/apk/world";
        let content = tokio::fs::read_to_string(world_path)
            .await
            .unwrap_or_default();

        let mut pinned_packages = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // If line contains version constraint, it's pinned
            if line.contains('=') {
                let pkg_name = if let Some(pos) = line.find('=') {
                    &line[..pos]
                } else {
                    continue;
                };
                pinned_packages.insert(pkg_name.to_string());
            }
        }

        Ok(pinned_packages)
    }

    pub async fn get_apk_package_repository(&self, package_name: &str) -> Option<String> {
        // Query package repository using apk policy
        let output = pkg_cmd("apk")
            .args(&["policy", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for repository information
        // Format:
        // package-name policy:
        //   @repo_tag http://url
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with('@') {
                // Extract repository tag
                if let Some(space_pos) = line.find(' ') {
                    let repo = &line[1..space_pos]; // Skip '@' and take until space
                    if !repo.is_empty() {
                        return Some(repo.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn get_apk_package_architecture(&self, package_name: &str) -> Option<String> {
        // Query package architecture using apk info
        let output = pkg_cmd("apk")
            .args(&["info", "-a", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output for architecture
        // Format includes: arch:x86_64
        for line in stdout.lines() {
            if line.starts_with("arch:") {
                if let Some(arch) = line.split(':').nth(1) {
                    let arch = arch.trim();
                    if !arch.is_empty() {
                        return Some(arch.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn snapshot_brew(
        &self,
        config: &SnapshotConfig,
    ) -> Result<Vec<LockfilePackage>, PkgError> {
        // Homebrew snapshot implementation for macOS and Linux
        // Uses: brew list (installed packages), brew info --json (package details)

        // Get list of all installed formulae and casks
        let mut cmd = pkg_cmd("brew");
        cmd.arg("list");
        cmd.arg("--formula"); // List formulae only (not casks by default)

        // Apply timeout
        let output = cmd
            .bounded_output()
            .await
            .map_err(|e| PkgError::SnapshotFailed(format!("Failed to execute brew: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PkgError::SnapshotFailed(format!(
                "brew list failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();

        // Get explicitly installed packages (leaves)
        let user_packages = if config.include_install_reason {
            self.get_brew_leaves().await.unwrap_or_default()
        } else {
            HashSet::new()
        };

        // Get pinned packages
        let locked_packages = self.get_brew_pinned_packages().await.unwrap_or_default();

        // Parse package list
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let name = line.to_string();

            // Check exclude patterns
            if config.exclude_patterns.iter().any(|pattern| {
                if pattern.contains('*') {
                    // Simple wildcard matching
                    let pattern_regex = pattern.replace("*", ".*");
                    regex::Regex::new(&format!("^{}$", pattern_regex))
                        .map(|re| re.is_match(&name))
                        .unwrap_or(false)
                } else {
                    &name == pattern
                }
            }) {
                continue;
            }

            // Get version information if needed
            let version = if config.include_versions != SnapshotVersionMode::None {
                self.get_brew_package_version(&name).await
            } else {
                None
            };

            // Get repository information (tap) if needed
            let repository = if config.include_repo {
                self.get_brew_package_tap(&name).await
            } else {
                None
            };

            // Get architecture if needed
            let architecture = if config.include_arch {
                self.get_brew_package_architecture(&name).await
            } else {
                None
            };

            // Determine install reason (leaf packages are explicitly installed)
            let install_reason = if config.include_install_reason {
                if user_packages.contains(&name) {
                    Some("explicit".to_string())
                } else {
                    Some("dependency".to_string())
                }
            } else {
                None
            };

            // Check if package is pinned
            let pinned = locked_packages.contains(&name);

            packages.push(LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture,
                repository,
                install_reason,
                pinned,
            });
        }

        Ok(packages)
    }

    pub async fn get_brew_leaves(&self) -> Result<HashSet<String>, PkgError> {
        // Get leaf packages (explicitly installed, not dependencies)
        let output = pkg_cmd("brew")
            .args(&["leaves"])
            .bounded_output()
            .await
            .map_err(|e| {
                PkgError::SnapshotFailed(format!("Failed to execute brew leaves: {}", e))
            })?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                packages.insert(line.to_string());
            }
        }

        Ok(packages)
    }

    pub async fn get_brew_pinned_packages(&self) -> Result<HashSet<String>, PkgError> {
        // Get pinned packages using brew list --pinned
        let output = pkg_cmd("brew")
            .args(&["list", "--pinned"])
            .bounded_output()
            .await
            .map_err(|e| {
                PkgError::SnapshotFailed(format!("Failed to execute brew list --pinned: {}", e))
            })?;

        if !output.status.success() {
            return Ok(HashSet::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut pinned_packages = HashSet::new();

        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty() {
                pinned_packages.insert(line.to_string());
            }
        }

        Ok(pinned_packages)
    }

    pub async fn get_brew_package_version(&self, package_name: &str) -> Option<String> {
        // Query package version using brew info --json
        let output = pkg_cmd("brew")
            .args(&["info", "--json=v2", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            // Homebrew info --json=v2 format
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(versions) = formula.get("versions") {
                        if let Some(stable) = versions.get("stable").and_then(|v| v.as_str()) {
                            return Some(stable.to_string());
                        }
                    }
                }
            }
            // Also check installed version
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(installed) = formula.get("installed").and_then(|i| i.as_array()) {
                        if let Some(first_install) = installed.first() {
                            if let Some(version) =
                                first_install.get("version").and_then(|v| v.as_str())
                            {
                                return Some(version.to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub async fn get_brew_package_tap(&self, package_name: &str) -> Option<String> {
        // Query package tap (repository) using brew info --json
        let output = pkg_cmd("brew")
            .args(&["info", "--json=v2", package_name])
            .bounded_output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output for tap
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(formulae) = json.get("formulae").and_then(|f| f.as_array()) {
                if let Some(formula) = formulae.first() {
                    if let Some(tap) = formula.get("tap").and_then(|t| t.as_str()) {
                        // Convert "homebrew/core" to just "core" for brevity
                        if let Some(short_tap) = tap.strip_prefix("homebrew/") {
                            return Some(short_tap.to_string());
                        }
                        return Some(tap.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn get_brew_package_architecture(&self, _package_name: &str) -> Option<String> {
        // Get system architecture for Homebrew packages
        // Homebrew bottles are architecture-specific
        let output = pkg_cmd("uname").arg("-m").bounded_output().await.ok()?;

        if !output.status.success() {
            return None;
        }

        let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Normalize architecture names
        match arch.as_str() {
            "x86_64" => Some("x86_64".to_string()),
            "arm64" => Some("arm64".to_string()),
            "aarch64" => Some("arm64".to_string()),
            _ => Some(arch),
        }
    }

    // ===============================
    // Restore implementation functions
    // ===============================

    fn parse_lockfile(&self, content: &str, format: &LockfileFormat) -> Result<Lockfile, PkgError> {
        match format {
            LockfileFormat::Auto => {
                // Try JSON first
                if let Ok(lockfile) = serde_json::from_str::<Lockfile>(content) {
                    return Ok(lockfile);
                }

                // Try YAML next
                if let Ok(lockfile) = serde_yaml::from_str::<Lockfile>(content) {
                    return Ok(lockfile);
                }

                // Fall back to text format
                self.parse_text_lockfile(content)
            }
            LockfileFormat::Json => serde_json::from_str::<Lockfile>(content).map_err(|e| {
                PkgError::RestoreInvalidLockfile(format!("Invalid JSON lockfile: {}", e))
            }),
            LockfileFormat::Yaml => serde_yaml::from_str::<Lockfile>(content).map_err(|e| {
                PkgError::RestoreInvalidLockfile(format!("Invalid YAML lockfile: {}", e))
            }),
            LockfileFormat::Text => self.parse_text_lockfile(content),
        }
    }

    /// Reads a text lockfile: `name[=version]` per line, optionally followed
    /// by ` [arch]`, ` @repository`, ` (install reason)` and ` [pinned]` as
    /// `snapshot` writes them. `#` lines are comments, except
    /// `# manager: <name>`, which records the manager; header lines of
    /// earlier releases (`manager: ...`, `os: ...`, `scope: ...`) are read the
    /// same way.
    fn parse_text_lockfile(&self, content: &str) -> Result<Lockfile, PkgError> {
        let mut packages = Vec::new();
        let mut manager = "auto".to_string();
        let mut scope = "all".to_string();
        let mut minimal = false;
        for (number, raw) in content.lines().enumerate() {
            let line = raw.trim();
            let header = line.strip_prefix('#').map(str::trim).unwrap_or(line);
            if let Some(name) = header.strip_prefix("manager:") {
                if let Some(word) = name.split_whitespace().next() {
                    manager = word.to_string();
                }
                continue;
            }
            if let Some(value) = header.strip_prefix("scope:") {
                scope = value.trim().to_string();
                continue;
            }
            if let Some(value) = header.strip_prefix("include_versions:") {
                minimal = value.trim() == "minimal";
                continue;
            }
            if line.is_empty() || line.starts_with('#') || header.starts_with("os:") {
                continue;
            }
            let mut words = line.split_whitespace();
            let first = words.next().unwrap_or_default();
            let (name, version) = match first.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (first.to_string(), None),
            };
            let mut pkg = LockfilePackage {
                name,
                version,
                version_spec: None,
                architecture: None,
                repository: None,
                install_reason: None,
                pinned: false,
            };
            for word in words {
                if word == "[pinned]" {
                    pkg.pinned = true;
                } else if let Some(arch) = word.strip_prefix('[').and_then(|w| w.strip_suffix(']'))
                {
                    pkg.architecture = Some(arch.to_string());
                } else if let Some(repo) = word.strip_prefix('@') {
                    pkg.repository = Some(repo.to_string());
                } else if let Some(reason) =
                    word.strip_prefix('(').and_then(|w| w.strip_suffix(')'))
                {
                    pkg.install_reason = Some(reason.to_string());
                } else {
                    return Err(PkgError::RestoreInvalidLockfile(format!(
                        "text lockfile line {}: unexpected {:?} after the package (expected \
                         [arch], @repository, (reason) or [pinned])",
                        number + 1,
                        word
                    )));
                }
            }
            packages.push(pkg);
        }
        Ok(Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "unknown".to_string(),
            manager: ManagerInfo {
                name: manager,
                alias: "system".to_string(),
                version: None,
                config: minimal.then(|| json!({ "include_versions": "minimal" })),
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope,
            packages,
        })
    }

    /// Checks the lockfile version and package names, and applies
    /// `on_platform_mismatch`. Returns the platform warnings.
    async fn validate_lockfile(
        &self,
        lockfile: &Lockfile,
        config: &RestoreConfig,
    ) -> Result<Vec<String>, PkgError> {
        // Validate lockfile version
        if !lockfile.lockfile_version.starts_with("pkg-lock/v1") {
            return Err(PkgError::RestoreInvalidLockfile(format!(
                "Unsupported lockfile version: {}",
                lockfile.lockfile_version
            )));
        }

        // Lockfile package names become package-manager arguments; check
        // them before anything runs (also in dry run), so a name can never be
        // read as an option, shell syntax, a path or a URL.
        for pkg in &lockfile.packages {
            check_lockfile_pkg_name(&pkg.name).map_err(PkgError::RestoreInvalidLockfile)?;
            if let Some(v) = &pkg.version {
                check_pkg_token("version", v).map_err(PkgError::RestoreInvalidLockfile)?;
            }
            if let Some(arch) = &pkg.architecture {
                check_pkg_token("arch", arch).map_err(PkgError::RestoreInvalidLockfile)?;
            }
        }

        // Platform: the host is described the way snapshot describes it.
        let mut warnings = Vec::new();
        if config.on_platform_mismatch != PlatformPolicy::Ignore {
            let host = self.collect_platform_info().await;
            let locked = &lockfile.platform;
            let mut differences = Vec::new();
            if let (Some(h), Some(l)) = (&host.os_name, &locked.os_name) {
                if h != l {
                    differences.push(format!("OS {l} (host: {h})"));
                }
            }
            if let (Some(h), Some(l)) = (&host.architecture, &locked.architecture) {
                if h != l {
                    differences.push(format!("architecture {l} (host: {h})"));
                }
            }
            if !differences.is_empty() {
                let text = format!(
                    "the lockfile was taken on another platform: {}",
                    differences.join(", ")
                );
                if config.on_platform_mismatch == PlatformPolicy::Fail {
                    return Err(PkgError::RestorePlatformIncompatible(format!(
                        "{text} (on_platform_mismatch=fail); nothing was changed"
                    )));
                }
                warnings.push(text);
            }
        }
        Ok(warnings)
    }

    /// Chooses the manager for `restore`. `detected` is the auto-detected system
    /// manager, used only when both the request and the lockfile say "auto"
    /// (a text lockfile without a `# manager:` line records none).
    fn resolve_restore_manager(
        &self,
        config_manager: &ManagerKind,
        lockfile: &Lockfile,
        detected: Option<ManagerKind>,
    ) -> Result<ManagerKind, PkgError> {
        let locked = match lockfile.manager.name.as_str() {
            "auto" => None,
            "apt" => Some(ManagerKind::Apt),
            "yum" => Some(ManagerKind::Yum),
            "dnf" => Some(ManagerKind::Dnf),
            "pacman" => Some(ManagerKind::Pacman),
            "apk" => Some(ManagerKind::Apk),
            "brew" => Some(ManagerKind::Brew),
            other => {
                return Err(PkgError::RestoreInvalidLockfile(format!(
                    "the lockfile names an unknown manager {other:?} (expected apt, dnf, yum, \
                     pacman, apk or brew)"
                )));
            }
        };
        match (config_manager, locked) {
            (ManagerKind::Auto, None) => detected.ok_or_else(|| {
                PkgError::ManagerNotAvailable("No supported package manager found".to_string())
            }),
            (ManagerKind::Auto, Some(locked)) => Ok(locked),
            (explicit, None) => Ok(explicit.clone()),
            (explicit, Some(locked)) => {
                let rpm_pair = matches!(
                    (explicit, &locked),
                    (ManagerKind::Dnf, ManagerKind::Yum) | (ManagerKind::Yum, ManagerKind::Dnf)
                );
                if *explicit != locked && !rpm_pair {
                    return Err(PkgError::RestoreManagerMismatch(format!(
                        "Config manager {} does not match lockfile manager {}",
                        manager_name(explicit),
                        manager_name(&locked)
                    )));
                }
                Ok(explicit.clone())
            }
        }
    }

    /// Compares the lockfile with the host, refuses what cannot be done
    /// (before anything runs, dry run included), and then runs one command
    /// per package (see `pkg.md` 3.4).
    async fn perform_restore(
        &self,
        config: &RestoreConfig,
        lockfile: &Lockfile,
        manager: &ManagerKind,
        mut warnings: Vec<String>,
    ) -> Result<Value, PkgError> {
        let current_packages = self.get_current_packages(manager).await?;

        // on_repo_mismatch (fails before anything runs, dry run included)
        // and include_dependencies warnings.
        warnings.extend(
            self.check_restore_repositories(lockfile, &current_packages, manager, config)
                .await?,
        );
        warnings.extend(dependency_filter_warnings(lockfile, config));

        let mut plan =
            self.compute_restore_plan_for(lockfile, &current_packages, config, manager)?;
        let at_repo_version = self
            .locked_at_repo_version(&plan, lockfile, config, manager)
            .await;
        let builds = self.upstream_builds(&plan, lockfile, manager).await;
        let ops = restore_operations_with(
            &mut plan,
            lockfile,
            &current_packages,
            config,
            manager,
            &at_repo_version,
            &builds,
        )?;
        warnings.extend(restore_mode_warnings(&ops, config, manager));

        if !plan.unresolved.is_empty() {
            let names: Vec<String> = plan
                .unresolved
                .iter()
                .map(|u| format!("{} ({})", u.name, u.reason))
                .collect();
            match config.on_missing_package {
                MissingPolicy::Fail => {
                    return Err(PkgError::RestoreUnresolved(format!(
                        "{} locked package(s) cannot be brought to the lockfile state \
                         (on_missing_package=fail): {}; nothing was changed",
                        names.len(),
                        name_list(&names)
                    )));
                }
                MissingPolicy::Warn => warnings.push(format!(
                    "{} locked package(s) are left as they are: {}",
                    names.len(),
                    name_list(&names)
                )),
                MissingPolicy::Ignore => {}
            }
        }

        let mode = match config.mode {
            RestoreMode::Exact => "exact",
            RestoreMode::BestEffort => "best_effort",
        };
        if config.dry_run {
            let commands: Vec<String> = ops
                .iter()
                .map(|op| restore_command(op, manager, config, true).map(|c| c.to_string()))
                .collect::<Result<_, _>>()?;
            return Ok(json!({
                "backend": "pkg",
                "action": "restore",
                "manager": manager_name(manager),
                "alias": &self.alias,
                "mode": mode,
                "dry_run": true,
                "plan": plan,
                "commands": commands,
                "warnings": warnings
            }));
        }

        let results = self
            .execute_restore_ops(&ops, manager, config, &mut warnings)
            .await?;
        let summary = self.compute_restore_summary(&plan, &results, config);
        Ok(json!({
            "backend": "pkg",
            "action": "restore",
            "manager": manager_name(manager),
            "alias": &self.alias,
            "mode": mode,
            "dry_run": false,
            "plan": plan,
            "results": results,
            "summary": summary,
            "warnings": warnings
        }))
    }

    /// Looks up the host repository of each installed locked package that
    /// records one (with the same per-manager query snapshot uses, so both
    /// sides have the same form) and applies `on_repo_mismatch`.
    async fn check_restore_repositories(
        &self,
        lockfile: &Lockfile,
        current_packages: &[InstalledPackage],
        manager: &ManagerKind,
        config: &RestoreConfig,
    ) -> Result<Vec<String>, PkgError> {
        let installed: HashSet<String> = current_packages.iter().map(|p| p.name.clone()).collect();
        let mut host_repos = HashMap::new();
        if config.on_repo_mismatch != RepoPolicy::Ignore {
            for pkg in &lockfile.packages {
                if pkg.repository.is_some()
                    && installed.contains(&pkg.name)
                    && !restore_excludes(pkg, config)
                {
                    let repo = self.host_package_repository(manager, &pkg.name).await;
                    host_repos.insert(pkg.name.clone(), repo);
                }
            }
        }
        repo_mismatch_warnings(lockfile, &installed, &host_repos, config)
    }

    /// The repository of an installed package as `snapshot` records it.
    async fn host_package_repository(
        &self,
        manager: &ManagerKind,
        package_name: &str,
    ) -> Option<String> {
        match manager {
            ManagerKind::Apt => self.get_apt_package_repository(package_name).await,
            ManagerKind::Dnf => self.get_dnf_package_repository(package_name).await,
            ManagerKind::Yum => self.get_yum_package_repository(package_name).await,
            ManagerKind::Pacman => self.get_pacman_package_repository(package_name).await,
            ManagerKind::Apk => self.get_apk_package_repository(package_name).await,
            ManagerKind::Brew => self.get_brew_package_tap(package_name).await,
            ManagerKind::Auto => None,
        }
    }

    /// For `mode: exact` with pacman: the packages to install or upgrade
    /// whose locked version is the version the repositories carry (`pacman
    /// -Si`), so installing by name reaches it exactly.
    async fn locked_at_repo_version(
        &self,
        plan: &RestorePlan,
        lockfile: &Lockfile,
        config: &RestoreConfig,
        manager: &ManagerKind,
    ) -> HashSet<String> {
        let mut found = HashSet::new();
        if config.mode != RestoreMode::Exact || *manager != ManagerKind::Pacman {
            return found;
        }
        let wanted: HashMap<&str, &str> = lockfile
            .packages
            .iter()
            .filter(|p| plan.install.contains(&p.name) || plan.upgrade.contains(&p.name))
            .filter_map(|p| Some((p.name.as_str(), p.version.as_deref()?)))
            .collect();
        if wanted.is_empty() {
            return found;
        }
        let mut names: Vec<&str> = wanted.keys().copied().collect();
        names.sort();
        let Ok(output) = pkg_cmd("pacman")
            .arg("-Si")
            .args(&names)
            .bounded_output()
            .await
        else {
            return found;
        };
        let mut name = String::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "Name" => name = value.trim().to_string(),
                "Version" => {
                    let repo = if lockfile_is_minimal(lockfile) {
                        upstream_version(manager, value.trim())
                    } else {
                        value.trim().to_string()
                    };
                    if wanted.get(name.as_str()).is_some_and(|locked| {
                        version_cmp::pacman(locked, &repo) == std::cmp::Ordering::Equal
                    }) {
                        found.insert(name.clone());
                    }
                }
                _ => {}
            }
        }
        found
    }

    /// For a lockfile of upstream versions: the newest build of each locked
    /// upstream version that the repositories carry, for the packages to
    /// install, upgrade or downgrade (apt `madison`, dnf/yum `list
    /// --showduplicates`, apk `policy`).
    async fn upstream_builds(
        &self,
        plan: &RestorePlan,
        lockfile: &Lockfile,
        manager: &ManagerKind,
    ) -> HashMap<String, String> {
        let mut builds = HashMap::new();
        if !lockfile_is_minimal(lockfile) || !supports_version_pin(manager) {
            return builds;
        }
        for pkg in &lockfile.packages {
            let Some(locked) = pkg.version.as_deref() else {
                continue;
            };
            let name = &pkg.name;
            if !(plan.install.contains(name)
                || plan.upgrade.contains(name)
                || plan.downgrade.contains(name))
            {
                continue;
            }
            let mut cmd = match manager {
                ManagerKind::Apt => {
                    let mut c = pkg_cmd("apt-cache");
                    c.arg("madison");
                    c
                }
                ManagerKind::Dnf | ManagerKind::Yum => {
                    let mut c = pkg_cmd(manager_name(manager));
                    c.args(["-q", "list", "--showduplicates", "--available"]);
                    c
                }
                _ => {
                    let mut c = pkg_cmd("apk");
                    c.arg("policy");
                    c
                }
            };
            cmd.arg(name);
            let Ok(output) = cmd.bounded_output().await else {
                break;
            };
            let stdout = String::from_utf8_lossy(&output.stdout);
            let best = available_versions(manager, name, &stdout)
                .into_iter()
                .filter(|v| upstream_version(manager, v) == upstream_version(manager, locked))
                .max_by(|a, b| compare_package_versions(manager, a, b));
            if let Some(best) = best {
                builds.insert(name.clone(), normalize_version(manager, &best));
            }
        }
        builds
    }

    /// Every installed package with its version (no limit, and under the
    /// restore's own deadline).
    async fn get_current_packages(
        &self,
        manager: &ManagerKind,
    ) -> Result<Vec<InstalledPackage>, PkgError> {
        let list_config = ListInstalledConfig {
            manager: manager.clone(),
            filter: None,
            prefix: None,
            include_versions: true,
            include_repo: false,
            include_size: false,
            include_install_reason: false,
            limit: u32::MAX,
            offset: 0,
            timeout_ms: 1,
            env: None,
        };
        let results = self.perform_list_installed(&list_config, manager).await?;

        // An unreadable list must not look like an empty host: every locked
        // package would be planned for install and nothing compared.
        serde_json::from_value::<ListInstalledResults>(results)
            .map(|list| list.results)
            .map_err(|e| {
                PkgError::RestoreApplyFailed(format!(
                    "could not read the installed packages: {}; nothing was changed",
                    e
                ))
            })
    }

    /// The plan with version ordering by string comparison (only for tests
    /// written before the manager-aware ordering; see
    /// `compute_restore_plan_for`).
    #[cfg(test)]
    fn compute_restore_plan(
        &self,
        lockfile: &Lockfile,
        current_packages: &[InstalledPackage],
        config: &RestoreConfig,
    ) -> Result<RestorePlan, PkgError> {
        self.compute_restore_plan_for(lockfile, current_packages, config, &ManagerKind::Brew)
    }

    /// Compares each locked package with the host: not installed goes to
    /// `install`, an older installed version to `upgrade`, a newer one is
    /// kept (`allow_newer`), downgraded (`allow_downgrades`) or unresolved;
    /// installed packages missing from the lockfile go to `extra`, or to
    /// `remove` with `allow_removals`. Versions are ordered as `manager`
    /// orders them.
    fn compute_restore_plan_for(
        &self,
        lockfile: &Lockfile,
        current_packages: &[InstalledPackage],
        config: &RestoreConfig,
        manager: &ManagerKind,
    ) -> Result<RestorePlan, PkgError> {
        let mut plan = RestorePlan {
            install: Vec::new(),
            upgrade: Vec::new(),
            downgrade: Vec::new(),
            remove: Vec::new(),
            keep: Vec::new(),
            extra: Vec::new(),
            unresolved: Vec::new(),
            skipped_dependencies: Vec::new(),
        };

        let minimal = lockfile_is_minimal(lockfile);
        let mut current_map = std::collections::HashMap::new();
        for pkg in current_packages {
            current_map.insert(&pkg.name, pkg);
        }

        for lock_pkg in &lockfile.packages {
            if restore_excludes(lock_pkg, config) {
                // Out of the plan entirely: also not "extra", so
                // allow_removals never removes it.
                current_map.remove(&lock_pkg.name);
                plan.skipped_dependencies.push(lock_pkg.name.clone());
                continue;
            }
            match current_map.remove(&lock_pkg.name) {
                Some(current_pkg) => match lock_pkg.version.as_deref() {
                    Some(lock_version) => {
                        // An upstream-only lockfile accepts any build.
                        let current_version = if minimal {
                            upstream_version(manager, &current_pkg.version)
                        } else {
                            current_pkg.version.clone()
                        };
                        match compare_package_versions(manager, &current_version, lock_version) {
                            std::cmp::Ordering::Equal => plan.keep.push(lock_pkg.name.clone()),
                            std::cmp::Ordering::Less => plan.upgrade.push(lock_pkg.name.clone()),
                            std::cmp::Ordering::Greater => {
                                if config.allow_newer {
                                    plan.keep.push(lock_pkg.name.clone());
                                } else if config.allow_downgrades {
                                    plan.downgrade.push(lock_pkg.name.clone());
                                } else {
                                    plan.unresolved.push(UnresolvedPackage {
                                        name: lock_pkg.name.clone(),
                                        reason: "newer_version_installed_downgrade_not_allowed"
                                            .to_string(),
                                    });
                                }
                            }
                        }
                    }
                    None => plan.keep.push(lock_pkg.name.clone()),
                },
                None => plan.install.push(lock_pkg.name.clone()),
            }
        }

        let mut rest: Vec<String> = current_map.into_keys().cloned().collect();
        rest.sort();
        if config.allow_removals {
            plan.remove = rest;
        } else {
            plan.extra = rest;
        }
        Ok(plan)
    }

    /// The commands a restore would run for `plan` (for tests; `perform_restore`
    /// builds them from the operations).
    #[cfg(test)]
    fn generate_restore_commands(
        &self,
        plan: &RestorePlan,
        manager: &ManagerKind,
        config: &RestoreConfig,
    ) -> Vec<String> {
        let mut plan = plan.clone();
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: String::new(),
            manager: ManagerInfo {
                name: manager_name(manager).to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages: Vec::new(),
        };
        restore_operations(&mut plan, &lockfile, &[], config, manager)
            .unwrap_or_default()
            .iter()
            .filter_map(|op| restore_command(op, manager, config, true).ok())
            .map(|c| c.to_string())
            .collect()
    }

    /// Runs the operations in order (installs, upgrades, downgrades,
    /// removals), one command each, and checks the version each one left.
    /// `exact` fails an operation that did not reach the locked version;
    /// `best_effort` retries a failed pinned install by name and accepts the
    /// version it gets, with a warning.
    async fn execute_restore_ops(
        &self,
        ops: &[RestoreOp],
        manager: &ManagerKind,
        config: &RestoreConfig,
        warnings: &mut Vec<String>,
    ) -> Result<RestoreResults, PkgError> {
        let mut results = RestoreResults {
            install: Vec::new(),
            upgrade: Vec::new(),
            downgrade: Vec::new(),
            remove: Vec::new(),
        };
        let mut unpinned = Vec::new();
        for op in ops {
            if crate::core::process::has_lost() {
                // The deadline passed: nothing more is started.
                break;
            }
            let mut outcome = self
                .run_restore_command(&restore_command(op, manager, config, true)?)
                .await;
            let pinned = op.kind != RestoreKind::Remove && op.version.is_some();
            if outcome.is_err()
                && pinned
                && config.mode == RestoreMode::BestEffort
                && supports_version_pin(manager)
                && !crate::core::process::has_lost()
            {
                // best_effort: the locked version may be gone from the
                // repositories; take what they carry.
                let retry = restore_command(op, manager, config, false)?;
                if self.run_restore_command(&retry).await.is_ok() {
                    unpinned.push(op.name.clone());
                    outcome = Ok(());
                }
            }
            let now = self.installed_version_of(&op.name, manager).await;
            let outcome =
                outcome.and_then(|()| verify_restore_op(op, now.as_deref(), config, manager));
            let result = PackageOpResult {
                name: op.name.clone(),
                status: if outcome.is_ok() { "success" } else { "failed" }.to_string(),
                from_version: op.from.clone(),
                to_version: now,
                locked_version: op.version.clone(),
                error: outcome.err().map(|e| error_value(&e)),
            };
            match op.kind {
                RestoreKind::Install => results.install.push(result),
                RestoreKind::Upgrade => results.upgrade.push(result),
                RestoreKind::Downgrade => results.downgrade.push(result),
                RestoreKind::Remove => results.remove.push(result),
            }
        }
        if !unpinned.is_empty() {
            warnings.push(format!(
                "best_effort: the locked version of {} package(s) could not be installed, so \
                 the repository version was installed instead: {}",
                unpinned.len(),
                name_list(&unpinned)
            ));
        }
        Ok(results)
    }

    /// Runs one restore command; its standard error is the failure reason.
    async fn run_restore_command(&self, cmd: &CmdLine) -> Result<(), PkgError> {
        let output = cmd
            .command()
            .bounded_output()
            .await
            .map_err(|e| PkgError::RestoreApplyFailed(format!("could not run {cmd}: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(PkgError::RestoreApplyFailed(format!(
                "{cmd} failed: {}{}",
                stderr.trim(),
                tail_lines(&stdout, 3)
            )))
        }
    }

    fn compute_restore_summary(
        &self,
        plan: &RestorePlan,
        results: &RestoreResults,
        config: &RestoreConfig,
    ) -> RestoreSummary {
        let installed = results
            .install
            .iter()
            .filter(|r| r.status == "success")
            .count() as u32;
        let upgraded = results
            .upgrade
            .iter()
            .filter(|r| r.status == "success")
            .count() as u32;
        let downgraded = results
            .downgrade
            .iter()
            .filter(|r| r.status == "success")
            .count() as u32;
        let removed = results
            .remove
            .iter()
            .filter(|r| r.status == "success")
            .count() as u32;
        let failed = results
            .install
            .iter()
            .chain(&results.upgrade)
            .chain(&results.downgrade)
            .chain(&results.remove)
            .filter(|r| r.status == "failed")
            .count() as u32;

        let success = match config.on_missing_package {
            MissingPolicy::Fail => plan.unresolved.is_empty() && failed == 0,
            _ => failed == 0,
        };

        RestoreSummary {
            installed,
            upgraded,
            downgraded,
            removed,
            kept: plan.keep.len() as u32,
            extra: plan.extra.len() as u32,
            unresolved: plan.unresolved.len() as u32,
            failed,
            mode: format!("{:?}", config.mode).to_lowercase(),
            success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_update_config_validation_invalid_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            upgrade: true,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };

        let result = handle.validate_update_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );
    }

    #[test]
    fn test_update_config_validation_nothing_to_do() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: false,
            upgrade: false,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_update_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nothing to do"));
    }

    #[test]
    fn test_update_config_validation_valid() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpdateConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            upgrade: true,
            assume_yes: true,
            security_only: false,
            check_only: false,
            dry_run: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_update_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_apt_update_line() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line =
            "curl/jammy-updates 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.14]";
        let result = handle.parse_apt_update_line(line);

        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "curl");
        assert_eq!(update.candidate_version, "7.81.0-1ubuntu1.15");
        assert_eq!(
            update.current_version,
            Some("7.81.0-1ubuntu1.14".to_string())
        );
    }

    #[test]
    fn test_parse_pacman_update_line() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line = "linux 6.9.1.arch1-1 -> 6.9.2.arch1-1";
        let result = handle.parse_pacman_update_line(line);

        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "linux");
        assert_eq!(update.candidate_version, "6.9.2.arch1-1");
        assert_eq!(update.current_version, Some("6.9.1.arch1-1".to_string()));
    }

    #[test]
    fn test_parse_brew_update_line() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line = "curl (7.85.0) < 7.86.0";
        let result = handle.parse_brew_update_line(line);

        assert!(result.is_some());
        let update = result.unwrap();
        assert_eq!(update.name, "curl");
        assert_eq!(update.candidate_version, "7.86.0");
        assert_eq!(update.current_version, Some("7.85.0".to_string()));
    }

    #[test]
    fn test_upgrade_config_validation_invalid_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![],
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };

        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );
    }

    #[test]
    fn test_upgrade_config_validation_empty_packages() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "".to_string()], // Contains empty package name
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("package names cannot be empty")
        );
    }

    #[test]
    fn test_upgrade_config_validation_meaningless_combination() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![],     // Empty packages
            refresh_index: false, // No index refresh
            assume_yes: true,
            security_only: false,
            dry_run: true,    // Dry run
            check_only: true, // And check only
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Nothing meaningful to do")
        );
    }

    #[test]
    fn test_upgrade_config_validation_valid() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "git".to_string()],
            refresh_index: true,
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: false,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_upgrade_config_validation_valid_check_only() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = UpgradeConfig {
            manager: ManagerKind::Auto,
            packages: vec![],    // Empty packages is OK with check_only
            refresh_index: true, // With refresh index
            assume_yes: true,
            security_only: false,
            dry_run: false,
            check_only: true,
            timeout_ms: 900000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_upgrade_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_verbs_list() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let verbs = handle.verbs();
        assert!(verbs.contains(&"update"));
        assert!(verbs.contains(&"install"));
        assert!(verbs.contains(&"remove"));
        assert!(verbs.contains(&"upgrade"));
        assert!(verbs.contains(&"info"));
    }

    #[test]
    fn test_info_config_validation_empty_packages() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec![], // Empty packages
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 5000,
            env: None,
        };

        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("packages cannot be empty")
        );
    }

    #[test]
    fn test_info_config_validation_empty_package_name() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string(), "".to_string()], // One empty package name
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 5000,
            env: None,
        };

        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("package name cannot be empty")
        );
    }

    #[test]
    fn test_info_config_validation_zero_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = InfoConfig {
            manager: ManagerKind::Auto,
            packages: vec!["curl".to_string()],
            include_dependencies: false,
            include_reverse_deps: false,
            include_files: false,
            include_repo: true,
            timeout_ms: 0, // Invalid timeout
            env: None,
        };

        let result = handle.validate_info_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );
    }

    #[test]
    fn test_info_config_validation_valid() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = InfoConfig {
            manager: ManagerKind::Apt,
            packages: vec!["curl".to_string(), "git".to_string()],
            include_dependencies: true,
            include_reverse_deps: true,
            include_files: true,
            include_repo: true,
            timeout_ms: 5000,
            env: Some(
                [("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let result = handle.validate_info_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_apt_dependencies_parsing() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line = "Depends: libc6 (>= 2.27), libssl1.1 (>= 1.1.1), zlib1g (>= 1:1.1.4)";
        let deps = handle.parse_apt_dependencies(line);

        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&"libc6".to_string()));
        assert!(deps.contains(&"libssl1.1".to_string()));
        assert!(deps.contains(&"zlib1g".to_string()));
    }

    #[test]
    fn test_pacman_dependencies_parsing() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line = "glibc>=2.31 openssl>=1.1.1 zlib";
        let deps = handle.parse_pacman_dependencies(line);

        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&"glibc".to_string()));
        assert!(deps.contains(&"openssl".to_string()));
        assert!(deps.contains(&"zlib".to_string()));
    }

    #[test]
    fn test_pacman_dependencies_parsing_none() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let line = "None";
        let deps = handle.parse_pacman_dependencies(line);

        assert!(deps.is_empty());
    }

    // Search configuration validation tests

    #[test]
    fn test_search_config_validation_valid() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name, SearchField::Description],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_search_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_search_config_validation_empty_query() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Query cannot be empty")
        );
    }

    #[test]
    fn test_search_config_validation_zero_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 0,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Timeout must be greater than 0")
        );
    }

    #[test]
    fn test_search_config_validation_zero_limit() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 0,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_search_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Limit must be greater than 0")
        );
    }

    // Search scoring tests

    #[test]
    fn test_calculate_search_score_exact_match() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let result = SearchResult {
            name: "curl".to_string(),
            version: Some("7.68.0".to_string()),
            installed: true,
            summary: Some("command line tool for transferring data".to_string()),
            description: None,
            repository: None,
            repository_url: None,
            homepage: None,
            score: 0.0,
        };

        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_calculate_search_score_starts_with() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let result = SearchResult {
            name: "curl-dev".to_string(),
            version: Some("7.68.0".to_string()),
            installed: false,
            summary: Some("development files for curl".to_string()),
            description: None,
            repository: None,
            repository_url: None,
            homepage: None,
            score: 0.0,
        };

        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.9);
    }

    #[test]
    fn test_calculate_search_score_contains() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let result = SearchResult {
            name: "libcurl4".to_string(),
            version: Some("7.68.0".to_string()),
            installed: false,
            summary: Some("library for transferring data".to_string()),
            description: None,
            repository: None,
            repository_url: None,
            homepage: None,
            score: 0.0,
        };

        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.7);
    }

    #[test]
    fn test_calculate_search_score_description_match() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let result = SearchResult {
            name: "wget".to_string(),
            version: Some("1.20.3".to_string()),
            installed: false,
            summary: Some("retrieves files from the web using curl-like protocol".to_string()),
            description: None,
            repository: None,
            repository_url: None,
            homepage: None,
            score: 0.0,
        };

        let score = handle.calculate_search_score(&result, "curl", false);
        assert_eq!(score, 0.5);
    }

    #[test]
    fn test_calculate_search_score_case_sensitive() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let result = SearchResult {
            name: "CURL".to_string(),
            version: Some("7.68.0".to_string()),
            installed: true,
            summary: Some("command line tool".to_string()),
            description: None,
            repository: None,
            repository_url: None,
            homepage: None,
            score: 0.0,
        };

        let score = handle.calculate_search_score(&result, "curl", true);
        assert_eq!(score, 0.1); // Should not match exactly due to case sensitivity

        let score_exact = handle.calculate_search_score(&result, "CURL", true);
        assert_eq!(score_exact, 1.0); // Should match exactly
    }

    // Search filter tests

    #[test]
    fn test_filter_and_sort_results_exact_match() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let results = vec![
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl-dev".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("development files".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
        ];

        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: true,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "curl");
    }

    #[test]
    fn test_filter_and_sort_results_fuzzy_match() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let results = vec![
            SearchResult {
                name: "curl-dev".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("development files".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                installed: false,
                summary: Some("library for transferring data".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
        ];

        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "curl".to_string(),
            search_in: vec![SearchField::Name],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 3);
        // Results should be sorted by score: exact match first, then starts with, then contains
        assert_eq!(filtered[0].name, "curl"); // score: 1.0
        assert_eq!(filtered[1].name, "curl-dev"); // score: 0.9
        assert_eq!(filtered[2].name, "libcurl4"); // score: 0.7
    }

    #[test]
    fn test_filter_and_sort_results_description_only() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let results = vec![
            SearchResult {
                name: "wget".to_string(),
                version: Some("1.20.3".to_string()),
                installed: false,
                summary: Some("retrieves files from web using http protocol".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
            SearchResult {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                installed: true,
                summary: Some("command line tool".to_string()),
                description: None,
                repository: None,
                repository_url: None,
                homepage: None,
                score: 0.0,
            },
        ];

        let config = SearchConfig {
            manager: ManagerKind::Apt,
            query: "http".to_string(),
            search_in: vec![SearchField::Description],
            exact: false,
            case_sensitive: false,
            limit: 50,
            offset: 0,
            include_installed: true,
            include_versions: true,
            include_repo: true,
            timeout_ms: 5000,
            extra_args: None,
            env: None,
        };

        let filtered = handle.filter_and_sort_results(results, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "wget");
    }

    // ===============================
    // SNAPSHOT TESTS
    // ===============================

    #[test]
    fn test_snapshot_config_validation_invalid_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SnapshotConfig {
            manager: ManagerKind::Auto,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            timeout_ms: 0, // Invalid
            env: None,
        };

        let result = handle.validate_snapshot_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );
    }

    #[test]
    fn test_snapshot_config_validation_valid() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            timeout_ms: 15000,
            env: None,
        };

        let result = handle.validate_snapshot_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_filter_snapshot_packages_all() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let mut packages = vec![
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("manual".to_string()),
                pinned: false,
            },
            LockfilePackage {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("dependency".to_string()),
                pinned: false,
            },
        ];

        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::All,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            timeout_ms: 15000,
            env: None,
        };

        let result = handle.filter_snapshot_packages(&mut packages, &config);
        assert!(result.is_ok());
        assert_eq!(packages.len(), 2); // Both packages should remain
    }

    #[test]
    fn test_filter_snapshot_packages_manual_only() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let mut packages = vec![
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("manual".to_string()),
                pinned: false,
            },
            LockfilePackage {
                name: "libcurl4".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("dependency".to_string()),
                pinned: false,
            },
        ];

        let config = SnapshotConfig {
            manager: ManagerKind::Apt,
            scope: SnapshotScope::Manual,
            include_versions: SnapshotVersionMode::Exact,
            include_repo: true,
            include_arch: true,
            include_install_reason: true,
            include_os_metadata: true,
            exclude_patterns: vec![],
            format: SnapshotFormat::Json,
            timeout_ms: 15000,
            env: None,
        };

        let result = handle.filter_snapshot_packages(&mut packages, &config);
        assert!(result.is_ok());
        assert_eq!(packages.len(), 1); // Only manual package should remain
        assert_eq!(packages[0].name, "curl");
    }

    #[test]
    fn test_apply_exclude_patterns() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let mut packages = vec![
            LockfilePackage {
                name: "linux-image-generic".to_string(),
                version: Some("5.15.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            },
            LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            },
            LockfilePackage {
                name: "wget".to_string(),
                version: Some("1.20.3".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: None,
                install_reason: None,
                pinned: false,
            },
        ];

        let patterns = vec!["linux-*".to_string()];
        handle.apply_exclude_patterns(&mut packages, &patterns);

        assert_eq!(packages.len(), 2); // linux-image-generic should be excluded
        assert!(packages.iter().any(|p| p.name == "curl"));
        assert!(packages.iter().any(|p| p.name == "wget"));
        assert!(!packages.iter().any(|p| p.name.starts_with("linux")));
    }

    #[test]
    fn test_serialize_lockfile_text() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2025-02-21T14:35:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: Some("2.4.10".to_string()),
                config: None,
            },
            platform: PlatformInfo {
                os_family: Some("debian".to_string()),
                os_name: Some("Ubuntu".to_string()),
                os_version: Some("22.04".to_string()),
                kernel: Some("Linux 5.15.0-94-generic".to_string()),
                architecture: Some("x86_64".to_string()),
            },
            scope: "all".to_string(),
            packages: vec![LockfilePackage {
                name: "curl".to_string(),
                version: Some("7.68.0-1ubuntu2.19".to_string()),
                version_spec: None,
                architecture: Some("amd64".to_string()),
                repository: Some("ubuntu-focal/main".to_string()),
                install_reason: Some("manual".to_string()),
                pinned: false,
            }],
        };

        let result = handle.serialize_lockfile_text(&lockfile);
        assert!(result.is_ok());

        let text = result.unwrap();
        assert!(text.contains("# pkg-lock/v1"));
        assert!(text.contains("manager: apt (2.4.10)"));
        assert!(text.contains("os: Ubuntu 22.04 (x86_64)"));
        assert!(text.contains("scope: all"));
        assert!(text.contains("curl=7.68.0-1ubuntu2.19 [amd64] @ubuntu-focal/main (manual)"));
    }

    #[test]
    fn test_determine_os_family() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };

        // Test async function in sync context by creating a simple runtime
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Test Ubuntu -> debian
        let ubuntu_result =
            rt.block_on(handle.determine_os_family(&Some("Ubuntu 22.04".to_string())));
        assert_eq!(ubuntu_result, Some("debian".to_string()));

        // Test Fedora -> rhel
        let fedora_result = rt.block_on(handle.determine_os_family(&Some("Fedora 38".to_string())));
        assert_eq!(fedora_result, Some("rhel".to_string()));

        // Test Arch -> arch
        let arch_result = rt.block_on(handle.determine_os_family(&Some("Arch Linux".to_string())));
        assert_eq!(arch_result, Some("arch".to_string()));

        // Test Alpine -> alpine
        let alpine_result =
            rt.block_on(handle.determine_os_family(&Some("Alpine Linux".to_string())));
        assert_eq!(alpine_result, Some("alpine".to_string()));

        // Test unknown -> None
        let unknown_result =
            rt.block_on(handle.determine_os_family(&Some("Unknown OS".to_string())));
        assert_eq!(unknown_result, None);
    }

    // ===============================
    // Restore (apply_lock) tests
    // ===============================

    #[test]
    fn test_restore_config_validation_empty_lockfile() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = RestoreConfig {
            manager: ManagerKind::Auto,
            lockfile: "".to_string(),
            format: LockfileFormat::Auto,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: false,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };

        let result = handle.validate_restore_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("lockfile content cannot be empty")
        );
    }

    #[test]
    fn test_restore_config_validation_invalid_timeout() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let config = RestoreConfig {
            manager: ManagerKind::Auto,
            lockfile: "test content".to_string(),
            format: LockfileFormat::Auto,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: false,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 0, // Invalid
            extra_args: None,
            env: None,
        };

        let result = handle.validate_restore_config(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timeout_ms must be greater than 0")
        );
    }

    #[test]
    fn test_parse_json_lockfile() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let lockfile_json = json!({
            "lockfile_version": "pkg-lock/v1",
            "generated_at": "2023-01-01T00:00:00Z",
            "manager": {
                "name": "apt",
                "alias": "system",
                "version": "2.0.0",
                "config": null
            },
            "platform": {
                "os_family": "debian",
                "os_name": "Ubuntu",
                "os_version": "20.04",
                "kernel": "5.4.0",
                "architecture": "x86_64"
            },
            "scope": "all",
            "packages": [
                {
                    "name": "curl",
                    "version": "7.68.0-1ubuntu2.19",
                    "architecture": "amd64",
                    "repository": "ubuntu-focal/main",
                    "install_reason": "manual",
                    "pinned": false
                }
            ]
        })
        .to_string();

        let result = handle.parse_lockfile(&lockfile_json, &LockfileFormat::Json);
        assert!(result.is_ok());

        let lockfile = result.unwrap();
        assert_eq!(lockfile.lockfile_version, "pkg-lock/v1");
        assert_eq!(lockfile.manager.name, "apt");
        assert_eq!(lockfile.packages.len(), 1);
        assert_eq!(lockfile.packages[0].name, "curl");
    }

    #[test]
    fn test_parse_text_lockfile() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let lockfile_text = "curl=7.68.0-1ubuntu2.19\ngit\nvim=8.2.0716-3ubuntu2";

        let result = handle.parse_lockfile(lockfile_text, &LockfileFormat::Text);
        assert!(result.is_ok());

        let lockfile = result.unwrap();
        assert_eq!(lockfile.packages.len(), 3);
        assert_eq!(lockfile.packages[0].name, "curl");
        assert_eq!(
            lockfile.packages[0].version,
            Some("7.68.0-1ubuntu2.19".to_string())
        );
        assert_eq!(lockfile.packages[1].name, "git");
        assert_eq!(lockfile.packages[1].version, None);
        assert_eq!(lockfile.packages[2].name, "vim");
        assert_eq!(
            lockfile.packages[2].version,
            Some("8.2.0716-3ubuntu2".to_string())
        );
    }

    #[test]
    fn test_restore_manager_resolution() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2023-01-01T00:00:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages: vec![],
        };

        // Test auto resolution
        let result = handle.resolve_restore_manager(&ManagerKind::Auto, &lockfile, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ManagerKind::Apt);

        // Test compatible explicit manager
        let result = handle.resolve_restore_manager(&ManagerKind::Apt, &lockfile, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ManagerKind::Apt);

        // Test incompatible manager
        let result = handle.resolve_restore_manager(&ManagerKind::Pacman, &lockfile, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn test_restore_manager_resolution_text_lockfile() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        // A text lockfile records its manager as "auto".
        let lockfile = handle.parse_text_lockfile("curl=7.0\nvim\n").unwrap();
        assert_eq!(lockfile.manager.name, "auto");

        // An explicitly requested manager is used as-is.
        let result = handle.resolve_restore_manager(&ManagerKind::Pacman, &lockfile, None);
        assert_eq!(result.unwrap(), ManagerKind::Pacman);
        let result =
            handle.resolve_restore_manager(&ManagerKind::Apt, &lockfile, Some(ManagerKind::Dnf));
        assert_eq!(result.unwrap(), ManagerKind::Apt);

        // manager=auto uses the detected system manager.
        let result =
            handle.resolve_restore_manager(&ManagerKind::Auto, &lockfile, Some(ManagerKind::Apk));
        assert_eq!(result.unwrap(), ManagerKind::Apk);

        // manager=auto with nothing detected fails instead of looking up "auto".
        let err = handle
            .resolve_restore_manager(&ManagerKind::Auto, &lockfile, None)
            .unwrap_err();
        assert!(matches!(err, PkgError::ManagerNotAvailable(_)));
    }

    #[test]
    fn test_compute_restore_plan() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let lockfile = Lockfile {
            lockfile_version: "pkg-lock/v1".to_string(),
            generated_at: "2023-01-01T00:00:00Z".to_string(),
            manager: ManagerInfo {
                name: "apt".to_string(),
                alias: "system".to_string(),
                version: None,
                config: None,
            },
            platform: PlatformInfo {
                os_family: None,
                os_name: None,
                os_version: None,
                kernel: None,
                architecture: None,
            },
            scope: "all".to_string(),
            packages: vec![
                LockfilePackage {
                    name: "curl".to_string(),
                    version: Some("7.68.0".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
                LockfilePackage {
                    name: "git".to_string(),
                    version: Some("2.34.1".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
                LockfilePackage {
                    name: "vim".to_string(),
                    version: Some("8.2.0".to_string()),
                    version_spec: None,
                    architecture: None,
                    repository: None,
                    install_reason: None,
                    pinned: false,
                },
            ],
        };

        let current_packages = vec![
            InstalledPackage {
                name: "curl".to_string(),
                version: "7.68.0".to_string(), // Same version
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
            InstalledPackage {
                name: "git".to_string(),
                version: "2.30.0".to_string(), // Older version
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
            InstalledPackage {
                name: "htop".to_string(), // Extra package not in lockfile
                version: "3.0.0".to_string(),
                architecture: None,
                repository: None,
                installed_size_bytes: None,
                install_reason: None,
                manager_specific: None,
            },
        ];

        let config = RestoreConfig {
            manager: ManagerKind::Apt,
            lockfile: "".to_string(),
            format: LockfileFormat::Json,
            mode: RestoreMode::Exact,
            allow_downgrades: false,
            allow_removals: true,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: false,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };

        let result = handle.compute_restore_plan(&lockfile, &current_packages, &config);
        assert!(result.is_ok());

        let plan = result.unwrap();

        // vim should be installed (missing)
        assert_eq!(plan.install.len(), 1);
        assert!(plan.install.contains(&"vim".to_string()));

        // git should be upgraded (older version)
        assert_eq!(plan.upgrade.len(), 1);
        assert!(plan.upgrade.contains(&"git".to_string()));

        // curl should be kept (same version)
        assert_eq!(plan.keep.len(), 1);
        assert!(plan.keep.contains(&"curl".to_string()));

        // htop should be removed (extra package, allow_removals=true)
        assert_eq!(plan.remove.len(), 1);
        assert!(plan.remove.contains(&"htop".to_string()));

        assert_eq!(plan.downgrade.len(), 0);
        assert_eq!(plan.extra.len(), 0);
        assert_eq!(plan.unresolved.len(), 0);
    }

    #[test]
    fn test_generate_restore_commands_apt() {
        let handle = PkgHandle {
            alias: "test".to_string(),
        };
        let plan = RestorePlan {
            install: vec!["curl".to_string(), "git".to_string()],
            upgrade: vec!["vim".to_string()],
            downgrade: vec!["nginx".to_string()],
            remove: vec!["htop".to_string()],
            keep: vec!["bash".to_string()],
            extra: vec![],
            unresolved: vec![],
            skipped_dependencies: vec![],
        };

        let config = RestoreConfig {
            manager: ManagerKind::Apt,
            lockfile: "".to_string(),
            format: LockfileFormat::Json,
            mode: RestoreMode::Exact,
            allow_downgrades: true,
            allow_removals: true,
            allow_newer: true,
            on_missing_package: MissingPolicy::Fail,
            on_repo_mismatch: RepoPolicy::Warn,
            on_platform_mismatch: PlatformPolicy::Warn,
            include_dependencies: true,
            dry_run: true,
            timeout_ms: 180000,
            extra_args: None,
            env: None,
        };

        let commands = handle.generate_restore_commands(&plan, &ManagerKind::Apt, &config);

        // One command per package, in order: installs, upgrades,
        // downgrades, removals (no versions in this plan's empty lockfile).
        assert_eq!(
            commands,
            [
                "DEBIAN_FRONTEND=noninteractive apt-get install -y curl",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y git",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y vim",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades nginx",
                "DEBIAN_FRONTEND=noninteractive apt-get remove -y htop",
            ]
        );
    }

    #[test]
    fn test_platform_info_structure() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: Some("Ubuntu".to_string()),
            os_version: Some("22.04".to_string()),
            kernel: Some("5.15.0-76-generic".to_string()),
            architecture: Some("x86_64".to_string()),
        };

        assert_eq!(platform.os_family.unwrap(), "linux");
        assert_eq!(platform.os_name.unwrap(), "Ubuntu");
        assert_eq!(platform.os_version.unwrap(), "22.04");
        assert_eq!(platform.kernel.unwrap(), "5.15.0-76-generic");
        assert_eq!(platform.architecture.unwrap(), "x86_64");
    }

    #[test]
    fn test_platform_info_optional_fields() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: None,
            os_version: None,
            kernel: None,
            architecture: Some("x86_64".to_string()),
        };

        assert!(platform.os_family.is_some());
        assert!(platform.os_name.is_none());
        assert!(platform.os_version.is_none());
        assert!(platform.kernel.is_none());
        assert!(platform.architecture.is_some());
    }

    #[test]
    fn test_platform_info_serialization() {
        let platform = PlatformInfo {
            os_family: Some("linux".to_string()),
            os_name: Some("Debian".to_string()),
            os_version: Some("11".to_string()),
            kernel: Some("5.10.0".to_string()),
            architecture: Some("x86_64".to_string()),
        };

        // Test JSON serialization
        let json = serde_json::to_value(&platform).unwrap();
        assert_eq!(json["os_family"], "linux");
        assert_eq!(json["os_name"], "Debian");
        assert_eq!(json["os_version"], "11");
        assert_eq!(json["kernel"], "5.10.0");
        assert_eq!(json["architecture"], "x86_64");

        // Test deserialization
        let deserialized: PlatformInfo = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.os_family, Some("linux".to_string()));
        assert_eq!(deserialized.os_name, Some("Debian".to_string()));
        assert_eq!(deserialized.os_version, Some("11".to_string()));
        assert_eq!(deserialized.kernel, Some("5.10.0".to_string()));
        assert_eq!(deserialized.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_platform_info_clone() {
        let platform = PlatformInfo {
            os_family: Some("darwin".to_string()),
            os_name: Some("macOS".to_string()),
            os_version: Some("13.0".to_string()),
            kernel: Some("22.1.0".to_string()),
            architecture: Some("aarch64".to_string()),
        };

        let cloned = platform.clone();
        assert_eq!(cloned.os_family, platform.os_family);
        assert_eq!(cloned.os_name, platform.os_name);
        assert_eq!(cloned.os_version, platform.os_version);
        assert_eq!(cloned.kernel, platform.kernel);
        assert_eq!(cloned.architecture, platform.architecture);
    }
}
// SEC-04: package-manager commands run without a shell. Nothing here
// invokes a real package manager; execution is checked with a mock
// executable inside a temporary directory.
/// The source (URL, suite/component) in one package's `apt-cache policy`
/// output of the installed version, or of the candidate when nothing is
/// installed. A version known only from `/var/lib/dpkg/status` has none.
fn apt_policy_source(policy: &str) -> Option<(String, String)> {
    let field = |name: &str| {
        policy
            .lines()
            .find_map(|l| l.trim().strip_prefix(name))
            .map(str::trim)
            .filter(|v| *v != "(none)")
    };
    let target = field("Installed:").or_else(|| field("Candidate:"))?;
    let mut current: Option<&str> = None;
    for line in policy
        .lines()
        .skip_while(|l| !l.contains("Version table:"))
        .skip(1)
    {
        let words: Vec<&str> = line.split_whitespace().collect();
        let is_source = words.len() >= 2
            && words[0].bytes().all(|b| b.is_ascii_digit() || b == b'-')
            && (words[1].contains(':') || words[1].starts_with('/'));
        if is_source {
            if current == Some(target) && words.len() >= 3 && words[1].contains(':') {
                return Some((words[1].to_string(), words[2].to_string()));
            }
        } else if let Some(v) = words.iter().find(|w| **w != "***") {
            current = Some(v);
        }
    }
    None
}

/// Splits `apt-cache policy` output for several packages into (package,
/// section) pairs: each section starts with a `<name>:` line at column 0.
fn apt_policy_sections(policy: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, String)> = Vec::new();
    for line in policy.lines() {
        if !line.starts_with(char::is_whitespace) && line.ends_with(':') && !line.is_empty() {
            sections.push((line[..line.len() - 1].to_string(), String::new()));
        } else if let Some((_, text)) = sections.last_mut() {
            text.push_str(line);
            text.push('\n');
        }
    }
    sections
}

/// The repository of the installed version in `apt-cache policy <name>`
/// output, as `<suite>/<component>` (e.g. `noble/main`) or, for a flat
/// repository, its path (e.g. `./`).
///
/// The version table lists each version on a line indented by five columns,
/// the installed one marked `***`, followed by its sources indented further:
///
/// ```text
///  *** 1.24.0-2ubuntu7 500
///         500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
///         100 /var/lib/dpkg/status
/// ```
///
/// The first source of the installed version that is a repository (`<prio>
/// <uri> <suite/component> ...`) is taken. `/var/lib/dpkg/status` alone (a
/// package installed from a local file, or whose repository is gone) gives
/// None: the repository is not known. Not installed also gives None.
fn apt_policy_installed_repository(policy: &str) -> Option<String> {
    let mut in_installed = false;
    for line in policy.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("***") {
            in_installed = true;
            continue;
        }
        if !in_installed {
            continue;
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();
        // A source line starts with its priority; anything else (the next
        // version line, or the end of the table) ends the installed block.
        let is_source = words.len() >= 2
            && words[0].bytes().all(|b| b.is_ascii_digit() || b == b'-')
            && (words[1].contains(':') || words[1].starts_with('/'));
        if !is_source {
            return None;
        }
        // `<prio> <uri> <suite/component|path> [arch] Packages`; the dpkg
        // status file has only `<prio> /var/lib/dpkg/status`.
        if words.len() >= 3 && words[1].contains(':') {
            return Some(words[2].to_string());
        }
    }
    None
}

/// `list_installed` with `include_versions: false`: every result keeps its
/// `version` key, set to null (as `repository` is with `include_repo: false`).
fn omit_installed_versions(list_result: &mut Value) {
    if let Some(results) = list_result.get_mut("results").and_then(Value::as_array_mut) {
        for entry in results {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("version".to_string(), Value::Null);
            }
        }
    }
}

/// Whether a locked package is left out of the restore plan: with
/// `include_dependencies: false`, packages the lockfile records as installed
/// as a dependency (`install_reason: "dependency"`).
fn restore_excludes(pkg: &LockfilePackage, config: &RestoreConfig) -> bool {
    !config.include_dependencies && pkg.install_reason.as_deref() == Some("dependency")
}

/// Names for a warning: at most ten, then how many more.
fn name_list(names: &[String]) -> String {
    const SHOWN: usize = 10;
    if names.len() <= SHOWN {
        names.join(", ")
    } else {
        format!(
            "{} and {} more",
            names[..SHOWN].join(", "),
            names.len() - SHOWN
        )
    }
}

/// Warnings for `include_dependencies: false` when the lockfile cannot say
/// which packages are dependencies (a text lockfile, or a snapshot taken with
/// `include_install_reason: false`): those packages stay in the plan.
fn dependency_filter_warnings(lockfile: &Lockfile, config: &RestoreConfig) -> Vec<String> {
    if config.include_dependencies {
        return Vec::new();
    }
    let unknown: Vec<String> = lockfile
        .packages
        .iter()
        .filter(|p| p.install_reason.is_none())
        .map(|p| p.name.clone())
        .collect();
    if unknown.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "include_dependencies=false: the lockfile records no install reason for {} package(s), \
         so they stay in the plan: {}",
        unknown.len(),
        name_list(&unknown)
    )]
}

/// Applies `on_repo_mismatch` to the locked packages that are in the plan.
///
/// A locked package's recorded `repository` is compared with the host's
/// repository for the same package, which is only known for installed
/// packages (`host_repos`, looked up the same way snapshot records it). A
/// mismatch fails the restore (`fail`) or adds a warning (`warn`); `ignore`
/// skips the check. Packages that cannot be compared (no repository in the
/// lockfile, not installed on the host, or a host repository that could not
/// be determined) are reported in a warning for `fail` and `warn`, never
/// silently passed.
fn repo_mismatch_warnings(
    lockfile: &Lockfile,
    installed: &HashSet<String>,
    host_repos: &HashMap<String, Option<String>>,
    config: &RestoreConfig,
) -> Result<Vec<String>, PkgError> {
    if config.on_repo_mismatch == RepoPolicy::Ignore {
        return Ok(Vec::new());
    }
    let mut mismatched = Vec::new();
    let mut no_recorded_repo = Vec::new();
    let mut not_installed = Vec::new();
    let mut host_unknown = Vec::new();
    for pkg in lockfile
        .packages
        .iter()
        .filter(|p| !restore_excludes(p, config))
    {
        let Some(locked) = &pkg.repository else {
            no_recorded_repo.push(pkg.name.clone());
            continue;
        };
        if !installed.contains(&pkg.name) {
            not_installed.push(pkg.name.clone());
            continue;
        }
        match host_repos.get(&pkg.name) {
            Some(Some(host)) if host == locked => {}
            Some(Some(host)) => mismatched.push(format!(
                "{} (lockfile: {}, host: {})",
                pkg.name, locked, host
            )),
            _ => host_unknown.push(pkg.name.clone()),
        }
    }

    if !mismatched.is_empty() && config.on_repo_mismatch == RepoPolicy::Fail {
        return Err(PkgError::RestoreRepoMismatch(format!(
            "{} package(s) come from a different repository than the lockfile records \
             (on_repo_mismatch=fail): {}; nothing was changed",
            mismatched.len(),
            name_list(&mismatched)
        )));
    }

    let mut warnings = Vec::new();
    if !mismatched.is_empty() {
        warnings.push(format!(
            "repository mismatch for {} package(s): {}",
            mismatched.len(),
            name_list(&mismatched)
        ));
    }
    if !no_recorded_repo.is_empty() {
        warnings.push(format!(
            "on_repo_mismatch: the lockfile records no repository for {} package(s), \
             so their repository was not checked: {}",
            no_recorded_repo.len(),
            name_list(&no_recorded_repo)
        ));
    }
    if !not_installed.is_empty() {
        warnings.push(format!(
            "on_repo_mismatch: {} package(s) are not installed on the host, so their \
             repository could not be compared: {}",
            not_installed.len(),
            name_list(&not_installed)
        ));
    }
    if !host_unknown.is_empty() {
        warnings.push(format!(
            "on_repo_mismatch: the host repository of {} installed package(s) could not be \
             determined, so it was not compared: {}",
            host_unknown.len(),
            name_list(&host_unknown)
        ));
    }
    Ok(warnings)
}

/// The exit status for a verb's printed result. A mutating verb fails
/// (`pkg.partial_failure`, exit 1) when any package operation failed
/// (`summary.failed > 0`), the summary says `success: false`, or the
/// autoremove step failed, even if other packages succeeded. `info` fails
/// (`pkg.not_found`) when a requested package is unknown to the manager.
fn result_status(verb: &str, result: &Value) -> Status {
    use crate::core::status::exit::FAILED;
    if verb == "info" {
        let packages = || {
            result
                .get("packages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        };
        let query_failed = packages()
            .filter(|p| p.pointer("/raw/error").is_some())
            .count();
        if query_failed > 0 {
            return Status::coded(
                FAILED,
                "pkg.partial_failure",
                format!("pkg info: {query_failed} package queries failed (see raw.error)"),
            );
        }
        let missing: Vec<String> = result
            .get("packages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.get("found") == Some(&Value::Bool(false)))
            .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        if missing.is_empty() {
            return Status::success();
        }
        return Status::coded(
            FAILED,
            "pkg.not_found",
            format!(
                "pkg info: {} package(s) not found: {}",
                missing.len(),
                name_list(&missing)
            ),
        );
    }
    let summary = result.get("summary");
    let failed = summary
        .and_then(|s| s.get("failed"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let success = summary
        .and_then(|s| s.get("success"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let autoremove = result.get("autoremove_error");
    if failed == 0 && success && autoremove.is_none() {
        return Status::success();
    }
    let total = result
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::len);
    let reason = match (failed, total) {
        (0, _) if autoremove.is_some() => format!(
            "pkg {}: the packages were removed but removing unused dependencies failed",
            verb
        ),
        (0, _) => format!("pkg {}: operation did not complete successfully", verb),
        (n, Some(t)) => format!("pkg {}: {} of {} package operations failed", verb, n, t),
        (n, None) => format!("pkg {}: {} package operations failed", verb, n),
    };
    Status::coded(FAILED, "pkg.partial_failure", reason)
}

#[cfg(test)]
mod result_status_tests {
    use super::*;

    // FUNC-02: a partial failure is a failure.
    #[test]
    fn partial_failures_fail_the_command() {
        let ok = json!({"packages": [{"name": "jq"}], "summary": {"installed": 1, "failed": 0}});
        assert!(result_status("install", &ok).ok);
        let dry = json!({"dry_run": true, "packages": []});
        assert!(result_status("install", &dry).ok);

        let partial = json!({"packages": [{"name": "jq"}, {"name": "nope"}], "summary": {"installed": 1, "failed": 1}});
        let st = result_status("install", &partial);
        assert!(!st.ok);
        assert_eq!(st.exit_code(), 1);
        assert_eq!(
            st.reason.as_deref(),
            Some("[pkg.partial_failure] pkg install: 1 of 2 package operations failed")
        );

        let restore = json!({"summary": {"failed": 0, "success": false, "unresolved": 2}});
        assert!(!result_status("restore", &restore).ok);
        let restore_ok = json!({"summary": {"failed": 0, "success": true}});
        assert!(result_status("restore", &restore_ok).ok);
    }
}

#[cfg(test)]
mod cmdline_safety_tests {
    use super::*;
    use tempfile::TempDir;

    fn handle() -> PkgHandle {
        PkgHandle {
            alias: "test".to_string(),
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    const HOSTILE: &[&str] = &[
        "jq;touch SENTINEL",
        "$(touch SENTINEL)",
        "`touch SENTINEL`",
        "jq|touch SENTINEL",
        "jq&&touch SENTINEL",
        "jq>SENTINEL",
        "jq touch",
        "'jq'",
        "\"jq\"",
        "jq\ntouch",
        "-y",
        "--force-yes",
        "",
        "*",
        "jq?",
        "jq\\",
        "jq#x",
        "jq!",
        "$HOME",
        "jq{a,b}",
    ];

    #[test]
    fn package_tokens_accept_real_names_and_reject_shell_syntax() {
        for ok in [
            "jq",
            "libssl1.1",
            "g++",
            "python3-pip",
            "nginx-core",
            "homebrew/cask/firefox",
            "1password",
            "pkg@2",
            "1:2.3.4-1ubuntu1",
            "2.0~rc1",
            "1.6-2",
            "amd64",
            "x86_64",
            "jq=1.6",
        ] {
            check_pkg_token("package name", ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in HOSTILE {
            assert!(
                check_pkg_token("package name", bad).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    fn restore_config(lockfile: String, format: &str) -> RestoreConfig {
        serde_json::from_value(serde_json::json!({
            "manager": "apt", "lockfile": lockfile, "format": format,
            "dry_run": true, "on_platform_mismatch": "ignore"
        }))
        .unwrap()
    }

    fn json_lockfile(names: &[&str]) -> String {
        let packages: Vec<_> = names
            .iter()
            .map(|n| serde_json::json!({ "name": n, "version": "1.0" }))
            .collect();
        serde_json::json!({
            "lockfile_version": "pkg-lock/v1", "generated_at": "2026-01-01T00:00:00Z",
            "manager": { "name": "apt", "alias": "system", "version": null, "config": null },
            "platform": { "os_family": null, "os_name": null, "os_version": null, "kernel": null, "architecture": null },
            "scope": "system", "packages": packages
        }).to_string()
    }

    /// SEC-08: restore validates every lockfile package name before any
    /// package-manager command runs, dry run included. A hostile name in a
    /// JSON or text lockfile fails the whole restore.
    #[test]
    fn restore_rejects_hostile_lockfile_names_before_running_anything() {
        let tmp = TempDir::new().unwrap();
        let sentinel = tmp.path().join("SENTINEL");
        let s = sentinel.to_string_lossy();
        let hostile = [
            format!("jq;touch {s}"),
            format!("$(touch {s})"),
            format!("jq && touch {s}"),
            "-oAPT::Get::Assume-Yes=1".to_string(),
            "--allow-unauthenticated".to_string(),
            "https://evil.example/x.rpm".to_string(),
            "ftp://evil.example/pkg".to_string(),
            "/tmp/evil.deb".to_string(),
            "tmp/evil.rpm".to_string(),
            "evil.pkg.tar.zst".to_string(),
            "a/../../etc/x".to_string(),
            "".to_string(),
        ];
        for name in &hostile {
            for (lockfile, format) in [
                (json_lockfile(&["jq", name]), "json"),
                (format!("jq=1.6\n{name}=1.0\n"), "text"),
            ] {
                let err = rt()
                    .block_on(handle().restore_async(restore_config(lockfile, format)))
                    .expect_err(&format!("{name:?} accepted in {format} lockfile"));
                assert!(
                    matches!(
                        err,
                        PkgError::RestoreInvalidLockfile(_) | PkgError::InvalidRestoreConfig(_)
                    ),
                    "{name:?}: {err}"
                );
            }
        }
        assert!(!sentinel.exists());

        let bad_version = json_lockfile(&["jq"]).replace("\"1.0\"", "\"1.0;id\"");
        assert!(
            rt().block_on(handle().restore_async(restore_config(bad_version, "json")))
                .is_err()
        );
    }

    #[test]
    fn valid_lockfile_names_still_pass_restore_validation() {
        let names = [
            "jq",
            "libssl1.1",
            "g++",
            "python3-pip",
            "homebrew/cask/firefox",
            "1password",
            "pkg@2",
            "jq=1.6",
        ];
        for (lockfile, format) in [
            (json_lockfile(&names), "json"),
            ("jq=1.6\nnginx-core=1.24.0-2\n".to_string(), "text"),
        ] {
            let config = restore_config(lockfile, format);
            let lock = handle()
                .parse_lockfile(&config.lockfile, &config.format)
                .unwrap();
            rt().block_on(handle().validate_lockfile(&lock, &config))
                .unwrap();
        }
        for ok in ["1:2.3.4-1ubuntu1", "2.0~rc1"] {
            check_pkg_token("version", ok).unwrap();
        }
    }

    fn install_config(name: &str, version: Option<&str>, dry_run: bool) -> InstallConfig {
        InstallConfig {
            manager: ManagerKind::Apt,
            packages: vec![PackageSpec {
                name: name.into(),
                version: version.map(Into::into),
                source: None,
            }],
            update_cache: false,
            assume_yes: true,
            only_if_missing: true,
            reinstall: false,
            upgrade: false,
            allow_downgrade: false,
            dry_run,
            timeout_ms: 1000,
            arch: None,
            extra_args: None,
            env: None,
        }
    }

    #[test]
    fn hostile_names_versions_and_arch_fail_validation() {
        let h = handle();
        for bad in HOSTILE {
            assert!(
                h.validate_config(&install_config(bad, None, true)).is_err(),
                "name {bad:?}"
            );
            assert!(
                h.validate_config(&install_config("jq", Some(bad), true))
                    .is_err(),
                "version {bad:?}"
            );
            let mut c = install_config("jq", None, true);
            c.arch = Some(bad.to_string());
            assert!(h.validate_config(&c).is_err(), "arch {bad:?}");
        }
        assert!(
            h.validate_config(&install_config("jq", Some("1.6-2"), false))
                .is_ok()
        );
    }

    /// Dry run with a hostile name is rejected through the real verb entry
    /// point, before any status query (formerly `sh -c "dpkg -s <name>"`).
    #[test]
    fn dry_run_with_hostile_names_runs_nothing() {
        let dir = TempDir::new().unwrap();
        let sentinel = dir.path().join("pwned");
        let s = sentinel.display().to_string();
        for name in [
            format!("jq;touch {s}"),
            format!("$(touch {s})"),
            format!("`touch {s}`"),
        ] {
            for verb in ["install", "remove"] {
                let input =
                    json!({"manager": "apt", "dry_run": true, "packages": [{"name": name}]});
                let mut args = Args::new();
                args.insert("input".into(), input.to_string());
                let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
                let mut io = IoStreams {
                    stdin: &mut i,
                    stdout: &mut o,
                    stderr: &mut e,
                };
                let status = handle().call(verb, &args, &mut io).unwrap();
                assert_eq!(status.exit_code(), 2, "{verb} {name}");
            }
            for verb in ["update", "upgrade"] {
                let input = json!({"manager": "apt", "dry_run": true, "packages": [name]});
                let mut args = Args::new();
                args.insert("input".into(), input.to_string());
                let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
                let mut io = IoStreams {
                    stdin: &mut i,
                    stdout: &mut o,
                    stderr: &mut e,
                };
                let status = handle().call(verb, &args, &mut io).unwrap();
                assert_eq!(status.exit_code(), 2, "{verb} {name}");
            }
        }
        assert!(!sentinel.exists());
    }

    #[test]
    fn install_command_keeps_display_text_and_single_arguments() {
        let mut c = install_config("jq", Some("1.6-2"), false);
        c.arch = Some("amd64".into());
        c.extra_args = Some(vec![
            "-o".into(),
            "Dpkg::Options::=--force-confold".into(),
            "$(touch X); a b".into(),
        ]);
        let cmd = handle()
            .build_install_command(&c, &c.packages[0], &ManagerKind::Apt, InstallStep::Install)
            .unwrap();
        assert_eq!(
            cmd.to_string(),
            "DEBIAN_FRONTEND=noninteractive apt-get install -y jq:amd64=1.6-2 -o Dpkg::Options::=--force-confold $(touch X); a b"
        );
        assert_eq!(
            cmd.argv(),
            &[
                "apt-get",
                "install",
                "-y",
                "jq:amd64=1.6-2",
                "-o",
                "Dpkg::Options::=--force-confold",
                "$(touch X); a b",
            ]
        );
        assert_eq!(
            cmd.env,
            vec![("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string())]
        );
    }

    #[test]
    fn remove_and_upgrade_commands_keep_display_text() {
        let h = handle();
        let pkg = PackageSpec {
            name: "jq".into(),
            version: None,
            source: None,
        };
        let rc = RemoveConfig {
            manager: ManagerKind::Pacman,
            packages: vec![pkg.clone()],
            purge: false,
            recursive: true,
            assume_yes: true,
            only_if_installed: true,
            fail_if_missing: false,
            dry_run: false,
            timeout_ms: 1000,
            arch: None,
            extra_args: None,
            env: None,
        };
        let cmd = rt()
            .block_on(h.build_remove_command(&[&pkg], &rc, &ManagerKind::Pacman))
            .unwrap();
        assert_eq!(cmd.to_string(), "pacman -Rs --noconfirm jq");
        let cmd = rt()
            .block_on(h.build_remove_command(
                &[&pkg],
                &RemoveConfig {
                    purge: true,
                    ..rc.clone()
                },
                &ManagerKind::Apt,
            ))
            .unwrap();
        assert_eq!(
            cmd.to_string(),
            "DEBIAN_FRONTEND=noninteractive apt-get purge -y jq"
        );
        assert_eq!(
            h.build_autoremove_command(&ManagerKind::Dnf)
                .unwrap()
                .unwrap()
                .argv(),
            &["dnf", "autoremove", "-y"]
        );
        assert!(
            h.build_autoremove_command(&ManagerKind::Apk)
                .unwrap()
                .is_none()
        );

        let uc = UpgradeConfig {
            manager: ManagerKind::Dnf,
            packages: vec!["jq".into(), "curl".into()],
            refresh_index: false,
            assume_yes: true,
            security_only: true,
            dry_run: false,
            check_only: false,
            timeout_ms: 1000,
            extra_args: Some(vec!["--setopt=x=1".into()]),
            env: None,
        };
        let cmd = rt()
            .block_on(h.build_upgrade_command_for_execution(&uc, &ManagerKind::Dnf, &[]))
            .unwrap();
        assert_eq!(
            cmd.to_string(),
            "dnf upgrade -y --security jq curl --setopt=x=1"
        );
        let cmd = rt()
            .block_on(h.build_upgrade_command_for_execution(&uc, &ManagerKind::Apt, &[]))
            .unwrap();
        assert_eq!(
            cmd.argv(),
            &[
                "apt-get",
                "install",
                "--only-upgrade",
                "-y",
                "jq",
                "curl",
                "--setopt=x=1"
            ]
        );

        let (cmd, ignore, skip) = h
            .list_updates_command(&["jq".into()], &ManagerKind::Apt)
            .unwrap();
        assert_eq!(
            (cmd.to_string().as_str(), ignore, skip),
            ("apt list --upgradable jq", true, true)
        );
    }

    /// The executor passes each argument to the program as-is: shell syntax
    /// arrives literally and nothing is executed by a shell.
    #[test]
    fn execution_uses_argv_not_a_shell() {
        let dir = TempDir::new().unwrap();
        let sentinel = dir.path().join("pwned");
        let out = dir.path().join("argv.txt");
        let mock = dir.path().join("mock-pkg");
        fs_write_exec(
            &mock,
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$OUT\"\n",
        );
        let s = sentinel.display().to_string();
        let hostile = [
            format!("$(touch {s})"),
            format!("`touch {s}`"),
            format!("jq;touch {s}"),
            format!("jq && touch {s}"),
            "with space".to_string(),
            "'quoted'".to_string(),
            "\"dq\"".to_string(),
        ];
        let mut cmd = CmdLine::lit(&format!("OUT={} {}", out.display(), mock.display()));
        for a in &hostile {
            cmd.arg(a);
        }
        let status = rt()
            .block_on(async { cmd.command().status().await })
            .unwrap();
        assert!(status.success());
        let got: Vec<String> = std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(got, hostile.to_vec());
        assert!(!sentinel.exists(), "a shell interpreted an argument");
    }

    #[test]
    fn execution_failures_are_reported() {
        let missing = CmdLine::lit("/nonexistent/resh-test-pkg-manager");
        assert!(
            rt().block_on(async { missing.command().bounded_output().await })
                .is_err()
        );
        let dir = TempDir::new().unwrap();
        let mock = dir.path().join("failing");
        fs_write_exec(&mock, "#!/bin/sh\necho boom >&2\nexit 3\n");
        let failing = CmdLine::lit(&mock.display().to_string());
        let out = rt()
            .block_on(async { failing.command().bounded_output().await })
            .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "boom");
    }

    /// Stage 4: security_only must never widen into a full upgrade. Where
    /// the manager's command has no security filter, update and upgrade fail
    /// before running anything, in dry run and check-only mode too.
    #[test]
    fn security_only_is_refused_where_it_cannot_be_honored() {
        let run = |verb: &str, input: serde_json::Value| {
            let mut args = Args::new();
            args.insert("input".into(), input.to_string());
            let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            let status = handle()
                .call(verb, &args, &mut io)
                .map_err(|e| e.to_string())?;
            if status.ok {
                Ok(true)
            } else {
                assert_eq!(status.exit_code(), 2, "{:?}", status.reason);
                Err(status.reason.unwrap_or_default())
            }
        };
        let unsupported = [
            ("update", vec!["apt", "pacman", "apk", "brew"]),
            ("upgrade", vec!["apt", "yum", "pacman", "apk", "brew"]),
        ];
        for (verb, managers) in unsupported {
            for manager in managers {
                for mode in [
                    json!({}),
                    json!({"dry_run": true}),
                    json!({"check_only": true}),
                ] {
                    let mut input =
                        json!({"manager": manager, "security_only": true, "refresh_index": false});
                    input
                        .as_object_mut()
                        .unwrap()
                        .extend(mode.as_object().unwrap().clone());
                    let err = run(verb, input.clone()).expect_err(&format!("{verb} {input}"));
                    assert!(
                        err.contains("security_only is not supported"),
                        "{verb} {manager}: {err}"
                    );
                    assert!(err.contains("nothing was run"), "{err}");
                }
            }
        }
        assert!(security_only_supported("update", &ManagerKind::Dnf));
        assert!(security_only_supported("update", &ManagerKind::Yum));
        assert!(security_only_supported("upgrade", &ManagerKind::Dnf));
        assert!(!security_only_supported("upgrade", &ManagerKind::Yum));
        // The refused managers really build an unfiltered command.
        let cfg: UpdateConfig =
            serde_json::from_value(json!({"manager": "apt", "security_only": true})).unwrap();
        let cmd = rt()
            .block_on(handle().build_upgrade_command(&cfg, &ManagerKind::Apt, &[]))
            .unwrap();
        assert!(!cmd.to_string().contains("security"), "{cmd}");
    }

    fn fs_write_exec(path: &std::path::Path, script: &str) {
        crate::core::test_support::write_executable(path, script);
    }
}

/// The options wired up in this release, checked on the pure parts of each
/// verb (plan building, policies, output shaping). The verbs themselves are
/// run end to end against fake package managers in
/// `tests/option_wiring.rs`, since pkg runs its managers as subprocesses.
#[cfg(test)]
mod option_tests {
    use super::*;
    use serde_json::json;

    fn handle() -> PkgHandle {
        PkgHandle {
            alias: "test".to_string(),
        }
    }

    fn lockfile(packages: Value) -> Lockfile {
        serde_json::from_value(json!({
            "lockfile_version": "pkg-lock/v1", "generated_at": "2026-01-01T00:00:00Z",
            "manager": { "name": "apt", "alias": "system", "version": null, "config": null },
            "platform": { "os_family": null, "os_name": null, "os_version": null,
                          "kernel": null, "architecture": null },
            "scope": "all", "packages": packages
        }))
        .unwrap()
    }

    fn restore_config(extra: Value) -> RestoreConfig {
        let mut base = json!({ "manager": "apt", "lockfile": "x" });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    fn installed(name: &str, version: &str) -> InstalledPackage {
        InstalledPackage {
            name: name.into(),
            version: version.into(),
            architecture: None,
            repository: None,
            installed_size_bytes: None,
            install_reason: None,
            manager_specific: None,
        }
    }

    // ---- PackageSpec.source ------------------------------------------------

    #[test]
    fn package_source_is_refused_for_install_and_remove() {
        let h = handle();
        let install: InstallConfig = serde_json::from_value(json!({
            "manager": "apt",
            "packages": [{ "name": "jq", "source": "https://example.com/jq.deb" }]
        }))
        .unwrap();
        let err = h.validate_config(&install).unwrap_err().to_string();
        assert!(
            err.contains("source=") && err.contains("nothing was run"),
            "{err}"
        );

        let remove: RemoveConfig = serde_json::from_value(json!({
            "manager": "apt", "packages": [{ "name": "jq", "source": "main" }]
        }))
        .unwrap();
        assert!(h.validate_remove_config(&remove).is_err());

        // Without source (or with an explicit null) nothing changes.
        for spec in [
            json!({ "name": "jq" }),
            json!({ "name": "jq", "source": null }),
        ] {
            let install: InstallConfig =
                serde_json::from_value(json!({ "manager": "apt", "packages": [spec] })).unwrap();
            assert!(h.validate_config(&install).is_ok());
        }
    }

    // ---- list_installed include_versions -----------------------------------

    #[test]
    fn list_installed_versions_are_nulled_when_not_wanted() {
        let mut value = serde_json::to_value(ListInstalledResults {
            backend: "pkg".into(),
            manager: "apt".into(),
            alias: "system".into(),
            limit: 500,
            offset: 0,
            total_installed: 1,
            results: vec![installed("jq", "1.7")],
        })
        .unwrap();
        assert_eq!(value["results"][0]["version"], "1.7");
        omit_installed_versions(&mut value);
        assert_eq!(value["results"][0]["version"], Value::Null);
        assert_eq!(value["results"][0]["name"], "jq");
    }

    // ---- restore include_dependencies --------------------------------------

    #[test]
    fn excluded_dependencies_are_neither_installed_nor_removed() {
        let lock = lockfile(json!([
            { "name": "app", "install_reason": "manual" },
            { "name": "libdep", "install_reason": "dependency" },
            { "name": "libold", "install_reason": "dependency" },
            { "name": "unknown" }
        ]));
        // libold is installed; app, libdep and unknown are not.
        let current = vec![installed("libold", "1.0"), installed("extra", "1.0")];

        let on = restore_config(json!({ "allow_removals": true }));
        let plan = handle().compute_restore_plan(&lock, &current, &on).unwrap();
        assert_eq!(plan.install, ["app", "libdep", "unknown"]);
        assert_eq!(plan.keep, ["libold"]);
        assert_eq!(plan.remove, ["extra"]);
        assert!(plan.skipped_dependencies.is_empty());
        assert!(dependency_filter_warnings(&lock, &on).is_empty());

        let off = restore_config(json!({ "allow_removals": true, "include_dependencies": false }));
        let plan = handle()
            .compute_restore_plan(&lock, &current, &off)
            .unwrap();
        assert_eq!(plan.install, ["app", "unknown"]);
        assert!(plan.keep.is_empty());
        // libold is out of the plan, so allow_removals does not remove it.
        assert_eq!(plan.remove, ["extra"]);
        assert_eq!(plan.skipped_dependencies, ["libdep", "libold"]);
        // "unknown" has no recorded reason: it stays and is reported.
        let warnings = dependency_filter_warnings(&lock, &off);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("1 package(s)") && warnings[0].contains("unknown"));
    }

    // ---- restore on_repo_mismatch --------------------------------------------

    fn repo_lock() -> Lockfile {
        lockfile(json!([
            { "name": "same", "repository": "stable/main" },
            { "name": "moved", "repository": "stable/main" },
            { "name": "absent", "repository": "stable/main" },
            { "name": "unknownhost", "repository": "stable/main" },
            { "name": "norepo" }
        ]))
    }

    fn host_view() -> (HashSet<String>, HashMap<String, Option<String>>) {
        let installed: HashSet<String> = ["same", "moved", "unknownhost", "norepo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let repos = HashMap::from([
            ("same".to_string(), Some("stable/main".to_string())),
            ("moved".to_string(), Some("backports/main".to_string())),
            ("unknownhost".to_string(), None),
        ]);
        (installed, repos)
    }

    #[test]
    fn repo_mismatch_policies() {
        let (installed, repos) = host_view();
        let lock = repo_lock();

        let fail = restore_config(json!({ "on_repo_mismatch": "fail" }));
        let err = repo_mismatch_warnings(&lock, &installed, &repos, &fail)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("moved (lockfile: stable/main, host: backports/main)")
                && err.contains("nothing was changed"),
            "{err}"
        );

        let warn = restore_config(json!({ "on_repo_mismatch": "warn" }));
        let warnings = repo_mismatch_warnings(&lock, &installed, &repos, &warn).unwrap();
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        assert!(warnings[0].starts_with("repository mismatch for 1 package(s): moved"));
        assert!(warnings[1].contains("records no repository") && warnings[1].contains("norepo"));
        assert!(warnings[2].contains("not installed") && warnings[2].contains("absent"));
        assert!(
            warnings[3].contains("could not be determined") && warnings[3].contains("unknownhost")
        );
        // The default policy is warn.
        let default = restore_config(json!({}));
        assert_eq!(
            repo_mismatch_warnings(&lock, &installed, &repos, &default).unwrap(),
            warnings
        );

        let ignore = restore_config(json!({ "on_repo_mismatch": "ignore" }));
        assert!(
            repo_mismatch_warnings(&lock, &installed, &repos, &ignore)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn repo_mismatch_fail_without_a_mismatch_only_warns_about_unknowns() {
        let (installed, repos) = host_view();
        let lock = lockfile(json!([
            { "name": "same", "repository": "stable/main" },
            { "name": "absent", "repository": "stable/main" }
        ]));
        let fail = restore_config(json!({ "on_repo_mismatch": "fail" }));
        let warnings = repo_mismatch_warnings(&lock, &installed, &repos, &fail).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("absent"));
    }

    #[test]
    fn excluded_dependencies_are_not_repo_checked() {
        let (installed, repos) = host_view();
        let lock = lockfile(json!([
            { "name": "moved", "repository": "stable/main", "install_reason": "dependency" }
        ]));
        let cfg =
            restore_config(json!({ "on_repo_mismatch": "fail", "include_dependencies": false }));
        assert!(
            repo_mismatch_warnings(&lock, &installed, &repos, &cfg)
                .unwrap()
                .is_empty()
        );
        let cfg = restore_config(json!({ "on_repo_mismatch": "fail" }));
        assert!(repo_mismatch_warnings(&lock, &installed, &repos, &cfg).is_err());
    }

    #[test]
    fn long_name_lists_are_shortened() {
        let names: Vec<String> = (0..12).map(|i| format!("p{i}")).collect();
        assert_eq!(
            name_list(&names),
            "p0, p1, p2, p3, p4, p5, p6, p7, p8, p9 and 2 more"
        );
        assert_eq!(name_list(&names[..2]), "p0, p1");
    }
}

/// `apt-cache policy` parsing and the removed snapshot `inline` key.
#[cfg(test)]
mod apt_policy_and_snapshot_tests {
    use super::*;

    // Real `apt-cache policy` output, captured in throwaway containers
    // (ubuntu:24.04 with apt 2.8.4, debian:12-slim with apt 2.6.2,
    // debian:13-slim with apt 3.0.4). The versions came from the archives at
    // the time; the layout is what the parser depends on.

    /// Ubuntu 24.04, curl installed from noble/main with a newer candidate in
    /// noble-updates and noble-security.
    const POLICY_UPDATES: &str = "curl:
  Installed: 8.5.0-2ubuntu10
  Candidate: 8.5.0-2ubuntu10.16
  Version table:
     8.5.0-2ubuntu10.16 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
 *** 8.5.0-2ubuntu10 500
        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
        100 /var/lib/dpkg/status
";

    /// Debian 12, curl installed from bookworm-security with a newer
    /// candidate in bookworm/main.
    const POLICY_SECURITY: &str = "curl:
  Installed: 7.88.1-10+deb12u5
  Candidate: 7.88.1-10+deb12u15
  Version table:
     7.88.1-10+deb12u15 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
 *** 7.88.1-10+deb12u5 500
        500 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
        100 /var/lib/dpkg/status
";

    /// Debian 12, the installed version is the candidate; an older version
    /// follows the installed one.
    const POLICY_CURRENT: &str = "libc6:
  Installed: 2.36-9+deb12u14
  Candidate: 2.36-9+deb12u14
  Version table:
 *** 2.36-9+deb12u14 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
        100 /var/lib/dpkg/status
     2.36-9+deb12u7 500
        500 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
";

    /// Debian 13, the installed version is no longer in any repository.
    const POLICY_GONE: &str = "libc6:
  Installed: 2.41-12+deb13u3
  Candidate: 2.41-12+deb13u4
  Version table:
     2.41-12+deb13u4 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
 *** 2.41-12+deb13u3 100
        100 /var/lib/dpkg/status
";

    /// Installed from a local .deb (Ubuntu 24.04): only the dpkg status file.
    const POLICY_LOCAL: &str = "vendor-agent:
  Installed: 2:4.1-1
  Candidate: 2:4.1-1
  Version table:
 *** 2:4.1-1 100
        100 /var/lib/dpkg/status
";

    /// Installed from a flat `file:` repository, with an epoch in the
    /// version (the same on all three releases).
    const POLICY_FLAT: &str = "vendor-agent:
  Installed: 2:4.1-1
  Candidate: 2:4.1-1
  Version table:
 *** 2:4.1-1 500
        500 file:/srv/repo ./ Packages
        100 /var/lib/dpkg/status
";

    /// Not installed (Debian 13).
    const POLICY_NOT_INSTALLED: &str = "jq:
  Installed: (none)
  Candidate: 1.7.1-6+deb13u4
  Version table:
     1.7.1-6+deb13u4 500
        500 http://deb.debian.org/debian-security trixie-security/main amd64 Packages
     1.7.1-6+deb13u3 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
";

    #[test]
    fn apt_policy_reports_the_installed_versions_repository() {
        assert_eq!(
            apt_policy_installed_repository(POLICY_UPDATES).as_deref(),
            Some("noble/main")
        );
        assert_eq!(
            apt_policy_installed_repository(POLICY_SECURITY).as_deref(),
            Some("bookworm-security/main")
        );
        assert_eq!(
            apt_policy_installed_repository(POLICY_CURRENT).as_deref(),
            Some("bookworm/main")
        );
        assert_eq!(
            apt_policy_installed_repository(POLICY_FLAT).as_deref(),
            Some("./")
        );
        assert_eq!(apt_policy_installed_repository(POLICY_GONE), None);
        assert_eq!(apt_policy_installed_repository(POLICY_LOCAL), None);
        assert_eq!(apt_policy_installed_repository(POLICY_NOT_INSTALLED), None);
        assert_eq!(apt_policy_installed_repository(""), None);
        // Never the priority, which the old parser returned.
        for policy in [POLICY_UPDATES, POLICY_SECURITY, POLICY_CURRENT, POLICY_FLAT] {
            assert_ne!(
                apt_policy_installed_repository(policy).as_deref(),
                Some("500")
            );
        }
    }

    /// `apt-cache policy a b c` prints the sections one after another; an
    /// unknown package prints nothing.
    #[test]
    fn apt_policy_sections_split_a_batched_query() {
        let batched = format!("{POLICY_UPDATES}{POLICY_LOCAL}{POLICY_NOT_INSTALLED}");
        let sections = apt_policy_sections(&batched);
        let names: Vec<&str> = sections.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["curl", "vendor-agent", "jq"]);
        let repos: Vec<Option<String>> = sections
            .iter()
            .map(|(_, s)| apt_policy_installed_repository(s))
            .collect();
        assert_eq!(repos, [Some("noble/main".to_string()), None, None]);
    }

    #[test]
    fn snapshot_refuses_inline_before_anything_runs() {
        let handle = PkgHandle {
            alias: "system".into(),
        };
        for input in [
            r#"{"manager":"brew","inline":true}"#,
            r#"{"manager":"brew","inline":false}"#,
        ] {
            let mut args = Args::new();
            args.insert("input".into(), input.into());
            let mut i: &[u8] = &[];
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            // Refused before the manager is looked up (brew is not installed
            // here, which would otherwise fail later with exit 1).
            let status = handle.call("snapshot", &args, &mut io).unwrap();
            assert_eq!(status.exit_code(), 2);
            let reason = status.reason.unwrap_or_default();
            assert!(
                reason.starts_with("[pkg.invalid_argument] inline is not supported"),
                "{reason}"
            );
            assert!(o.is_empty());
        }
    }
}

#[cfg(test)]
#[path = "pkg_tests.rs"]
mod pkg_tests;
