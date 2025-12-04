# Package Manager Handle (pkg://)

The Package Manager Handle helps you work with software packages on your computer. You can install, remove, update, and search for programs using different package managers. Think of it like a smart app store that works with many different systems.

## What Package Managers Are Supported?

The pkg handle works with these package managers automatically:
- **apt** (Ubuntu, Debian)
- **dnf** (Fedora, CentOS Stream)
- **yum** (CentOS, RHEL)
- **pacman** (Arch Linux)
- **apk** (Alpine Linux)  
- **brew** (macOS, Linux)

## Available Actions (Verbs)

### install

Install new packages on your system.

**What it does:** Downloads and installs software packages, with options to update package lists and handle dependencies.

**Input example:**
```json
{
  "manager": "auto",
  "packages": [
    {
      "name": "curl"
    },
    {
      "name": "git"
    }
  ],
  "dry_run": true,
  "update_cache": true,
  "assume_yes": true,
  "only_if_missing": true,
  "timeout_ms": 300000
}
```

**Expected output:**
```json
{
  "installed": 2,
  "upgraded": 0,
  "reinstalled": 0,
  "unchanged": 0,
  "failed": 0
}
```

**Configuration options:**
- `manager`: Which package manager to use ("auto", "apt", "dnf", "yum", "pacman", "apk", "brew")
- `packages`: List of packages to install, each with a `name` and optional `version`
- `dry_run`: Test the operation without actually installing (true/false)
- `update_cache`: Update package lists before installing (true/false)
- `assume_yes`: Answer yes to all prompts automatically (true/false)
- `only_if_missing`: Only install if package isn't already installed (true/false)
- `reinstall`: Force reinstallation even if already installed (true/false)
- `upgrade`: Upgrade to newer versions if available (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### remove

Remove packages from your system.

**What it does:** Uninstalls software packages, with options to clean up configuration files and dependencies.

**Input example:**
```json
{
  "manager": "auto",
  "packages": [
    {
      "name": "curl"
    },
    {
      "name": "git"
    }
  ],
  "dry_run": true,
  "purge": false,
  "recursive": false,
  "assume_yes": true,
  "only_if_installed": true,
  "fail_if_missing": false,
  "timeout_ms": 300000
}
```

**Expected output:**
```json
{
  "removed": 2,
  "purged": 0,
  "not_installed": 0,
  "skipped": 0,
  "failed": 0,
  "autoremove_run": false
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `packages`: List of packages to remove, each with a `name`
- `dry_run`: Test the operation without actually removing (true/false)
- `purge`: Also remove configuration files (true/false)
- `recursive`: Remove dependencies no longer needed (true/false)
- `assume_yes`: Answer yes to all prompts automatically (true/false)
- `only_if_installed`: Only try to remove if package is installed (true/false)
- `fail_if_missing`: Fail if package is not found (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### update

Update package lists and upgrade existing packages.

**What it does:** Refreshes the list of available packages and updates installed packages to newer versions.

**Input example:**
```json
{
  "manager": "auto",
  "packages": [],
  "refresh_index": true,
  "upgrade": true,
  "assume_yes": true,
  "security_only": false,
  "check_only": false,
  "dry_run": false,
  "timeout_ms": 900000
}
```

**Expected output:**
```json
{
  "upgraded": 15,
  "unchanged": 5,
  "failed": 0
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `packages`: List of specific packages to update (empty list means all)
- `refresh_index`: Update the package list before upgrading (true/false)
- `upgrade`: Actually upgrade packages (true/false)
- `assume_yes`: Answer yes to all prompts automatically (true/false)
- `security_only`: Only install security updates (true/false)
- `check_only`: Only check for updates, don't install (true/false)
- `dry_run`: Test the operation without actually updating (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### upgrade

Upgrade all packages to their latest versions.

**What it does:** Like update, but focuses on upgrading all packages to the newest available versions.

**Input example:**
```json
{
  "manager": "auto",
  "packages": [],
  "refresh_index": true,
  "assume_yes": true,
  "security_only": false,
  "dry_run": false,
  "check_only": false,
  "timeout_ms": 900000
}
```

**Expected output:**
```json
{
  "upgraded": 20,
  "unchanged": 2,
  "failed": 0
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `packages`: List of specific packages to upgrade (empty list means all)
- `refresh_index`: Update the package list before upgrading (true/false)
- `assume_yes`: Answer yes to all prompts automatically (true/false)
- `security_only`: Only install security upgrades (true/false)
- `dry_run`: Test the operation without actually upgrading (true/false)
- `check_only`: Only check for upgrades, don't install (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### info

Get detailed information about packages.

**What it does:** Shows information about packages like version, description, dependencies, and installation status.

**Input example:**
```json
{
  "manager": "auto",
  "packages": ["curl"],
  "include_dependencies": false,
  "include_reverse_deps": false,
  "include_files": false,
  "include_repo": true,
  "timeout_ms": 5000
}
```

**Expected output:**
```json
{
  "packages": [
    {
      "name": "curl",
      "found": true,
      "installed": true,
      "installed_version": "7.68.0-1ubuntu2.19",
      "candidate_version": "7.68.0-1ubuntu2.19",
      "architecture": "amd64",
      "summary": "command line tool for transferring data with URL syntax",
      "description": "curl is a command line tool for transferring data with URL syntax...",
      "homepage": "https://curl.haxx.se/",
      "license": "curl",
      "repository": "main"
    }
  ]
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `packages`: List of package names to get information about
- `include_dependencies`: Include dependency information (true/false)
- `include_reverse_deps`: Include packages that depend on this one (true/false)
- `include_files`: Include list of files in the package (true/false)
- `include_repo`: Include repository information (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### search

Search for packages by name or description.

**What it does:** Finds packages that match your search terms in their names or descriptions.

**Input example:**
```json
{
  "manager": "auto",
  "query": "curl",
  "search_in": ["name", "description"],
  "exact": false,
  "case_sensitive": false,
  "limit": 50,
  "offset": 0,
  "include_installed": true,
  "include_versions": true,
  "include_repo": true,
  "timeout_ms": 5000
}
```

**Expected output:**
```json
{
  "backend": "pkg",
  "manager": "apt",
  "alias": "system",
  "query": "curl",
  "search_in": ["name", "description"],
  "exact": false,
  "case_sensitive": false,
  "limit": 50,
  "offset": 0,
  "total_matches": 25,
  "results": [
    {
      "name": "curl",
      "version": "7.68.0-1ubuntu2.19",
      "installed": true,
      "summary": "command line tool for transferring data with URL syntax",
      "description": "curl is a command line tool for transferring data...",
      "repository": "main",
      "homepage": "https://curl.haxx.se/",
      "score": 1.0
    }
  ]
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `query`: What to search for
- `search_in`: Where to search ("name", "description", "all")
- `exact`: Require exact matches only (true/false)
- `case_sensitive`: Match case exactly (true/false)
- `limit`: Maximum number of results to return
- `offset`: Skip this many results (for paging)
- `include_installed`: Show installed packages in results (true/false)
- `include_versions`: Show version information (true/false)
- `include_repo`: Show repository information (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### list_installed

List packages that are currently installed.

**What it does:** Shows all the packages installed on your system, with optional filtering.

**Input example:**
```json
{
  "manager": "auto",
  "filter": null,
  "prefix": null,
  "include_versions": true,
  "include_repo": true,
  "include_size": false,
  "include_install_reason": false,
  "limit": 500,
  "offset": 0,
  "timeout_ms": 600000
}
```

**Expected output:**
```json
{
  "total_packages": 1247,
  "packages": [
    {
      "name": "curl",
      "version": "7.68.0-1ubuntu2.19",
      "repository": "main",
      "architecture": "amd64",
      "installed": true
    }
  ]
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `filter`: Filter packages by pattern (optional)
- `prefix`: Only show packages starting with this prefix (optional)
- `include_versions`: Show version information (true/false)
- `include_repo`: Show repository information (true/false)
- `include_size`: Show package sizes (true/false)
- `include_install_reason`: Show why package was installed (true/false)
- `limit`: Maximum number of packages to return
- `offset`: Skip this many packages (for paging)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### snapshot

Create a snapshot of currently installed packages.

**What it does:** Makes a complete list of all installed packages that can be used to recreate the same setup later.

**Input example:**
```json
{
  "manager": "auto",
  "scope": "all",
  "include_versions": "exact",
  "include_repo": true,
  "include_arch": true,
  "include_install_reason": true,
  "include_os_metadata": true,
  "exclude_patterns": [],
  "format": "json",
  "inline": true,
  "timeout_ms": 15000
}
```

**Expected output:**
```json
{
  "lockfile_version": "1.0",
  "generated_at": "2024-12-04T10:30:00Z",
  "manager": {
    "name": "apt",
    "alias": "system",
    "version": "2.4.8"
  },
  "platform": {
    "os_family": "unix",
    "os_name": "ubuntu",
    "os_version": "20.04",
    "kernel": "Linux",
    "architecture": "x86_64"
  },
  "scope": "all",
  "packages": [
    {
      "name": "curl",
      "version": "7.68.0-1ubuntu2.19",
      "architecture": "amd64",
      "repository": "main",
      "install_reason": "manual"
    }
  ]
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `scope`: Which packages to include ("all", "manual", "dependency")
- `include_versions`: Version detail level ("exact", "minimal", "none")
- `include_repo`: Include repository information (true/false)
- `include_arch`: Include architecture information (true/false)
- `include_install_reason`: Include why each package was installed (true/false)
- `include_os_metadata`: Include system information (true/false)
- `exclude_patterns`: Patterns of packages to exclude
- `format`: Output format ("json", "yaml", "text")
- `inline`: Return data directly instead of saving to file (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### restore

Restore packages from a snapshot.

**What it does:** Installs packages from a snapshot file to recreate a previous system state.

**Input example:**
```json
{
  "manager": "auto",
  "lockfile": "{\"lockfile_version\":\"1.0\",\"packages\":[{\"name\":\"curl\",\"version\":\"7.68.0\"}]}",
  "format": "auto",
  "mode": "exact",
  "allow_downgrades": false,
  "allow_removals": false,
  "allow_newer": true,
  "on_missing_package": "fail",
  "on_repo_mismatch": "warn",
  "on_platform_mismatch": "warn",
  "include_dependencies": true,
  "dry_run": false,
  "timeout_ms": 180000
}
```

**Expected output:**
```json
{
  "status": "success",
  "restored": 15,
  "skipped": 2,
  "failed": 0,
  "warnings": [
    "Repository mismatch for package xyz"
  ]
}
```

**Configuration options:**
- `manager`: Which package manager to use
- `lockfile`: The snapshot data as a string
- `format`: Format of the lockfile ("auto", "json", "yaml", "text")
- `mode`: Restoration mode ("exact", "best_effort")
- `allow_downgrades`: Allow installing older versions (true/false)
- `allow_removals`: Allow removing packages not in snapshot (true/false)
- `allow_newer`: Allow newer versions if exact version unavailable (true/false)
- `on_missing_package`: What to do if package not found ("fail", "warn", "ignore")
- `on_repo_mismatch`: What to do if repository doesn't match ("fail", "warn", "ignore")
- `on_platform_mismatch`: What to do if platform is different ("fail", "warn", "ignore")
- `include_dependencies`: Also restore dependencies (true/false)
- `dry_run`: Test the operation without actually restoring (true/false)
- `timeout_ms`: How long to wait before giving up (in milliseconds)

### apply_lock

An alias for the `restore` verb. Works exactly the same way.

## How to Use

All pkg handle operations use this format:
```
resh pkg://alias.verb input='{"json": "config"}'
```

For example:
```bash
# Install curl with dry run
resh pkg://system.install input='{"manager": "auto", "packages": [{"name": "curl"}], "dry_run": true}'

# Search for packages
resh pkg://system.search input='{"manager": "auto", "query": "text editor"}'

# Create a snapshot
resh pkg://system.snapshot input='{"manager": "auto", "scope": "all", "format": "json"}'
```

## Tips

- Use `dry_run: true` to test operations safely
- Use `manager: "auto"` to automatically detect your package manager
- Set reasonable timeouts for your network speed
- Use snapshots to backup your package state before major changes
- The `only_if_missing` option prevents reinstalling packages unnecessarily
- Search results are sorted by relevance score