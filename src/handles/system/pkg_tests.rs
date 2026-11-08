//! Unit tests of the pkg handle's argument checking, error codes, per-manager
//! commands and restore planning. The verbs are run against fake package
//! managers in `tests/pkg_verbs.rs` and against real ones in Docker in
//! `tests/pkg_e2e_docker.rs`.

use super::*;
use crate::core::status::is_valid_error_code;

const DOC: &str = include_str!("../../../docs/Packages_Software/pkg.md");

fn handle() -> PkgHandle {
    PkgHandle {
        alias: "system".into(),
    }
}

/// Runs a verb with the given command-line arguments; returns the status and
/// stdout.
fn call(verb: &str, args: &[(&str, &str)]) -> (Status, String) {
    let mut a = Args::new();
    for (k, v) in args {
        a.insert(k.to_string(), v.to_string());
    }
    let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
    let mut io = IoStreams {
        stdin: &mut i,
        stdout: &mut o,
        stderr: &mut e,
    };
    let status = handle().call(verb, &a, &mut io).unwrap();
    (status, String::from_utf8(o).unwrap())
}

fn call_input(verb: &str, input: Value) -> (Status, String) {
    call(verb, &[("input", &input.to_string())])
}

fn refused(verb: &str, input: Value) -> String {
    let (status, out) = call_input(verb, input.clone());
    assert_eq!(status.exit_code(), 2, "{verb} {input}: {:?}", status.reason);
    assert!(out.is_empty(), "{verb} printed {out}");
    let reason = status.reason.unwrap_or_default();
    assert!(
        reason.starts_with("[pkg.invalid_argument] ")
            || reason.starts_with("[pkg.unsupported_option] "),
        "{reason}"
    );
    reason
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[test]
fn every_error_code_is_valid_and_documented() {
    for (code, exit) in pkg_args::ERROR_CODES {
        assert!(is_valid_error_code(code), "{code}");
        assert!(code.starts_with("pkg."), "{code}");
        assert!(
            DOC.contains(&format!("`{code}`")),
            "{code} is not documented in pkg.md"
        );
        assert!([1, 2, 124].contains(exit), "{code} exit {exit}");
    }
}

#[test]
fn every_error_maps_to_a_listed_code() {
    let s = || "x".to_string();
    let all = [
        PkgError::InvalidInstallConfig(s()),
        PkgError::ManagerNotAvailable(s()),
        PkgError::UpdateCacheFailed(s()),
        PkgError::InstallNotFound(s()),
        PkgError::InstallDependencyFailure(s()),
        PkgError::InstallConflict(s()),
        PkgError::InstallPermissionDenied(s()),
        PkgError::InstallInvalidVersion(s()),
        PkgError::InstallFailed(s()),
        PkgError::InvalidRemoveConfig(s()),
        PkgError::RemoveNotFound(s()),
        PkgError::RemoveNotInstalled(s()),
        PkgError::RemoveDependencyFailure(s()),
        PkgError::RemovePermissionDenied(s()),
        PkgError::RemoveFailed(s()),
        PkgError::InvalidUpdateConfig(s()),
        PkgError::UpdateIndexFailed(s()),
        PkgError::UpdateCheckFailed(s()),
        PkgError::UpdatePermissionDenied(s()),
        PkgError::UpdateTimeout,
        PkgError::UpdateFailed(s()),
        PkgError::InvalidUpgradeConfig(s()),
        PkgError::UpgradeIndexFailed(s()),
        PkgError::UpgradeCheckFailed(s()),
        PkgError::UpgradePermissionDenied(s()),
        PkgError::UpgradeTimeout,
        PkgError::UpgradeFailed(s()),
        PkgError::InvalidInfoConfig(s()),
        PkgError::InfoTimeout,
        PkgError::InfoQueryFailed(s()),
        PkgError::InfoPartialFailure(s()),
        PkgError::InvalidSearchConfig(s()),
        PkgError::SearchTimeout,
        PkgError::SearchFailed(s()),
        PkgError::InvalidListInstalledConfig(s()),
        PkgError::ListInstalledTimeout,
        PkgError::ListInstalledFailed(s()),
        PkgError::InvalidSnapshotConfig(s()),
        PkgError::SnapshotTimeout,
        PkgError::SnapshotFailed(s()),
        PkgError::SnapshotScopeUnsupported(s()),
        PkgError::InvalidRestoreConfig(s()),
        PkgError::RestoreInvalidLockfile(s()),
        PkgError::RestoreManagerMismatch(s()),
        PkgError::RestorePlatformIncompatible(s()),
        PkgError::RestoreTimeout,
        PkgError::RestoreApplyFailed(s()),
        PkgError::RestoreRepoNotAvailable(s()),
        PkgError::RestoreRepoMismatch(s()),
        PkgError::Unsupported(s()),
        PkgError::RestoreUnresolved(s()),
        PkgError::DowngradeRefused(s()),
    ];
    let listed: HashMap<&str, i32> = pkg_args::ERROR_CODES.iter().copied().collect();
    let mut seen = HashSet::new();
    for e in &all {
        let (exit, code) = e.code();
        assert_eq!(listed.get(code), Some(&exit), "{e:?} -> {code} {exit}");
        assert_eq!(e.is_timeout(), code == "pkg.timeout");
        seen.insert(code);
    }
    // Codes not produced by a PkgError come from the dispatcher and the
    // result checks.
    for code in listed.keys() {
        assert!(
            seen.contains(code) || ["pkg.partial_failure"].contains(code),
            "{code} is listed but never produced"
        );
    }
}

#[test]
fn error_lines_use_the_standard_format() {
    let (status, _) = call("info", &[]);
    let line = crate::core::status::error_line(
        "pkg.invalid_argument",
        status
            .reason
            .as_deref()
            .unwrap()
            .trim_start_matches("[pkg.invalid_argument] "),
    );
    assert!(line.starts_with("Error: [pkg.invalid_argument] missing input=<json>"));
}

// ---------------------------------------------------------------------------
// Strict arguments
// ---------------------------------------------------------------------------

#[test]
fn only_input_is_accepted_on_the_command_line() {
    for verb in PKG_VERBS {
        let (status, _) = call(verb, &[]);
        assert_eq!(status.exit_code(), 2, "{verb}");
        assert!(status.reason.unwrap().contains("missing input=<json>"));

        let (status, out) = call(
            verb,
            &[("input", r#"{"manager":"apt"}"#), ("manager", "apt")],
        );
        assert_eq!(status.exit_code(), 2, "{verb}");
        assert!(out.is_empty());
        let reason = status.reason.unwrap();
        assert!(reason.contains("unknown argument `manager`"), "{reason}");
        assert!(reason.contains("put it inside the JSON object"), "{reason}");

        let (status, _) = call(verb, &[("inptu", "{}")]);
        assert!(
            status.reason.unwrap().contains("did you mean `input`?"),
            "{verb}"
        );
    }
}

#[test]
fn unknown_input_keys_are_refused_with_a_suggestion() {
    let reason = refused(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq"}], "asume_yes": true}),
    );
    assert!(reason.contains("unknown input key `asume_yes`"), "{reason}");
    assert!(reason.contains("did you mean `assume_yes`?"), "{reason}");

    let reason = refused(
        "search",
        json!({"manager": "apt", "query": "jq", "Limit": 3}),
    );
    assert!(reason.contains("did you mean `limit`?"), "{reason}");

    // A key of another verb is still unknown here.
    let reason = refused(
        "info",
        json!({"manager": "apt", "packages": ["jq"], "purge": true}),
    );
    assert!(reason.contains("unknown input key `purge`"), "{reason}");

    // Package entries are checked too.
    let reason = refused(
        "remove",
        json!({"manager": "apt", "packages": [{"name": "jq", "verison": "1"}]}),
    );
    assert!(
        reason.contains("unknown key `verison` in packages[0]"),
        "{reason}"
    );
    assert!(reason.contains("did you mean `version`?"), "{reason}");
    let reason = refused("install", json!({"manager": "apt", "packages": ["jq"]}));
    assert!(reason.contains("packages[0] must be an object"), "{reason}");
}

#[test]
fn options_that_cannot_work_are_refused_with_a_reason() {
    for verb in ["info", "list_installed", "snapshot"] {
        let mut input = json!({"manager": "apt", "extra_args": ["-q"]});
        if verb == "info" {
            input["packages"] = json!(["jq"]);
        }
        let reason = refused(verb, input);
        assert!(reason.contains("extra_args is not supported"), "{reason}");
    }
    for verb in ["info", "search", "list_installed", "snapshot"] {
        let input = json!({"manager": "apt", "dry_run": true});
        let reason = refused(verb, input);
        assert!(
            reason.contains("dry_run is not supported"),
            "{verb}: {reason}"
        );
    }
    let reason = refused("snapshot", json!({"manager": "apt", "inline": true}));
    assert!(reason.contains("inline is not supported"), "{reason}");
}

#[test]
fn invalid_values_are_refused_naming_the_key() {
    for (verb, input, key) in [
        (
            "info",
            json!({"manager": "apt", "packages": ["jq"], "include_repo": "false"}),
            "include_repo",
        ),
        (
            "list_installed",
            json!({"manager": "apt", "limit": -1}),
            "limit",
        ),
        (
            "snapshot",
            json!({"manager": "apt", "format": "xml"}),
            "format",
        ),
        (
            "restore",
            json!({"manager": "apt", "lockfile": "x", "mode": "fast"}),
            "mode",
        ),
        ("update", json!({"manager": "zypper"}), "manager"),
        (
            "upgrade",
            json!({"manager": "apt", "timeout_ms": "5s"}),
            "timeout_ms",
        ),
    ] {
        let reason = refused(verb, input.clone());
        assert!(
            reason.contains(&format!("invalid value for `{key}`")),
            "{verb} {input}: {reason}"
        );
    }
    let reason = refused("info", json!({"manager": "apt"}));
    assert!(reason.contains("missing field `packages`"), "{reason}");
    let reason = refused("info", json!(["apt"]));
    assert!(reason.contains("must be a JSON object"), "{reason}");
    let reason = refused("info", json!("x"));
    assert!(reason.contains("must be a JSON object"), "{reason}");
    let (status, _) = call("info", &[("input", "{not json")]);
    assert_eq!(status.exit_code(), 2);
    assert!(status.reason.unwrap().contains("not valid JSON"));
}

#[test]
fn zero_timeouts_and_bad_env_are_refused() {
    for verb in PKG_VERBS {
        let mut input = json!({"manager": "apt", "timeout_ms": 0});
        match *verb {
            "info" => input["packages"] = json!(["jq"]),
            "install" | "remove" => input["packages"] = json!([{"name": "jq"}]),
            "search" => input["query"] = json!("jq"),
            "restore" | "apply_lock" => input["lockfile"] = json!("jq"),
            _ => {}
        }
        let reason = refused(verb, input.clone());
        assert!(
            reason.contains("timeout_ms must be greater than 0"),
            "{verb}: {reason}"
        );

        input["timeout_ms"] = json!(1000);
        input["env"] = json!({"A=B": "x"});
        let reason = refused(verb, input.clone());
        assert!(reason.contains("env name"), "{verb}: {reason}");
        input["env"] = json!({"A": 1});
        let reason = refused(verb, input);
        assert!(reason.contains("must be a string"), "{verb}: {reason}");
    }
}

#[test]
fn hostile_query_and_info_names_are_refused() {
    let reason = refused("search", json!({"manager": "apt", "query": "-o=Dir=/tmp"}));
    assert!(reason.contains("not start with '-'"), "{reason}");
    let reason = refused("search", json!({"manager": "apt", "query": "a\nb"}));
    assert!(reason.contains("control characters"), "{reason}");
    let reason = refused(
        "search",
        json!({"manager": "apt", "query": "jq", "search_in": []}),
    );
    assert!(reason.contains("search_in cannot be empty"), "{reason}");
    let reason = refused("info", json!({"manager": "apt", "packages": ["-L"]}));
    assert!(
        reason.contains("must start with a letter or digit"),
        "{reason}"
    );
    let reason = refused(
        "snapshot",
        json!({"manager": "apt", "exclude_patterns": ["lib[abc"]}),
    );
    assert!(reason.contains("invalid pattern"), "{reason}");
}

/// The keys each verb accepts are exactly the keys its help usage lists.
#[test]
fn accepted_keys_match_the_help_usage() {
    let mut every: HashSet<&str> = HashSet::new();
    for verb in PKG_VERBS {
        every.extend(pkg_args::accepted(verb).iter().copied());
    }
    for verb in PKG_VERBS {
        let usage = PKG_HELP
            .verbs
            .iter()
            .find(|v| v.name == *verb)
            .and_then(|v| v.detail.as_ref())
            .map(|d| d.usage)
            .unwrap();
        let usage = if *verb == "apply_lock" {
            // "the same as restore"
            PKG_HELP
                .verbs
                .iter()
                .find(|v| v.name == "restore")
                .and_then(|v| v.detail.as_ref())
                .map(|d| d.usage)
                .unwrap()
        } else {
            usage
        };
        // The key list runs from "<json> keys:" to the first line that does
        // not end with a comma (prose follows); values in parentheses (such
        // as `exact`) are not keys.
        let mut block = String::new();
        let mut open = 0i32;
        for line in usage.lines().skip_while(|l| !l.contains("<json> keys:")) {
            block.push_str(line);
            block.push('\n');
            open += line.matches('(').count() as i32 - line.matches(')').count() as i32;
            if open == 0 && !line.trim_end().ends_with(',') {
                break;
            }
        }
        let mut keys_only = String::new();
        let mut depth = 0;
        for c in block.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ if depth == 0 => keys_only.push(c),
                _ => {}
            }
        }
        let all_words: HashSet<&str> = usage
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        let words: HashSet<&str> = keys_only
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .collect();
        let accepted = pkg_args::accepted(verb);
        for key in accepted {
            assert!(all_words.contains(key), "{verb} usage lacks {key}");
        }
        for key in &every {
            if !accepted.contains(key) && key != verb {
                assert!(!words.contains(key), "{verb} usage lists {key}");
            }
        }
        // Every verb's example names the manager.
        let example = PKG_HELP
            .verbs
            .iter()
            .find(|v| v.name == *verb)
            .and_then(|v| v.detail.as_ref())
            .map(|d| d.example)
            .unwrap();
        assert!(
            example.contains("manager") || example.contains("restore.json"),
            "{verb}: {example}"
        );
    }
}

// ---------------------------------------------------------------------------
// Manager capabilities and commands
// ---------------------------------------------------------------------------

fn install(packages: Value, extra: Value) -> InstallConfig {
    let mut input = json!({"manager": "apt", "packages": packages});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(input).unwrap()
}

fn remove(packages: Value, extra: Value) -> RemoveConfig {
    let mut input = json!({"manager": "apt", "packages": packages});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(input).unwrap()
}

const ALL: [ManagerKind; 6] = [
    ManagerKind::Apt,
    ManagerKind::Dnf,
    ManagerKind::Yum,
    ManagerKind::Pacman,
    ManagerKind::Apk,
    ManagerKind::Brew,
];

#[test]
fn package_arguments_use_each_managers_syntax() {
    let arg = |m, v, a| package_argument(m, "jq", v, a);
    assert_eq!(
        arg(&ManagerKind::Apt, Some("1.6-2"), Some("amd64")),
        "jq:amd64=1.6-2"
    );
    assert_eq!(
        arg(&ManagerKind::Dnf, Some("1.6-2"), Some("x86_64")),
        "jq-1.6-2.x86_64"
    );
    assert_eq!(arg(&ManagerKind::Yum, Some("1.6-2"), None), "jq-1.6-2");
    assert_eq!(
        arg(&ManagerKind::Apk, Some("1.7.1-r0"), None),
        "jq=1.7.1-r0"
    );
    assert_eq!(arg(&ManagerKind::Pacman, None, None), "jq");
}

#[test]
fn install_refuses_what_the_manager_cannot_do() {
    let versioned = install(json!([{"name": "jq", "version": "1.0"}]), json!({}));
    let arch = install(json!([{"name": "jq"}]), json!({"arch": "amd64"}));
    let no_yes = install(json!([{"name": "jq"}]), json!({"assume_yes": false}));
    for m in &ALL {
        let ok = |c: &InstallConfig| check_install_support(c, m).is_ok();
        assert_eq!(ok(&versioned), supports_version_pin(m), "{m:?} version");
        assert_eq!(ok(&arch), supports_arch(m), "{m:?} arch");
        assert_eq!(ok(&no_yes), supports_confirmation(m), "{m:?} assume_yes");
        for c in [&versioned, &arch, &no_yes] {
            if let Err(e) = check_install_support(c, m) {
                assert_eq!(e.code(), (2, "pkg.unsupported_option"));
                assert!(e.to_string().contains("nothing was run"), "{e}");
            }
        }
    }
    assert!(!supports_version_pin(&ManagerKind::Brew));
    assert!(!supports_version_pin(&ManagerKind::Pacman));
}

#[test]
fn remove_refuses_what_the_manager_cannot_do() {
    let purge = remove(json!([{"name": "jq"}]), json!({"purge": true}));
    let versioned = remove(json!([{"name": "jq", "version": "1"}]), json!({}));
    for m in &ALL {
        let purge_ok = matches!(m, ManagerKind::Apt | ManagerKind::Apk | ManagerKind::Pacman);
        assert_eq!(check_remove_support(&purge, m).is_ok(), purge_ok, "{m:?}");
        let version_ok = matches!(m, ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Yum);
        assert_eq!(
            check_remove_support(&versioned, m).is_ok(),
            version_ok,
            "{m:?}"
        );
    }
}

#[test]
fn install_steps() {
    let apt = &ManagerKind::Apt;
    let plain = install(json!([{"name": "jq"}]), json!({}));
    let pkg = &plain.packages[0];
    assert_eq!(install_step(&plain, pkg, None, apt), InstallStep::Install);
    assert_eq!(
        install_step(&plain, pkg, Some("1.0"), apt),
        InstallStep::Skip
    );
    let up = install(
        json!([{"name": "jq"}]),
        json!({"only_if_missing": false, "upgrade": true}),
    );
    assert_eq!(
        install_step(&up, &up.packages[0], Some("1.0"), apt),
        InstallStep::Upgrade
    );
    let re = install(
        json!([{"name": "jq"}]),
        json!({"only_if_missing": false, "reinstall": true}),
    );
    assert_eq!(
        install_step(&re, &re.packages[0], Some("1.0"), apt),
        InstallStep::Reinstall
    );
    let again = install(json!([{"name": "jq"}]), json!({"only_if_missing": false}));
    assert_eq!(
        install_step(&again, &again.packages[0], Some("1.0"), apt),
        InstallStep::Install
    );
    // A requested version: newer installs, equal skips, older downgrades,
    // in the manager's order (dpkg: 1.10 > 1.9).
    let pinned = install(json!([{"name": "jq", "version": "1.10"}]), json!({}));
    let p = &pinned.packages[0];
    assert_eq!(
        install_step(&pinned, p, Some("1.9"), apt),
        InstallStep::Install
    );
    assert_eq!(
        install_step(&pinned, p, Some("1.10"), apt),
        InstallStep::Skip
    );
    assert_eq!(
        install_step(&pinned, p, Some("1.11"), apt),
        InstallStep::Downgrade
    );
    let rpm = install(json!([{"name": "jq", "version": "1.6-2"}]), json!({}));
    assert_eq!(
        install_step(&rpm, &rpm.packages[0], Some("0:1.6-2"), &ManagerKind::Dnf),
        InstallStep::Skip
    );
}

#[test]
fn install_commands_per_manager() {
    let h = handle();
    let c = install(json!([{"name": "jq"}]), json!({"extra_args": ["--x"]}));
    let p = &c.packages[0];
    let cmd = |m: ManagerKind, step| {
        h.build_install_command(&c, p, &m, step)
            .unwrap()
            .to_string()
    };
    use InstallStep::*;
    assert_eq!(
        cmd(ManagerKind::Apt, Install),
        "DEBIAN_FRONTEND=noninteractive apt-get install -y jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apt, Upgrade),
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apt, Reinstall),
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall jq --x"
    );
    assert_eq!(cmd(ManagerKind::Dnf, Upgrade), "dnf upgrade -y jq --x");
    assert_eq!(cmd(ManagerKind::Yum, Reinstall), "yum reinstall -y jq --x");
    assert_eq!(
        cmd(ManagerKind::Pacman, Install),
        "pacman -S --noconfirm --needed jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Pacman, Reinstall),
        "pacman -S --noconfirm jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apk, Install),
        "apk add --no-interactive jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apk, Upgrade),
        "apk add --no-interactive --upgrade jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apk, Reinstall),
        "apk fix --no-interactive jq --x"
    );
    assert_eq!(cmd(ManagerKind::Brew, Upgrade), "brew upgrade jq --x");
    assert_eq!(
        cmd(ManagerKind::Apt, Downgrade),
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades jq --x"
    );
    assert_eq!(cmd(ManagerKind::Dnf, Downgrade), "dnf downgrade -y jq --x");
    assert_eq!(cmd(ManagerKind::Yum, Downgrade), "yum downgrade -y jq --x");
    assert_eq!(
        cmd(ManagerKind::Apk, Downgrade),
        "apk add --no-interactive jq --x"
    );
    let no = install(json!([{"name": "jq"}]), json!({"assume_yes": false}));
    assert_eq!(
        h.build_install_command(&no, &no.packages[0], &ManagerKind::Dnf, Install)
            .unwrap()
            .to_string(),
        "dnf install jq"
    );
}

#[test]
fn remove_commands_per_manager() {
    let h = handle();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let c = remove(
        json!([{"name": "jq"}]),
        json!({"purge": true, "recursive": true, "extra_args": ["--x"]}),
    );
    let p = &c.packages[0];
    let cmd = |m: ManagerKind| {
        rt.block_on(h.build_remove_command(&[p], &c, &m))
            .unwrap()
            .to_string()
    };
    assert_eq!(cmd(ManagerKind::Pacman), "pacman -Rsn --noconfirm jq --x");
    assert_eq!(
        cmd(ManagerKind::Apk),
        "apk del --no-interactive --purge jq --x"
    );
    assert_eq!(
        cmd(ManagerKind::Apt),
        "DEBIAN_FRONTEND=noninteractive apt-get purge -y jq --x"
    );
    assert_eq!(
        h.build_autoremove_command(&ManagerKind::Brew)
            .unwrap()
            .unwrap()
            .to_string(),
        "brew autoremove"
    );
    assert!(
        h.build_autoremove_command(&ManagerKind::Pacman)
            .unwrap()
            .is_none()
    );
}

#[test]
fn remove_steps() {
    let c = remove(json!([{"name": "jq"}]), json!({}));
    let p = &c.packages[0];
    assert_eq!(remove_step(&c, p, Some("1")), RemoveStep::Remove);
    assert_eq!(remove_step(&c, p, None), RemoveStep::NotInstalled);
    let strict = remove(
        json!([{"name": "jq"}]),
        json!({"only_if_installed": false, "fail_if_missing": true}),
    );
    assert_eq!(
        remove_step(&strict, &strict.packages[0], None),
        RemoveStep::Missing
    );
    let any = remove(json!([{"name": "jq"}]), json!({"only_if_installed": false}));
    assert_eq!(
        remove_step(&any, &any.packages[0], None),
        RemoveStep::Remove
    );
    let v = remove(json!([{"name": "jq", "version": "2"}]), json!({}));
    assert_eq!(
        remove_step(&v, &v.packages[0], Some("1")),
        RemoveStep::OtherVersion
    );
    assert_eq!(
        remove_step(&v, &v.packages[0], Some("2")),
        RemoveStep::Remove
    );
}

#[test]
fn upgrade_commands_per_manager() {
    let all = |m| {
        upgrade_command(&m, &[], true, false, None)
            .unwrap()
            .to_string()
    };
    let some = |m| {
        upgrade_command(&m, &["jq".into()], true, false, None)
            .unwrap()
            .to_string()
    };
    assert_eq!(
        all(ManagerKind::Apt),
        "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    );
    assert_eq!(
        some(ManagerKind::Apt),
        "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y jq"
    );
    assert_eq!(all(ManagerKind::Yum), "yum update -y");
    assert_eq!(all(ManagerKind::Pacman), "pacman -Su --noconfirm");
    assert_eq!(
        some(ManagerKind::Pacman),
        "pacman -S --needed --noconfirm jq"
    );
    assert_eq!(all(ManagerKind::Apk), "apk upgrade --no-interactive");
    assert_eq!(some(ManagerKind::Brew), "brew upgrade jq");
    assert_eq!(
        upgrade_command(&ManagerKind::Dnf, &[], true, true, Some(&["--x".into()]))
            .unwrap()
            .to_string(),
        "dnf upgrade -y --security --x"
    );
    assert!(check_confirmation_support("update", false, &ManagerKind::Apk).is_err());
    assert!(check_confirmation_support("update", false, &ManagerKind::Apt).is_ok());
}

/// apk search prints `name-version-rN` (checked in an Alpine container).
#[test]
fn apk_names_drop_the_version() {
    assert_eq!(apk_package_name("tree-2.3.2-r0"), "tree");
    assert_eq!(apk_package_name("tree-sitter-c-0.24.1-r0"), "tree-sitter-c");
    assert_eq!(apk_package_name("py3-foo-1.0_rc1-r12"), "py3-foo");
    assert_eq!(apk_package_name("plain"), "plain");
}

#[test]
fn installed_versions_are_read_per_manager() {
    let v = |m, name, out| parse_installed_version(m, name, out);
    assert_eq!(
        v(&ManagerKind::Apt, "jq", "installed\t1.7.1-3\n").as_deref(),
        Some("1.7.1-3")
    );
    // Removed with configuration files left: not installed.
    assert_eq!(v(&ManagerKind::Apt, "jq", "config-files\t1.7.1-3\n"), None);
    assert_eq!(
        v(&ManagerKind::Dnf, "kernel", "6.1-1\n6.2-1\n").as_deref(),
        Some("6.2-1")
    );
    assert_eq!(
        v(&ManagerKind::Pacman, "jq", "jq 1.7.1-2\n").as_deref(),
        Some("1.7.1-2")
    );
    assert_eq!(
        v(&ManagerKind::Apk, "jq", "jq-1.8.2-r0\n").as_deref(),
        Some("1.8.2-r0")
    );
    assert_eq!(
        v(&ManagerKind::Brew, "jq", "jq 1.7.1 1.6\n").as_deref(),
        Some("1.7.1")
    );
    assert_eq!(v(&ManagerKind::Apk, "jq", ""), None);
    assert_eq!(normalize_version(&ManagerKind::Dnf, "0:1.2-3"), "1.2-3");
    assert_eq!(normalize_version(&ManagerKind::Dnf, "1:1.2-3"), "1:1.2-3");
    assert_eq!(normalize_version(&ManagerKind::Apt, "0:1.2"), "0:1.2");
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

fn lockfile(manager: &str, packages: Value) -> Lockfile {
    serde_json::from_value(json!({
        "lockfile_version": "pkg-lock/v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "manager": {"name": manager, "alias": "system", "version": null, "config": null},
        "platform": {"os_family": null, "os_name": null, "os_version": null,
                     "kernel": null, "architecture": null},
        "scope": "all",
        "packages": packages
    }))
    .unwrap()
}

fn restore_config(extra: Value) -> RestoreConfig {
    let mut input = json!({"manager": "auto", "lockfile": "x"});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(input).unwrap()
}

fn host(packages: &[(&str, &str)]) -> Vec<InstalledPackage> {
    packages
        .iter()
        .map(|(n, v)| InstalledPackage {
            name: n.to_string(),
            version: v.to_string(),
            architecture: None,
            repository: None,
            installed_size_bytes: None,
            install_reason: None,
            manager_specific: None,
        })
        .collect()
}

/// The plan orders versions the way the manager does (not as strings).
#[test]
fn restore_plan_uses_manager_version_order() {
    let lock = lockfile(
        "apt",
        json!([
            {"name": "a", "version": "1.10"},
            {"name": "b", "version": "1.0~rc1"},
            {"name": "c", "version": "2.0"},
            {"name": "d", "version": "3.0"}
        ]),
    );
    let current = host(&[("a", "1.9"), ("b", "1.0"), ("c", "2.0"), ("x", "1")]);
    let config = restore_config(json!({"allow_newer": false, "allow_downgrades": true}));
    let plan = handle()
        .compute_restore_plan_for(&lock, &current, &config, &ManagerKind::Apt)
        .unwrap();
    // As strings "1.9" > "1.10"; dpkg says 1.9 < 1.10.
    assert_eq!(plan.upgrade, ["a"]);
    assert_eq!(plan.downgrade, ["b"]);
    assert_eq!(plan.keep, ["c"]);
    assert_eq!(plan.install, ["d"]);
    assert_eq!(plan.extra, ["x"]);

    let config = restore_config(json!({"allow_newer": false}));
    let plan = handle()
        .compute_restore_plan_for(&lock, &current, &config, &ManagerKind::Apt)
        .unwrap();
    assert_eq!(plan.unresolved[0].name, "b");
    assert_eq!(
        plan.unresolved[0].reason,
        "newer_version_installed_downgrade_not_allowed"
    );
}

#[test]
fn restore_exact_passes_locked_versions() {
    let lock = lockfile(
        "apt",
        json!([
            {"name": "a", "version": "1.10"},
            {"name": "b", "version": "1.0~rc1"},
            {"name": "d", "version": "3.0"},
            {"name": "e"}
        ]),
    );
    let current = host(&[("a", "1.9"), ("b", "1.0"), ("x", "1")]);
    let config = restore_config(json!({
        "allow_newer": false, "allow_downgrades": true, "allow_removals": true,
        "extra_args": ["-o", "Debug::X=1"]
    }));
    let m = ManagerKind::Apt;
    let mut plan = handle()
        .compute_restore_plan_for(&lock, &current, &config, &m)
        .unwrap();
    let ops = restore_operations(&mut plan, &lock, &current, &config, &m).unwrap();
    let commands: Vec<String> = ops
        .iter()
        .map(|op| restore_command(op, &m, &config, true).unwrap().to_string())
        .collect();
    let x = " -o Debug::X=1";
    assert_eq!(
        commands,
        [
            format!("DEBIAN_FRONTEND=noninteractive apt-get install -y d=3.0{x}"),
            format!("DEBIAN_FRONTEND=noninteractive apt-get install -y e{x}"),
            format!("DEBIAN_FRONTEND=noninteractive apt-get install -y a=1.10{x}"),
            format!(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades b=1.0~rc1{x}"
            ),
            format!("DEBIAN_FRONTEND=noninteractive apt-get remove -y x{x}"),
        ]
    );
    assert_eq!(ops[2].from.as_deref(), Some("1.9"));
    // The unpinned retry of best_effort installs by name.
    assert_eq!(
        restore_command(&ops[0], &m, &config, false).unwrap().argv(),
        &["apt-get", "install", "-y", "d", "-o", "Debug::X=1"]
    );
}

#[test]
fn restore_commands_per_manager() {
    let op = |kind, version: Option<&str>| RestoreOp {
        kind,
        name: "jq".into(),
        version: version.map(str::to_string),
        from: None,
        locked: None,
    };
    let config = restore_config(json!({}));
    let cmd =
        |m: ManagerKind, o: &RestoreOp| restore_command(o, &m, &config, true).unwrap().to_string();
    use RestoreKind::*;
    assert_eq!(
        cmd(ManagerKind::Dnf, &op(Install, Some("1.0-1"))),
        "dnf install -y jq-1.0-1"
    );
    assert_eq!(
        cmd(ManagerKind::Dnf, &op(Upgrade, Some("1.0-1"))),
        "dnf upgrade -y jq-1.0-1"
    );
    assert_eq!(
        cmd(ManagerKind::Yum, &op(Upgrade, Some("1.0-1"))),
        "yum update -y jq-1.0-1"
    );
    assert_eq!(
        cmd(ManagerKind::Dnf, &op(Downgrade, Some("1.0-1"))),
        "dnf downgrade -y jq-1.0-1"
    );
    assert_eq!(cmd(ManagerKind::Yum, &op(Remove, None)), "yum remove -y jq");
    assert_eq!(
        cmd(ManagerKind::Apk, &op(Install, Some("1.7.1-r0"))),
        "apk add --no-interactive jq=1.7.1-r0"
    );
    assert_eq!(
        cmd(ManagerKind::Apk, &op(Upgrade, None)),
        "apk add --no-interactive --upgrade jq"
    );
    assert_eq!(
        cmd(ManagerKind::Apk, &op(Remove, None)),
        "apk del --no-interactive jq"
    );
    // pacman and brew never pin.
    assert_eq!(
        cmd(ManagerKind::Pacman, &op(Install, Some("1.7"))),
        "pacman -S --noconfirm --needed jq"
    );
    assert_eq!(
        cmd(ManagerKind::Pacman, &op(Remove, None)),
        "pacman -R --noconfirm jq"
    );
    assert_eq!(
        cmd(ManagerKind::Brew, &op(Upgrade, Some("1.7"))),
        "brew upgrade jq"
    );
    assert_eq!(
        cmd(ManagerKind::Brew, &op(Remove, None)),
        "brew uninstall jq"
    );
}

#[test]
fn restore_modes_where_versions_cannot_be_pinned() {
    let lock = lockfile(
        "pacman",
        json!([{"name": "a", "version": "2.0-1"}, {"name": "b", "version": "1.0-1"}]),
    );
    let current = host(&[("b", "2.0-1")]);
    let m = ManagerKind::Pacman;
    let exact = restore_config(json!({"allow_newer": false, "allow_downgrades": true}));
    let mut plan = handle()
        .compute_restore_plan_for(&lock, &current, &exact, &m)
        .unwrap();
    let err = restore_operations(&mut plan, &lock, &current, &exact, &m).unwrap_err();
    assert_eq!(err.code(), (2, "pkg.unsupported_option"));
    assert!(err.to_string().contains("mode=exact"), "{err}");

    let best = restore_config(json!({
        "mode": "best_effort", "allow_newer": false, "allow_downgrades": true
    }));
    let mut plan = handle()
        .compute_restore_plan_for(&lock, &current, &best, &m)
        .unwrap();
    let ops = restore_operations(&mut plan, &lock, &current, &best, &m).unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(plan.downgrade, Vec::<String>::new());
    assert_eq!(
        plan.unresolved[0].reason,
        "downgrade_not_supported_by_pacman"
    );
    let warnings = restore_mode_warnings(&ops, &best, &m);
    assert!(
        warnings[0].contains("pacman cannot install a given version"),
        "{warnings:?}"
    );
    assert!(restore_mode_warnings(&ops, &best, &ManagerKind::Apt).is_empty());
}

#[test]
fn restore_verification() {
    let exact = restore_config(json!({}));
    let best = restore_config(json!({"mode": "best_effort"}));
    let op = RestoreOp {
        kind: RestoreKind::Install,
        name: "jq".into(),
        version: Some("1.6-2".into()),
        from: None,
        locked: None,
    };
    let m = ManagerKind::Dnf;
    assert!(verify_restore_op(&op, Some("1.6-2"), &exact, &m).is_ok());
    assert!(verify_restore_op(&op, Some("0:1.6-2"), &exact, &m).is_ok());
    let err = verify_restore_op(&op, Some("1.7-1"), &exact, &m).unwrap_err();
    assert!(
        err.to_string().contains("not the locked version 1.6-2"),
        "{err}"
    );
    assert!(verify_restore_op(&op, Some("1.7-1"), &best, &m).is_ok());
    assert!(verify_restore_op(&op, None, &best, &m).is_err());
    let rm = RestoreOp {
        kind: RestoreKind::Remove,
        version: None,
        ..op
    };
    assert!(verify_restore_op(&rm, None, &exact, &m).is_ok());
    assert!(verify_restore_op(&rm, Some("1"), &exact, &m).is_err());
}

#[test]
fn restore_manager_resolution() {
    let h = handle();
    let lock = |name: &str| lockfile(name, json!([]));
    assert_eq!(
        h.resolve_restore_manager(&ManagerKind::Auto, &lock("apk"), None)
            .unwrap(),
        ManagerKind::Apk
    );
    assert_eq!(
        h.resolve_restore_manager(&ManagerKind::Yum, &lock("dnf"), None)
            .unwrap(),
        ManagerKind::Yum
    );
    let err = h
        .resolve_restore_manager(&ManagerKind::Apt, &lock("dnf"), None)
        .unwrap_err();
    assert_eq!(err.code(), (2, "pkg.manager_mismatch"));
    let err = h
        .resolve_restore_manager(&ManagerKind::Auto, &lock("zypper"), None)
        .unwrap_err();
    assert_eq!(err.code(), (2, "pkg.invalid_lockfile"));
    let err = h
        .resolve_restore_manager(&ManagerKind::Auto, &lock("auto"), None)
        .unwrap_err();
    assert_eq!(err.code(), (1, "pkg.manager_not_found"));
}

#[test]
fn text_and_yaml_lockfiles_round_trip() {
    let h = handle();
    let mut lock = lockfile(
        "apt",
        json!([
            {"name": "jq", "version": "1.7.1-3", "architecture": "amd64",
             "repository": "noble/main", "install_reason": "manual", "pinned": true},
            {"name": "libonig5"}
        ]),
    );
    lock.platform.os_name = Some("Ubuntu".into());
    lock.platform.os_version = Some("24.04".into());
    let text = h.serialize_lockfile_text(&lock).unwrap();
    assert!(text.starts_with("# pkg-lock/v1\n# manager: apt (unknown)\n# os: Ubuntu 24.04"));
    let back = h.parse_lockfile(&text, &LockfileFormat::Auto).unwrap();
    assert_eq!(back.manager.name, "apt");
    assert_eq!(back.packages.len(), 2);
    let jq = &back.packages[0];
    assert_eq!(jq.version.as_deref(), Some("1.7.1-3"));
    assert_eq!(jq.architecture.as_deref(), Some("amd64"));
    assert_eq!(jq.repository.as_deref(), Some("noble/main"));
    assert_eq!(jq.install_reason.as_deref(), Some("manual"));
    assert!(jq.pinned);
    assert_eq!(back.packages[1].version, None);

    // Header lines of earlier releases (without '#') are headers too.
    let old =
        "# pkg-lock/v1\nmanager: dnf (dnf 4.18)\nos: Fedora 42 (x86_64)\nscope: manual\n\njq=1.7\n";
    let back = h.parse_text_lockfile(old).unwrap();
    assert_eq!(back.manager.name, "dnf");
    assert_eq!(back.scope, "manual");
    assert_eq!(back.packages.len(), 1);

    let err = h.parse_text_lockfile("jq=1 junk\n").unwrap_err();
    assert_eq!(err.code(), (2, "pkg.invalid_lockfile"));

    let yaml = h.serialize_lockfile_yaml(&lock).unwrap();
    assert!(yaml.contains("lockfile_version: pkg-lock/v1"), "{yaml}");
    assert!(
        serde_json::from_str::<Value>(&yaml).is_err(),
        "YAML, not JSON"
    );
    let back = h.parse_lockfile(&yaml, &LockfileFormat::Yaml).unwrap();
    assert_eq!(back.packages[0].repository.as_deref(), Some("noble/main"));
}

#[test]
fn exclude_patterns_are_shell_globs() {
    let h = handle();
    let mut packages: Vec<LockfilePackage> = ["libc6", "libssl3", "linux-image-6.8", "jq", "jqx"]
        .iter()
        .map(|n| LockfilePackage {
            name: n.to_string(),
            version: None,
            version_spec: None,
            architecture: None,
            repository: None,
            install_reason: None,
            pinned: false,
        })
        .collect();
    h.apply_exclude_patterns(
        &mut packages,
        &["lib*".into(), "linux-image-*".into(), "jq?".into()],
    );
    let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["jq"]);
    assert!(exclude_matchers(&["[".into()]).is_err());
}

#[test]
fn result_status_codes() {
    let info =
        json!({"packages": [{"name": "jq", "found": true}, {"name": "nope", "found": false}]});
    let st = result_status("info", &info);
    assert_eq!(st.exit_code(), 1);
    assert_eq!(
        st.reason.as_deref(),
        Some("[pkg.not_found] pkg info: 1 package(s) not found: nope")
    );
    let errored = json!({"packages": [{"name": "jq", "found": false, "raw": {"error": {}}}]});
    assert!(
        result_status("info", &errored)
            .reason
            .unwrap()
            .starts_with("[pkg.partial_failure]")
    );
    let autoremove = json!({"summary": {"failed": 0}, "autoremove_error": {"code": "x"}});
    let st = result_status("remove", &autoremove);
    assert_eq!(st.exit_code(), 1);
    assert!(
        st.reason
            .unwrap()
            .contains("removing unused dependencies failed")
    );
    assert!(result_status("search", &json!({"results": []})).ok);
}

/// A verb that finds no manager binary fails with `pkg.manager_not_found`
/// (brew is never installed where the unit tests run).
#[test]
fn a_missing_manager_is_reported() {
    if which("brew").is_ok() {
        return;
    }
    let (status, _) = call_input("list_installed", json!({"manager": "brew"}));
    assert_eq!(status.exit_code(), 1);
    assert!(
        status
            .reason
            .unwrap()
            .starts_with("[pkg.manager_not_found] Manager not available"),
    );
}

// ---------------------------------------------------------------------------
// Upstream-only versions (include_versions: minimal)
// ---------------------------------------------------------------------------

#[test]
fn upstream_versions_per_manager() {
    let up = |m, v| upstream_version(m, v);
    assert_eq!(up(&ManagerKind::Apt, "1:2.36-9+deb12u14"), "2.36");
    assert_eq!(up(&ManagerKind::Apt, "8.5.0-2ubuntu10.16"), "8.5.0");
    assert_eq!(up(&ManagerKind::Apt, "1.0"), "1.0");
    assert_eq!(up(&ManagerKind::Dnf, "2:4.1-10.fc42"), "4.1");
    assert_eq!(up(&ManagerKind::Yum, "1.8.0-10.el9"), "1.8.0");
    assert_eq!(up(&ManagerKind::Pacman, "1:2.2.1-3"), "2.2.1");
    assert_eq!(up(&ManagerKind::Apk, "1.8.2-r10"), "1.8.2");
    assert_eq!(up(&ManagerKind::Apk, "1.0_rc1"), "1.0_rc1");
    assert_eq!(up(&ManagerKind::Brew, "1.7.1_1"), "1.7.1");
    assert_eq!(up(&ManagerKind::Brew, "3.4"), "3.4");
}

/// Listings of available builds, as the managers print them (captured in
/// Ubuntu 24.04, Fedora 42 and Alpine containers).
#[test]
fn available_builds_are_read_per_manager() {
    let madison = "      curl | 8.5.0-2ubuntu10.16 | http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
      curl | 8.5.0-2ubuntu10 | http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
";
    assert_eq!(
        available_versions(&ManagerKind::Apt, "curl", madison),
        ["8.5.0-2ubuntu10.16", "8.5.0-2ubuntu10"]
    );
    let dnf = "Available packages
tzdata.noarch 2025b-1.fc42 fedora
tzdata.noarch 2026b-1.fc42 updates
";
    assert_eq!(
        available_versions(&ManagerKind::Dnf, "tzdata", dnf),
        ["2025b-1.fc42", "2026b-1.fc42"]
    );
    let apk = "jq policy:
  1.8.2-r0:
    https://dl-cdn.alpinelinux.org/alpine/v3.24/main
";
    assert_eq!(
        available_versions(&ManagerKind::Apk, "jq", apk),
        ["1.8.2-r0"]
    );
}

/// A lockfile of upstream versions keeps any installed build of the
/// version, installs the newest build of it, and checks the upstream part.
#[test]
fn restore_with_upstream_versions_accepts_any_build() {
    let mut lock = lockfile(
        "apt",
        json!([
            {"name": "a", "version": "8.5.0"},
            {"name": "b", "version": "2.0"},
            {"name": "c", "version": "3.1"}
        ]),
    );
    lock.manager.config = Some(json!({"include_versions": "minimal"}));
    assert!(lockfile_is_minimal(&lock));
    let current = host(&[("a", "8.5.0-2ubuntu10.16"), ("b", "1.9-1")]);
    let config = restore_config(json!({}));
    let m = ManagerKind::Apt;
    let mut plan = handle()
        .compute_restore_plan_for(&lock, &current, &config, &m)
        .unwrap();
    assert_eq!(plan.keep, ["a"]);
    assert_eq!(plan.upgrade, ["b"]);
    assert_eq!(plan.install, ["c"]);
    let builds: HashMap<String, String> = [("c".to_string(), "3.1-4".to_string())]
        .into_iter()
        .collect();
    let ops = restore_operations_with(
        &mut plan,
        &lock,
        &current,
        &config,
        &m,
        &HashSet::new(),
        &builds,
    )
    .unwrap();
    assert_eq!(
        restore_command(&ops[0], &m, &config, true).unwrap().argv(),
        &["apt-get", "install", "-y", "c=3.1-4"]
    );
    assert_eq!(ops[0].locked.as_deref(), Some("3.1"));
    assert!(verify_restore_op(&ops[0], Some("3.1-4"), &config, &m).is_ok());
    assert!(verify_restore_op(&ops[0], Some("3.1-9"), &config, &m).is_ok());
    let err = verify_restore_op(&ops[0], Some("3.2-1"), &config, &m).unwrap_err();
    assert!(
        err.to_string().contains("locked upstream version 3.1"),
        "{err}"
    );

    // The text lockfile keeps the marker.
    let h = handle();
    let text = h.serialize_lockfile_text(&lock).unwrap();
    assert!(text.contains("# include_versions: minimal\n"), "{text}");
    assert!(lockfile_is_minimal(&h.parse_text_lockfile(&text).unwrap()));
}

#[test]
fn a_refused_downgrade_is_exit_1() {
    let e = PkgError::DowngradeRefused("x".into());
    assert_eq!(e.code(), (1, "pkg.downgrade_refused"));
}
