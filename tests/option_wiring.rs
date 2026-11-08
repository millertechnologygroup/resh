//! End-to-end checks of the cron and pkg options wired up in this release,
//! run through the real `resh` binary. Each test runs in its own temporary
//! directory with HOME and PATH pointed inside it and with fake `crontab`,
//! `systemctl` and apt tools (`apt-get`, `apt-cache`, `apt-mark`, `dpkg`,
//! `dpkg-query`) that read canned data from the temporary directory, record
//! their argv and change nothing else. No crontab, cron file, unit file or
//! package on the host is read for writing or changed: the only host path
//! named is a /etc/cron.d file that is only read, under dry_run.

mod common;

use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Appends `CALL\0<program>\0<arg>\0...END\0` to $RESH_TEST_LOG.
const RECORD: &str = r#"{ printf 'CALL\0%s\0' "$(basename "$0")"; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG""#;

/// `crontab [-u user] -l` prints $FAKE_CRONTAB_FILE, `crontab [-u user] -`
/// replaces it, and `crontab -V` prints $FAKE_CRONTAB_VERSION when set (as
/// cronie's crontab does) and otherwise fails like Debian's.
const FAKE_CRONTAB: &str = r#"
for last in "$@"; do :; done
case "$last" in
  -l) [ -f "$FAKE_CRONTAB_FILE" ] && cat "$FAKE_CRONTAB_FILE"; exit 0 ;;
  -) cat > "$FAKE_CRONTAB_FILE"; exit 0 ;;
  -V) [ -n "$FAKE_CRONTAB_VERSION" ] || { echo "crontab: invalid option -- 'V'" >&2; exit 1; }
      echo "$FAKE_CRONTAB_VERSION"; exit 0 ;;
esac
exit 0
"#;

/// `dpkg-query -W -f=<fmt> <name>` (one package: its dpkg state and
/// version) or `dpkg-query -W -f <fmt>` (every installed package).
const FAKE_DPKG_QUERY: &str = r#"
if [ "${2#-f=}" != "$2" ]; then
  line=$(grep "^$3	" "$FAKE_PKG_DIR/installed") || exit 1
  printf 'installed\t%s\n' "$(echo "$line" | cut -f2)"; exit 0
fi
cat "$FAKE_PKG_DIR/installed"
"#;

/// `dpkg -s <name>` for packages listed in $FAKE_PKG_DIR/installed.
const FAKE_DPKG: &str = r#"
[ "$1" = "-s" ] || exit 1
line=$(grep "^$2	" "$FAKE_PKG_DIR/installed") || exit 1
printf 'Package: %s\nVersion: %s\nArchitecture: %s\n' "$2" "$(echo "$line" | cut -f2)" "$(echo "$line" | cut -f3)"
"#;

/// `apt-cache policy <name>` prints apt's version table: a newer candidate
/// from stable-updates/main, then the installed version (`***`) from the
/// repository in $FAKE_PKG_DIR/repo_<name> (default stable/main), or only
/// from the dpkg status file when $FAKE_PKG_DIR/local_<name> exists.
/// `apt-cache show <name>` prints a minimal record. `apt-cache policy` takes
/// several names, as apt's does.
const FAKE_APT_CACHE: &str = r#"
name=$2
case "$1" in
  show) printf 'Package: %s\nVersion: 2.0\nDescription: fake %s\n' "$name" "$name" ;;
  policy)
    shift
    for name in "$@"; do
    repo=stable/main
    [ -f "$FAKE_PKG_DIR/repo_$name" ] && repo=$(cat "$FAKE_PKG_DIR/repo_$name")
    printf '%s:\n  Installed: 1.0\n  Candidate: 2.0\n  Version table:\n' "$name"
    printf '     2.0 500\n        500 http://deb.example.org/debian stable-updates/main amd64 Packages\n'
    printf ' *** 1.0 500\n'
    [ -f "$FAKE_PKG_DIR/local_$name" ] ||
      printf '        500 http://deb.example.org/debian %s amd64 Packages\n' "$repo"
    printf '        100 /var/lib/dpkg/status\n'
    done ;;
esac
exit 0
"#;

const FAKE_APT_MARK: &str = r#"
[ "$1" = "showmanual" ] && cat "$FAKE_PKG_DIR/manual"
exit 0
"#;

const FAKE_OK: &str = "exit 0\n";

struct Fixture {
    tmp: TempDir,
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        std::fs::create_dir(f.bin()).unwrap();
        std::fs::create_dir(f.pkg_dir()).unwrap();
        for (name, body) in [
            ("crontab", FAKE_CRONTAB),
            ("systemctl", FAKE_OK),
            ("apt", FAKE_OK),
            ("apt-get", FAKE_OK),
            ("apt-cache", FAKE_APT_CACHE),
            ("apt-mark", FAKE_APT_MARK),
            ("dpkg", FAKE_DPKG),
            ("dpkg-query", FAKE_DPKG_QUERY),
        ] {
            common::write_executable(&f.bin().join(name), &format!("#!/bin/sh\n{RECORD}\n{body}"));
        }
        std::fs::write(f.pkg_dir().join("installed"), "").unwrap();
        std::fs::write(f.pkg_dir().join("manual"), "").unwrap();
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }
    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }
    fn pkg_dir(&self) -> PathBuf {
        self.path().join("pkg")
    }
    fn log(&self) -> PathBuf {
        self.path().join("invocations.log")
    }
    fn crontab_file(&self) -> PathBuf {
        self.path().join("crontab.txt")
    }

    /// Installed packages (name, version) and which of them were installed
    /// by request (the rest count as dependencies).
    fn installed(&self, packages: &[(&str, &str)], manual: &[&str]) {
        let lines: String = packages
            .iter()
            .map(|(n, v)| format!("{n}\t{v}\tamd64\n"))
            .collect();
        std::fs::write(self.pkg_dir().join("installed"), lines).unwrap();
        std::fs::write(self.pkg_dir().join("manual"), manual.join("\n") + "\n").unwrap();
    }

    fn host_repo(&self, name: &str, repo: &str) {
        std::fs::write(self.pkg_dir().join(format!("repo_{name}")), repo).unwrap();
    }

    fn resh(&self, crontab_version: Option<&str>) -> Command {
        let dir = self.path();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(dir)
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("HOME", dir)
            .env("USER", "resh-test")
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("XDG_STATE_HOME", dir.join("state"))
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("RESH_TEST_LOG", self.log())
            .env("FAKE_CRONTAB_FILE", self.crontab_file())
            .env("FAKE_PKG_DIR", self.pkg_dir())
            .env_remove("SSH_AUTH_SOCK");
        match crontab_version {
            Some(v) => cmd.env("FAKE_CRONTAB_VERSION", v),
            None => cmd.env_remove("FAKE_CRONTAB_VERSION"),
        };
        cmd
    }

    fn run(&self, crontab_version: Option<&str>, args: &[&str]) -> Run {
        self.run_tz("UTC", crontab_version, args)
    }

    /// Like `run`, with the TZ variable (the host's local zone) set to `tz`.
    fn run_tz(&self, tz: &str, crontab_version: Option<&str>, args: &[&str]) -> Run {
        let out = self
            .resh(crontab_version)
            .env("TZ", tz)
            .args(args)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Every recorded invocation as argv (program first).
    fn calls_to(&self, program: &str) -> Vec<Vec<String>> {
        let Ok(raw) = std::fs::read(self.log()) else {
            return vec![];
        };
        let mut calls = Vec::new();
        let mut cur: Option<Vec<String>> = None;
        for field in raw.split(|b| *b == 0).filter(|f| !f.is_empty()) {
            let s = String::from_utf8_lossy(field).into_owned();
            match (s.as_str(), cur.as_mut()) {
                ("CALL", _) => cur = Some(Vec::new()),
                ("END", Some(_)) => calls.push(cur.take().unwrap()),
                (_, Some(c)) => c.push(s),
                (_, None) => panic!("malformed invocation log"),
            }
        }
        calls.into_iter().filter(|c| c[0] == program).collect()
    }

    fn crontab_writes(&self) -> usize {
        self.calls_to("crontab")
            .iter()
            .filter(|c| c.last().map(String::as_str) == Some("-"))
            .count()
    }
}

const CRONIE: Option<&str> = Some("cronie 1.7.2");
const MARKER: &str = "# resh: time-zone block - each job below runs in the CRON_TZ set just above it; add jobs without a time zone above this line";

// ---------------------------------------------------------------------------
// cron add timezone
// ---------------------------------------------------------------------------

#[test]
fn cron_add_timezone_is_refused_when_cron_is_not_cronie() {
    for dry in ["dry_run=true", "dry_run=false"] {
        let f = Fixture::new();
        let r = f.run(
            None,
            &[
                "cron://local.add",
                "backend=cron",
                "schedule=0 2 * * *",
                "command=/opt/backup.sh",
                "timezone=Europe/Berlin",
                dry,
            ],
        );
        assert_eq!(r.code, 2, "{dry}: {}", r.stdout);
        assert_eq!(r.json["error"]["code"], "cron.add_timezone_unsupported");
        assert!(
            r.stderr.contains("only cronie honors CRON_TZ"),
            "{}",
            r.stderr
        );
        assert!(!f.crontab_file().exists());
        assert_eq!(f.crontab_writes(), 0);
    }
}

#[test]
fn cron_add_timezone_dry_run_previews_the_block_and_writes_nothing() {
    let f = Fixture::new();
    let r = f.run(
        CRONIE,
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=0 2 * * *",
            "command=/opt/backup.sh",
            "id=backup",
            "timezone=Europe/Berlin",
            "now_unix=1772366400", // 2026-03-01T12:00:00Z
            "dry_run=true",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(
        r.json["preview"]["cron_line"],
        format!("{MARKER}\nCRON_TZ=Europe/Berlin\n# job-id=backup\n0 2 * * * /opt/backup.sh")
    );
    assert_eq!(
        r.json["job"]["next_run_iso8601"],
        "2026-03-02T02:00:00+01:00"
    );
    assert!(!f.crontab_file().exists());
    assert_eq!(f.crontab_writes(), 0);
}

#[test]
fn cron_add_timezone_writes_the_block_under_cronie() {
    let f = Fixture::new();
    std::fs::write(f.crontab_file(), "*/5 * * * * /usr/bin/poll\n").unwrap();
    for args in [
        &[
            "schedule=0 2 * * *",
            "command=/opt/de.sh",
            "timezone=Europe/Berlin",
        ][..],
        &["schedule=15 * * * *", "command=/opt/plain.sh"][..],
    ] {
        let mut all = vec!["cron://local.add", "backend=cron"];
        all.extend_from_slice(args);
        let r = f.run(CRONIE, &all);
        assert_eq!(r.code, 0, "{}", r.stdout);
    }
    assert_eq!(
        std::fs::read_to_string(f.crontab_file()).unwrap(),
        format!(
            "*/5 * * * * /usr/bin/poll\n15 * * * * /opt/plain.sh\n{MARKER}\nCRON_TZ=Europe/Berlin\n0 2 * * * /opt/de.sh\n"
        )
    );

    // list shows the zone and computes the next run in it.
    let r = f.run(
        CRONIE,
        &[
            "cron://local.list",
            "include_next_run=true",
            "now_unix=1772366400",
            "match_command=/opt/de.sh",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["entries"][0]["timezone"], "Europe/Berlin");
    assert_eq!(
        r.json["entries"][0]["next_run_iso8601"],
        "2026-03-02T02:00:00+01:00"
    );

    // rm takes the job's CRON_TZ line and the empty block with it.
    let r = f.run(
        CRONIE,
        &[
            "cron://local.rm",
            "backend=cron",
            "scope=current",
            "command=/opt/de.sh",
            "schedule=0 2 * * *",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["removed"]["cron"][0]["timezone"], "Europe/Berlin");
    assert_eq!(
        std::fs::read_to_string(f.crontab_file()).unwrap(),
        "*/5 * * * * /usr/bin/poll\n15 * * * * /opt/plain.sh\n"
    );
}

#[test]
fn cron_add_systemd_timezone_dry_run_and_user_units() {
    let f = Fixture::new();
    let base = [
        "cron://local.add",
        "backend=systemd",
        "unit_scope=user",
        "unit_name=resh-tz-probe",
        "schedule=0 2 * * *",
        "command=/opt/backup.sh",
        "timezone=Europe/Berlin",
    ];
    let mut dry = base.to_vec();
    dry.push("dry_run=true");
    let r = f.run(None, &dry);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.json["preview"]["timer_unit"]
            .as_str()
            .unwrap()
            .contains("\nOnCalendar=2:0 Europe/Berlin\n")
    );
    let unit_dir = f.path().join(".config/systemd/user");
    assert!(!unit_dir.exists());
    assert!(
        f.calls_to("systemctl")
            .iter()
            .all(|c| !c.contains(&"enable".to_string()))
    );

    // For real: the unit goes into the temporary HOME, systemctl is the fake.
    let r = f.run(None, &base);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let timer = std::fs::read_to_string(unit_dir.join("resh-tz-probe.timer")).unwrap();
    assert!(
        timer.contains("\nOnCalendar=2:0 Europe/Berlin\n"),
        "{timer}"
    );
}

#[test]
fn cron_timezone_must_be_an_iana_name() {
    let f = Fixture::new();
    let r = f.run(
        CRONIE,
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=0 2 * * *",
            "command=/bin/true",
            "timezone=Mars/Olympus",
            "dry_run=true",
        ],
    );
    assert_eq!(r.code, 2);
    assert_eq!(r.json["error"]["code"], "cron.add_invalid_argument");
    assert_eq!(r.json["error"]["field"], "timezone");

    let r = f.run(CRONIE, &["cron://local.list", "timezone=Mars/Olympus"]);
    assert_eq!(r.code, 2);
    assert_eq!(r.json["error"]["code"], "cron.list_invalid_argument");
    assert_eq!(r.json["error"]["field"], "timezone");
    assert!(
        r.stderr
            .starts_with("Error: [cron.list_invalid_argument] timezone must be an IANA"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("Mars/Olympus"), "{}", r.stderr);
}

// ---------------------------------------------------------------------------
// cron rm / enable cron_file
// ---------------------------------------------------------------------------

#[test]
fn cron_rm_and_enable_refuse_cron_files_outside_cron_directories() {
    for verb in ["rm", "enable"] {
        let f = Fixture::new();
        let outside = f.path().join("not-a-cron-file");
        std::fs::write(&outside, "0 2 * * * root /bin/true\n").unwrap();
        let r = f.run(
            CRONIE,
            &[
                &format!("cron://local.{verb}"),
                "backend=cron",
                "command=/bin/true",
                "schedule=0 2 * * *",
                &format!("cron_file={}", outside.display()),
            ],
        );
        assert_eq!(r.code, 2, "{verb}: {}", r.stdout);
        assert_eq!(
            r.json["error"]["code"],
            format!("cron.{verb}_invalid_argument")
        );
        assert_eq!(r.json["error"]["field"], "cron_file");
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "0 2 * * * root /bin/true\n"
        );
        assert!(f.calls_to("crontab").is_empty(), "{verb}");
    }
}

#[test]
fn cron_rm_and_enable_dry_run_with_cron_file_skip_the_user_crontab() {
    for verb in ["rm", "enable"] {
        let f = Fixture::new();
        std::fs::write(
            f.crontab_file(),
            "# 0 2 * * * /bin/true\n0 2 * * * /bin/true\n",
        )
        .unwrap();
        let r = f.run(
            CRONIE,
            &[
                &format!("cron://local.{verb}"),
                "backend=cron",
                "scope=all",
                "match_command=/bin/true",
                // Only read (dry run); a name no cron package ships.
                "cron_file=/etc/cron.d/resh_option_wiring_probe",
                "require_match=false",
                "dry_run=true",
            ],
        );
        assert_eq!(r.code, 0, "{verb}: {}", r.stdout);
        assert_eq!(r.json["matched_count"]["cron"], 0, "{verb}");
        // scope=all alone would have read (and matched in) the user crontab.
        assert!(f.calls_to("crontab").is_empty(), "{verb}");
    }
}

// ---------------------------------------------------------------------------
// pkg
// ---------------------------------------------------------------------------

#[test]
fn pkg_info_include_repo() {
    let f = Fixture::new();
    f.installed(&[("jq", "1.7")], &["jq"]);
    let info = |extra: &str| {
        let r = f.run(
            None,
            &[
                "pkg://system.info",
                &format!(r#"input={{"manager":"apt","packages":["jq"]{extra}}}"#),
            ],
        );
        assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
        r.json["packages"][0].clone()
    };
    assert_eq!(info("")["repository"], "http://deb.example.org/debian");
    assert_eq!(
        info(r#","include_repo":true"#)["repository"],
        "http://deb.example.org/debian"
    );
    let off = info(r#","include_repo":false"#);
    assert_eq!(off["repository"], Value::Null);
    assert_eq!(off["installed_version"], "1.7");
}

#[test]
fn pkg_list_installed_include_versions() {
    let f = Fixture::new();
    f.installed(&[("curl", "8.5.0"), ("jq", "1.7")], &["jq"]);
    let list = |extra: &str| {
        let r = f.run(
            None,
            &[
                "pkg://system.list_installed",
                &format!(r#"input={{"manager":"apt","include_repo":false{extra}}}"#),
            ],
        );
        assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
        r.json["results"].clone()
    };
    let on = list("");
    assert_eq!(on[0]["name"], "curl");
    assert_eq!(on[0]["version"], "8.5.0");
    assert_eq!(on[1]["version"], "1.7");
    let off = list(r#","include_versions":false"#);
    assert_eq!(off[0]["name"], "curl");
    assert_eq!(off[0]["version"], Value::Null);
    assert_eq!(off[1]["version"], Value::Null);
}

#[test]
fn pkg_package_source_is_refused_before_anything_runs() {
    for verb in ["install", "remove"] {
        for dry in [true, false] {
            let f = Fixture::new();
            let input = json!({
                "manager": "apt",
                "packages": [{ "name": "jq", "source": "https://example.com/jq.deb" }],
                "dry_run": dry,
            });
            let r = f.run(
                None,
                &[&format!("pkg://system.{verb}"), &format!("input={input}")],
            );
            // A refused request: exit 2 (pkg.invalid_argument).
            assert_eq!(r.code, 2, "{verb} dry={dry}: {}", r.stdout);
            assert!(r.stderr.contains("[pkg.invalid_argument]"), "{}", r.stderr);
            assert!(r.stderr.contains("source="), "{}", r.stderr);
            assert!(f.calls_to("apt-get").is_empty(), "{verb} dry={dry}");
            assert!(f.calls_to("dpkg").is_empty(), "{verb} dry={dry}");
        }
    }
    // Without source, the dry run goes ahead.
    let f = Fixture::new();
    let r = f.run(
        None,
        &[
            "pkg://system.install",
            r#"input={"manager":"apt","packages":[{"name":"jq"}],"dry_run":true}"#,
        ],
    );
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.json["packages"][0]["action"], "would_install");
}

/// A host with `curl` (manual, from backports/main) and `libssl` (a
/// dependency); a lockfile with curl and libssl from stable/main, plus `app`
/// (manual) and `libdep` (dependency) that are not installed.
fn restore_fixture() -> (Fixture, String) {
    let f = Fixture::new();
    f.installed(&[("curl", "8.5.0"), ("libssl", "3.0")], &["curl"]);
    f.host_repo("curl", "backports/main");
    let lockfile = json!({
        "lockfile_version": "pkg-lock/v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "manager": { "name": "apt", "alias": "system", "version": null, "config": null },
        "platform": { "os_family": null, "os_name": null, "os_version": null,
                      "kernel": null, "architecture": null },
        "scope": "all",
        "packages": [
            { "name": "app", "repository": "stable/main", "install_reason": "manual" },
            { "name": "curl", "version": "8.5.0", "repository": "stable/main",
              "install_reason": "manual" },
            { "name": "libdep", "repository": "stable/main", "install_reason": "dependency" },
            { "name": "libssl", "version": "3.0", "repository": "stable/main",
              "install_reason": "dependency" }
        ]
    })
    .to_string();
    (f, lockfile)
}

fn restore(f: &Fixture, lockfile: &str, options: Value) -> Run {
    let mut input = json!({ "manager": "apt", "lockfile": lockfile });
    input
        .as_object_mut()
        .unwrap()
        .extend(options.as_object().unwrap().clone());
    f.run(None, &["pkg://system.restore", &format!("input={input}")])
}

#[test]
fn pkg_restore_on_repo_mismatch_fail_refuses_before_anything_runs() {
    for dry in [true, false] {
        let (f, lockfile) = restore_fixture();
        let r = restore(
            &f,
            &lockfile,
            json!({ "on_repo_mismatch": "fail", "dry_run": dry }),
        );
        assert_eq!(r.code, 1, "dry={dry}: {}", r.stdout);
        assert!(
            r.stderr
                .contains("curl (lockfile: stable/main, host: backports/main)"),
            "{}",
            r.stderr
        );
        assert!(f.calls_to("apt-get").is_empty(), "dry={dry}");
    }
}

#[test]
fn pkg_restore_on_repo_mismatch_warn_and_ignore() {
    let (f, lockfile) = restore_fixture();
    for options in [
        json!({ "dry_run": true }),
        json!({ "on_repo_mismatch": "warn", "dry_run": true }),
    ] {
        let r = restore(&f, &lockfile, options);
        assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
        let warnings: Vec<&str> = r.json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].starts_with("repository mismatch for 1 package(s): curl"));
        assert!(warnings[1].contains("not installed") && warnings[1].contains("app, libdep"));
    }
    assert!(f.calls_to("apt-get").is_empty());

    // ignore: no warnings, and no repository lookups (listing the installed
    // packages for the plan does not look up repositories).
    std::fs::remove_file(f.log()).unwrap();
    let r = restore(
        &f,
        &lockfile,
        json!({ "on_repo_mismatch": "ignore", "dry_run": true }),
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.json["warnings"], json!([]));
    assert_eq!(
        f.calls_to("apt-cache").len(),
        0,
        "{:?}",
        f.calls_to("apt-cache")
    );
    assert!(f.calls_to("apt-get").is_empty());
}

/// Malformed values of the keys wired up here are refused before any
/// package-manager command runs.
#[test]
fn pkg_malformed_option_values_are_refused() {
    let (f, lockfile) = restore_fixture();
    for (verb, input) in [
        (
            "restore",
            json!({ "manager": "apt", "lockfile": lockfile, "on_repo_mismatch": "maybe" }),
        ),
        (
            "restore",
            json!({ "manager": "apt", "lockfile": lockfile, "include_dependencies": "no" }),
        ),
        (
            "info",
            json!({ "manager": "apt", "packages": ["jq"], "include_repo": "false" }),
        ),
        (
            "list_installed",
            json!({ "manager": "apt", "include_versions": 0 }),
        ),
        (
            "install",
            json!({ "manager": "apt", "packages": [{ "name": "jq", "source": 1 }] }),
        ),
    ] {
        let r = f.run(
            None,
            &[&format!("pkg://system.{verb}"), &format!("input={input}")],
        );
        // A refused request: exit 2, naming the key.
        assert_eq!(r.code, 2, "{verb} {input}: {}", r.stdout);
        assert!(
            r.stderr
                .contains("[pkg.invalid_argument] invalid value for `"),
            "{verb}: {}",
            r.stderr
        );
    }
    for program in ["apt-get", "apt-cache", "apt-mark", "dpkg", "dpkg-query"] {
        assert!(f.calls_to(program).is_empty(), "{program} ran");
    }
}

#[test]
fn pkg_restore_include_dependencies() {
    let (f, lockfile) = restore_fixture();
    let plan = |include: bool| {
        let r = restore(
            &f,
            &lockfile,
            json!({
                "on_repo_mismatch": "ignore",
                "include_dependencies": include,
                "allow_removals": true,
                "dry_run": true
            }),
        );
        assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
        r.json["plan"].clone()
    };
    let on = plan(true);
    assert_eq!(on["install"], json!(["app", "libdep"]));
    assert_eq!(on["keep"], json!(["curl", "libssl"]));
    assert!(on.get("skipped_dependencies").is_none());

    let off = plan(false);
    assert_eq!(off["install"], json!(["app"]));
    assert_eq!(off["keep"], json!(["curl"]));
    // libssl is left alone: not kept, not removed despite allow_removals.
    assert_eq!(off["remove"], json!([]));
    assert_eq!(off["skipped_dependencies"], json!(["libdep", "libssl"]));
    assert!(f.calls_to("apt-get").is_empty());

    // For real (the apt-get here is the fake): only `app` is installed. The
    // fake installs nothing, so the check after the command reports that
    // app is still missing (exit 1).
    let r = restore(
        &f,
        &lockfile,
        json!({ "on_repo_mismatch": "ignore", "include_dependencies": false }),
    );
    assert_eq!(r.code, 1, "{} {}", r.stdout, r.stderr);
    assert!(r.stderr.contains("[pkg.partial_failure]"), "{}", r.stderr);
    assert_eq!(
        r.json["results"]["install"][0]["error"]["message"],
        "Restore apply failed: app is not installed after the command"
    );
    assert_eq!(
        f.calls_to("apt-get"),
        vec![vec!["apt-get", "install", "-y", "app"]]
    );
}

// ---------------------------------------------------------------------------
// --help of the changed verbs
// ---------------------------------------------------------------------------

#[test]
fn help_of_changed_verbs_lists_the_wired_options() {
    let f = Fixture::new();
    let cases: &[(&str, &str, &[&str], &[&str])] = &[
        (
            "cron",
            "add",
            &[
                "[timezone=<IANA zone>]",
                "[now_unix=<seconds>]",
                "[include_next_run=true|false]",
                "CRON_TZ",
                "cronie",
                "computed in timezone (default: the host's local zone) after now_unix",
            ],
            &[],
        ),
        (
            "cron",
            "list",
            &[
                "[timezone=<IANA zone>]",
                "[now_unix=<seconds>]",
                "default: the host's local zone",
                "Unix seconds 0-253402300799",
            ],
            &[],
        ),
        (
            "cron",
            "rm",
            &["[cron_file=<path>]", "/etc/cron.d/<name>"],
            &[],
        ),
        (
            "cron",
            "enable",
            &["[cron_file=<path>]", "/etc/cron.d/<name>"],
            &[],
        ),
        (
            "pkg",
            "info",
            &["include_repo (default true; false sets repository to null)"],
            &[],
        ),
        (
            "pkg",
            "list_installed",
            &["include_versions (default true; false sets version to null)"],
            &[],
        ),
        (
            "pkg",
            "install",
            &["{name, version}", "source is refused"],
            &["{name, version, source}"],
        ),
        ("pkg", "remove", &["source is refused"], &[]),
        (
            "pkg",
            "restore",
            &[
                "on_repo_mismatch (fail|warn|ignore, default warn)",
                "include_dependencies (default true)",
            ],
            &[],
        ),
        (
            "pkg",
            "snapshot",
            &["scope (all|manual|dependency)"],
            &["inline"],
        ),
    ];
    for (handle, verb, wanted, unwanted) in cases {
        let r = f.run(None, &[handle, verb, "--help"]);
        assert_eq!(r.code, 0, "{handle} {verb}: {}", r.stderr);
        assert!(r.stdout.contains(&format!("Verb: {verb}")), "{}", r.stdout);
        // Collapse the wrapped usage lines so a phrase may span two lines.
        let text = r.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
        for w in *wanted {
            assert!(
                text.contains(w),
                "{handle} {verb} --help lacks {w:?}:\n{}",
                r.stdout
            );
        }
        for u in *unwanted {
            assert!(
                !text.contains(u),
                "{handle} {verb} --help lists {u:?}:\n{}",
                r.stdout
            );
        }
    }
    // The help commands ran nothing.
    assert!(f.calls_to("crontab").is_empty() && f.calls_to("apt-get").is_empty());
}

// ---------------------------------------------------------------------------
// Local zone default, snapshot inline, apt repository
// ---------------------------------------------------------------------------

/// Next runs without timezone= use the host's local zone, here set with TZ.
#[test]
fn cron_next_runs_default_to_the_local_zone() {
    let f = Fixture::new();
    std::fs::write(f.crontab_file(), "0 2 * * * /opt/plain.sh\n").unwrap();
    let list = [
        "cron://local.list",
        "include_next_run=true",
        "now_unix=1772366400",
    ];
    for tz in [
        "Asia/Tokyo",
        ":Asia/Tokyo",
        "/usr/share/zoneinfo/Asia/Tokyo",
    ] {
        let r = f.run_tz(tz, None, &list);
        assert_eq!(r.code, 0, "{tz}: {}", r.stderr);
        assert_eq!(r.json["next_run_timezone"], "Asia/Tokyo", "{tz}");
        assert_eq!(
            r.json["entries"][0]["next_run_iso8601"], "2026-03-02T02:00:00+09:00",
            "{tz}"
        );
        assert_eq!(r.json["warnings"], json!([]));
    }
    // timezone= wins over the local zone.
    let mut with_tz = list.to_vec();
    with_tz.push("timezone=Europe/Berlin");
    let r = f.run_tz("Asia/Tokyo", None, &with_tz);
    assert_eq!(
        r.json["entries"][0]["next_run_iso8601"],
        "2026-03-02T02:00:00+01:00"
    );

    // add, dry run.
    let r = f.run_tz(
        "Asia/Tokyo",
        None,
        &[
            "cron://local.add",
            "backend=cron",
            "schedule=0 2 * * *",
            "command=/bin/true",
            "now_unix=1772366400",
            "dry_run=true",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["job"]["next_run_timezone"], "Asia/Tokyo");
    assert_eq!(
        r.json["job"]["next_run_iso8601"],
        "2026-03-02T02:00:00+09:00"
    );
    assert_eq!(f.crontab_writes(), 0);
}

/// A TZ value that names no known zone (a POSIX rule): only the offset is
/// known, and the output says so.
#[test]
fn cron_unnamed_local_zone_is_reported_as_an_offset() {
    let f = Fixture::new();
    std::fs::write(f.crontab_file(), "0 2 * * * /opt/plain.sh\n").unwrap();
    let r = f.run_tz(
        "XYZ-3",
        None,
        &[
            "cron://local.list",
            "include_next_run=true",
            "now_unix=1772366400",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let label = r.json["next_run_timezone"].as_str().unwrap();
    assert!(label.starts_with('+') || label.starts_with('-'), "{label}");
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("could not be identified by name"),
        "{}",
        r.stdout
    );
}

#[test]
fn pkg_snapshot_refuses_inline() {
    for value in ["true", "false"] {
        let f = Fixture::new();
        f.installed(&[("jq", "1.7")], &["jq"]);
        let r = f.run(
            None,
            &[
                "pkg://system.snapshot",
                &format!(r#"input={{"manager":"apt","inline":{value}}}"#),
            ],
        );
        assert_eq!(r.code, 2, "{}", r.stdout);
        assert!(
            r.stderr
                .contains("[pkg.invalid_argument] inline is not supported"),
            "{}",
            r.stderr
        );
        assert!(r.stdout.is_empty());
        for program in ["apt", "apt-cache", "apt-mark", "dpkg-query"] {
            assert!(f.calls_to(program).is_empty(), "{program} ran");
        }
    }
}

/// snapshot records the installed version's suite/component, not the
/// priority; a package known only from the dpkg status file has none.
#[test]
fn pkg_snapshot_records_the_installed_versions_apt_repository() {
    let f = Fixture::new();
    f.installed(
        &[("curl", "1.0"), ("jq", "1.0"), ("mytool", "1.0")],
        &["jq"],
    );
    f.host_repo("curl", "noble-security/main");
    std::fs::write(f.pkg_dir().join("local_mytool"), "").unwrap();
    let r = f.run(
        None,
        &["pkg://system.snapshot", r#"input={"manager":"apt"}"#],
    );
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let lock: Value = serde_json::from_str(r.json["lockfile"].as_str().unwrap()).unwrap();
    let repo = |name: &str| {
        lock["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .unwrap()
            .get("repository")
            .cloned()
    };
    assert_eq!(repo("curl"), Some(json!("noble-security/main")));
    assert_eq!(repo("jq"), Some(json!("stable/main")));
    assert_eq!(repo("mytool"), None);
}
