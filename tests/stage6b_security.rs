//! Stage 6B (v1.0.4-beta) security regression tests that need the real
//! `resh` binary. Each test runs it in its own temporary directory with HOME
//! and PATH pointed inside it, and with fake `tar`, `rsync`, `borg`, `restic`,
//! `crontab`, `systemctl` and `ssh` executables that record their argv and
//! do nothing else (the fake `ssh` runs the remote command with the local
//! `/bin/sh` inside the temporary directory, standing in for a POSIX login
//! shell). Probe values are option-shaped or shell-shaped markers that only
//! show where a value ends up; none of them is a working payload.

mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Records every invocation as `CALL\0<program>\0<arg>\0...END\0`.
const RECORDING_FAKE: &str = r#"#!/bin/sh
{ printf 'CALL\0%s\0' "$(basename "$0")"; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG"
exit "${FAKE_EXIT:-0}"
"#;

/// Like RECORDING_FAKE, and emulates `crontab -u <user> -l` / `crontab -u <user> -`
/// against one file.
const FAKE_CRONTAB: &str = r#"#!/bin/sh
{ printf 'CALL\0crontab\0'; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG"
for last in "$@"; do :; done
case "$last" in
  -l) [ -f "$FAKE_CRONTAB_FILE" ] && cat "$FAKE_CRONTAB_FILE"; exit 0 ;;
  -) cat > "$FAKE_CRONTAB_FILE"; exit 0 ;;
esac
exit 0
"#;

/// Records the invocation, then runs the last argument (the remote command)
/// with /bin/sh in $FAKE_REMOTE_DIR, as sshd would with a POSIX login shell.
const FAKE_SSH: &str = r#"#!/bin/sh
{ printf 'CALL\0ssh\0'; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG"
for last in "$@"; do :; done
cd "$FAKE_REMOTE_DIR" || exit 255
exec /bin/sh -c "$last"
"#;

struct Fixture {
    tmp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        std::fs::create_dir(f.bin()).unwrap();
        std::fs::create_dir(f.remote()).unwrap();
        for name in ["tar", "rsync", "borg", "restic", "systemctl"] {
            f.script(name, RECORDING_FAKE);
        }
        f.script("crontab", FAKE_CRONTAB);
        f.script("ssh", FAKE_SSH);
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn remote(&self) -> PathBuf {
        self.path().join("remote")
    }

    fn log(&self) -> PathBuf {
        self.path().join("invocations.log")
    }

    fn crontab_file(&self) -> PathBuf {
        self.path().join("crontab.txt")
    }

    fn script(&self, name: &str, body: &str) {
        common::write_executable(&self.bin().join(name), body);
    }

    fn resh(&self) -> Command {
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
            .env("FAKE_REMOTE_DIR", self.remote())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("RESTIC_PASSWORD")
            .env_remove("RESTIC_REPOSITORY")
            .env_remove("BORG_PASSPHRASE");
        cmd
    }

    /// Every recorded invocation as argv (program first).
    fn calls(&self) -> Vec<Vec<String>> {
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
        calls
    }

    fn calls_to(&self, program: &str) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter(|c| c[0] == program)
            .collect()
    }

    /// Every file and directory under the fixture except the fixture's own
    /// bookkeeping, relative to it.
    fn artifacts(&self) -> Vec<String> {
        let mut out = Vec::new();
        let skip = [self.bin(), self.remote(), self.log()];
        for entry in walk(self.path()) {
            if skip.iter().any(|s| entry.starts_with(s)) {
                continue;
            }
            out.push(
                entry
                    .strip_prefix(self.path())
                    .unwrap()
                    .display()
                    .to_string(),
            );
        }
        out.sort();
        out
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            out.push(p.clone());
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                out.extend(walk(&p));
            }
        }
    }
    out
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
}

fn run(cmd: &mut Command) -> Run {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let json = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    Run {
        code: out.status.code().unwrap_or(-1),
        json,
        stdout,
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// ---------------------------------------------------------------------------
// backup://
// ---------------------------------------------------------------------------

fn backend_args(backend: &str, repo: &Path) -> Vec<String> {
    let mut a = vec![
        format!("backend={backend}"),
        format!("repo_url={}", repo.display()),
    ];
    if matches!(backend, "restic" | "borg") {
        a.push("password=fixture-only".into());
    }
    a
}

fn assert_backup_rejected(r: &Run, field: &str) {
    assert_ne!(r.code, 0, "rejection must exit non-zero: {}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert_eq!(r.json["error"]["kind"], "INVALID_ARGS", "{}", r.stdout);
    assert_eq!(r.json["error"]["details"]["field"], field, "{}", r.stdout);
    assert!(
        r.json["error"]["message"].as_str().unwrap().contains(field),
        "{}",
        r.stdout
    );
}

/// B1: a source value that a backend would parse as an option, or (rsync) as
/// a remote location, is refused before the backend runs, for real runs and
/// dry runs alike.
#[test]
fn backup_create_refuses_option_shaped_sources_before_running() {
    for backend in ["tar", "rsync", "borg", "restic"] {
        for probe in ["--resh-probe-option", "-v"] {
            for dry in [false, true] {
                let f = Fixture::new();
                let repo = f.path().join("repo");
                let mut cmd = f.resh();
                cmd.arg("backup://db.create")
                    .arg(format!("src={probe}"))
                    .args(backend_args(backend, &repo));
                if dry {
                    cmd.arg("dry_run=true");
                }
                let r = run(&mut cmd);
                assert_backup_rejected(&r, "src");
                assert!(f.calls().is_empty(), "{backend}: backend ran");
                assert!(!repo.exists(), "{backend}: repository created");
            }
        }
    }
}

/// B1: legitimate sources still back up; positionals follow `--`, tar never
/// treats the archive as a remote `host:file`, and rsync never treats a
/// relative source containing `:` as a remote location.
#[test]
fn backup_create_passes_sources_as_positionals() {
    let f = Fixture::new();
    std::fs::create_dir(f.path().join("data")).unwrap();
    let repo = f.path().join("repo");
    for backend in ["tar", "rsync", "borg", "restic"] {
        let r = run(f
            .resh()
            .arg("backup://db.create")
            .arg("src=data;probe-host:dir")
            .args(backend_args(backend, &repo)));
        assert_eq!(r.code, 0, "{backend}: {}", r.stdout);
        assert_eq!(r.json["ok"], true);
        let call = f.calls_to(backend).pop().expect("backend ran");
        let sep = call.iter().position(|a| a == "--").expect("-- separator");
        let positionals = &call[sep + 1..];
        match backend {
            "tar" => {
                assert!(call.contains(&"--force-local".to_string()), "{call:?}");
                assert_eq!(positionals, s(&["data", "probe-host:dir"]));
            }
            "rsync" => {
                assert_eq!(&positionals[..2], s(&["./data", "./probe-host:dir"]));
                assert!(positionals[2].starts_with(&repo.display().to_string()));
            }
            "borg" => {
                assert!(positionals[0].starts_with(&format!("{}::", repo.display())));
                assert_eq!(&positionals[1..], s(&["data", "probe-host:dir"]));
            }
            _ => assert_eq!(positionals, s(&["data", "probe-host:dir"])),
        }
    }
}

/// B1: option values given by the caller are attached with `=`, so a value
/// starting with `-` can never be read as a separate option.
#[test]
fn backup_option_values_are_attached() {
    let f = Fixture::new();
    let repo = f.path().join("repo");
    let r = run(f
        .resh()
        .arg("backup://db.create")
        .arg("src=/etc")
        .arg("exclude=-probe")
        .arg("tag=daily")
        .arg("label=web01")
        .args(backend_args("restic", &repo)));
    assert_eq!(r.code, 0, "{}", r.stdout);
    let call = f.calls_to("restic").pop().unwrap();
    assert!(call.contains(&"--exclude=-probe".to_string()), "{call:?}");
    assert!(call.contains(&"--tag=daily".to_string()), "{call:?}");
    assert!(call.contains(&"--hostname=web01".to_string()), "{call:?}");
}

/// B2: restore refuses a snapshot id or destination that a backend would
/// parse as an option, and a tar/rsync snapshot id that leaves the repository.
#[test]
fn backup_restore_refuses_unsafe_ids_and_destinations() {
    let cases: &[(&str, &str, &str, &str)] = &[
        ("restic", "--resh-probe-option", "out", "snapshot_id"),
        ("borg", "-v", "out", "snapshot_id"),
        ("tar", "../outside", "out", "snapshot_id"),
        ("rsync", "a/b", "out", "snapshot_id"),
        ("tar", "backup_1", "-v", "dest"),
        ("rsync", "backup_1", "--resh-probe-option", "dest"),
        ("restic", "latest", "--resh-probe-option", "dest"),
    ];
    for (backend, id, dest, field) in cases {
        let f = Fixture::new();
        let repo = f.path().join("repo");
        let r = run(f
            .resh()
            .arg("backup://db.restore")
            .arg(format!("snapshot_id={id}"))
            .arg(format!("dest={dest}"))
            .args(backend_args(backend, &repo)));
        assert_backup_rejected(&r, field);
        assert!(f.calls().is_empty(), "{backend} {id} {dest}: backend ran");
        assert!(f.artifacts().is_empty(), "{:?}", f.artifacts());
    }
}

#[test]
fn backup_restore_passes_ids_and_destinations_as_positionals() {
    let f = Fixture::new();
    let repo = f.path().join("repo");
    let r = run(f
        .resh()
        .arg("backup://db.restore")
        .arg("snapshot_id=4f2a")
        .arg("dest=restore")
        .args(backend_args("restic", &repo)));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(
        f.calls_to("restic").pop().unwrap(),
        s(&["restic", "restore", "--target=restore", "--", "4f2a"])
    );

    let r = run(f
        .resh()
        .arg("backup://db.restore")
        .arg("snapshot_id=backup_1")
        .arg("dest=probe-host:dir")
        .args(backend_args("rsync", &repo)));
    assert_eq!(r.code, 0, "{}", r.stdout);
    let call = f.calls_to("rsync").pop().unwrap();
    assert_eq!(
        &call[call.len() - 3..],
        s(&[
            "--",
            &format!("{}/backup_1/", repo.display()),
            "./probe-host:dir"
        ])
    );
}

/// B3: repository URLs that would hand an option to ssh (borg's ssh
/// transport) or to the backend are refused, for every verb that uses them.
#[test]
fn backup_refuses_option_shaped_repository_hosts() {
    let repos = [
        "-probe",
        "ssh://-probe/repo",
        "user@-probe:repo",
        "sftp:-probe:/repo",
    ];
    for backend in ["borg", "restic"] {
        for repo in repos {
            for verb in ["list", "verify", "prune"] {
                let f = Fixture::new();
                let mut cmd = f.resh();
                cmd.arg(format!("backup://db.{verb}"))
                    .arg(format!("backend={backend}"))
                    .arg(format!("repo_url={repo}"))
                    .arg("password=fixture-only");
                if verb == "prune" {
                    cmd.args(["keep_daily=7", "dry_run=true"]);
                }
                let r = run(&mut cmd);
                assert_backup_rejected(&r, "repo_url");
                assert!(f.calls().is_empty(), "{backend} {verb} {repo}: ran");
            }
        }
    }
}

/// R-7: `prune dry_run=true` for restic/borg is the backend's own read-only
/// dry run (documented); it is labelled as such, and the argv is safe.
#[test]
fn backup_prune_dry_run_is_labelled_backend_dry_run() {
    let f = Fixture::new();
    let repo = f.path().join("borgrepo");
    let r = run(f
        .resh()
        .arg("backup://db.prune")
        .args(backend_args("borg", &repo))
        .args(["keep_daily=7", "dry_run=true"]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["dry_run"], true);
    assert_eq!(r.json["result"]["dry_run_mode"], "backend");
    assert_eq!(
        f.calls_to("borg").pop().unwrap(),
        s(&[
            "borg",
            "prune",
            "--list",
            "--keep-daily",
            "7",
            "--dry-run",
            "--",
            &repo.display().to_string()
        ])
    );

    // restic too; and for both, the output never claims nothing ran.
    let r = run(f
        .resh()
        .arg("backup://db.prune")
        .args(backend_args("restic", &repo))
        .args(["keep_daily=7", "dry_run=true"]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["dry_run_mode"], "backend");
    let restic = f.calls_to("restic").pop().unwrap();
    assert_eq!(
        restic,
        s(&[
            "restic",
            "forget",
            "--json",
            "--keep-daily",
            "7",
            "--dry-run"
        ])
    );
    assert_eq!(r.json["backend"]["simulated"], false);
    assert_eq!(r.json["backend"]["command"], serde_json::json!(restic));
    assert!(
        r.json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("its own --dry-run mode")),
        "{}",
        r.stdout
    );
}

/// R-7: tar/rsync `prune dry_run=true` is a pure plan: no backend runs and
/// no snapshot is removed.
#[test]
fn backup_prune_dry_run_for_local_backends_changes_nothing() {
    let f = Fixture::new();
    let repo = f.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    for i in 0..3 {
        std::fs::write(repo.join(format!("backup_{i}.tar.gz")), b"x").unwrap();
    }
    let before = f.artifacts();
    let r = run(f
        .resh()
        .arg("backup://db.prune")
        .args(backend_args("tar", &repo))
        .args(["keep_daily=1", "dry_run=true"]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["dry_run_mode"], "plan");
    assert!(
        r.json["result"]["would_prune"]["snapshots_removed"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(f.calls().is_empty());
    assert_eq!(f.artifacts(), before);

    // rsync snapshot directories likewise.
    let repo = f.path().join("rsyncrepo");
    for i in 0..3 {
        std::fs::create_dir_all(repo.join(format!("backup_{i}"))).unwrap();
    }
    let before = f.artifacts();
    let r = run(f
        .resh()
        .arg("backup://db.prune")
        .args(backend_args("rsync", &repo))
        .args(["keep_daily=1", "dry_run=true"]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["result"]["dry_run_mode"], "plan");
    assert!(f.calls().is_empty());
    assert_eq!(f.artifacts(), before);
}

/// A failed backend is never reported as success. Its exit code is passed
/// through (documented in backup.md 3.2), and the JSON names it.
#[test]
fn backup_backend_failure_is_a_failure() {
    let f = Fixture::new();
    let repo = f.path().join("repo");
    let r = run(f
        .resh()
        .env("FAKE_EXIT", "2")
        .arg("backup://db.create")
        .arg("src=/etc")
        .args(backend_args("tar", &repo)));
    assert_eq!(r.code, 2, "{}", r.stdout);
    assert_eq!(r.json["ok"], false);
    assert_eq!(r.json["error"]["kind"], "BACKEND_FAILED");
    assert_eq!(r.json["error"]["details"]["exit_code"], 2);
}

// ---------------------------------------------------------------------------
// cron://
// ---------------------------------------------------------------------------

fn assert_cron_rejected(r: &Run, field: &str) {
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert_eq!(
        r.json["error"]["code"], "cron.add_invalid_argument",
        "{}",
        r.stdout
    );
    assert_eq!(r.json["error"]["field"], field, "{}", r.stdout);
}

/// C1: control characters in any crontab field are refused before anything
/// is written, including under dry_run.
#[test]
fn cron_add_refuses_line_breaks_in_crontab_fields() {
    let cases: &[(&str, &str)] = &[
        ("description", "nightly\nresh-probe-line"),
        ("id", "nightly\rresh-probe"),
        ("command", "/bin/true\nresh-probe-line"),
        ("schedule", "0 4 * * *\nresh-probe"),
    ];
    for (field, value) in cases {
        for dry in [false, true] {
            let f = Fixture::new();
            let mut cmd = f.resh();
            cmd.args(["cron://local.add", "backend=cron"]);
            for (k, v) in [("schedule", "0 4 * * *"), ("command", "/bin/true")] {
                if k != *field {
                    cmd.arg(format!("{k}={v}"));
                }
            }
            cmd.arg(format!("{field}={value}"));
            if dry {
                cmd.arg("dry_run=true");
            }
            let r = run(&mut cmd);
            assert_cron_rejected(&r, field);
            assert!(!f.crontab_file().exists(), "{field}: crontab written");
            assert!(
                f.calls_to("crontab")
                    .iter()
                    .all(|c| c.last().map(String::as_str) != Some("-")),
                "{field}: crontab was replaced"
            );
        }
    }
}

/// Schedules must be five crontab fields or an `@` keyword: a six-field
/// expression makes cron read the sixth field as the command.
#[test]
fn cron_add_refuses_schedules_crontab_would_misread() {
    for schedule in ["0 0 4 * * *", "0 4 * * * 2027", "0 4 * *", "@midnight-ish"] {
        let f = Fixture::new();
        let r = run(f.resh().args([
            "cron://local.add",
            "backend=cron",
            &format!("schedule={schedule}"),
            "command=/bin/true",
            "dry_run=true",
        ]));
        assert_eq!(r.code, 1, "{schedule}: {}", r.stdout);
        assert_eq!(r.json["ok"], false, "{schedule}");
        assert!(!f.crontab_file().exists());
    }
}

/// cron turns an unescaped `%` into a line break and feeds the rest to the
/// command's stdin, so the job would not run the command that was asked for.
#[test]
fn cron_add_refuses_unescaped_percent() {
    let f = Fixture::new();
    let r = run(f.resh().args([
        "cron://local.add",
        "backend=cron",
        "schedule=0 4 * * *",
        "command=date +%F",
    ]));
    assert_cron_rejected(&r, "command");
    assert!(!f.crontab_file().exists());

    let r = run(f.resh().args([
        "cron://local.add",
        "backend=cron",
        "schedule=0 4 * * *",
        r"command=date +\%F",
        "id=stamp",
        "description=daily stamp",
    ]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(
        std::fs::read_to_string(f.crontab_file()).unwrap(),
        "# job-id=stamp description=daily stamp\n0 4 * * * date +\\%F\n"
    );
}

/// C1: `scope=system` writes only to /etc/crontab or a file directly in
/// /etc/cron.d, and `user` must be a user name.
#[test]
fn cron_add_system_scope_refuses_other_destinations() {
    let f = Fixture::new();
    let outside = f.path().join("not-a-cron-file");
    for (field, extra) in [
        ("cron_file", format!("cron_file={}", outside.display())),
        ("cron_file", "cron_file=/etc/cron.d/../passwd".to_string()),
        ("cron_file", "cron_file=/etc/cron.d/has.dot".to_string()),
        ("user", "user=-probe".to_string()),
        ("user", "user=root nobody".to_string()),
    ] {
        let r = run(f.resh().args([
            "cron://local.add",
            "backend=cron",
            "scope=system",
            "schedule=0 4 * * *",
            "command=/bin/true",
            &extra,
        ]));
        assert_cron_rejected(&r, field);
        assert!(!outside.exists());
    }
}

/// C2: unit names that leave the unit directory or that systemctl would read
/// as an option are refused before any file is written or systemctl runs.
#[test]
fn cron_add_systemd_refuses_unsafe_unit_names() {
    for name in [
        "../escape",
        "a/b",
        "-probe",
        ".hidden",
        "",
        "bad\nname",
        "x@",
    ] {
        let f = Fixture::new();
        let r = run(f.resh().args([
            "cron://local.add",
            "backend=systemd",
            "unit_scope=user",
            "schedule=0 4 * * *",
            "command=/bin/true",
            &format!("unit_name={name}"),
        ]));
        assert_cron_rejected(&r, "unit_name");
        assert!(f.artifacts().is_empty(), "{name:?}: {:?}", f.artifacts());
        assert!(
            f.calls_to("systemctl")
                .iter()
                .all(|c| !c.contains(&"enable".to_string())
                    && !c.contains(&"daemon-reload".to_string())),
            "{name:?}"
        );
    }
}

/// C2: every value written into a unit file is checked for its own syntax.
#[test]
fn cron_add_systemd_refuses_directive_injection() {
    let cases: &[(&str, &str)] = &[
        ("description", "x\nExecStartPre=/bin/true"),
        ("service_user", "root\nGroup=root"),
        ("service_user", "-probe"),
        ("service_working_dir", "relative/dir"),
        ("service_working_dir", "/srv/app\\"),
        ("env_PROBE", "a\nExecStartPre=/bin/true"),
        ("env_BAD-KEY", "x"),
        ("accuracy_sec", "1s\nUser=root"),
        ("random_delay_sec", "soon"),
        ("command", "+/bin/true"),
        ("command", "/bin/true \\"),
    ];
    for (field, value) in cases {
        let f = Fixture::new();
        let mut cmd = f.resh();
        cmd.args([
            "cron://local.add",
            "backend=systemd",
            "unit_scope=user",
            "unit_name=probe-job",
            "schedule=0 4 * * *",
        ]);
        if *field != "command" {
            cmd.arg("command=/bin/true");
        }
        cmd.arg(format!("{field}={value}"));
        let r = run(&mut cmd);
        let expect_field = if field.starts_with("env_") {
            "env"
        } else {
            field
        };
        assert_cron_rejected(&r, expect_field);
        assert!(f.artifacts().is_empty(), "{field}: {:?}", f.artifacts());
    }
}

/// C2: an existing symlink at a unit path is not replaced or followed.
#[test]
fn cron_add_systemd_refuses_symlinked_unit_paths() {
    let f = Fixture::new();
    let unit_dir = f.path().join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir).unwrap();
    let outside = f.path().join("outside.txt");
    std::fs::write(&outside, "unchanged").unwrap();
    std::os::unix::fs::symlink(&outside, unit_dir.join("probe-job.service")).unwrap();
    let r = run(f.resh().args([
        "cron://local.add",
        "backend=systemd",
        "unit_scope=user",
        "unit_name=probe-job",
        "schedule=0 4 * * *",
        "command=/bin/true",
    ]));
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_eq!(r.json["ok"], false);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "unchanged");
    assert!(!unit_dir.join("probe-job.timer").exists());
    assert!(
        f.calls_to("systemctl")
            .iter()
            .all(|c| !c.contains(&"enable".to_string()))
    );
}

/// Legitimate systemd jobs are still created, with values serialized so they
/// mean exactly what was passed.
#[test]
fn cron_add_systemd_creates_units_in_a_disposable_home() {
    let f = Fixture::new();
    let r = run(f.resh().args([
        "cron://local.add",
        "backend=systemd",
        "unit_scope=user",
        "unit_name=nightly-report",
        "schedule=0 4 * * *",
        "command=/opt/report.sh --day %d",
        "description=Nightly report (100%)",
        "service_working_dir=/srv/app",
        "service_user=reporter",
        r#"env_GREETING=say "hi" \ bye"#,
        "accuracy_sec=1min",
    ]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["ok"], true);
    let unit_dir = f.path().join(".config/systemd/user");
    let service = std::fs::read_to_string(unit_dir.join("nightly-report.service")).unwrap();
    assert!(
        service.contains("Description=Nightly report (100%%)\n"),
        "{service}"
    );
    assert!(service.contains("WorkingDirectory=/srv/app\n"), "{service}");
    assert!(service.contains("User=reporter\n"), "{service}");
    assert!(
        service.contains("Environment=\"GREETING=say \\\"hi\\\" \\\\ bye\"\n"),
        "{service}"
    );
    assert!(
        service.contains("ExecStart=/opt/report.sh --day %%d\n"),
        "{service}"
    );
    let timer = std::fs::read_to_string(unit_dir.join("nightly-report.timer")).unwrap();
    assert!(timer.contains("AccuracySec=1min\n"), "{timer}");
    let calls = f.calls_to("systemctl");
    assert!(calls.contains(&s(&["systemctl", "--user", "daemon-reload"])));
    assert!(calls.contains(&s(&[
        "systemctl",
        "--user",
        "enable",
        "--now",
        "--",
        "nightly-report.timer"
    ])));
}

#[test]
fn cron_add_cron_backend_still_writes_valid_jobs() {
    let f = Fixture::new();
    let r = run(f.resh().args([
        "cron://local.add",
        "backend=cron",
        "schedule=30 3 * * 1-5",
        "command=/opt/rotate.sh >/dev/null 2>&1",
        "id=rotate",
    ]));
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(
        std::fs::read_to_string(f.crontab_file()).unwrap(),
        "# job-id=rotate\n30 3 * * 1-5 /opt/rotate.sh >/dev/null 2>&1\n"
    );
}

/// `cron disable cron_file=` rewrites the file it names, so it gets the same
/// destination check as `add`.
#[test]
fn cron_disable_refuses_other_files() {
    let f = Fixture::new();
    let outside = f.path().join("notes.txt");
    let content = "# job-id=x\n0 4 * * * root /bin/true\n";
    std::fs::write(&outside, content).unwrap();
    let r = run(f.resh().args([
        "cron://local.disable",
        "backend=cron",
        "id=x",
        &format!("cron_file={}", outside.display()),
    ]));
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), content);
}

// ---------------------------------------------------------------------------
// ssh://
// ---------------------------------------------------------------------------

fn ssh_exec(f: &Fixture, extra: &[&str]) -> Run {
    run(f.resh().arg("ssh://probe@ssh.invalid.exec").args(extra))
}

/// S1: each command_args element reaches the remote command as exactly one
/// argument, whatever shell characters it contains (POSIX login shell).
#[test]
fn ssh_exec_preserves_argument_boundaries() {
    for mode in ["none", "sh"] {
        let f = Fixture::new();
        let r = ssh_exec(
            &f,
            &[
                "command=printf '<%s>'",
                "command_args=$(touch resh-probe-sentinel),a;b,*,it's,a b,`id`",
                &format!("shell_mode={mode}"),
            ],
        );
        assert_eq!(r.code, 0, "{mode}: {}", r.stdout);
        assert_eq!(
            r.json["result"]["stdout"], "<$(touch resh-probe-sentinel)><a;b><*><it's><a b><`id`>",
            "{mode}"
        );
        assert!(
            !f.remote().join("resh-probe-sentinel").exists(),
            "{mode}: argument was executed by the remote shell"
        );
    }
}

/// The reported command is the exact string sent to the remote shell.
#[test]
fn ssh_exec_reports_the_exact_remote_command() {
    let f = Fixture::new();
    let r = ssh_exec(
        &f,
        &[
            "command=ls",
            "command_args=-l,a b",
            "cwd=/srv/my app",
            "dry_run=true",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["command"]["raw"], "cd '/srv/my app' && ls -l 'a b'");
    assert!(f.calls().is_empty());
}

/// cmd.exe and PowerShell quoting cannot be made exact through ssh, so any
/// argument or cwd that would need quoting is refused, as is an unknown mode.
#[test]
fn ssh_exec_refuses_ambiguous_windows_arguments_and_unknown_modes() {
    let cases: &[&[&str]] = &[
        &["shell_mode=cmd", "command=dir", "command_args=a b"],
        &["shell_mode=cmd", "command=dir", "command_args=a&b"],
        &[
            "shell_mode=powershell",
            "command=Get-Item",
            "command_args=$x",
        ],
        &["shell_mode=powershell", "command=Get-Item", "cwd=C:\\a'b"],
        &["shell_mode=zsh", "command=ls"],
        &["shell_mode=sh", "command=ls", "command_args=a\nb"],
    ];
    for extra in cases {
        for dry in [false, true] {
            let f = Fixture::new();
            let mut a: Vec<&str> = extra.to_vec();
            if dry {
                a.push("dry_run=true");
            }
            let r = ssh_exec(&f, &a);
            assert_eq!(r.code, 1, "{extra:?}: {}", r.stdout);
            assert_eq!(r.json["ok"], false, "{extra:?}");
            assert!(f.calls().is_empty(), "{extra:?}: ssh ran");
        }
    }
    let f = Fixture::new();
    let r = ssh_exec(
        &f,
        &[
            "shell_mode=cmd",
            "command=dir",
            "command_args=C:\\Logs,/b",
            "dry_run=true",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["command"]["raw"], "cmd /c \"dir C:\\Logs /b\"");
}

/// A refused exec reports the dry_run mode the caller asked for and says
/// separately that nothing ran; the refused argument is not echoed back.
#[test]
fn ssh_exec_refusals_report_the_requested_mode() {
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "shell_mode=cmd",
                "command=dir",
                "command_args=resh probe marker",
            ],
            "COMMAND_ERROR",
        ),
        (&["shell_mode=zsh", "command=ls"], "PARSE_ERROR"),
    ];
    for (extra, code) in cases {
        for dry in [true, false] {
            let f = Fixture::new();
            let mut a: Vec<&str> = extra.to_vec();
            a.push(if dry { "dry_run=true" } else { "dry_run=false" });
            let r = ssh_exec(&f, &a);
            assert_eq!(r.code, 1, "{extra:?}: {}", r.stdout);
            assert_eq!(r.json["ok"], false, "{extra:?}");
            assert_eq!(r.json["dry_run"], dry, "{extra:?}: {}", r.stdout);
            assert_eq!(r.json["result"]["executed"], false, "{extra:?}");
            assert_eq!(r.json["error"]["code"], *code, "{extra:?}");
            assert!(r.json.get("command").is_none(), "{extra:?}");
            assert!(!r.stdout.contains("resh probe marker"), "{}", r.stdout);
            assert!(f.calls().is_empty(), "{extra:?}: ssh ran");
        }
    }
}

/// When ssh itself fails, the envelope is a failure in normal mode with a
/// non-zero exit code, and it does not claim the remote command completed.
#[test]
fn ssh_exec_subprocess_failures_are_reported() {
    // ssh starts but exits 255 (the fake cannot reach its "remote" directory).
    let f = Fixture::new();
    std::fs::remove_dir(f.remote()).unwrap();
    let r = ssh_exec(&f, &["command=true"]);
    assert_eq!(r.code, 255, "{}", r.stdout);
    assert_eq!(r.json["ok"], false);
    assert_eq!(r.json["dry_run"], false);
    assert_eq!(r.json["error"]["code"], "SSH_FAILED");
    assert_eq!(r.json["result"]["exit_code"], 255);
    assert_eq!(f.calls().len(), 1);

    // ssh cannot be started at all: nothing ran, and no result is reported.
    let f = Fixture::new();
    std::fs::remove_file(f.bin().join("ssh")).unwrap();
    let r = run(f
        .resh()
        .env("PATH", f.bin())
        .args(["ssh://probe@ssh.invalid.exec", "command=true"]));
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert_eq!(r.json["dry_run"], false);
    assert!(r.json["error"]["code"].is_string(), "{}", r.stdout);
    assert!(r.json.get("result").is_none(), "{}", r.stdout);
}

// ---------------------------------------------------------------------------
// cert://
// ---------------------------------------------------------------------------

fn openssl(dir: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("the openssl command-line tool is required for this test")
}

/// `signature_algorithm=ecdsa_sha512` with a P-384 key produces an ECDSA
/// signature over a SHA-512 digest. The key is generated and the signature
/// verified by OpenSSL, independently of the Rust crypto crates.
#[test]
fn cert_sign_p384_sha512_verifies_with_openssl() {
    let f = Fixture::new();
    let dir = f.path();
    std::fs::write(dir.join("data.bin"), b"resh stage 6b signing fixture\n").unwrap();
    assert!(
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-384",
                "-out",
                "key.pem"
            ]
        )
        .status
        .success()
    );
    assert!(
        openssl(
            dir,
            &["pkey", "-in", "key.pem", "-pubout", "-out", "pub.pem"]
        )
        .status
        .success()
    );

    for (alg, digest, other) in [
        ("ecdsa_sha512", "-sha512", "-sha384"),
        ("ecdsa_sha384", "-sha384", "-sha512"),
    ] {
        let sig = format!("{alg}.der");
        let r = run(f.resh().args([
            "cert://./fixture.sign",
            "signer_key=key.pem",
            "data_source=data.bin",
            &format!("signature_algorithm={alg}"),
            "signature_encoding=der",
            &format!("signature_output_path={sig}"),
        ]));
        assert_eq!(r.code, 0, "{alg}: {}", r.stdout);
        let verify = |d: &str| {
            openssl(
                dir,
                &[
                    "dgst",
                    d,
                    "-verify",
                    "pub.pem",
                    "-signature",
                    &sig,
                    "data.bin",
                ],
            )
            .status
            .success()
        };
        assert!(
            verify(digest),
            "{alg}: OpenSSL rejected the {digest} signature"
        );
        assert!(!verify(other), "{alg}: signature also verifies as {other}");
    }

    // P-256 cannot be combined with ecdsa_sha512: refused, nothing written.
    assert!(
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "p256.pem"
            ]
        )
        .status
        .success()
    );
    let r = run(f.resh().args([
        "cert://./fixture.sign",
        "signer_key=p256.pem",
        "data_source=data.bin",
        "signature_algorithm=ecdsa_sha512",
        "signature_output_path=p256.sig",
    ]));
    assert_ne!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["ok"], false, "{}", r.stdout);
    assert!(!dir.join("p256.sig").exists());
}
