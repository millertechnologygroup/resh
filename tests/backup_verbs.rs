//! Integration tests for `backup://`: every verb run through the built
//! `resh` binary in a temporary directory, with HOME and PATH pointed inside
//! it. PATH holds recording fakes for restic and borg and links to the
//! host's real tar, gzip and rsync, so local repositories are real and
//! nothing outside the temporary directory is read or written. Help output
//! is checked against golden files, and every help example runs.
//!
//! Real restic and borg are exercised in containers:
//! tests/backup_e2e_docker.rs.

mod common;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VERBS: &[&str] = &["create", "list", "restore", "verify", "prune", "schedule"];

/// restic: answers each subcommand with output of the real shape.
const FAKE_RESTIC: &str = r#"case "$1" in
  backup) echo '{"message_type":"summary","data_added":10,"total_bytes_processed":20,"snapshot_id":"4f2a9c1e0011"}' ;;
  snapshots) echo '[{"short_id":"4f2a9c1e","time":"2026-10-16T02:00:04.118372+00:00","hostname":"web01","tags":["daily"],"paths":["/etc"]}]' ;;
  check) echo 'no errors were found' ;;
  restore) echo '{"message_type":"status","percent_done":0.5}'
     echo '{"message_type":"summary","files_restored":12,"bytes_restored":3172}' ;;
  forget) echo '[{"keep":[{}],"remove":[{},{},{}]}]' ;;
esac
[ -n "$FAKE_SLEEP" ] && /bin/sleep "$FAKE_SLEEP"
exit "${FAKE_EXIT:-0}""#;

const FAKE_BORG: &str = r#"case "$1" in
  prune) printf 'Would prune:     a1\nWould prune:     a2\nWould prune:     a3\n' >&2 ;;
  list) echo '{"archives":[]}' ;;
esac
exit "${FAKE_EXIT:-0}""#;

/// `crontab -l` prints $HOME/crontab ("no crontab" exit 1 when missing),
/// `crontab -` replaces it.
const FAKE_CRONTAB: &str = r#"#!/bin/sh
[ "$1" = "-u" ] && shift 2
case "$1" in
  -l) [ -f "$HOME/crontab" ] || { echo "no crontab for tester" >&2; exit 1; }
      /bin/cat "$HOME/crontab" ;;
  -) /bin/cat > "$HOME/crontab" ;;
  *) exit 1 ;;
esac
"#;

struct Fixture {
    tmp: TempDir,
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("{e}: {} {}", self.stdout, self.stderr))
    }

    #[track_caller]
    fn ok(&self) -> Value {
        assert_eq!(self.code, 0, "{} {}", self.stdout, self.stderr);
        let v = self.json();
        assert_eq!(v["ok"], true);
        v
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> Value {
        assert_eq!(self.code, exit, "{} {}", self.stdout, self.stderr);
        let v = self.json();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], code, "{v}");
        assert!(
            self.stderr
                .lines()
                .any(|l| l.starts_with(&format!("Error: [{code}] "))),
            "{}",
            self.stderr
        );
        v
    }
}

impl Fixture {
    fn new() -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        std::fs::create_dir(f.bin()).unwrap();
        f.fake("restic", FAKE_RESTIC);
        f.fake("borg", FAKE_BORG);
        // cron add's tools: a crontab kept in $HOME/crontab (not recording
        // calls) and no systemctl on PATH, so `schedule` uses the crontab
        // and nothing on the host is changed.
        common::write_executable(&f.bin().join("crontab"), FAKE_CRONTAB);
        for tool in ["tar", "gzip", "rsync"] {
            if let Ok(p) = which::which(tool) {
                std::os::unix::fs::symlink(p, f.bin().join(tool)).unwrap();
            }
        }
        std::fs::write(f.path().join("pw"), "fixture-only\n").unwrap();
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn fake(&self, name: &str, body: &str) {
        let script = format!(
            "#!/bin/sh\n{{ printf '%s\\037' {name}; for a in \"$@\"; do printf '%s\\037' \"$a\"; done; \
             printf '\\n'; }} >> \"$RESH_TEST_LOG\"\n{body}\n"
        );
        common::write_executable(&self.bin().join(name), &script);
    }

    fn calls(&self) -> Vec<Vec<String>> {
        std::fs::read_to_string(self.path().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                l.split('\u{1f}')
                    .filter(|a| !a.is_empty())
                    .map(String::from)
                    .collect()
            })
            .collect()
    }

    fn cmd(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_resh"));
        cmd.current_dir(self.path())
            .env_clear()
            .env("PATH", self.bin())
            .env("HOME", self.path())
            .env("USER", "tester")
            .env("RESH_TEST_LOG", self.path().join("calls.log"))
            .env("RESTIC_PASSWORD_FILE", self.path().join("pw"))
            .env("BORG_PASSPHRASE", "fixture-only")
            .env("TZ", "UTC");
        cmd
    }

    fn run(&self, words: &[&str]) -> Run {
        self.run_env(words, &[])
    }

    fn run_env(&self, words: &[&str], env: &[(&str, &str)]) -> Run {
        let mut cmd = self.cmd();
        cmd.args(words);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// data/a.conf, data/b.txt, data/sub/c.conf.
    fn source(&self) {
        let d = self.path().join("data");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("a.conf"), "alpha").unwrap();
        std::fs::write(d.join("b.txt"), "bravo!").unwrap();
        std::fs::write(d.join("sub/c.conf"), "charlie").unwrap();
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// ===========================================================================
// Help
// ===========================================================================

fn golden(verb: &str) -> &'static str {
    match verb {
        "create" => include_str!("golden/backup_create_help.txt"),
        "list" => include_str!("golden/backup_list_help.txt"),
        "restore" => include_str!("golden/backup_restore_help.txt"),
        "verify" => include_str!("golden/backup_verify_help.txt"),
        "prune" => include_str!("golden/backup_prune_help.txt"),
        "schedule" => include_str!("golden/backup_schedule_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let f = Fixture::new();
    let want = include_str!("golden/backup_help.txt");
    for args in [
        &["backup", "--help"][..],
        &["backup", "-h"][..],
        &["backup", "help"][..],
        &["help", "backup"][..],
        &["backup://--help"][..],
    ] {
        let r = f.run(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden_in_every_form() {
    let f = Fixture::new();
    for verb in VERBS {
        let stage = format!("backup://db.{verb}");
        for args in [
            vec!["backup", verb, "--help"],
            vec!["backup", verb, "-h"],
            vec!["help", "backup", verb],
            vec![stage.as_str(), "--help"],
        ] {
            let r = f.run(&args);
            assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(
            golden(verb).lines().all(|l| l.len() <= 80),
            "{verb}: a help line is longer than 80 columns"
        );
    }
    let r = f.run(&["backup", "lst", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("list"), "{}", r.stderr);
}

/// Every help example runs against the fixture and gives output of the
/// documented shape.
#[test]
fn help_examples_run() {
    for verb in VERBS {
        let f = Fixture::new();
        let text = golden(verb);
        let example = text
            .lines()
            .skip_while(|l| *l != "Example:")
            .nth(1)
            .unwrap()
            .trim();
        let words = shell_words(example);
        assert_eq!(words[0], "resh");
        let words: Vec<&str> = words[1..].iter().map(String::as_str).collect();
        let json = f.run(&words).ok();
        let sample: Value = {
            let start = text.find("Example Output:").unwrap();
            let body: String = text[start..]
                .lines()
                .skip(1)
                .take_while(|l| !l.trim_start().starts_with("Shown"))
                .collect::<Vec<_>>()
                .join("\n");
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{verb}: {e}"))
        };
        let keys = |v: &Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(keys(&json), keys(&sample), "{verb}");
        assert_eq!(keys(&json["result"]), keys(&sample["result"]), "{verb}");
        // Generated snapshot names carry the current time.
        let digits = |v: &Value| v.to_string().replace(|c: char| c.is_ascii_digit(), "0");
        assert_eq!(
            digits(&json["backend"]["command"]),
            digits(&sample["backend"]["command"]),
            "{verb}"
        );
        assert_eq!(json["backend"]["id"], sample["backend"]["id"], "{verb}");
    }
}

/// Minimal POSIX word splitting for the help examples (single quotes).
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_word = false;
    for c in s.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                in_word = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

// ===========================================================================
// Verbs with real tar and rsync
// ===========================================================================

#[test]
fn tar_create_list_verify_restore_prune() {
    let f = Fixture::new();
    f.source();
    let base = ["backend=tar", "repo_url=repo"];
    let create = |extra: &[&str]| {
        let mut w = vec!["backup://db.create", "src=data"];
        w.extend(base);
        w.extend(extra);
        f.run(&w)
    };
    create(&["dry_run"]).ok();
    assert!(!f.path().join("repo").exists());
    let id = create(&["label=nightly"]).ok()["result"]["snapshot"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    create(&[]).ok();
    assert_eq!(mode(&f.path().join("repo")), 0o700);
    assert_eq!(mode(&f.path().join(format!("repo/{id}.tar.gz"))), 0o600);

    let v = f.run(&["backup://db.list", base[0], base[1]]).ok();
    assert_eq!(v["result"]["total_count"], 2);
    let v = f
        .run(&["backup://db.verify", base[0], base[1], "mode=thorough"])
        .ok();
    assert_eq!(v["result"]["verification"]["success"], true);

    let snap = format!("snapshot_id={id}");
    let v = f
        .run(&[
            "backup://db.restore",
            base[0],
            base[1],
            &snap,
            "dest=out",
            "include=data/*.conf",
        ])
        .ok();
    assert_eq!(v["result"]["restored"]["files_restored"], 1);
    assert_eq!(
        std::fs::read_to_string(f.path().join("out/data/a.conf")).unwrap(),
        "alpha"
    );
    assert!(!f.path().join("out/data/sub").exists());
    assert_eq!(mode(&f.path().join("out")), 0o700);

    let v = f
        .run(&[
            "backup://db.prune",
            base[0],
            base[1],
            "keep_daily=1",
            "dry_run=true",
        ])
        .ok();
    assert_eq!(v["result"]["would_prune"]["snapshots_removed"], 1);
    let v = f
        .run(&["backup://db.prune", base[0], base[1], "keep_daily=1"])
        .ok();
    assert_eq!(v["result"]["pruned"]["snapshots_removed"], 1);
    assert_eq!(std::fs::read_dir(f.path().join("repo")).unwrap().count(), 1);
    assert!(f.calls().is_empty(), "restic/borg never ran");
}

#[test]
fn rsync_create_and_restore() {
    if which::which("rsync").is_err() {
        return;
    }
    let f = Fixture::new();
    f.source();
    let v = f
        .run(&[
            "backup://db.create",
            "src=data",
            "backend=rsync",
            "repo_url=repo",
        ])
        .ok();
    let id = v["result"]["snapshot"]["id"].as_str().unwrap().to_string();
    let snap = format!("snapshot_id={id}");
    let v = f
        .run(&[
            "backup://db.restore",
            "backend=rsync",
            "repo_url=repo",
            &snap,
            "dest=out",
            "exclude=*.txt",
        ])
        .ok();
    assert_eq!(v["result"]["restored"]["files_restored"], 2);
    assert!(!f.path().join("out/data/b.txt").exists());
    let v = f
        .run(&[
            "backup://db.verify",
            "backend=rsync",
            "repo_url=repo",
            &snap,
        ])
        .ok();
    assert_eq!(v["result"]["verification"]["files_checked"], 3);
}

// ===========================================================================
// restic and borg through the fakes
// ===========================================================================

#[test]
fn restic_and_borg_commands() {
    let f = Fixture::new();
    let r = f.run(&[
        "backup://db.create",
        "src=/etc",
        "backend=restic",
        "repo_url=/srv/restic",
        "tag=daily",
    ]);
    assert_eq!(r.ok()["result"]["snapshot"]["id"], "4f2a9c1e0011");
    f.run(&[
        "backup://db.verify",
        "backend=borg",
        "repo_url=/srv/borg",
        "snapshot_id=a1",
    ])
    .ok();
    f.run(&["backup://db.list", "backend=borg", "repo_url=/srv/borg"])
        .ok();
    assert_eq!(
        f.calls(),
        vec![
            s(&["restic", "backup", "--tag=daily", "--json", "--", "/etc"]),
            s(&["borg", "check", "--", "/srv/borg::a1"]),
            s(&["borg", "list", "--json", "--", "/srv/borg"]),
        ]
    );
}

// ===========================================================================
// Errors and exit codes
// ===========================================================================

#[test]
fn usage_errors_exit_2_and_run_nothing() {
    let f = Fixture::new();
    let cases: &[&[&str]] = &[
        &[
            "backup://db.list",
            "backend=tar",
            "repo_url=r",
            "tmeout_ms=5",
        ],
        &[
            "backup://db.list",
            "backend=tar",
            "repo_url=r",
            "timeout_ms=soon",
        ],
        &["backup://db.list", "backend=tarr", "repo_url=r"],
        &["backup://db.list", "backend=tar"],
        &[
            "backup://db.list",
            "backend=tar",
            "repo_url=r",
            "password=x",
        ],
        &["backup://db.create", "backend=tar", "repo_url=r"],
        &["backup://db.create", "backend=tar", "repo_url=r", "src=-x"],
        &[
            "backup://db.create",
            "backend=tar",
            "repo_url=r",
            "src=data",
            "tag=t",
        ],
        &[
            "backup://db.prune",
            "backend=tar",
            "repo_url=r",
            "keep_daily=0",
        ],
        &[
            "backup://db.verify",
            "backend=tar",
            "repo_url=r",
            "mode=fast",
        ],
        &[
            "backup://db.verify",
            "backend=restic",
            "repo_url=r",
            "snapshot_id=x",
        ],
        &[
            "backup://db.restore",
            "backend=tar",
            "repo_url=r",
            "snapshot_id=x",
        ],
        &[
            "backup://db.schedule",
            "when=@daily",
            "src=/etc",
            "backend=tar",
            "repo_url=r",
            "timeout_ms=0",
        ],
        &[
            "backup://db.schedule",
            "when=every night",
            "src=/etc",
            "backend=tar",
            "repo_url=r",
        ],
        &[
            "backup://db.list",
            "backend=tar",
            "repo_url=r",
            "json_pretty=maybe",
        ],
    ];
    for words in cases {
        let r = f.run(words);
        r.fails(2, "backup.invalid_argument");
    }
    let r = f.run(&[
        "backup://db.list",
        "backend=tar",
        "repo_url=r",
        "tmeout_ms=5",
    ]);
    assert!(
        r.stderr.contains("did you mean timeout_ms?"),
        "{}",
        r.stderr
    );
    let r = f.run(&["backup://db.lst"]);
    r.fails(2, "backup.unknown_verb");
    // Without any password source, restic refuses before running.
    let mut cmd = f.cmd();
    cmd.env_remove("RESTIC_PASSWORD_FILE").args([
        "backup://db.list",
        "backend=restic",
        "repo_url=/srv/restic",
    ]);
    let out = cmd.output().unwrap();
    let r = Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    r.fails(2, "backup.missing_password");
    // restore/list/verify have no dry run; core refuses it before the handle.
    let r = f.run(&[
        "backup://db.list",
        "backend=tar",
        "repo_url=r",
        "dry_run=true",
    ]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.contains("does not support dry_run"),
        "{}",
        r.stderr
    );
    assert!(f.calls().is_empty());
    assert!(!f.path().join("r").exists());
}

#[test]
fn operation_failures_exit_1() {
    let f = Fixture::new();
    let r = f.run_env(
        &["backup://db.list", "backend=restic", "repo_url=/srv/restic"],
        &[("FAKE_EXIT", "3")],
    );
    let v = r.fails(1, "backup.backend_failed");
    assert_eq!(v["error"]["details"]["exit_code"], 3);
    let r = f.run(&["backup://db.list", "backend=tar", "repo_url=missing"]);
    r.fails(1, "backup.io");
    let r = f.run(&[
        "backup://db.list",
        "backend=restic",
        "repo_url=/srv/restic",
        "password_file=nope",
    ]);
    r.fails(1, "backup.password_file_unreadable");
    std::fs::remove_file(f.bin().join("borg")).unwrap();
    let r = f.run(&["backup://db.list", "backend=borg", "repo_url=/srv/borg"]);
    r.fails(1, "backup.backend_not_found");
    std::fs::create_dir(f.path().join("empty")).unwrap();
    let r = f.run(&["backup://db.verify", "backend=tar", "repo_url=empty"]);
    r.fails(1, "backup.verify_failed");
    let r = f.run(&[
        "backup://db.verify",
        "backend=tar",
        "repo_url=empty",
        "snapshot_id=x",
    ]);
    r.fails(1, "backup.snapshot_not_found");
}

#[test]
fn a_timeout_stops_the_backend_and_exits_124() {
    let f = Fixture::new();
    let start = Instant::now();
    let r = f.run_env(
        &[
            "backup://db.list",
            "backend=restic",
            "repo_url=/srv/restic",
            "timeout_ms=300",
        ],
        &[("FAKE_SLEEP", "30")],
    );
    assert!(start.elapsed() < Duration::from_secs(15));
    assert_eq!(r.code, 124, "{} {}", r.stdout, r.stderr);
    assert_eq!(r.json()["error"]["code"], "backup.timeout");
    assert!(
        r.stderr
            .contains("Error: [backup.timeout] outcome unknown: "),
        "{}",
        r.stderr
    );
}

#[test]
fn plain_password_warns_and_never_reaches_argv() {
    let f = Fixture::new();
    let r = f.run(&[
        "backup://db.list",
        "backend=restic",
        "repo_url=/srv/restic",
        "password=hunter2",
    ]);
    let v = r.ok();
    assert!(r.stderr.contains("Warning: password= puts"), "{}", r.stderr);
    assert!(!r.stdout.contains("hunter2"));
    assert_eq!(
        v["backend"]["env_redacted"]["RESTIC_PASSWORD"],
        "***REDACTED***"
    );
    assert!(!f.calls().concat().iter().any(|a| a.contains("hunter2")));
}

#[test]
fn schedule_installs_a_crontab_line_through_cron() {
    let f = Fixture::new();
    let crontab = f.path().join("crontab");
    let base = [
        "backup://db.schedule",
        "when=30 1 * * *",
        "src=/etc",
        "backend=restic",
        "repo_url=/srv/restic",
        "password_file=/root/.restic-pass",
    ];
    // Dry run: cron add's preview, nothing written.
    let mut words = base.to_vec();
    words.push("dry_run=true");
    let v = f.run(&words).ok();
    assert_eq!(v["result"]["schedule"]["installed"], false);
    assert_eq!(v["result"]["schedule"]["scheduler"], "cron");
    assert!(
        v["result"]["schedule"]["preview"]["cron_line"]
            .as_str()
            .unwrap()
            .contains("30 1 * * * "),
        "{v}"
    );
    assert!(!crontab.exists());

    let v = f.run(&base).ok();
    let sch = &v["result"]["schedule"];
    assert_eq!(sch["installed"], true);
    assert_eq!(sch["id"], "resh-backup-db");
    let exe = env!("CARGO_BIN_EXE_resh");
    let line = std::fs::read_to_string(&crontab).unwrap();
    assert!(
        line.contains(&format!(
            "30 1 * * * {exe} backup://db.create src=/etc backend=restic repo_url=/srv/restic password_file=/root/.restic-pass"
        )),
        "{line}"
    );
    assert!(line.contains("job-id=resh-backup-db"), "{line}");
    // The same schedule again changes nothing.
    let v = f.run(&base).ok();
    assert_eq!(v["result"]["schedule"]["duplicate"], true);
    assert_eq!(std::fs::read_to_string(&crontab).unwrap(), line);

    // remove_command removes it.
    let rm: Vec<String> = sch["remove_command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    assert_eq!(rm[0], "resh");
    let rm: Vec<&str> = rm[1..].iter().map(String::as_str).collect();
    let r = f.run(&rm);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    assert!(
        !std::fs::read_to_string(&crontab)
            .unwrap()
            .contains("backup://db.create")
    );

    // enabled=false installs the line commented out.
    let v = f
        .run(&[
            "backup://db.schedule",
            "when=@daily",
            "src=/etc",
            "backend=tar",
            "repo_url=/srv/b",
            "enabled=false",
        ])
        .ok();
    assert_eq!(v["result"]["schedule"]["enabled"], false);
    let line = std::fs::read_to_string(&crontab).unwrap();
    assert!(
        line.contains(&format!("# @daily {exe} backup://db.create")),
        "{line}"
    );

    // Scheduler unavailable: cron's refusal, as backup.schedule_failed.
    let r = f.run(&[
        "backup://db.schedule",
        "when=@daily",
        "src=/etc",
        "backend=tar",
        "repo_url=/srv/b",
        "scheduler=systemd",
    ]);
    let v = r.fails(1, "backup.schedule_failed");
    assert!(v["error"]["details"]["cron_error"]["code"].is_string());
    assert!(f.calls().is_empty(), "no backend ran");
}

#[test]
fn progress_events_are_streamed_before_the_envelope() {
    let f = Fixture::new();
    let r = f.run(&[
        "backup://db.restore",
        "backend=restic",
        "repo_url=/srv/restic",
        "snapshot_id=latest",
        "dest=out",
        "progress=true",
    ]);
    assert_eq!(r.code, 0, "{} {}", r.stdout, r.stderr);
    let lines: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{}", r.stdout);
    assert_eq!(lines[0]["event"], "progress");
    assert_eq!(lines[0]["progress"]["percent_done"], 0.5);
    assert_eq!(lines[1]["result"]["restored"]["bytes_restored"], 3172);
    let r = f.run(&[
        "backup://db.create",
        "backend=tar",
        "repo_url=r",
        "src=/etc",
        "progress=true",
    ]);
    r.fails(2, "backup.invalid_argument");
}
