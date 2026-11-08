//! Every `pkg://` verb run through the real `resh` binary against fake
//! package managers. Each test has its own temporary directory with PATH set
//! to the fake tools plus a few links to basic utilities, so no real package
//! manager can be reached: the fakes keep a package database in text files
//! and record their argv. Real managers are tested in Docker
//! (`tests/pkg_e2e_docker.rs`).

mod common;

use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Appends `CALL\0<program>\0<arg>\0...END\0` to $RESH_TEST_LOG.
const RECORD: &str = r#"{ printf 'CALL\0%s\0' "$(basename "$0")"; for a in "$@"; do printf '%s\0' "$a"; done; printf 'END\0'; } >> "$RESH_TEST_LOG""#;

/// The fake database ($FAKE_PKG_DIR): `installed` and `available` hold
/// `name version` lines (several versions per name in `available`, the last
/// is the candidate), `manual` the manually installed names, `rc` names in
/// dpkg state config-files, `repo_<name>` a repository. `sleep_<cmd>` makes
/// that apt-get command hang (writing its PID to `pid`); `fail_<cmd>` makes
/// it fail with the file's text on stderr.
const COMMON: &str = r#"
D=$FAKE_PKG_DIR
inst() { grep "^$1 " "$D/installed" | cut -d' ' -f2; }
avail() { grep "^$1 " "$D/available" | cut -d' ' -f2; }
setv() { grep -v "^$1 " "$D/installed" > "$D/i.tmp"; [ -n "$2" ] && echo "$1 $2" >> "$D/i.tmp"; mv "$D/i.tmp" "$D/installed"; }
"#;

const FAKE_APT_GET: &str = r#"
cmd=""; pkgs=""
for a in "$@"; do
  case "$a" in
    -*) ;;
    *) if [ -z "$cmd" ]; then cmd=$a; else pkgs="$pkgs $a"; fi ;;
  esac
done
[ -f "$D/sleep_$cmd" ] && { echo $$ > "$D/pid"; sleep 30; }
[ -f "$D/fail_$cmd" ] && { cat "$D/fail_$cmd" >&2; exit 100; }
case "$cmd" in
  install)
    for p in $pkgs; do
      n=${p%%=*}; n=${n%%:*}; v=""
      case "$p" in *=*) v=${p#*=} ;; esac
      all=$(avail "$n")
      [ -n "$all" ] || { echo "E: Unable to locate package $n" >&2; exit 100; }
      if [ -n "$v" ]; then
        echo "$all" | grep -qx "$v" || { echo "E: Version '$v' for '$n' was not found" >&2; exit 100; }
      else
        v=$(echo "$all" | tail -n 1)
      fi
      setv "$n" "$v"
    done ;;
  remove|purge)
    for p in $pkgs; do n=${p%%=*}; n=${n%%:*}; setv "$n" ""; done ;;
  upgrade)
    for n in $(cut -d' ' -f1 "$D/installed"); do
      v=$(avail "$n" | tail -n 1); [ -n "$v" ] && setv "$n" "$v"
    done ;;
esac
exit 0
"#;

const FAKE_DPKG_QUERY: &str = r#"
if [ "$1" = "-W" ] && [ "${2#-f=}" != "$2" ]; then
  v=$(inst "$3")
  [ -n "$v" ] || { echo "dpkg-query: no packages found matching $3" >&2; exit 1; }
  printf 'installed\t%s\n' "$v"; exit 0
fi
while read -r n v; do printf '%s\t%s\tamd64\tinstalled\t100\n' "$n" "$v"; done < "$D/installed"
[ -f "$D/rc" ] && while read -r n; do printf '%s\t1.0\tamd64\tconfig-files\t0\n' "$n"; done < "$D/rc"
exit 0
"#;

const FAKE_APT_CACHE: &str = r#"
sub=$1; shift
case "$sub" in
  policy)
    for n in "$@"; do
      all=$(avail "$n"); iv=$(inst "$n")
      [ -n "$all$iv" ] || continue
      cand=$(echo "$all" | tail -n 1)
      repo=stable/main; [ -f "$D/repo_$n" ] && repo=$(cat "$D/repo_$n")
      printf '%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n' "$n" "${iv:-(none)}" "${cand:-(none)}"
      if [ -n "$cand" ] && [ "$cand" != "$iv" ]; then
        printf '     %s 500\n        500 http://deb.example.org/debian stable-updates/main amd64 Packages\n' "$cand"
      fi
      if [ -n "$iv" ]; then
        printf ' *** %s 500\n        500 http://deb.example.org/debian %s amd64 Packages\n        100 /var/lib/dpkg/status\n' "$iv" "$repo"
      fi
    done ;;
  show)
    all=$(avail "$1"); [ -n "$all" ] || { echo "E: No packages found" >&2; exit 100; }
    printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nHomepage: https://example.org/%s\nDescription: fake %s\n more about %s\nDescription-md5: 0\n' \
      "$1" "$(echo "$all" | tail -n 1)" "$1" "$1" "$1" ;;
  search)
    cut -d' ' -f1 "$D/available" | sort -u | grep -- "$1" | while read -r n; do echo "$n - fake $n"; done ;;
  madison)
    avail "$1" | while read -r v; do
      echo "   $1 | $v | http://deb.example.org/debian stable/main amd64 Packages"
    done ;;
  depends) printf '%s\n  Depends: libfake\n' "$1" ;;
  rdepends) printf '%s\nReverse Depends:\n  fake-user\n' "$1" ;;
esac
exit 0
"#;

const FAKE_APT_MARK: &str = r#"
[ "$1" = "showmanual" ] && cat "$D/manual"
exit 0
"#;

const FAKE_APT: &str = r#"
case "$1" in
  --version) echo "apt 2.8.4 (amd64)" ;;
  list)
    echo "Listing... Done"
    while read -r n iv; do
      cand=$(avail "$n" | tail -n 1)
      if [ -n "$cand" ] && [ "$cand" != "$iv" ]; then
        echo "$n/stable-updates $cand amd64 [upgradable from: $iv]"
      fi
    done < "$D/installed" ;;
esac
exit 0
"#;

const FAKE_DPKG: &str = r#"
case "$1" in
  -s) v=$(inst "$2"); [ -n "$v" ] || exit 1
      printf 'Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n' "$2" "$v" ;;
  -L) printf '/usr/bin/%s\n' "$2" ;;
esac
exit 0
"#;

/// Other managers: present on PATH, with nothing installed.
const FAKE_NONE: &str = "exit 1\n";

/// Basic utilities the fakes use, linked into the fixture's PATH.
const UTILITIES: &[&str] = &[
    "sh", "cat", "grep", "cut", "basename", "sleep", "sort", "tail", "mv", "uname",
];

struct Fixture {
    tmp: TempDir,
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(&self) -> &Value {
        assert_eq!(
            self.code, 0,
            "stdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        &self.json
    }

    fn failed(&self, code: i32, error: &str) -> &Value {
        assert_eq!(
            self.code, code,
            "stdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        assert!(
            self.stderr.contains(&format!("Error: [{error}]")),
            "want {error}: {}",
            self.stderr
        );
        &self.json
    }
}

impl Fixture {
    /// A fixture with the apt tools, and dnf, pacman, apk and brew present
    /// but empty.
    fn new() -> Self {
        Self::with(&["dnf", "yum", "rpm", "pacman", "apk", "brew"])
    }

    /// A fixture with the apt tools plus `others` as empty fakes.
    fn with(others: &[&str]) -> Self {
        let f = Fixture {
            tmp: TempDir::new().unwrap(),
        };
        std::fs::create_dir(f.bin()).unwrap();
        std::fs::create_dir(f.db()).unwrap();
        for (name, body) in [
            ("apt-get", FAKE_APT_GET),
            ("apt-cache", FAKE_APT_CACHE),
            ("apt-mark", FAKE_APT_MARK),
            ("apt", FAKE_APT),
            ("dpkg", FAKE_DPKG),
            ("dpkg-query", FAKE_DPKG_QUERY),
        ] {
            common::write_executable(
                &f.bin().join(name),
                &format!("#!/bin/sh\n{RECORD}\n{COMMON}\n{body}"),
            );
        }
        for name in others {
            common::write_executable(
                &f.bin().join(name),
                &format!("#!/bin/sh\n{RECORD}\n{FAKE_NONE}"),
            );
        }
        for tool in UTILITIES {
            let real = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| Path::new(d).join(tool))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("no {tool}"));
            std::os::unix::fs::symlink(real, f.bin().join(tool)).unwrap();
        }
        for file in ["installed", "available", "manual"] {
            std::fs::write(f.db().join(file), "").unwrap();
        }
        f
    }

    fn path(&self) -> &Path {
        self.tmp.path()
    }
    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }
    fn db(&self) -> PathBuf {
        self.path().join("db")
    }
    fn log(&self) -> PathBuf {
        self.path().join("calls.log")
    }

    fn available(&self, packages: &[(&str, &str)]) -> &Self {
        let text: String = packages.iter().map(|(n, v)| format!("{n} {v}\n")).collect();
        std::fs::write(self.db().join("available"), text).unwrap();
        self
    }

    fn installed(&self, packages: &[(&str, &str)], manual: &[&str]) -> &Self {
        let text: String = packages.iter().map(|(n, v)| format!("{n} {v}\n")).collect();
        std::fs::write(self.db().join("installed"), text).unwrap();
        std::fs::write(self.db().join("manual"), manual.join("\n") + "\n").unwrap();
        self
    }

    fn installed_now(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = std::fs::read_to_string(self.db().join("installed"))
            .unwrap()
            .lines()
            .map(|l| {
                let (n, v) = l.split_once(' ').unwrap();
                (n.to_string(), v.to_string())
            })
            .collect();
        v.sort();
        v
    }

    fn touch(&self, name: &str, text: &str) {
        std::fs::write(self.db().join(name), text).unwrap();
    }

    /// The whole environment of a run: PATH holds only the fakes.
    fn envs(&self) -> Vec<(&'static str, PathBuf)> {
        let dir = self.path();
        vec![
            ("PATH", self.bin()),
            ("HOME", dir.to_path_buf()),
            ("XDG_CONFIG_HOME", dir.join("config")),
            ("XDG_DATA_HOME", dir.join("data")),
            ("XDG_STATE_HOME", dir.join("state")),
            ("XDG_CACHE_HOME", dir.join("cache")),
            ("RESH_TEST_LOG", self.log()),
            ("FAKE_PKG_DIR", self.db()),
        ]
    }

    fn cmd(&self) -> Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(self.path())
            .env_clear()
            .envs(self.envs())
            .timeout(Duration::from_secs(60));
        cmd
    }

    fn run(&self, args: &[&str]) -> Run {
        let out = self.cmd().args(args).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Run {
            code: out.status.code().unwrap_or(-1),
            json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn verb(&self, verb: &str, input: Value) -> Run {
        self.run(&[&format!("pkg://system.{verb}"), &format!("input={input}")])
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

    /// The calls that change something: apt-get other than `update`.
    fn changes(&self) -> Vec<Vec<String>> {
        self.calls_to("apt-get")
    }

    fn clear_log(&self) {
        let _ = std::fs::remove_file(self.log());
    }
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect()
}

// ===========================================================================
// info
// ===========================================================================

#[test]
fn info_reports_installed_and_candidate_versions() {
    let f = Fixture::new();
    f.available(&[("jq", "1.6"), ("jq", "1.7")])
        .installed(&[("jq", "1.6")], &["jq"]);
    let r = f.verb(
        "info",
        json!({"manager": "apt", "packages": ["jq"], "include_dependencies": true,
               "include_reverse_deps": true, "include_files": true}),
    );
    let p = &r.ok()["packages"][0];
    assert_eq!(p["found"], true);
    assert_eq!(p["installed"], true);
    assert_eq!(p["installed_version"], "1.6");
    assert_eq!(p["candidate_version"], "1.7");
    assert_eq!(p["homepage"], "https://example.org/jq");
    // The repository as snapshot records it, and its URL.
    assert_eq!(p["repository"], "stable/main");
    assert_eq!(p["repository_url"], "http://deb.example.org/debian");
    assert_eq!(p["dependencies"]["runtime"], json!(["libfake"]));
    assert_eq!(p["reverse_dependencies"], json!(["fake-user"]));
    assert_eq!(p["files"], json!(["/usr/bin/jq"]));
    assert!(f.changes().is_empty());
}

#[test]
fn info_of_an_unknown_package_exits_1_with_the_result() {
    let f = Fixture::new();
    f.available(&[("jq", "1.7")]);
    let r = f.verb(
        "info",
        json!({"manager": "apt", "packages": ["jq", "nope"]}),
    );
    let json = r.failed(1, "pkg.not_found");
    assert_eq!(json["packages"][0]["found"], true);
    assert_eq!(json["packages"][1]["found"], false);
    assert!(r.stderr.contains("not found: nope"), "{}", r.stderr);
}

// ===========================================================================
// search
// ===========================================================================

#[test]
fn search_filters_sorts_and_paginates() {
    let f = Fixture::new();
    f.available(&[
        ("jq", "1.7"),
        ("jq-doc", "1.7"),
        ("libjq1", "1.7"),
        ("curl", "8"),
    ])
    .installed(&[("jq", "1.7")], &["jq"]);
    let r = f.verb("search", json!({"manager": "apt", "query": "jq"}));
    let json = r.ok();
    assert_eq!(json["total_matches"], 3);
    assert_eq!(json["results"][0]["name"], "jq");
    assert_eq!(json["results"][0]["installed"], true);
    assert_eq!(json["results"][0]["version"], "1.7");

    let r = f.verb(
        "search",
        json!({"manager": "apt", "query": "jq", "limit": 1, "offset": 1}),
    );
    assert_eq!(r.ok()["results"].as_array().unwrap().len(), 1);
    let r = f.verb(
        "search",
        json!({"manager": "apt", "query": "jq", "exact": true, "search_in": ["name"]}),
    );
    assert_eq!(names(&r.ok()["results"]), ["jq"]);
}

// ===========================================================================
// list_installed
// ===========================================================================

#[test]
fn list_installed_filters_and_leaves_out_removed_packages() {
    let f = Fixture::new();
    f.installed(
        &[("curl", "8.5"), ("jq", "1.7"), ("libjq1", "1.7")],
        &["jq"],
    );
    f.touch("rc", "oldpkg\n");
    let r = f.verb(
        "list_installed",
        json!({"manager": "apt", "include_install_reason": true, "include_size": true}),
    );
    let json = r.ok();
    assert_eq!(json["total_installed"], 3, "config-files package listed");
    assert_eq!(names(&json["results"]), ["curl", "jq", "libjq1"]);
    assert_eq!(json["results"][1]["install_reason"], "manual");
    assert_eq!(json["results"][0]["install_reason"], "dependency");
    assert_eq!(json["results"][0]["installed_size_bytes"], 102400);
    assert_eq!(json["results"][0]["repository"], "stable/main");

    let r = f.verb(
        "list_installed",
        json!({"manager": "apt", "filter": "jq", "limit": 1, "offset": 1, "include_repo": false}),
    );
    let json = r.ok();
    assert_eq!(json["total_installed"], 2);
    assert_eq!(names(&json["results"]), ["libjq1"]);
    assert_eq!(json["results"][0]["repository"], Value::Null);
    let r = f.verb("list_installed", json!({"manager": "apt", "prefix": "LIB"}));
    assert_eq!(names(&r.ok()["results"]), ["libjq1"]);
    // One batched apt-cache policy per listing that includes repositories.
    assert_eq!(
        f.calls_to("apt-cache").len(),
        2,
        "one batched call per listing"
    );
}

// ===========================================================================
// snapshot and restore
// ===========================================================================

#[test]
fn snapshot_formats_scope_and_exclusions() {
    let f = Fixture::new();
    f.installed(
        &[("curl", "8.5"), ("jq", "1.7"), ("libjq1", "1.7")],
        &["jq", "curl"],
    );
    f.touch("repo_jq", "noble/main");
    let r = f.verb("snapshot", json!({"manager": "apt"}));
    let json = r.ok();
    assert_eq!(json["parsed"]["packages_count"], 3);
    let lock: Value = serde_json::from_str(json["lockfile"].as_str().unwrap()).unwrap();
    assert_eq!(lock["manager"]["name"], "apt");
    assert_eq!(lock["manager"]["version"], "apt 2.8.4 (amd64)");
    let jq = &lock["packages"][1];
    assert_eq!(jq["name"], "jq");
    assert_eq!(jq["version"], "1.7");
    assert_eq!(jq["repository"], "noble/main");
    assert_eq!(jq["install_reason"], "manual");

    let r = f.verb(
        "snapshot",
        json!({"manager": "apt", "scope": "manual", "exclude_patterns": ["c*"],
               "include_versions": "none", "format": "text"}),
    );
    let text = r.ok()["lockfile"].as_str().unwrap().to_string();
    assert!(text.starts_with("# pkg-lock/v1\n# manager: apt"), "{text}");
    assert!(
        text.contains("\njq [amd64] @noble/main (manual)\n"),
        "{text}"
    );
    assert!(!text.contains("curl") && !text.contains("libjq1"), "{text}");

    let r = f.verb("snapshot", json!({"manager": "apt", "format": "yaml"}));
    let yaml = r.ok()["lockfile"].as_str().unwrap().to_string();
    assert!(yaml.starts_with("lockfile_version: pkg-lock/v1"), "{yaml}");
    assert!(f.changes().is_empty());
}

/// A snapshot restores the recorded versions: missing packages are
/// installed and changed ones upgraded or downgraded to the locked version.
#[test]
fn restore_exact_returns_to_the_snapshot() {
    let f = Fixture::new();
    f.available(&[
        ("jq", "1.6"),
        ("jq", "1.7"),
        ("curl", "8.4"),
        ("curl", "8.5"),
        ("tree", "2.1"),
    ])
    .installed(
        &[("jq", "1.6"), ("curl", "8.5"), ("tree", "2.1")],
        &["jq", "curl", "tree"],
    );
    for format in ["json", "yaml", "text"] {
        f.installed(
            &[("jq", "1.6"), ("curl", "8.5"), ("tree", "2.1")],
            &["jq", "curl", "tree"],
        );
        let snap = f.verb("snapshot", json!({"manager": "apt", "format": format}));
        let lockfile = snap.ok()["lockfile"].as_str().unwrap().to_string();

        // The host drifts: jq upgraded, curl downgraded, tree removed, vim added.
        f.installed(
            &[("jq", "1.7"), ("curl", "8.4"), ("vim", "9")],
            &["jq", "curl", "vim"],
        );
        f.clear_log();
        let input = json!({
            "manager": "apt", "lockfile": lockfile, "allow_newer": false,
            "allow_downgrades": true, "allow_removals": true, "on_repo_mismatch": "ignore",
            "extra_args": ["--no-install-recommends"]
        });
        let mut dry = input.clone();
        dry["dry_run"] = json!(true);
        let r = f.verb("restore", dry);
        let json = r.ok();
        assert_eq!(json["mode"], "exact");
        assert_eq!(
            json["commands"],
            json!([
                "DEBIAN_FRONTEND=noninteractive apt-get install -y tree=2.1 --no-install-recommends",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y curl=8.5 --no-install-recommends",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades jq=1.6 --no-install-recommends",
                "DEBIAN_FRONTEND=noninteractive apt-get remove -y vim --no-install-recommends",
            ]),
            "{format}"
        );
        assert!(f.changes().is_empty(), "dry run changed something");

        let r = f.verb("apply_lock", input);
        let json = r.ok();
        assert_eq!(json["summary"]["success"], true, "{format}: {json}");
        assert_eq!(json["results"]["downgrade"][0]["to_version"], "1.6");
        assert_eq!(json["results"]["downgrade"][0]["from_version"], "1.7");
        assert_eq!(json["results"]["downgrade"][0]["locked_version"], "1.6");
        assert_eq!(
            f.installed_now(),
            [
                ("curl".into(), "8.5".into()),
                ("jq".into(), "1.6".into()),
                ("tree".into(), "2.1".into())
            ],
            "{format}"
        );
    }
}

#[test]
fn restore_best_effort_falls_back_and_exact_fails() {
    let f = Fixture::new();
    // The locked jq 1.5 is gone from the repositories.
    f.available(&[("jq", "1.7")]).installed(&[], &[]);
    let lockfile = json!({
        "lockfile_version": "pkg-lock/v1", "generated_at": "x",
        "manager": {"name": "apt", "alias": "system", "version": null, "config": null},
        "platform": {"os_family": null, "os_name": null, "os_version": null,
                     "kernel": null, "architecture": null},
        "scope": "all", "packages": [{"name": "jq", "version": "1.5"}]
    })
    .to_string();
    let r = f.verb(
        "restore",
        json!({"manager": "apt", "lockfile": lockfile, "on_repo_mismatch": "ignore"}),
    );
    let json = r.failed(1, "pkg.partial_failure");
    let op = &json["results"]["install"][0];
    assert_eq!(op["status"], "failed");
    assert_eq!(op["error"]["code"], "pkg.command_failed");
    assert!(
        op["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Version '1.5'"),
        "{op}"
    );
    assert!(f.installed_now().is_empty());

    let r = f.verb(
        "restore",
        json!({"manager": "apt", "lockfile": lockfile, "on_repo_mismatch": "ignore",
               "mode": "best_effort"}),
    );
    let json = r.ok();
    assert_eq!(json["results"]["install"][0]["to_version"], "1.7");
    assert!(
        json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("repository version was installed"),
        "{json}"
    );
    assert_eq!(f.installed_now(), [("jq".into(), "1.7".into())]);
}

#[test]
fn restore_refusals_run_nothing() {
    let f = Fixture::new();
    f.available(&[("jq", "1.7")])
        .installed(&[("jq", "1.7")], &["jq"]);
    let lock = |manager: &str, version: &str| {
        json!({
            "lockfile_version": "pkg-lock/v1", "generated_at": "x",
            "manager": {"name": manager, "alias": "system", "version": null, "config": null},
            "platform": {"os_family": null, "os_name": "Plan9", "os_version": null,
                         "kernel": null, "architecture": null},
            "scope": "all", "packages": [{"name": "jq", "version": version}]
        })
        .to_string()
    };
    // jq 1.5 is locked, 1.7 installed: newer, downgrades not allowed.
    let base = json!({"manager": "apt", "lockfile": lock("apt", "1.5"), "allow_newer": false});
    for dry in [true, false] {
        let mut input = base.clone();
        input["dry_run"] = json!(dry);
        f.verb("restore", input).failed(1, "pkg.unresolved");

        let mut input = base.clone();
        input["dry_run"] = json!(dry);
        input["on_platform_mismatch"] = json!("fail");
        f.verb("restore", input).failed(1, "pkg.platform_mismatch");
    }
    let mut warn = base.clone();
    warn["on_missing_package"] = json!("warn");
    warn["dry_run"] = json!(true);
    let r = f.verb("restore", warn);
    let warnings = r.ok()["warnings"].to_string();
    assert!(
        warnings.contains("another platform: OS Plan9"),
        "{warnings}"
    );
    assert!(warnings.contains("left as they are: jq"), "{warnings}");

    f.verb(
        "restore",
        json!({"manager": "apt", "lockfile": lock("dnf", "1")}),
    )
    .failed(2, "pkg.manager_mismatch");
    f.verb(
        "restore",
        json!({"manager": "apt", "lockfile": lock("zypper", "1")}),
    )
    .failed(2, "pkg.invalid_lockfile");
    f.verb(
        "restore",
        json!({"manager": "apt", "lockfile": "jq=1 garbage"}),
    )
    .failed(2, "pkg.invalid_lockfile");
    // A pacman host with nothing installed: mode exact needs jq 1.5, which
    // pacman cannot install.
    common::write_executable(
        &f.bin().join("pacman"),
        &format!("#!/bin/sh\n{RECORD}\nexit 0\n"),
    );
    f.verb(
        "restore",
        json!({"manager": "auto", "lockfile": lock("pacman", "1.5")}),
    )
    .failed(2, "pkg.unsupported_option");
    assert!(f.changes().is_empty());
    assert!(
        f.calls_to("pacman")
            .iter()
            .all(|c| c[1] == "-Q" || c[1] == "-Si"),
        "{:?}",
        f.calls_to("pacman")
    );
}

// ===========================================================================
// install
// ===========================================================================

#[test]
fn install_installs_skips_upgrades_and_pins() {
    let f = Fixture::new();
    f.available(&[("jq", "1.6"), ("jq", "1.7"), ("curl", "8.5")])
        .installed(&[("curl", "8.5")], &["curl"]);
    let r = f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq", "version": "1.6"}, {"name": "curl"}]}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "installed");
    assert_eq!(json["packages"][0]["installed_version"], "1.6");
    assert_eq!(json["packages"][1]["action"], "unchanged");
    assert_eq!(json["summary"]["installed"], 1);
    assert_eq!(
        f.changes(),
        [
            vec!["apt-get", "update"],
            vec!["apt-get", "install", "-y", "jq=1.6"],
        ]
    );

    f.clear_log();
    let r = f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq"}], "only_if_missing": false,
               "upgrade": true, "update_cache": false, "extra_args": ["--no-install-recommends"]}),
    );
    assert_eq!(r.ok()["packages"][0]["action"], "upgraded");
    assert_eq!(
        f.changes(),
        [vec![
            "apt-get",
            "install",
            "-y",
            "--only-upgrade",
            "jq",
            "--no-install-recommends"
        ]]
    );
    assert_eq!(f.installed_now()[1], ("jq".into(), "1.7".into()));
}

#[test]
fn install_reports_failed_packages_and_exits_1() {
    let f = Fixture::new();
    f.available(&[("jq", "1.7")]);
    let r = f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "nope"}, {"name": "jq"}], "update_cache": false}),
    );
    let json = r.failed(1, "pkg.partial_failure");
    assert_eq!(json["packages"][0]["action"], "failed");
    assert_eq!(json["packages"][0]["error"]["code"], "pkg.not_found");
    assert_eq!(json["packages"][1]["action"], "installed");
    assert!(r.stderr.contains("1 of 2 package operations failed"));

    f.touch(
        "fail_update",
        "E: Could not open lock file - are you root?\n",
    );
    f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq"}]}),
    )
    .failed(1, "pkg.index_failed");
}

#[test]
fn install_dry_run_runs_nothing() {
    let f = Fixture::new();
    f.available(&[("jq", "1.7")])
        .installed(&[("curl", "8.5")], &[]);
    let r = f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq"}, {"name": "curl"}], "dry_run": true}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "would_install");
    assert_eq!(json["packages"][1]["action"], "already_installed");
    assert_eq!(
        json["commands"],
        json!([
            "apt-get update",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y jq"
        ])
    );
    assert!(f.changes().is_empty());
}

#[test]
fn options_a_manager_cannot_honor_are_refused() {
    let f = Fixture::new();
    for (manager, input) in [
        (
            "pacman",
            json!({"packages": [{"name": "jq", "version": "1.7"}]}),
        ),
        (
            "brew",
            json!({"packages": [{"name": "jq", "version": "1.7"}]}),
        ),
        (
            "apk",
            json!({"packages": [{"name": "jq"}], "arch": "x86_64"}),
        ),
        (
            "apk",
            json!({"packages": [{"name": "jq"}], "assume_yes": false}),
        ),
    ] {
        let mut input = input;
        input["manager"] = json!(manager);
        for dry in [true, false] {
            input["dry_run"] = json!(dry);
            f.verb("install", input.clone())
                .failed(2, "pkg.unsupported_option");
        }
    }
    f.verb(
        "remove",
        json!({"manager": "dnf", "packages": [{"name": "jq"}], "purge": true}),
    )
    .failed(2, "pkg.unsupported_option");
    f.verb("update", json!({"manager": "apt", "security_only": true}))
        .failed(2, "pkg.unsupported_option");
    f.verb("upgrade", json!({"manager": "brew", "assume_yes": false}))
        .failed(2, "pkg.unsupported_option");
    assert!(f.calls().is_empty(), "{:?}", f.calls());
}

// ===========================================================================
// remove
// ===========================================================================

#[test]
fn remove_removes_and_reports_missing_packages() {
    let f = Fixture::new();
    f.installed(&[("jq", "1.7"), ("curl", "8.5")], &[]);
    let r = f.verb(
        "remove",
        json!({"manager": "apt", "packages": [{"name": "jq"}, {"name": "nope"}],
               "purge": true, "recursive": true}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "not_installed");
    assert_eq!(json["packages"][1]["action"], "purged");
    assert_eq!(json["packages"][1]["installed_version"], "1.7");
    assert_eq!(json["summary"]["autoremove_run"], true);
    assert_eq!(
        f.changes(),
        [
            vec!["apt-get", "purge", "-y", "jq"],
            vec!["apt-get", "autoremove", "-y"]
        ]
    );
    assert_eq!(f.installed_now(), [("curl".into(), "8.5".into())]);

    let r = f.verb(
        "remove",
        json!({"manager": "apt", "packages": [{"name": "nope"}],
               "only_if_installed": false, "fail_if_missing": true}),
    );
    let json = r.failed(1, "pkg.partial_failure");
    assert_eq!(json["packages"][0]["error"]["code"], "pkg.not_found");

    f.touch("fail_autoremove", "E: autoremove broke\n");
    let r = f.verb(
        "remove",
        json!({"manager": "apt", "packages": [{"name": "curl"}], "recursive": true}),
    );
    let json = r.failed(1, "pkg.partial_failure");
    assert_eq!(json["autoremove_error"]["code"], "pkg.command_failed");
}

#[test]
fn remove_dry_run_runs_nothing() {
    let f = Fixture::new();
    f.installed(&[("jq", "1.7")], &[]);
    let r = f.verb(
        "remove",
        json!({"manager": "apt", "packages": [{"name": "jq"}], "recursive": true, "dry_run": true}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "would_remove");
    assert_eq!(
        json["commands"],
        json!([
            "DEBIAN_FRONTEND=noninteractive apt-get remove -y jq",
            "DEBIAN_FRONTEND=noninteractive apt-get autoremove -y"
        ])
    );
    assert!(f.changes().is_empty());
}

// ===========================================================================
// update and upgrade
// ===========================================================================

#[test]
fn update_and_upgrade_check_and_apply() {
    let f = Fixture::new();
    f.available(&[("jq", "1.6"), ("jq", "1.7"), ("curl", "8.5")])
        .installed(&[("jq", "1.6"), ("curl", "8.5")], &[]);
    for verb in ["update", "upgrade"] {
        let r = f.verb(verb, json!({"manager": "apt", "check_only": true}));
        let json = r.ok();
        let key = if verb == "update" {
            "available_updates"
        } else {
            "available_upgrades"
        };
        assert_eq!(json[key][0]["name"], "jq", "{verb}");
        assert_eq!(json[key][0]["candidate_version"], "1.7");
        assert_eq!(json["commands"], json!(["apt-get update"]));
        let r = f.verb(
            verb,
            json!({"manager": "apt", "dry_run": true, "packages": ["jq"]}),
        );
        assert_eq!(
            r.ok()["commands"],
            json!([
                "apt-get update",
                "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y jq"
            ])
        );
    }
    assert!(f.changes().is_empty());

    let r = f.verb("upgrade", json!({"manager": "apt"}));
    let json = r.ok();
    assert_eq!(json["summary"]["upgraded"], 1);
    assert_eq!(
        f.changes(),
        [vec!["apt-get", "update"], vec!["apt-get", "upgrade", "-y"]]
    );
    assert_eq!(f.installed_now()[1], ("jq".into(), "1.7".into()));

    f.clear_log();
    f.installed(&[("jq", "1.6")], &[]);
    let r = f.verb(
        "update",
        json!({"manager": "apt", "refresh_index": false, "packages": ["jq"]}),
    );
    r.ok();
    assert_eq!(
        f.changes(),
        [vec!["apt-get", "install", "--only-upgrade", "-y", "jq"]]
    );
}

// ===========================================================================
// Timeouts
// ===========================================================================

/// Whether the process still exists (as anything but a zombie that has not
/// been collected yet), allowing a moment for it to be collected.
fn alive(pid: &str) -> bool {
    let stat = format!("/proc/{}/stat", pid.trim());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let running = std::fs::read_to_string(&stat)
            .map(|s| {
                !s.rsplit_once(')')
                    .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
            })
            .unwrap_or(false);
        if !running || Instant::now() >= deadline {
            return running;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// At the deadline the hanging manager is stopped, exit 124.
#[test]
fn a_timeout_stops_the_package_manager() {
    for (verb, sleeper, input) in [
        (
            "install",
            "sleep_install",
            json!({"manager": "apt", "packages": [{"name": "jq"}], "update_cache": false}),
        ),
        ("update", "sleep_update", json!({"manager": "apt"})),
        (
            "remove",
            "sleep_remove",
            json!({"manager": "apt", "packages": [{"name": "jq"}]}),
        ),
    ] {
        let f = Fixture::new();
        f.available(&[("jq", "1.7")])
            .installed(&[("jq", "1.6")], &[]);
        if verb == "install" {
            f.installed(&[], &[]);
        }
        f.touch(sleeper, "");
        let mut input = input;
        input["timeout_ms"] = json!(1500);
        let start = Instant::now();
        let r = f.verb(verb, input);
        assert!(start.elapsed() < Duration::from_secs(15), "{verb} waited");
        r.failed(124, "pkg.timeout");
        let pid = std::fs::read_to_string(f.db().join("pid")).unwrap();
        assert!(!alive(&pid), "{verb}: the manager {pid} still runs");
    }
}

/// The deadline covers dry runs and queries too.
#[test]
fn a_timeout_covers_queries() {
    let f = Fixture::new();
    // apt-cache hangs through a fake that sleeps.
    common::write_executable(
        &f.bin().join("apt-cache"),
        &format!("#!/bin/sh\n{RECORD}\necho $$ > \"$FAKE_PKG_DIR/pid\"\nsleep 30\n"),
    );
    f.available(&[("jq", "1.7")]);
    let r = f.verb(
        "info",
        json!({"manager": "apt", "packages": ["jq"], "timeout_ms": 1000}),
    );
    r.failed(124, "pkg.timeout");
    let pid = std::fs::read_to_string(f.db().join("pid")).unwrap();
    assert!(!alive(&pid));
}

// ===========================================================================
// Arguments and managers
// ===========================================================================

#[test]
fn invalid_requests_exit_2_before_anything_runs() {
    let f = Fixture::new();
    for args in [
        vec!["pkg://system.install".to_string()],
        vec![
            "pkg://system.install".into(),
            r#"input={"manager":"apt","packages":[{"name":"jq"}]}"#.into(),
            "manager=apt".into(),
        ],
        vec![
            "pkg://system.install".into(),
            r#"input={"manager":"apt","packages":[{"name":"jq"}],"dryrun":true}"#.into(),
        ],
        vec![
            "pkg://system.info".into(),
            r#"input={"manager":"apt","packages":["jq"],"extra_args":["-q"]}"#.into(),
        ],
        vec![
            "pkg://system.install".into(),
            r#"input={"manager":"apt","packages":[{"name":"jq","source":"x.deb"}]}"#.into(),
        ],
        vec![
            "pkg://system.search".into(),
            r#"input={"manager":"apt","query":"-oDir=/"}"#.into(),
        ],
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        f.run(&args).failed(2, "pkg.invalid_argument");
    }
    assert!(f.calls().is_empty(), "{:?}", f.calls());
}

#[test]
fn managers_are_detected_or_reported_missing() {
    let f = Fixture::with(&[]);
    f.verb("list_installed", json!({"manager": "dnf"}))
        .failed(1, "pkg.manager_not_found");
    f.installed(&[("jq", "1.7")], &[]);
    let r = f.verb("list_installed", json!({"manager": "auto"}));
    assert_eq!(r.ok()["manager"], "apt");
}

#[test]
fn env_is_set_for_the_package_manager() {
    let f = Fixture::new();
    common::write_executable(
        &f.bin().join("apt-mark"),
        &format!(
            "#!/bin/sh\n{RECORD}\nprintf '%s %s\\n' \"$LC_ALL\" \"$RESH_PKG_PROBE\" > \"$FAKE_PKG_DIR/env\"\n"
        ),
    );
    f.installed(&[("jq", "1.7")], &[]);
    f.verb(
        "list_installed",
        json!({"manager": "apt", "include_install_reason": true, "include_repo": false,
               "env": {"RESH_PKG_PROBE": "on"}}),
    )
    .ok();
    assert_eq!(
        std::fs::read_to_string(f.db().join("env")).unwrap(),
        "C on\n"
    );
}

// ===========================================================================
// Help
// ===========================================================================

const VERBS: &[&str] = &[
    "info",
    "search",
    "list_installed",
    "snapshot",
    "install",
    "remove",
    "update",
    "upgrade",
    "restore",
    "apply_lock",
];

fn golden(verb: &str) -> &'static str {
    match verb {
        "info" => include_str!("golden/pkg_info_help.txt"),
        "search" => include_str!("golden/pkg_search_help.txt"),
        "list_installed" => include_str!("golden/pkg_list_installed_help.txt"),
        "snapshot" => include_str!("golden/pkg_snapshot_help.txt"),
        "install" => include_str!("golden/pkg_install_help.txt"),
        "remove" => include_str!("golden/pkg_remove_help.txt"),
        "update" => include_str!("golden/pkg_update_help.txt"),
        "upgrade" => include_str!("golden/pkg_upgrade_help.txt"),
        "restore" => include_str!("golden/pkg_restore_help.txt"),
        "apply_lock" => include_str!("golden/pkg_apply_lock_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let f = Fixture::new();
    let want = include_str!("golden/pkg_help.txt");
    for args in [
        &["pkg", "--help"][..],
        &["pkg", "-h"][..],
        &["pkg", "help"][..],
        &["help", "pkg"][..],
        &["pkg://--help"][..],
        &["pkg://help"][..],
    ] {
        let r = f.run(args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden() {
    let f = Fixture::new();
    for verb in VERBS {
        for args in [
            vec!["pkg", verb, "--help"],
            vec!["pkg", verb, "-h"],
            vec!["help", "pkg", verb],
        ] {
            let r = f.run(&args);
            assert_eq!(r.code, 0, "{args:?}");
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(
            golden(verb).lines().all(|l| l.len() <= 80),
            "{verb} help is wider than 80 columns"
        );
    }
    let r = f.run(&["pkg", "instal", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("install"), "{}", r.stderr);
}

/// Every help example runs against the fake tools (through a shell, as
/// written) and prints the top-level keys of the example output.
#[test]
fn help_examples_run() {
    for verb in VERBS {
        let f = Fixture::new();
        f.available(&[("nginx", "1.24.0"), ("jq", "1.7.1-3build1")])
            .installed(&[("nginx", "1.24.0"), ("jq", "1.7.1-3build1")], &["nginx"]);
        let lockfile = json!({
            "lockfile_version": "pkg-lock/v1", "generated_at": "x",
            "manager": {"name": "apt", "alias": "system", "version": null, "config": null},
            "platform": {"os_family": null, "os_name": null, "os_version": null,
                         "kernel": null, "architecture": null},
            "scope": "all",
            "packages": [{"name": "jq", "version": "1.7.1-3build1"}, {"name": "nginx"}]
        });
        std::fs::write(
            f.path().join("restore.json"),
            json!({"manager": "apt", "lockfile": lockfile.to_string(), "dry_run": true,
                   "on_repo_mismatch": "ignore"})
            .to_string(),
        )
        .unwrap();
        if *verb == "install" {
            f.installed(&[("nginx", "1.24.0")], &["nginx"]);
        }
        let example = golden(verb)
            .lines()
            .skip_while(|l| *l != "Example:")
            .nth(1)
            .unwrap()
            .trim()
            .to_string();
        assert!(example.starts_with("resh "), "{example}");
        let resh = assert_cmd::cargo::cargo_bin!("resh");
        let script = format!("{}{}", resh.display(), &example["resh".len()..]);
        let out = f.cmd_sh(&script);
        assert_eq!(out.code, 0, "{verb}: {}\n{}", out.stdout, out.stderr);
        if let Some(start) = golden(verb).find("Example Output:") {
            let body: String = golden(verb)[start..]
                .lines()
                .skip(1)
                .take_while(|l| !l.trim_start().starts_with("Shown"))
                .collect::<Vec<_>>()
                .join("\n");
            let sample: Value = serde_json::from_str(&body).unwrap();
            for key in sample.as_object().unwrap().keys() {
                assert!(
                    out.json.get(key).is_some(),
                    "{verb}: output lacks {key}: {}",
                    out.stdout
                );
            }
        }
    }
}

impl Fixture {
    /// Runs a shell command line in the fixture (PATH as for `resh`).
    fn cmd_sh(&self, script: &str) -> Run {
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", script])
            .current_dir(self.path())
            .env_clear()
            .envs(self.envs())
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
}

// ===========================================================================
// Owner decisions: upstream-only lockfiles, allow_downgrade
// ===========================================================================

/// `include_versions: minimal` records the upstream version; restore
/// accepts any installed build of it and installs the newest build.
#[test]
fn minimal_snapshot_restores_any_build_of_the_upstream_version() {
    let f = Fixture::new();
    f.available(&[
        ("jq", "1.7-1"),
        ("jq", "1.7-2"),
        ("jq", "1.8-1"),
        ("curl", "1:8.5-3"),
    ])
    .installed(&[("jq", "1.7-1"), ("curl", "1:8.5-3")], &["jq", "curl"]);
    for format in ["json", "text"] {
        f.installed(&[("jq", "1.7-1"), ("curl", "1:8.5-3")], &["jq", "curl"]);
        let r = f.verb(
            "snapshot",
            json!({"manager": "apt", "include_versions": "minimal", "format": format}),
        );
        let lockfile = r.ok()["lockfile"].as_str().unwrap().to_string();
        if format == "json" {
            let lock: Value = serde_json::from_str(&lockfile).unwrap();
            assert_eq!(lock["manager"]["config"]["include_versions"], "minimal");
            assert_eq!(
                lock["packages"][0]["version"], "8.5",
                "epoch and revision dropped"
            );
            assert_eq!(lock["packages"][1]["version"], "1.7");
        } else {
            assert!(lockfile.contains("\njq=1.7 "), "{lockfile}");
        }

        // Another build of 1.7 is kept; a missing jq gets the newest 1.7 build.
        f.installed(&[("jq", "1.7-2"), ("curl", "1:8.5-3")], &[]);
        let input = json!({"manager": "apt", "lockfile": lockfile, "on_repo_mismatch": "ignore"});
        let mut dry = input.clone();
        dry["dry_run"] = json!(true);
        assert_eq!(
            f.verb("restore", dry).ok()["plan"]["keep"],
            json!(["curl", "jq"])
        );
        f.installed(&[("curl", "1:8.5-3")], &[]);
        f.clear_log();
        let r = f.verb("restore", input);
        let json = r.ok();
        assert_eq!(
            json["results"]["install"][0]["to_version"], "1.7-2",
            "{json}"
        );
        assert_eq!(
            f.changes(),
            [vec!["apt-get", "install", "-y", "jq=1.7-2"]],
            "{format}"
        );
    }
}

#[test]
fn install_refuses_an_older_version_unless_allowed() {
    let f = Fixture::new();
    f.available(&[("jq", "1.6"), ("jq", "1.7")])
        .installed(&[("jq", "1.7")], &[]);
    for dry in [true, false] {
        f.verb(
            "install",
            json!({"manager": "apt", "packages": [{"name": "jq", "version": "1.6"}],
                   "dry_run": dry}),
        )
        .failed(1, "pkg.downgrade_refused");
    }
    assert!(f.changes().is_empty());

    let r = f.verb(
        "install",
        json!({"manager": "apt", "packages": [{"name": "jq", "version": "1.6"}],
               "allow_downgrade": true, "update_cache": false}),
    );
    let json = r.ok();
    assert_eq!(json["packages"][0]["action"], "downgraded");
    assert_eq!(json["summary"]["downgraded"], 1);
    assert_eq!(
        f.changes(),
        [vec![
            "apt-get",
            "install",
            "-y",
            "--allow-downgrades",
            "jq=1.6"
        ]]
    );
    assert_eq!(f.installed_now(), [("jq".into(), "1.6".into())]);
}
