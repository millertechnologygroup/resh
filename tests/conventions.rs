//! Project-wide conventions, checked mechanically for every handle and verb
//! through the built binary (see the brief's conventions 1, 2 and 8):
//!
//! - an unknown argument is refused with exit 2, the standard
//!   `Error: [<handle>.<code>] <message>` line naming the argument, and no
//!   stdout other than a JSON error object;
//! - a typo of a real option gets a "did you mean";
//! - `dry_run=true` is refused where the usage does not list `dry_run`;
//! - `timeout_ms=abc` is refused (exit 2) everywhere: as an invalid value
//!   where the verb accepts `timeout_ms`, as an unknown argument elsewhere;
//! - every option the usage lists is accepted (not refused as unknown);
//! - every help form renders the same text, within 80 columns.
//!
//! Every probe is refused before the verb does anything. They still run
//! with a throwaway HOME and XDG directories, the working directory in a
//! temporary directory, targets that do not exist (a temporary path, an
//! unused service or user name, a port nothing listens on) and the test
//! keyring disabled, so a verb that failed to refuse could not touch the
//! host's real files, services or accounts.
//!
//! The opposite direction (every argument a verb accepts is in its usage)
//! needs each handle's accepted-options list, so it lives in the per-handle
//! tests; `every_handle_tests_its_accepted_options_against_its_usage`
//! checks that each handle has one.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

const UNKNOWN: &str = "zzz_unknown_arg";

/// A throwaway environment for running the binary.
struct Env {
    dir: tempfile::TempDir,
    /// A child process the `proc` probes can name; killed on drop.
    sleeper: Child,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["home", "config", "data", "state", "cache", "runtime", "tmp"] {
            std::fs::create_dir(dir.path().join(d)).unwrap();
        }
        let sleeper = Command::new("sleep")
            .arg("600")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        Env { dir, sleeper }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn run(&self, args: &[&str]) -> Output {
        let p = self.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_resh"));
        cmd.args(args)
            .current_dir(p.join("tmp"))
            .env("HOME", p.join("home"))
            .env("XDG_CONFIG_HOME", p.join("config"))
            .env("XDG_DATA_HOME", p.join("data"))
            .env("XDG_STATE_HOME", p.join("state"))
            .env("XDG_CACHE_HOME", p.join("cache"))
            .env("XDG_RUNTIME_DIR", p.join("runtime"))
            .env("TMPDIR", p.join("tmp"))
            .env("RESH_TEST_KEYRING", "unavailable")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null());
        cmd.output().unwrap()
    }

    /// The stage for `handle`'s `verb`, on a target the handle accepts but
    /// that names nothing real.
    fn stage(&self, handle: &str, verb: &str) -> String {
        let tmp = self.path().join("tmp");
        let tmp = tmp.display();
        let target = match (handle, verb) {
            ("archive", _) => "archive://".to_string(),
            ("backup", _) => "backup://probe".to_string(),
            ("cache", _) => "cache://redis/probe".to_string(),
            ("cert", _) => format!("cert://{tmp}/probe.pem"),
            ("config", _) => "config://probe/key".to_string(),
            ("cron", _) => "cron://probe".to_string(),
            ("db", _) => "db://sqlite/probe".to_string(),
            ("dns", _) => "dns://".to_string(),
            ("event", _) => "event://".to_string(),
            ("file", _) => format!("file://{tmp}/probe.txt"),
            ("firewall", _) => "firewall://".to_string(),
            ("fs", _) => "fs://probe".to_string(),
            ("git", _) => "git://probe".to_string(),
            // Port 9 (discard): nothing listens there on a test machine.
            ("http", _) => "http://127.0.0.1:9/probe".to_string(),
            ("https", _) => "https://127.0.0.1:9/probe".to_string(),
            ("log", _) => format!("log://{tmp}/probe.log"),
            // The mail target is the verb itself: mail://send.
            ("mail", _) => return format!("mail://{verb}"),
            ("mq", _) => "mq://probe".to_string(),
            // net list reads interfaces; its usage names the target `if`.
            ("net", "list") => "net://if".to_string(),
            ("net", "tcp_check") => "net://127.0.0.1:9".to_string(),
            ("net", _) => "net://127.0.0.1".to_string(),
            ("pkg", _) => "pkg://probe".to_string(),
            // The catalog, inventory and trusted-key verbs take no plugin id.
            ("plugin", v)
                if ["available.", "installed.", "keys."]
                    .iter()
                    .any(|p| v.starts_with(p)) =>
            {
                return format!("plugin://{verb}");
            }
            ("plugin", _) => "plugin://resh-conventions-probe".to_string(),
            ("proc", _) => format!("proc://{}", self.sleeper.id()),
            ("secret", "ls") => "secret://local/probe".to_string(),
            ("secret", _) => "secret://local/probe/key".to_string(),
            // restore names a snapshot; the others name the snapshotted path.
            ("snapshot", "restore") => "snapshot://resh-conventions-probe".to_string(),
            ("snapshot", _) => format!("snapshot://{tmp}/probe"),
            ("ssh", _) => "ssh://probe@127.0.0.1:9".to_string(),
            ("svc", _) => "svc://resh-conventions-probe".to_string(),
            ("system", _) => "system://".to_string(),
            ("template", _) => format!("template://{tmp}/probe.txt"),
            ("user", _) => "user://resh-conventions-probe".to_string(),
            (h, _) => panic!("no probe target for handle {h}: add one to Env::stage"),
        };
        format!("{target}.{verb}")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Each handle and the verbs its help lists.
fn handles_and_verbs(env: &Env) -> Vec<(String, Vec<String>)> {
    let out = env.run(&["--list-schemas"]);
    assert!(out.status.success());
    let handles: Vec<String> = text(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    assert!(handles.len() >= 29, "{handles:?}");
    handles
        .into_iter()
        .map(|h| {
            let out = env.run(&[&h, "--help"]);
            assert!(out.status.success(), "{h} --help");
            let help = text(&out.stdout);
            let verbs: Vec<String> = help
                .split("Available Verbs:\n")
                .nth(1)
                .unwrap_or_else(|| panic!("{h}: no verb list"))
                .split("\n\n")
                .next()
                .unwrap()
                .lines()
                .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
                .map(|l| l.split_whitespace().next().unwrap().to_string())
                .collect();
            assert!(!verbs.is_empty(), "{h}: no verbs");
            (h, verbs)
        })
        .collect()
}

/// The verb a stage for `handle`'s `verb` runs. `cert://<t>.csr.sign` is
/// the `sign` verb on the target `<t>.csr` (its help says so), so it takes
/// sign's options and its stage help is sign's help.
fn effective_verb<'a>(handle: &str, verb: &'a str) -> &'a str {
    match (handle, verb) {
        ("cert", "csr.sign") => "sign",
        _ => verb,
    }
}

/// The handle name in the error codes of `handle`'s stages: `https://` is
/// the http handle and uses its `http.` codes (docs/.../http.md).
fn code_prefix(handle: &str) -> &str {
    match handle {
        "https" => "http",
        h => h,
    }
}

/// The text of the `Usage:` section of the help of the verb a stage runs.
fn usage(env: &Env, handle: &str, verb: &str) -> String {
    let verb = effective_verb(handle, verb);
    let out = env.run(&[handle, verb, "--help"]);
    assert!(out.status.success(), "{handle} {verb} --help");
    text(&out.stdout)
        .split("Usage:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .to_string()
}

/// An option a usage lists.
struct Opt {
    name: String,
    /// A value its placeholder allows: `name=true|false` gives "false" (but
    /// `dry_run=true`), another `a|b` list its first choice, `<n>`-like
    /// placeholders "1", JSON placeholders an empty array or object, and
    /// anything else "x".
    value: String,
    /// Listed outside `[...]` and `(...)` and not as an alternative
    /// (`a=<x>|b=<y>` makes only `a` required).
    required: bool,
}

/// The options a usage lists. Templated names such as `header_<Name>=` or
/// `<resource>=` are skipped, and so are names in note lines (`defaults:
/// x=1`), which repeat options already listed.
fn usage_options(usage: &str) -> Vec<Opt> {
    let mut out: Vec<Opt> = Vec::new();
    let mut depth = 0i32;
    for line in usage.lines() {
        let note = line.contains(": ");
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'[' | b'(' => depth += 1,
                b']' | b')' => depth -= 1,
                _ => {}
            }
            let starts = i == 0 || matches!(b[i - 1], b' ' | b'[' | b'|' | b'(');
            if !(starts && b[i].is_ascii_lowercase()) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < b.len()
                && (b[j].is_ascii_lowercase() || b[j].is_ascii_digit() || b[j] == b'_')
            {
                j += 1;
            }
            if j >= b.len() || b[j] != b'=' {
                i = j.max(i + 1);
                continue;
            }
            let name = &line[i..j];
            let raw = line[j + 1..]
                .split(|c: char| c.is_whitespace() || c == ']' || c == ')')
                .next()
                .unwrap_or("");
            let value = if name == "dry_run" {
                "true".to_string()
            } else if raw.starts_with("true|false") || raw == "true" {
                "false".to_string()
            } else if raw.starts_with('<') {
                let ph = raw.split('>').next().unwrap_or("").trim_start_matches('<');
                match ph {
                    "n" | "ms" | "seconds" | "bytes" | "bits" | "0-100" | "0-10" => "1",
                    "json-array" => "[]",
                    "json" | "json-object" => "{}",
                    _ => "x",
                }
                .to_string()
            } else {
                raw.split('|').next().unwrap_or("x").to_string()
            };
            let alternative = i > 0 && b[i - 1] == b'|';
            if !out.iter().any(|o| o.name == name) {
                out.push(Opt {
                    name: name.to_string(),
                    value,
                    required: depth == 0 && !alternative && !note,
                });
            }
            i = j;
        }
    }
    out
}

/// What is wrong with a refusal, if anything: exit 2, the first stderr line
/// in the standard format with a valid code of `handle`, and stdout either
/// empty or JSON objects whose `error.code` is that code.
fn refusal_problem(handle: &str, out: &Output) -> Option<String> {
    let stderr = text(&out.stderr);
    let stdout = text(&out.stdout);
    if out.status.code() != Some(2) {
        return Some(format!(
            "exit {:?}, expected 2; stderr: {stderr}",
            out.status.code()
        ));
    }
    let Some(line) = stderr.lines().find(|l| l.starts_with("Error: ")) else {
        return Some(format!("no `Error: ` line on stderr: {stderr:?}"));
    };
    let prefix = format!("Error: [{}.", code_prefix(handle));
    if !line.starts_with(&prefix) {
        return Some(format!("stderr does not start with {prefix:?}: {line}"));
    }
    let code = line["Error: [".len()..].split(']').next().unwrap_or("");
    if !resh::core::status::is_valid_error_code(code) {
        return Some(format!("invalid error code {code:?}: {line}"));
    }
    // stdout: nothing, or the error as JSON (one object, compact or
    // pretty), with the same code.
    let is_error =
        |v: &serde_json::Value| v.pointer("/error/code").and_then(|c| c.as_str()) == Some(code);
    if !stdout.trim().is_empty() {
        let whole = serde_json::from_str::<serde_json::Value>(&stdout)
            .ok()
            .is_some_and(|v| is_error(&v));
        let each_line = stdout.lines().filter(|l| !l.trim().is_empty()).all(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .is_some_and(|v| is_error(&v))
        });
        if !whole && !each_line {
            return Some(format!(
                "stdout is not a JSON error object with {code}: {stdout:?}"
            ));
        }
    }
    None
}

/// The code of the first `Error: [<code>]` line on stderr.
fn error_code(out: &Output) -> Option<String> {
    let stderr = text(&out.stderr);
    let line = stderr.lines().find(|l| l.starts_with("Error: ["))?;
    Some(line["Error: [".len()..].split(']').next()?.to_string())
}

/// Runs `probe` for every verb and fails with every problem found.
fn for_every_verb(probe: impl Fn(&Env, &str, &str) -> Vec<String>) {
    let env = Env::new();
    let mut problems = Vec::new();
    for (handle, verbs) in handles_and_verbs(&env) {
        for verb in verbs {
            for p in probe(&env, &handle, &verb) {
                problems.push(format!("{handle} {verb}: {p}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn unknown_arguments_are_refused_in_the_standard_format() {
    for_every_verb(|env, handle, verb| {
        let out = env.run(&[&env.stage(handle, verb), &format!("{UNKNOWN}=1")]);
        let mut problems: Vec<String> = refusal_problem(handle, &out).into_iter().collect();
        if !text(&out.stderr).contains(UNKNOWN) {
            problems.push(format!(
                "the refusal does not name {UNKNOWN}: {}",
                text(&out.stderr)
            ));
        }
        problems
    });
}

/// A typo of a real option: one letter from the middle dropped. Options too
/// short to misspell recognisably (fewer than 4 letters) are skipped.
fn typo_of(name: &str, others: &[Opt]) -> Option<String> {
    if name.len() < 4 {
        return None;
    }
    let mid = name.len() / 2;
    let t = format!("{}{}", &name[..mid], &name[mid + 1..]);
    (!others.iter().any(|o| o.name == t)).then_some(t)
}

#[test]
fn a_misspelled_option_gets_a_suggestion() {
    for_every_verb(|env, handle, verb| {
        let opts = usage_options(&usage(env, handle, verb));
        // Prefer an option of the verb's own over a shared one.
        let Some((name, typo)) = opts
            .iter()
            .filter(|o| o.name != "timeout_ms" && o.name != "dry_run")
            .chain(opts.iter())
            .find_map(|o| typo_of(&o.name, &opts).map(|t| (o.name.clone(), t)))
        else {
            return Vec::new();
        };
        let out = env.run(&[&env.stage(handle, verb), &format!("{typo}=1")]);
        let mut problems: Vec<String> = refusal_problem(handle, &out).into_iter().collect();
        let err = text(&out.stderr);
        // The suggestion may be another option just as close (`kes` gives
        // `key` as well as `keys`); it must be one of the verb's options.
        let suggested = err
            .to_ascii_lowercase()
            .split_once("did you mean")
            .is_some_and(|(_, rest)| opts.iter().any(|o| rest.contains(o.name.as_str())));
        if !(err.contains(&typo) && suggested) {
            problems.push(format!(
                "{typo}=1 (a typo of {name}) gets no \"did you mean\": {err}"
            ));
        }
        problems
    });
}

#[test]
fn an_unknown_verb_is_refused_in_the_standard_format() {
    let env = Env::new();
    let mut problems = Vec::new();
    for (handle, _) in handles_and_verbs(&env) {
        let verb = "zzz_unknown_verb";
        let out = env.run(&[&env.stage(&handle, verb)]);
        if let Some(p) = refusal_problem(&handle, &out) {
            problems.push(format!("{handle}: {p}"));
        } else if !text(&out.stderr).contains(verb) {
            problems.push(format!(
                "{handle}: the refusal does not name the verb: {}",
                text(&out.stderr)
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn dry_run_is_refused_where_the_usage_does_not_list_it() {
    for_every_verb(|env, handle, verb| {
        if usage(env, handle, verb).contains("dry_run") {
            return Vec::new();
        }
        let stage = env.stage(handle, verb);
        let out = env.run(&[&stage, "dry_run=true"]);
        let mut problems: Vec<String> = refusal_problem(handle, &out).into_iter().collect();
        if !text(&out.stderr).contains("dry_run") {
            problems.push(format!(
                "the refusal does not name dry_run: {}",
                text(&out.stderr)
            ));
        }
        // resh refuses it before the handle runs, with the code the handle
        // gives any other argument the verb does not take.
        let other = env.run(&[&stage, &format!("{UNKNOWN}=1")]);
        let (a, b) = (error_code(&out), error_code(&other));
        if a != b {
            problems.push(format!("dry_run=true is {a:?}, an unknown argument {b:?}"));
        }
        problems
    });
}

/// The arguments that go with `timeout_ms=abc`, so that the refusal is
/// about the timeout and not about something else missing or malformed:
/// the required options with their placeholder values, or, for a verb that
/// checks the form of other values first, a set it accepts. All name
/// things that do not exist, in case a verb ran anyway.
fn timeout_probe_args(handle: &str, verb: &str, opts: &[Opt]) -> Vec<String> {
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl probe";
    let given: &[&str] = match (handle, verb) {
        ("archive", "list" | "info" | "test") => &["archive=probe.tar.gz"],
        ("archive", "extract") => &["archive=probe.tar.gz", "destination=out"],
        ("archive", "create") => &["output=probe.tar.gz", r#"sources=["a"]"#],
        ("archive", "add") => &["archive=probe.tar.gz", r#"inputs=["a"]"#],
        ("archive", "remove") => &["archive=probe.tar.gz", r#"paths=["a"]"#],
        // A real URL in place of the placeholder; the rest as listed.
        ("cache", v) if v != "connect" => {
            return opts
                .iter()
                .filter(|o| o.required && o.name != "url")
                .map(|o| format!("{}={}", o.name, o.value))
                .chain(["url=redis://127.0.0.1:9".to_string()])
                .collect();
        }
        ("cert", "csr.create") => &[r#"subject={"common_name":"probe"}"#, "existing_key_path=k"],
        ("cert", "sign" | "csr.sign") => &["signer_key=k", "data_source=d"],
        ("db", "transaction") => &[r#"statements=["SELECT 1"]"#],
        ("mail", "send") => &["to=a@example.invalid", "subject=s", "text_body=b"],
        ("mail", "send_template") => &["template=welcome", "to=a@example.invalid"],
        ("ssh", "download") => &["source=s", "dest=d"],
        ("ssh", "key.add") => &[KEY],
        ("ssh", "tunnel") => &["mode=dynamic"],
        _ => {
            return opts
                .iter()
                .filter(|o| o.required)
                .map(|o| format!("{}={}", o.name, o.value))
                .collect();
        }
    };
    // key.add takes the key line as public_key=.
    given
        .iter()
        .map(|a| {
            if *a == KEY {
                format!("public_key={KEY}")
            } else {
                a.to_string()
            }
        })
        .collect()
}

#[test]
fn a_malformed_timeout_is_refused() {
    for_every_verb(|env, handle, verb| {
        let opts = usage_options(&usage(env, handle, verb));
        let accepts = opts.iter().any(|o| o.name == "timeout_ms");
        // The required arguments go along, so that the refusal is about the
        // timeout and not about something missing.
        let required = timeout_probe_args(handle, verb, &opts);
        let stage = env.stage(handle, verb);
        let mut args: Vec<&str> = vec![&stage];
        args.extend(required.iter().map(String::as_str));
        args.push("timeout_ms=abc");
        let out = env.run(&args);
        let mut problems: Vec<String> = refusal_problem(handle, &out).into_iter().collect();
        let err = text(&out.stderr);
        if !err.contains("timeout_ms") {
            problems.push(format!(
                "timeout_ms=abc (accepted: {accepts}): the refusal does not name timeout_ms: {err}"
            ));
        } else if accepts && !err.contains("abc") {
            problems.push(format!(
                "timeout_ms=abc: the refusal does not show the bad value: {err}"
            ));
        }
        problems
    });
}

#[test]
fn every_option_in_the_usage_is_accepted() {
    // Each listed option goes with an unknown argument, so the verb is
    // refused whatever happens; the refusal must be about the unknown
    // argument or the option's value, never "unknown option".
    for_every_verb(|env, handle, verb| {
        let mut problems = Vec::new();
        for o in usage_options(&usage(env, handle, verb)) {
            let arg = format!("{}={}", o.name, o.value);
            let out = env.run(&[&env.stage(handle, verb), &arg, &format!("{UNKNOWN}=1")]);
            let err = text(&out.stderr);
            if out.status.code() != Some(2) {
                problems.push(format!(
                    "{arg} {UNKNOWN}=1: exit {:?}: {err}",
                    out.status.code()
                ));
                continue;
            }
            if err.contains(UNKNOWN) {
                continue;
            }
            let lower = err.to_ascii_lowercase();
            let refused_as_unknown = [
                "unknown argument",
                "unknown option",
                "unrecognized",
                "unrecognised",
                "not accepted",
                "does not accept",
                "unexpected argument",
            ]
            .iter()
            .any(|w| lower.contains(w));
            if refused_as_unknown {
                problems.push(format!("{arg} is refused as unknown: {err}"));
            }
        }
        problems
    });
}

#[test]
fn every_help_form_renders_within_80_columns() {
    for_every_verb(|env, handle, verb| {
        let mut problems = Vec::new();
        let canonical = env.run(&[handle, verb, "--help"]);
        let expected = text(&canonical.stdout);
        // The stage forms show the help of the verb the stage runs.
        let staged = text(
            &env.run(&[handle, effective_verb(handle, verb), "--help"])
                .stdout,
        );
        if !canonical.status.success() || expected.is_empty() {
            return vec![format!("--help failed: {}", text(&canonical.stderr))];
        }
        if let Some(l) = expected.lines().find(|l| l.chars().count() > 80) {
            problems.push(format!("help line over 80 columns: {l:?}"));
        }
        let stage = env.stage(handle, verb);
        for (args, expected) in [
            (vec![handle, verb, "-h"], &expected),
            (vec![handle, verb, "help"], &expected),
            (vec!["help", handle, verb], &expected),
            (vec![stage.as_str(), "--help"], &staged),
            (vec![stage.as_str(), "-h"], &staged),
        ] {
            let out = env.run(&args);
            if !out.status.success() {
                problems.push(format!(
                    "{args:?}: exit {:?}: {}",
                    out.status.code(),
                    text(&out.stderr)
                ));
            } else if text(&out.stdout) != *expected {
                problems.push(format!("{args:?} differs from `{handle} {verb} --help`"));
            }
        }
        problems
    });
    // The handle-level forms, including `<scheme>://help`.
    let env = Env::new();
    for (handle, _) in handles_and_verbs(&env) {
        let expected = text(&env.run(&[&handle, "--help"]).stdout);
        assert!(
            expected.lines().all(|l| l.chars().count() <= 80),
            "{handle} --help: a line over 80 columns"
        );
        for form in [format!("{handle}://help"), format!("{handle}://--help")] {
            let out = env.run(&[&form]);
            assert!(out.status.success(), "{form}: {}", text(&out.stderr));
            assert_eq!(text(&out.stdout), expected, "{form}");
        }
    }
}

/// Each handle's tests compare its accepted-options list with its help
/// usage (the other half of `every_option_in_the_usage_is_accepted`).
/// This keeps a record of where that test is, so a handle cannot lose it.
#[test]
fn every_handle_tests_its_accepted_options_against_its_usage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests: &[(&str, &str, &str)] = &[
        (
            "archive",
            "src/handles/filesystem/archive_verb_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_options",
        ),
        (
            "backup",
            "src/handles/automation/backuph_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "cache",
            "src/handles/data/cacheh/tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "cert",
            "src/handles/security/certh/tests.rs",
            "fn accepted_options_match_the_help_usage",
        ),
        (
            "config",
            "src/handles/data/config.rs",
            "fn verb_args_match_help_usage",
        ),
        (
            "cron",
            "src/handles/processes/cronh_tests.rs",
            "fn verb_args_match_help_usage",
        ),
        ("db", "tests/db_verbs.rs", "verb_args(verb)"),
        (
            "dns",
            "src/handles/network/dnsh/verb_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_options",
        ),
        (
            "event",
            "src/handles/data/eventh/tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "file",
            "tests/file_help.rs",
            "fn usage_options_are_exactly_the_parsed_options",
        ),
        (
            "firewall",
            "tests/firewall_verbs.rs",
            "assert_eq!(listed, accepted(verb)",
        ),
        (
            "fs",
            "src/handles/filesystem/fsh_tests.rs",
            "fn option_lists_match_help_usage",
        ),
        (
            "git",
            "tests/git_help.rs",
            "fn usage_options_are_exactly_the_accepted_arguments",
        ),
        (
            "http",
            "src/handles/network/httph_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_options",
        ),
        (
            "log",
            "src/handles/data/logh/tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "mail",
            "src/handles/network/mailh.rs",
            "fn verb_args_match_help_usage",
        ),
        (
            "mq",
            "src/handles/data/mqh/tests.rs",
            "fn every_verb_has_its_arguments_in_the_help_usage",
        ),
        (
            "net",
            "src/handles/network/neth_tests.rs",
            "fn verb_args_match_help_usage",
        ),
        (
            "pkg",
            "src/handles/system/pkg_tests.rs",
            "fn accepted_keys_match_the_help_usage",
        ),
        (
            "plugin",
            "src/handles/pluginh/tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "proc",
            "src/handles/processes/proch_tests.rs",
            "fn verb_args_match_help_usage",
        ),
        (
            "secret",
            "src/handles/security/secreth_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "snapshot",
            "src/handles/filesystem/snapshot_tests.rs",
            "fn help_usage_lists_exactly_the_accepted_options",
        ),
        (
            "ssh",
            "src/handles/network/sshh/tests.rs",
            "fn help_usage_lists_exactly_the_accepted_arguments",
        ),
        (
            "svc",
            "src/handles/processes/svch/tests.rs",
            "assert_eq!(listed, accepted",
        ),
        (
            "system",
            "src/handles/system/systemh/tests.rs",
            "fn accepted_options_match_help_usage_exactly",
        ),
        (
            "template",
            "src/handles/automation/templateh.rs",
            "fn verb_args_match_help_usage",
        ),
        (
            "user",
            "src/handles/security/userh/tests.rs",
            "fn accepted_options_match_the_help_usage",
        ),
    ];
    let env = Env::new();
    let mut missing = Vec::new();
    for (handle, _) in handles_and_verbs(&env) {
        // https is the http handle on another scheme.
        let name = if handle == "https" {
            "http"
        } else {
            handle.as_str()
        };
        match tests.iter().find(|(h, _, _)| *h == name) {
            None => missing.push(format!("{handle}: no entry")),
            Some((_, file, needle)) => {
                let src = std::fs::read_to_string(root.join(file)).unwrap_or_default();
                if !src.contains(needle) {
                    missing.push(format!("{handle}: {file} has no {needle:?}"));
                }
            }
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}
