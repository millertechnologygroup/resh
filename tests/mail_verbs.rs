//! `mail://` verbs and help, run through the real `resh` binary against an
//! in-process SMTP server on 127.0.0.1. Each test uses its own temporary
//! directory as HOME and XDG_CONFIG_HOME (so the profile store is private)
//! and clears the MAIL_* environment. Nothing outside it is touched and no
//! other host is contacted.

#[path = "../src/handles/network/mail_fake_smtp.rs"]
mod fake_smtp;

use fake_smtp::{Behavior, FakeSmtp, header};
use resh::handles::network::mailh::verb_args;
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.out.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
    }

    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "stdout: {}\nstderr: {}", self.out, self.err);
        self
    }

    /// Exit `exit`, JSON error `code`, and the standard stderr line.
    fn fails(self, exit: i32, code: &str) -> Self {
        assert_eq!(
            self.code, exit,
            "stdout: {}\nstderr: {}",
            self.out, self.err
        );
        assert_eq!(self.json()["error"]["code"], code, "{}", self.out);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        self
    }

    /// Exit 2 with no JSON and `Error: [code] ...` naming the problem.
    fn usage(self, code: &str, needle: &str) -> Self {
        assert_eq!(self.code, 2, "stdout: {}\nstderr: {}", self.out, self.err);
        assert!(self.out.is_empty(), "{}", self.out);
        assert!(
            self.err.starts_with(&format!("Error: [{code}] ")),
            "{}",
            self.err
        );
        assert!(self.err.contains(needle), "{:?} lacks {needle:?}", self.err);
        self
    }
}

struct Env {
    tmp: TempDir,
    vars: Vec<(String, String)>,
}

impl Env {
    fn new() -> Self {
        Self {
            tmp: TempDir::new().unwrap(),
            vars: Vec::new(),
        }
    }

    fn var(mut self, k: &str, v: &str) -> Self {
        self.vars.push((k.into(), v.into()));
        self
    }

    fn dir(&self) -> &Path {
        self.tmp.path()
    }

    fn run(&self, args: &[&str]) -> Run {
        let d = self.dir();
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
        cmd.current_dir(d)
            .env("HOME", d)
            .env("XDG_CONFIG_HOME", d.join("config"))
            // Never the host's OS keyring: the debug-build test file store
            // (a test may override this with `unavailable`).
            .env(
                "RESH_TEST_KEYRING",
                format!("file:{}", d.join("keyring.json").display()),
            );
        for k in [
            "MAIL_SMTP_HOST",
            "MAIL_SMTP_PORT",
            "MAIL_SMTP_USERNAME",
            "MAIL_SMTP_PASSWORD",
            "MAIL_FROM",
        ] {
            cmd.env_remove(k);
        }
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let out = cmd.args(args).output().unwrap();
        Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8(out.stdout).unwrap(),
            err: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// Stores and activates profile `work` for `server` (plain text).
    fn profile(&self, server: &FakeSmtp, extra: &[&str]) {
        let mut args = vec![
            "mail://config".to_string(),
            "action=set".into(),
            "profile=work".into(),
            "smtp_host=127.0.0.1".into(),
            server.port_arg(),
            "use_tls=none".into(),
            "from=resh@example.com".into(),
            "is_default=true".into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&a).ok();
    }
}

// --- send -----------------------------------------------------------------

#[test]
fn send_help_example_delivers_through_the_active_profile() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior::default());
    env.profile(&server, &[]);
    // The help example, verbatim.
    let r = env
        .run(&[
            "mail://send",
            "to=alice@example.com",
            "subject=Backup",
            "text_body=Backup done",
        ])
        .ok();
    let v = r.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["attempts"], 1);
    let s = &server.messages()[0];
    assert_eq!(s.rcpt_to, ["alice@example.com"]);
    let data = s.data.as_deref().unwrap();
    assert_eq!(header(data, "Subject").unwrap(), "Backup");
    assert_eq!(
        v["result"]["message_id"],
        header(data, "Message-ID").unwrap().as_str()
    );
}

#[test]
fn send_joins_unquoted_words_and_keeps_values_exact() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior::default());
    env.profile(&server, &[]);
    env.run(&[
        "mail://send",
        "to=a@example.com,b@example.com",
        "bcc=hidden@example.com",
        r#"subject=He said "hi", twice"#,
        "text_body=Backup",
        "done",
    ])
    .ok();
    let s = &server.messages()[0];
    assert_eq!(
        s.rcpt_to,
        ["a@example.com", "b@example.com", "hidden@example.com"]
    );
    let data = s.data.as_deref().unwrap();
    assert_eq!(header(data, "Subject").unwrap(), r#"He said "hi", twice"#);
    assert!(header(data, "Bcc").is_none());
    assert!(!data.contains("hidden@example.com"));
    assert!(data.contains("\r\n\r\nBackup done"), "{data}");
}

#[test]
fn send_uses_mail_environment() {
    let server = FakeSmtp::start(Behavior::default());
    let env = Env::new()
        .var("MAIL_SMTP_HOST", "127.0.0.1")
        .var("MAIL_SMTP_PORT", &server.port.to_string())
        .var("MAIL_FROM", "env@example.com");
    env.run(&[
        "mail://send",
        "to=a@example.com",
        "subject=s",
        "text_body=b",
        "use_tls=none",
    ])
    .ok();
    assert_eq!(
        server.messages()[0].mail_from.as_deref(),
        Some("<env@example.com>")
    );
}

#[test]
fn send_errors_use_the_standard_format_and_exit_codes() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior {
        reject_rcpt: vec!["nobody@example.com".into()],
        ..Behavior::default()
    });
    let port = server.port_arg();
    let base = [
        "mail://send",
        "subject=s",
        "text_body=b",
        "from=f@example.com",
        "smtp_host=127.0.0.1",
        port.as_str(),
        "use_tls=none",
    ];
    let with = |extra: &[&str]| -> Vec<String> {
        base.iter().chain(extra).map(|s| s.to_string()).collect()
    };
    let run = |a: Vec<String>| env.run(&a.iter().map(String::as_str).collect::<Vec<_>>());

    run(with(&["to=nobody@example.com"])).fails(1, "mail.send_smtp_rejected");
    run(with(&[])).fails(2, "mail.send_missing_recipients");
    run(with(&["to=a@example.com", "subjet=x"]))
        .usage("mail.invalid_argument", "did you mean `subject`?");
    // The dispatcher refuses the dry run before the handle runs.
    let r = run(with(&["to=a@example.com", "dry_run"]));
    assert_eq!(r.code, 2);
    assert!(r.err.contains("does not support dry_run"), "{}", r.err);
    let r = run(with(&[
        "to=a@example.com",
        "text_body=b",
        "smtp_port=1",
        "word",
    ]));
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(server.messages().is_empty());
    // No host anywhere.
    env.run(&[
        "mail://send",
        "to=a@example.com",
        "subject=s",
        "text_body=b",
    ])
    .fails(2, "mail.send_smtp_not_configured");
}

#[test]
fn send_times_out_with_exit_124() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior {
        greeting_delay: Duration::from_secs(10),
        ..Behavior::default()
    });
    env.profile(&server, &[]);
    let t = Instant::now();
    let r = env
        .run(&[
            "mail://send",
            "to=a@example.com",
            "subject=s",
            "text_body=b",
            "timeout_ms=400",
        ])
        .fails(124, "mail.send_timeout");
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(r.json()["ok"], false);
}

// --- send_template --------------------------------------------------------

#[test]
fn send_template_help_example_and_real_send() {
    let env = Env::new();
    let r = env
        .run(&[
            "mail://send_template",
            "template=welcome",
            "to=bob@example.com",
            "dry_run=true",
        ])
        .ok();
    assert_eq!(r.json()["rendered"]["subject"], "Welcome to , !");

    let server = FakeSmtp::start(Behavior::default());
    env.profile(&server, &[]);
    env.run(&[
        "mail://send_template",
        "template=welcome",
        "to=bob@example.com",
        r#"vars={"user_name":"Bob","app_name":"Acme"}"#,
    ])
    .ok();
    let s = &server.messages()[0];
    // The profile's sender wins over the template's built-in one.
    assert_eq!(s.mail_from.as_deref(), Some("<resh@example.com>"));
    assert_eq!(
        header(s.data.as_deref().unwrap(), "Subject").unwrap(),
        "Welcome to Acme, Bob!"
    );
    env.run(&["mail://send_template", "template=nope", "to=b@example.com"])
        .fails(1, "mail.send_template_not_found");
}

// --- test -----------------------------------------------------------------

#[test]
fn test_help_example_opens_a_session() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior {
        auth_mechs: Some("PLAIN LOGIN"),
        credentials: Some(("u".into(), "p".into())),
        ..Behavior::default()
    });
    env.profile(&server, &["smtp_username=u", "smtp_password=p"]);
    let r = env.run(&["mail://test", "connection_only=true"]).ok();
    let c = &r.json()["connection"];
    assert_eq!(c["auth_succeeded"], true);
    assert_eq!(c["resolved_ip"], "127.0.0.1");
    assert!(server.wait_sessions(1)[0].auth.is_some());

    let port = format!("smtp_port={}", server.port);
    env.run(&[
        "mail://test",
        "smtp_host=127.0.0.1",
        &port,
        "use_tls=none",
        "smtp_username=u",
        "smtp_password=wrong",
    ])
    .fails(1, "mail.test_auth_failed");
    env.run(&[
        "mail://test",
        "connection_only=true",
        "send_test_email=true",
    ])
    .usage("mail.invalid_argument", "conflict");
}

// --- config ---------------------------------------------------------------

#[test]
fn config_help_example_and_store_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let r = env.run(&["mail://config", "action=list"]).ok();
    assert_eq!(r.json()["profiles"], serde_json::json!([]));
    assert!(!env.dir().join("config").exists());
    env.run(&[
        "mail://config",
        "action=set",
        "profile=work",
        "smtp_host=smtp.example.com",
        "smtp_password=secret",
    ])
    .ok();
    let store = env.dir().join("config/resh/mail/smtp_profiles.json");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&store), 0o600);
    assert_eq!(mode(store.parent().unwrap()), 0o700);
    assert_eq!(mode(&env.dir().join("config/resh")), 0o700);
    let r = env
        .run(&["mail://config", "action=get", "profile=work"])
        .ok();
    assert!(!r.out.contains("secret"));
    env.run(&["mail://config", "action=get", "profile=none"])
        .fails(1, "mail.config_profile_not_found");
    env.run(&["mail://config", "action=list", "timeout_ms=5"])
        .usage("mail.invalid_argument", "timeout_ms");
    env.run(&["mail://config", "action=list", "profile=work"])
        .usage("mail.config_invalid_flag", "profile");
    env.run(&["mail://config", "action=frob"])
        .usage("mail.config_invalid_action", "frob");
}

// --- keyring and ca_file ----------------------------------------------------

#[test]
fn profile_passwords_live_in_the_keyring_not_the_file() {
    let env = Env::new();
    let server = FakeSmtp::start(Behavior {
        auth_mechs: Some("LOGIN"),
        credentials: Some(("u".into(), "p@ss".into())),
        ..Behavior::default()
    });
    env.profile(&server, &["smtp_username=u", "smtp_password=p@ss"]);
    let store =
        std::fs::read_to_string(env.dir().join("config/resh/mail/smtp_profiles.json")).unwrap();
    assert!(!store.contains("p@ss") && store.contains("keyring:resh-mail-smtp/work"));
    let keyring = std::fs::read_to_string(env.dir().join("keyring.json")).unwrap();
    assert!(keyring.contains("p@ss"));
    env.run(&["mail://test"]).ok();
    assert_eq!(server.wait_sessions(1)[0].auth.as_ref().unwrap().2, "p@ss");

    // Without a keyring: refused, nothing changed.
    let env2 = Env::new().var("RESH_TEST_KEYRING", "unavailable");
    env2.run(&[
        "mail://config",
        "action=set",
        "profile=x",
        "smtp_host=h.example.com",
        "smtp_password=p",
    ])
    .fails(1, "mail.config_keyring_unavailable");
    assert!(
        !env2
            .dir()
            .join("config/resh/mail/smtp_profiles.json")
            .exists()
    );
}

#[test]
fn ca_file_is_validated() {
    let env = Env::new();
    std::fs::write(env.dir().join("bad.pem"), "nope").unwrap();
    env.run(&[
        "mail://test",
        "smtp_host=127.0.0.1",
        "use_tls=tls",
        "ca_file=bad.pem",
    ])
    .usage("mail.invalid_argument", "no PEM certificate");
    env.run(&[
        "mail://test",
        "smtp_host=127.0.0.1",
        "use_tls=none",
        "ca_file=bad.pem",
    ])
    .usage("mail.invalid_argument", "conflicts with use_tls=none");
}

// --- help -----------------------------------------------------------------

const VERBS: [&str; 4] = ["test", "config", "send", "send_template"];

fn golden(verb: Option<&str>) -> &'static str {
    match verb {
        None => include_str!("golden/mail_help.txt"),
        Some("test") => include_str!("golden/mail_test_help.txt"),
        Some("config") => include_str!("golden/mail_config_help.txt"),
        Some("send") => include_str!("golden/mail_send_help.txt"),
        Some("send_template") => include_str!("golden/mail_send_template_help.txt"),
        Some(v) => panic!("no golden for {v}"),
    }
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii() && !out.contains('\x1b'));
    for l in out.lines() {
        assert!(l.len() <= 80, "line over 80 columns: {l:?}");
        assert!(!l.ends_with(' '), "trailing space: {l:?}");
    }
}

#[test]
fn handle_help_matches_golden_and_lists_registered_verbs() {
    let env = Env::new();
    for form in [
        vec!["mail", "--help"],
        vec!["mail", "-h"],
        vec!["mail", "help"],
        vec!["help", "mail"],
        vec!["mail://--help"],
        vec!["mail://-h"],
    ] {
        let r = env.run(&form).ok();
        assert_eq!(r.out, golden(None), "{form:?}");
    }
    let out = golden(None);
    assert_plain_text(out);
    let listed: Vec<&str> = out
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    let mut sorted = listed.clone();
    sorted.sort();
    let mut expected = VERBS.to_vec();
    expected.sort();
    assert_eq!(sorted, expected);
}

#[test]
fn verb_help_matches_golden_and_lists_exactly_the_accepted_options() {
    let env = Env::new();
    for verb in VERBS {
        for form in [
            vec!["mail", verb, "--help"],
            vec!["mail", verb, "-h"],
            vec!["help", "mail", verb],
        ] {
            let r = env.run(&form).ok();
            assert_eq!(r.out, golden(Some(verb)), "{form:?}");
        }
        let out = golden(Some(verb));
        assert_plain_text(out);
        for section in ["Usage:\n", "Example:\n", "Example Output:\n"] {
            assert!(out.contains(section), "{verb}: {section}");
        }
        let usage = out
            .split("Usage:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        let mut listed: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .filter(|k| *k != "header_<Name>")
            .collect();
        listed.sort();
        listed.dedup();
        let mut accepted = verb_args(verb).unwrap().to_vec();
        accepted.sort();
        assert_eq!(listed, accepted, "{verb}");
    }
}

/// Writes the goldens from the current binary: run with
/// `UPDATE_GOLDEN=1 cargo test --test mail_verbs write_goldens`.
#[test]
fn write_goldens() {
    if std::env::var("UPDATE_GOLDEN").is_err() {
        return;
    }
    let env = Env::new();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    std::fs::write(dir.join("mail_help.txt"), env.run(&["mail", "--help"]).out).unwrap();
    for verb in VERBS {
        std::fs::write(
            dir.join(format!("mail_{verb}_help.txt")),
            env.run(&["mail", verb, "--help"]).out,
        )
        .unwrap();
    }
}
