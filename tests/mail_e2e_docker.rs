//! `mail://` against a real SMTP server (axllent/mailpit) in a throwaway
//! Docker container, published on 127.0.0.1 only: STARTTLS and implicit TLS
//! with a self-signed certificate (refused unless
//! tls_accept_invalid_certs=true), AUTH, and the message as mailpit stored
//! it. Run with `cargo test --features e2e-docker --test mail_e2e_docker`.
#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

const IMAGE: &str = "axllent/mailpit:v1.21";

/// A mailpit container, removed on drop.
struct Mailpit {
    id: String,
    smtp_port: u16,
    api: String,
    _certs: TempDir,
}

impl Mailpit {
    /// `implicit_tls`: TLS from the first byte; otherwise STARTTLS is
    /// required. Any user name and password are accepted.
    fn start(implicit_tls: bool) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![
            "127.0.0.1".to_string(),
            "localhost".to_string(),
        ])
        .unwrap();
        Self::start_with(
            implicit_tls,
            &cert.serialize_pem().unwrap(),
            &cert.serialize_private_key_pem(),
        )
    }

    /// Like `start`, with the given server certificate and key.
    fn start_with(implicit_tls: bool, cert_pem: &str, key_pem: &str) -> Self {
        let certs = TempDir::new().unwrap();
        std::fs::write(certs.path().join("cert.pem"), cert_pem).unwrap();
        std::fs::write(certs.path().join("key.pem"), key_pem).unwrap();
        // The container user must read the key.
        use std::os::unix::fs::PermissionsExt;
        for f in ["cert.pem", "key.pem"] {
            std::fs::set_permissions(certs.path().join(f), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        std::fs::set_permissions(certs.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let mode = if implicit_tls {
            "--smtp-require-tls"
        } else {
            "--smtp-require-starttls"
        };
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "-p",
                "127.0.0.1::1025",
                "-p",
                "127.0.0.1::8025",
            ])
            .arg("-v")
            .arg(format!("{}:/certs:ro", certs.path().display()))
            .args([
                IMAGE,
                "--smtp-tls-cert",
                "/certs/cert.pem",
                "--smtp-tls-key",
                "/certs/key.pem",
                mode,
                "--smtp-auth-accept-any",
            ])
            .output()
            .expect("docker");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let port = |p: &str| -> u16 {
            let o = Command::new("docker")
                .args(["port", &id, p])
                .output()
                .unwrap();
            let s = String::from_utf8(o.stdout).unwrap();
            s.lines()
                .next()
                .and_then(|l| l.rsplit(':').next())
                .and_then(|p| p.trim().parse().ok())
                .unwrap_or_else(|| panic!("no port for {p}: {s}"))
        };
        let m = Self {
            smtp_port: port("1025/tcp"),
            api: format!("http://127.0.0.1:{}/api/v1", port("8025/tcp")),
            id,
            _certs: certs,
        };
        for _ in 0..100 {
            if reqwest::blocking::get(format!("{}/messages", m.api))
                .is_ok_and(|r| r.status().is_success())
            {
                return m;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("mailpit did not start");
    }

    fn messages(&self) -> Vec<Value> {
        let v: Value = reqwest::blocking::get(format!("{}/messages", self.api))
            .unwrap()
            .json()
            .unwrap();
        v["messages"].as_array().cloned().unwrap_or_default()
    }

    fn raw(&self, id: &str) -> String {
        reqwest::blocking::get(format!("{}/message/{id}/raw", self.api))
            .unwrap()
            .text()
            .unwrap()
    }

    fn message(&self, id: &str) -> Value {
        reqwest::blocking::get(format!("{}/message/{id}", self.api))
            .unwrap()
            .json()
            .unwrap()
    }
}

impl Drop for Mailpit {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn resh(home: &Path, args: &[&str]) -> (i32, Value, String) {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        // Never the host's OS keyring (the real keyring is tested inside a
        // container below).
        .env(
            "RESH_TEST_KEYRING",
            format!("file:{}", home.join("keyring.json").display()),
        )
        .env_remove("MAIL_SMTP_HOST")
        .env_remove("MAIL_SMTP_PORT")
        .env_remove("MAIL_FROM")
        .env_remove("MAIL_SMTP_USERNAME")
        .env_remove("MAIL_SMTP_PASSWORD")
        .args(args)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (
        out.status.code().unwrap_or(-1),
        json,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn starttls_send_with_auth_cc_bcc_and_attachment() {
    let mp = Mailpit::start(false);
    let home = TempDir::new().unwrap();
    let port = format!("smtp_port={}", mp.smtp_port);
    let att = home.path().join("report.csv");
    std::fs::write(&att, "a,b\n1,2\n").unwrap();
    let atts = format!(r#"attachments=[{{"path":"{}"}}]"#, att.display());
    let base = [
        "mail://send",
        "smtp_host=127.0.0.1",
        port.as_str(),
        "use_tls=starttls",
        "smtp_username=alice",
        "smtp_password=pw",
        "from=resh@example.com",
        "to=alice@example.com",
        "cc=carol@example.com",
        "bcc=dave@example.com",
        "subject=E2E report",
        "text_body=see attachment",
        "html_body=<p>see attachment</p>",
    ];

    // The self-signed certificate is refused by default.
    let (code, v, err) = resh(home.path(), &base);
    assert_eq!(code, 1, "{v} {err}");
    assert_eq!(v["error"]["code"], "mail.send_smtp_tls_error", "{v}");
    assert!(mp.messages().is_empty());

    let mut args = base.to_vec();
    args.push("tls_accept_invalid_certs=true");
    args.push(&atts);
    let (code, v, err) = resh(home.path(), &args);
    assert_eq!(code, 0, "{v} {err}");
    let msgs = mp.messages();
    assert_eq!(msgs.len(), 1);
    let id = msgs[0]["ID"].as_str().unwrap();
    let m = mp.message(id);
    assert_eq!(m["Subject"], "E2E report");
    assert_eq!(m["To"][0]["Address"], "alice@example.com");
    assert_eq!(m["Cc"][0]["Address"], "carol@example.com");
    // Bcc is delivered (envelope) but not in the headers.
    assert_eq!(m["Bcc"][0]["Address"], "dave@example.com");
    // mailpit prepends its own Bcc/Return-Path/Received lines; the message
    // resh sent starts at its Message-ID header and has no Bcc header.
    let raw = mp.raw(id);
    let sent = &raw[raw.find("Message-ID:").expect("Message-ID")..];
    assert!(
        !sent
            .lines()
            .any(|l| l.to_ascii_lowercase().starts_with("bcc:")),
        "{raw}"
    );
    assert_eq!(m["Attachments"][0]["FileName"], "report.csv");
    assert_eq!(m["Text"].as_str().unwrap().trim(), "see attachment");
    assert_eq!(
        v["result"]["message_id"]
            .as_str()
            .unwrap()
            .trim_matches(['<', '>']),
        m["MessageID"].as_str().unwrap()
    );
}

#[test]
fn implicit_tls_test_and_send_template() {
    let mp = Mailpit::start(true);
    let home = TempDir::new().unwrap();
    let port = format!("smtp_port={}", mp.smtp_port);
    let (code, v, err) = resh(
        home.path(),
        &[
            "mail://config",
            "action=set",
            "profile=pit",
            "smtp_host=127.0.0.1",
            &port,
            "use_tls=tls",
            "smtp_username=u",
            "smtp_password=p",
            "tls_accept_invalid_certs=true",
            "from=pit@example.com",
            "is_default=true",
        ],
    );
    assert_eq!(code, 0, "{v} {err}");

    let (code, v, err) = resh(home.path(), &["mail://test", "connection_only=true"]);
    assert_eq!(code, 0, "{v} {err}");
    assert_eq!(v["connection"]["tls_established"], true);
    assert_eq!(v["connection"]["auth_succeeded"], true);

    let (code, v, err) = resh(
        home.path(),
        &[
            "mail://send_template",
            "template=password_reset",
            "to=bob@example.com",
            r#"vars={"user_name":"Bob","reset_link":"https://example.com/r/1"}"#,
        ],
    );
    assert_eq!(code, 0, "{v} {err}");
    let msgs = mp.messages();
    assert_eq!(msgs.len(), 1);
    let m = mp.message(msgs[0]["ID"].as_str().unwrap());
    assert_eq!(m["From"]["Address"], "pit@example.com");
    assert_eq!(m["Subject"], "Reset your password");
    assert!(
        m["HTML"]
            .as_str()
            .unwrap()
            .contains("https://example.com/r/1")
    );

    // Certificate verification on: the test fails with a TLS error.
    let (code, v, _) = resh(
        home.path(),
        &["mail://test", "tls_accept_invalid_certs=false"],
    );
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["error"]["code"], "mail.test_tls_error");
}

/// A server certificate signed by a private CA: refused by default,
/// accepted with `ca_file=` (verification on, host name checked).
#[test]
fn private_ca_with_ca_file() {
    use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "resh test CA");
    let ca = Certificate::from_params(ca_params).unwrap();
    let mut leaf_params = CertificateParams::new(Vec::<String>::new());
    leaf_params.subject_alt_names = vec![
        SanType::DnsName("localhost".into()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    let leaf = Certificate::from_params(leaf_params).unwrap();
    let mp = Mailpit::start_with(
        false,
        &leaf.serialize_pem_with_signer(&ca).unwrap(),
        &leaf.serialize_private_key_pem(),
    );
    let home = TempDir::new().unwrap();
    std::fs::write(home.path().join("ca.pem"), ca.serialize_pem().unwrap()).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["x".to_string()]).unwrap();
    std::fs::write(
        home.path().join("other.pem"),
        other.serialize_pem().unwrap(),
    )
    .unwrap();
    let port = format!("smtp_port={}", mp.smtp_port);
    let send = |extra: &[&str]| {
        let mut a = vec![
            "mail://send",
            "smtp_host=127.0.0.1",
            port.as_str(),
            "use_tls=starttls",
            "from=resh@example.com",
            "to=a@example.com",
            "subject=private CA",
            "text_body=b",
        ];
        a.extend_from_slice(extra);
        resh(home.path(), &a)
    };
    let (code, v, _) = send(&[]);
    assert_eq!(
        (code, v["error"]["code"].as_str()),
        (1, Some("mail.send_smtp_tls_error"))
    );
    let (code, v, _) = send(&["ca_file=other.pem"]);
    assert_eq!(
        (code, v["error"]["code"].as_str()),
        (1, Some("mail.send_smtp_tls_error"))
    );
    let (code, v, err) = send(&["ca_file=ca.pem"]);
    assert_eq!(code, 0, "{v} {err}");
    assert_eq!(mp.messages().len(), 1);
    // test and send_template take it too.
    let (code, v, err) = resh(
        home.path(),
        &[
            "mail://test",
            "smtp_host=127.0.0.1",
            &port,
            "ca_file=ca.pem",
        ],
    );
    assert_eq!(code, 0, "{v} {err}");
    assert_eq!(v["connection"]["tls_established"], true);
    let (code, v, err) = resh(
        home.path(),
        &[
            "mail://send_template",
            "template=welcome",
            "to=b@example.com",
            "from=resh@example.com",
            "smtp_host=127.0.0.1",
            &port,
            "ca_file=ca.pem",
        ],
    );
    assert_eq!(code, 0, "{v} {err}");
    assert_eq!(mp.messages().len(), 2);
}

/// The real OS keyring: a Debian container with gnome-keyring as the
/// Secret Service on a private D-Bus session. `config set` stores the
/// password in the keyring (not the file), `test` reads it back, `delete`
/// removes it; without a session bus `config set` refuses.
#[test]
fn real_keyring_in_a_container() {
    const IMAGE: &str = "resh-mail-keyring:1";
    let have = Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .output()
        .unwrap();
    if !have.status.success() {
        let mut child = Command::new("docker")
            .args(["build", "-q", "-t", IMAGE, "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"FROM debian:13-slim\nRUN apt-get update && apt-get install -y --no-install-recommends dbus dbus-x11 gnome-keyring libsecret-tools ca-certificates && rm -rf /var/lib/apt/lists/*\n",
            )
            .unwrap();
        assert!(child.wait().unwrap().success(), "image build failed");
    }
    let bin = std::path::Path::new(env!("CARGO_BIN_EXE_resh"));
    let script = r#"
set -u
export HOME=/tmp/h; mkdir -p $HOME
dbus-run-session -- bash -c '
  echo -n unlock | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
  sleep 1
  resh mail://config action=set profile=k smtp_host=127.0.0.1 smtp_port=1 use_tls=none smtp_username=u smtp_password=s3cr3t-pw is_default=true >/dev/null; echo "SET=$?"
  echo "FILE=$(tr -d "\n " < $HOME/.config/resh/mail/smtp_profiles.json)"
  echo "LOOKUP=$(secret-tool lookup service resh-mail-smtp username k)"
  resh mail://test > /tmp/test.json; echo "TEST=$?"; echo "TESTCODE=$(grep -o "mail\.test_[a-z_]*" /tmp/test.json | head -1)"
  resh mail://config action=delete profile=k >/dev/null; echo "DEL=$?"
  echo "AFTER=$(secret-tool lookup service resh-mail-smtp username k)"
'
env -u DBUS_SESSION_BUS_ADDRESS resh mail://config action=set profile=n smtp_host=h.example.com smtp_password=x > /tmp/nokr.json 2>/dev/null; echo "NOKR=$?"
echo "NOKRCODE=$(grep -o "mail\.config_[a-z_]*" /tmp/nokr.json | head -1)"
"#;
    let out = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/usr/local/bin/resh:ro", bin.display()))
        .args([IMAGE, "bash", "-c", script])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("no {k} in {text}\n{}", String::from_utf8_lossy(&out.stderr)))
            .to_string()
    };
    assert_eq!(get("SET"), "0", "{text}");
    let file = get("FILE");
    assert!(!file.contains("s3cr3t-pw"), "{file}");
    assert!(file.contains("keyring:resh-mail-smtp/k"), "{file}");
    assert_eq!(get("LOOKUP"), "s3cr3t-pw", "{text}");
    // The password was read from the keyring; the session then failed to
    // connect (nothing listens on port 1).
    assert_eq!(get("TEST"), "1");
    assert_eq!(get("TESTCODE"), "mail.test_connection_failed", "{text}");
    assert_eq!(get("DEL"), "0");
    assert_eq!(get("AFTER"), "");
    assert_eq!(get("NOKR"), "1", "{text}");
    assert_eq!(get("NOKRCODE"), "mail.config_keyring_unavailable", "{text}");
}
