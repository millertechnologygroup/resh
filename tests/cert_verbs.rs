//! Integration tests for `cert://` through the built `resh` binary, in
//! temporary directories. Each verb runs at least once here, outputs are
//! cross-checked with `openssl` when it is installed, and every help form
//! is compared with its golden file; the help examples run here too.

use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const VERBS: &[&str] = &[
    "info",
    "verify",
    "chain.info",
    "generate",
    "csr.create",
    "sign",
    "csr.sign",
    "renew",
];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.code, 0, "{}\n{}", self.stdout, self.stderr);
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) {
        assert_eq!(self.code, exit, "{}\n{}", self.stdout, self.stderr);
        assert!(
            self.stderr
                .lines()
                .any(|l| l.starts_with(&format!("Error: [{code}] "))),
            "{code}: {}",
            self.stderr
        );
        if !self.stdout.is_empty() {
            assert_eq!(self.json["ok"], false, "{}", self.stdout);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
    }
}

fn resh_in(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(assert_cmd::cargo::cargo_bin!("resh"))
        .env_remove("SSH_AUTH_SOCK")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn openssl(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    assert!(
        out.status.success(),
        "openssl {args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

fn have_openssl() -> bool {
    which::which("openssl").is_ok()
}

/// ca.pem/ca-key.pem (encrypted with "ca pass"), web-key.pem, web.csr and
/// web.pem issued by the CA, made through the binary.
fn workflow(d: &Path) {
    resh_in(
        d,
        &[
            "cert://./ca.generate",
            "mode=self_signed",
            "algorithm=ecdsa",
            "is_ca=true",
            r#"subject={"common_name":"Example CA"}"#,
            "key_passphrase=ca pass",
        ],
    )
    .ok();
    resh_in(
        d,
        &[
            "cert://./web.csr.csr.create",
            "key_strategy=generate",
            "algorithm=rsa",
            "new_key_output_path=web-key.pem",
            r#"subject={"common_name":"web.test"}"#,
            r#"sans=["DNS:web.test","IP:127.0.0.1"]"#,
            "key_usage=digitalSignature,keyEncipherment",
            "extended_key_usage=serverAuth",
        ],
    )
    .ok();
    resh_in(
        d,
        &[
            "cert://./ca.sign",
            "mode=csr",
            "csr_source=web.csr",
            "signer_cert=ca.pem",
            "signer_key=ca-key.pem",
            "signer_key_passphrase=ca pass",
            "cert_output_path=web.pem",
            "key_usage=digitalSignature,keyEncipherment",
        ],
    )
    .ok();
}

// ---------------------------------------------------------------------------
// One test per verb
// ---------------------------------------------------------------------------

#[test]
fn generate_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    let mode = std::fs::metadata(d.join("ca-key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let key = std::fs::read_to_string(d.join("ca-key.pem")).unwrap();
    assert!(key.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    resh_in(
        d,
        &[
            "cert://./x.generate",
            "ecdsa_curve=P-521",
            "algorithm=ecdsa",
        ],
    )
    .fails(2, "cert.invalid_argument");
    resh_in(d, &["cert://./x.generate", "rsa_bits=4096", "timeout_ms=1"])
        .fails(124, "cert.timeout");
    assert!(!d.join("x-key.pem").exists());
    if have_openssl() {
        let text = openssl(d, &["x509", "-in", "ca.pem", "-noout", "-text"]).unwrap();
        assert!(text.contains("CA:TRUE"), "{text}");
        openssl(
            d,
            &[
                "pkey",
                "-in",
                "ca-key.pem",
                "-passin",
                "pass:ca pass",
                "-noout",
            ],
        );
        // A key encrypted by openssl is read with its passphrase.
        openssl(
            d,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-384",
                "-aes256",
                "-pass",
                "pass:ossl pass",
                "-out",
                "ossl-key.pem",
            ],
        );
        let v = resh_in(
            d,
            &[
                "cert://./o.csr.csr.create",
                r#"subject={"common_name":"o"}"#,
                "existing_key_path=ossl-key.pem",
                "existing_key_passphrase=ossl pass",
            ],
        )
        .ok()
        .clone();
        assert_eq!(v["key"]["ecdsa_curve"], "P-384");
        assert_eq!(v["key"]["encrypted"], true);
        openssl(d, &["req", "-in", "o.csr", "-noout", "-verify"]);
    }
}

#[test]
fn csr_create_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    let mode = std::fs::metadata(d.join("web-key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    if have_openssl() {
        let text = openssl(d, &["req", "-in", "web.csr", "-noout", "-verify", "-text"]).unwrap();
        assert!(text.contains("DNS:web.test"), "{text}");
        assert!(text.contains("Key Encipherment"), "{text}");
        assert!(text.contains("TLS Web Server Authentication"), "{text}");
    }
    resh_in(
        d,
        &["cert://./z.csr.csr.create", "existing_key_path=web-key.pem"],
    )
    .fails(2, "cert.invalid_argument");
}

#[test]
fn sign_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    std::fs::write(d.join("data"), b"signed data").unwrap();
    resh_in(
        d,
        &[
            "cert://./web.sign",
            "signer_key=web-key.pem",
            "signature_algorithm=rsa_pkcs1_sha256",
            "data_source=data",
            "signature_encoding=der",
            "signature_output_path=data.sig",
        ],
    )
    .ok();
    if have_openssl() {
        openssl(
            d,
            &[
                "x509",
                "-in",
                "web.pem",
                "-pubkey",
                "-noout",
                "-out",
                "web-pub.pem",
            ],
        );
        let out = openssl(
            d,
            &[
                "dgst",
                "-sha256",
                "-verify",
                "web-pub.pem",
                "-signature",
                "data.sig",
                "data",
            ],
        )
        .unwrap();
        assert!(out.contains("Verified OK"), "{out}");
        let text = openssl(d, &["x509", "-in", "web.pem", "-noout", "-text"]).unwrap();
        assert!(text.contains("Issuer: CN=Example CA"), "{text}");
        assert!(text.contains("IP Address:127.0.0.1"), "{text}");
        let out = openssl(d, &["verify", "-CAfile", "ca.pem", "web.pem"]).unwrap();
        assert!(out.contains("web.pem: OK"), "{out}");
    }
    resh_in(
        d,
        &[
            "cert://./web.sign",
            "signer_key=ca-key.pem",
            "data_source=data",
        ],
    )
    .fails(2, "cert.passphrase_required");
}

#[test]
fn info_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    let v = resh_in(
        d,
        &["cert://./web.pem.info", "fingerprint_algs=sha1,sha256"],
    )
    .ok()
    .clone();
    let o = &v["objects"][0];
    assert_eq!(o["public_key"]["algorithm"], "RSA");
    assert_eq!(o["public_key"]["key_size"], 2048);
    if have_openssl() {
        let fp = openssl(
            d,
            &[
                "x509",
                "-in",
                "web.pem",
                "-noout",
                "-fingerprint",
                "-sha256",
            ],
        )
        .unwrap();
        assert!(
            fp.contains(o["fingerprints"]["sha256"].as_str().unwrap()),
            "{fp}"
        );
        let serial = openssl(d, &["x509", "-in", "web.pem", "-noout", "-serial"]).unwrap();
        assert!(
            serial.contains(o["serial_number"].as_str().unwrap()),
            "{serial}"
        );
    }
    resh_in(d, &["cert://./missing.pem.info"]).fails(1, "cert.not_found");
}

#[test]
fn verify_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    let v = resh_in(
        d,
        &[
            "cert://./web.pem.verify",
            "ca_file=ca.pem",
            "hostname=web.test",
            "purpose=server_auth",
            "keypair_target=web-key.pem",
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["checks"]["chain"]["status"], "passed");
    let r = resh_in(
        d,
        &[
            "cert://./web.pem.verify",
            "ca_file=ca.pem",
            "hostname=other.test",
        ],
    );
    r.fails(1, "cert.verification_failed");
    assert_eq!(r.json["checks"]["hostname"]["status"], "failed");
    // The default trust=system reads SSL_CERT_FILE.
    let out = Command::new(assert_cmd::cargo::cargo_bin!("resh"))
        .current_dir(d)
        .env("SSL_CERT_FILE", d.join("ca.pem"))
        .args(["cert://./web.pem.verify"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn chain_info_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    let bundle = std::fs::read_to_string(d.join("web.pem")).unwrap()
        + &std::fs::read_to_string(d.join("ca.pem")).unwrap();
    std::fs::write(d.join("bundle.pem"), bundle).unwrap();
    let v = resh_in(d, &["cert://./bundle.pem.chain.info", "ca_file=ca.pem"])
        .ok()
        .clone();
    assert_eq!(v["chains"][0]["trust_status"], "trusted");
    assert_eq!(v["chains"][0]["length"], 2);
    let v = resh_in(d, &["cert://./bundle.pem.chain.info"]).ok().clone();
    assert_eq!(v["chains"][0]["trust_status"], "untrusted_root");
    resh_in(d, &["cert://./bundle.pem.chain.info", "trust=inline"])
        .fails(2, "cert.invalid_argument");
}

#[test]
fn renew_verb() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    workflow(d);
    resh_in(d, &["cert://./web.pem.renew"]).fails(2, "cert.signer_required");
    let v = resh_in(
        d,
        &[
            "cert://./web.pem.renew",
            "signer_ca=ca.pem",
            "signer_key=ca-key.pem",
            "signer_key_passphrase=ca pass",
            "existing_key_path=web-key.pem",
            "not_after_offset_days=90",
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["new_cert"]["sans"][0], "DNS:web.test");
    if have_openssl() {
        let out = openssl(d, &["verify", "-CAfile", "ca.pem", "web-renewed.pem"]).unwrap();
        assert!(out.contains("OK"), "{out}");
        let a = openssl(d, &["x509", "-in", "web.pem", "-noout", "-pubkey"]).unwrap();
        let b = openssl(d, &["x509", "-in", "web-renewed.pem", "-noout", "-pubkey"]).unwrap();
        assert_eq!(a, b);
    }
}

/// csr.sign cannot be reached from the command line: `cert://x.csr.sign`
/// runs `sign` with the target `x.csr` (see tests/help_coverage.rs).
#[test]
fn csr_sign_is_parsed_as_sign() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let r = resh_in(d, &["cert://./req.csr.sign", "signer_ca=ca.pem"]);
    r.fails(2, "cert.invalid_argument");
    assert!(r.stderr.contains("cert sign"), "{}", r.stderr);
}

#[test]
fn text_failures_print_only_the_error_line() {
    let tmp = tempfile::tempdir().unwrap();
    let r = resh_in(tmp.path(), &["cert://./none.pem.info", "format=text"]);
    r.fails(1, "cert.not_found");
    assert!(r.stdout.is_empty());
    let r = resh_in(tmp.path(), &["cert://./x.info", "incldue_pem=true"]);
    r.fails(2, "cert.invalid_argument");
    assert!(
        r.stderr.contains("did you mean `include_pem`"),
        "{}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn golden(verb: &str) -> &'static str {
    match verb {
        "info" => include_str!("golden/cert_info_help.txt"),
        "verify" => include_str!("golden/cert_verify_help.txt"),
        "chain.info" => include_str!("golden/cert_chain_info_help.txt"),
        "generate" => include_str!("golden/cert_generate_help.txt"),
        "csr.create" => include_str!("golden/cert_csr_create_help.txt"),
        "sign" => include_str!("golden/cert_sign_help.txt"),
        "csr.sign" => include_str!("golden/cert_csr_sign_help.txt"),
        "renew" => include_str!("golden/cert_renew_help.txt"),
        _ => unreachable!(),
    }
}

#[test]
fn handle_help_matches_golden_in_every_form() {
    let tmp = tempfile::tempdir().unwrap();
    let want = include_str!("golden/cert_help.txt");
    for args in [
        &["cert", "--help"][..],
        &["cert", "-h"][..],
        &["cert", "help"][..],
        &["help", "cert"][..],
        &["cert://--help"][..],
    ] {
        let r = resh_in(tmp.path(), args);
        assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
        assert_eq!(r.stdout, want, "{args:?}");
    }
    assert!(want.lines().all(|l| l.len() <= 80));
}

#[test]
fn verb_help_matches_golden() {
    let tmp = tempfile::tempdir().unwrap();
    for verb in VERBS {
        for args in [
            vec!["cert", verb, "--help"],
            vec!["cert", verb, "-h"],
            vec!["help", "cert", verb],
        ] {
            let r = resh_in(tmp.path(), &args);
            assert_eq!(r.code, 0, "{args:?}");
            assert_eq!(r.stdout, golden(verb), "{args:?}: help differs from golden");
        }
        assert!(golden(verb).lines().all(|l| l.len() <= 80), "{verb}");
    }
    let r = resh_in(tmp.path(), &["cert", "verfy", "--help"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("verify"), "{}", r.stderr);
}

/// The example command line and its sample output from a golden file.
fn example(verb: &str) -> (Vec<String>, String) {
    let text = golden(verb);
    let line = text
        .lines()
        .skip_while(|l| *l != "Example:")
        .nth(1)
        .unwrap()
        .trim();
    // Minimal shell splitting: single quotes only.
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    words.push(cur);
    assert_eq!(words[0], "resh");
    let sample = match text.find("Example Output:") {
        Some(start) => text[start..]
            .lines()
            .skip(1)
            .take_while(|l| !l.trim_start().starts_with("Shown"))
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    };
    (words[1..].to_vec(), sample.trim().to_string())
}

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// The text before ':' on every line (the labels of a text report).
fn labels(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.split(':').next().unwrap_or("").trim_end().to_string())
        .collect()
}

/// Every help example runs in a directory holding the files it names, and
/// its output has the shape of the sample.
#[test]
fn help_examples_run() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    let r = |args: &[&str]| resh_in(d, args).ok().clone();
    r(&[
        "cert://./ca.generate",
        "mode=self_signed",
        "algorithm=ecdsa",
        "is_ca=true",
        r#"subject={"common_name":"Example CA"}"#,
    ]);
    r(&[
        "cert://./web.generate",
        "mode=leaf_cert",
        "algorithm=ecdsa",
        r#"subject={"common_name":"web.test"}"#,
        "sans=DNS:web.test",
        "signer_ca=ca.pem",
        "signer_key=ca-key.pem",
    ]);
    std::fs::copy(d.join("web.pem"), d.join("server.pem")).unwrap();
    let bundle = std::fs::read_to_string(d.join("web.pem")).unwrap()
        + &std::fs::read_to_string(d.join("ca.pem")).unwrap();
    std::fs::write(d.join("bundle.pem"), bundle).unwrap();
    r(&["cert://./k.generate", "algorithm=ecdsa"]);
    std::fs::rename(d.join("k-key.pem"), d.join("k")).unwrap();
    std::fs::write(d.join("app.tar"), vec![0u8; 20480]).unwrap();

    for verb in [
        "info",
        "verify",
        "chain.info",
        "generate",
        "csr.create",
        "sign",
        "renew",
    ] {
        if verb == "renew" {
            // The renew sample is a self-signed certificate.
            std::fs::copy(d.join("ca.pem"), d.join("server.pem")).unwrap();
            std::fs::copy(d.join("ca-key.pem"), d.join("server-key.pem")).unwrap();
        }
        let (args, sample) = example(verb);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = resh_in(d, &args);
        assert_eq!(run.code, 0, "{verb}: {}\n{}", run.stdout, run.stderr);
        if sample.starts_with('{') {
            let want: Value = serde_json::from_str(&sample).unwrap();
            assert_eq!(keys(&run.json), keys(&want), "{verb}");
            if verb == "info" {
                assert_eq!(keys(&run.json["objects"][0]), keys(&want["objects"][0]));
            }
            if verb == "sign" {
                assert_eq!(run.json["warnings"], want["warnings"]);
            }
        } else {
            assert_eq!(
                labels(run.stdout.trim()),
                labels(&sample),
                "{verb}: {}",
                run.stdout
            );
        }
    }
    // csr.sign's example is the sign help.
    assert_eq!(example("csr.sign").0, vec!["cert", "sign", "--help"]);
}
