//! `cert sign signature_format=cms_detached|cms_attached` through the real
//! `resh` binary, cross-checked with `openssl cms -verify`. Keys and
//! self-signed certificates are made with the openssl CLI; every test is
//! skipped when `openssl` is not on PATH. Each test runs in its own
//! temporary directory.

use assert_cmd::Command;
use std::path::Path;
use std::process::Command as Process;
use tempfile::TempDir;

fn resh(dir: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_CACHE_HOME", dir.join("cache"));
    cmd
}

fn openssl_available() -> bool {
    Process::new("openssl").arg("version").output().is_ok()
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Process::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Key types: (file stem, `openssl genpkey` arguments, algorithms to test).
const SIGNERS: &[(&str, &[&str], &[&str])] = &[
    (
        "rsa",
        &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        &[
            "rsa_pss_sha256",
            "rsa_pss_sha384",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
        ],
    ),
    (
        "p256",
        &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        &["ecdsa_sha256"],
    ),
    (
        "p384",
        &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        &["ecdsa_sha384", "ecdsa_sha512"],
    ),
    ("ed25519", &["-algorithm", "ED25519"], &["ed25519"]),
];

/// Makes `<stem>.key` and a self-signed `<stem>.pem` for each signer.
fn make_signers(dir: &Path) {
    for (stem, genpkey, _) in SIGNERS {
        let key = format!("{stem}.key");
        let cert = format!("{stem}.pem");
        let mut args = vec!["genpkey"];
        args.extend_from_slice(genpkey);
        args.extend_from_slice(&["-out", &key]);
        openssl(dir, &args);
        let subject = format!("/CN={stem} signer");
        openssl(
            dir,
            &[
                "req", "-x509", "-new", "-key", &key, "-subj", &subject, "-days", "30", "-out",
                &cert,
            ],
        );
    }
}

/// Signs data.bin with `resh` and verifies the result with openssl,
/// detached (with -content) or attached (content recovered and compared).
fn sign_and_verify(dir: &Path, format: &str, encoding: &str) {
    for (stem, _, algorithms) in SIGNERS {
        for alg in *algorithms {
            let out = format!("{stem}-{alg}-{format}.{encoding}");
            resh(dir)
                .args([
                    "cert://./signer.sign",
                    &format!("signer_key={stem}.key"),
                    &format!("signer_cert={stem}.pem"),
                    "data_source=data.bin",
                    &format!("signature_algorithm={alg}"),
                    &format!("signature_format={format}"),
                    &format!("signature_encoding={encoding}"),
                    &format!("signature_output_path={out}"),
                ])
                .assert()
                .success();

            let inform = if encoding == "pem" { "PEM" } else { "DER" };
            let recovered = format!("{out}.content");
            let mut args = vec![
                "cms", "-verify", "-binary", "-inform", inform, "-in", &out, "-CAfile",
            ];
            let ca = format!("{stem}.pem");
            args.push(&ca);
            args.extend_from_slice(&["-purpose", "any", "-out", &recovered]);
            if format == "cms_detached" {
                args.extend_from_slice(&["-content", "data.bin"]);
            }
            openssl(dir, &args);
            assert_eq!(
                std::fs::read(dir.join(&recovered)).unwrap(),
                std::fs::read(dir.join("data.bin")).unwrap(),
                "{stem} {alg} {format} {encoding}: content differs"
            );
        }
    }
}

fn setup() -> Option<TempDir> {
    if !openssl_available() {
        eprintln!("skipping: openssl not found on PATH");
        return None;
    }
    let tmp = TempDir::new().unwrap();
    let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 256) as u8).collect();
    std::fs::write(tmp.path().join("data.bin"), data).unwrap();
    make_signers(tmp.path());
    Some(tmp)
}

#[test]
fn cms_detached_from_the_binary_verifies_with_openssl() {
    let Some(tmp) = setup() else { return };
    for encoding in ["der", "pem"] {
        sign_and_verify(tmp.path(), "cms_detached", encoding);
    }
}

#[test]
fn cms_attached_from_the_binary_verifies_with_openssl() {
    let Some(tmp) = setup() else { return };
    for encoding in ["der", "pem"] {
        sign_and_verify(tmp.path(), "cms_attached", encoding);
    }
}

#[test]
fn cms_without_signer_cert_fails_with_invalid_argument() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("data.bin"), b"x").unwrap();
    // The options are rejected before the key is read, so no key is needed.
    let out = resh(tmp.path())
        .args([
            "cert://./signer.sign",
            "signer_key=missing.key",
            "data_source=data.bin",
            "signature_format=cms_detached",
            "signature_output_path=sig.der",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["error"]["code"], "cert.invalid_argument");
    assert!(!tmp.path().join("sig.der").exists());
}
