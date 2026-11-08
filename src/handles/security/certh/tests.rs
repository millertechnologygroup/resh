//! Dispatch-level tests for every cert verb: each runs through
//! `Handle::call` in a temporary directory.

use super::errors::{CHECK_CODES, ERROR_CODES};
use super::*;
use crate::core::status::is_valid_error_code;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The result of one call.
struct Run {
    exit: i32,
    json: Value,
    stdout: String,
    reason: String,
}

impl Run {
    #[track_caller]
    fn ok(&self) -> &Value {
        assert_eq!(self.exit, 0, "{}\n{}", self.stdout, self.reason);
        &self.json
    }

    #[track_caller]
    fn fails(&self, exit: i32, code: &str) -> &Value {
        assert_eq!(self.exit, exit, "{}\n{}", self.stdout, self.reason);
        assert!(
            self.reason.starts_with(&format!("[{code}] ")),
            "{code}: {}",
            self.reason
        );
        if !self.stdout.is_empty() {
            assert_eq!(self.json["ok"], false, "{}", self.stdout);
            assert_eq!(self.json["error"]["code"], code, "{}", self.stdout);
        }
        &self.json
    }
}

fn call(target: &str, verb: &str, pairs: &[(&str, &str)]) -> Run {
    let handle = CertHandle {
        target_path: target.to_string(),
    };
    let args: Args = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut stdin = std::io::empty();
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let status = {
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut out,
            stderr: &mut err,
        };
        handle.call(verb, &args, &mut io).unwrap()
    };
    let stdout = String::from_utf8(out).unwrap();
    Run {
        exit: status.exit_code(),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        reason: status.reason.unwrap_or_default(),
    }
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Fixtures: a root CA, an intermediate CA and leaves, made with rcgen.
// ---------------------------------------------------------------------------

fn ec_key() -> KeyPair {
    KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
}

fn params(cn: &str, key: KeyPair, days_from: i64, days_to: i64) -> CertificateParams {
    let mut p = CertificateParams::new(vec![]);
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.alg = key.algorithm();
    p.key_pair = Some(key);
    p.not_before = ::time::OffsetDateTime::now_utc() + ::time::Duration::days(days_from);
    p.not_after = ::time::OffsetDateTime::now_utc() + ::time::Duration::days(days_to);
    p
}

fn ca(cn: &str) -> Certificate {
    let mut p = params(cn, ec_key(), -1, 30);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    Certificate::from_params(p).unwrap()
}

fn leaf_params(cn: &str, sans: &[&str]) -> CertificateParams {
    let mut p = params(cn, ec_key(), -1, 30);
    p.subject_alt_names = sans
        .iter()
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(s.to_string()),
        })
        .collect();
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p
}

fn pem(der: &[u8]) -> String {
    pem_encode_lf(&Pem::new("CERTIFICATE", der.to_vec()))
}

/// root -> intermediate -> leaf ("web.test", 127.0.0.1) written to `dir`:
/// root.pem, inter.pem, leaf.pem (leaf + intermediate), leaf-only.pem,
/// leaf-key.pem, root-key.pem.
struct Pki {
    root: Certificate,
}

fn pki(dir: &Path) -> Pki {
    let root = ca("Test Root");
    let mut ip = params("Test Intermediate", ec_key(), -1, 30);
    ip.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ip.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let inter = Certificate::from_params(ip).unwrap();
    let inter_der = inter.serialize_der_with_signer(&root).unwrap();
    let leaf =
        Certificate::from_params(leaf_params("web.test", &["web.test", "127.0.0.1"])).unwrap();
    let leaf_der = leaf.serialize_der_with_signer(&inter).unwrap();
    fs::write(dir.join("root.pem"), pem(&root.serialize_der().unwrap())).unwrap();
    fs::write(dir.join("root-key.pem"), root.serialize_private_key_pem()).unwrap();
    fs::write(dir.join("inter.pem"), pem(&inter_der)).unwrap();
    fs::write(dir.join("leaf.pem"), pem(&leaf_der) + &pem(&inter_der)).unwrap();
    fs::write(dir.join("leaf-only.pem"), pem(&leaf_der)).unwrap();
    fs::write(dir.join("leaf-key.pem"), leaf.serialize_private_key_pem()).unwrap();
    Pki { root }
}

/// A self-signed CA written as `<name>.pem` and `<name>-key.pem` by the
/// generate verb.
fn gen_ca(dir: &Path, name: &str) {
    call(
        &p(dir, name),
        "generate",
        &[
            ("mode", "self_signed"),
            ("algorithm", "ecdsa"),
            ("is_ca", "true"),
            ("subject", r#"{"common_name":"Gen CA"}"#),
        ],
    )
    .ok();
}

fn openssl() -> bool {
    which::which("openssl").is_ok()
}

fn openssl_ok(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

// ---------------------------------------------------------------------------
// Conventions: strict arguments, codes, help
// ---------------------------------------------------------------------------

/// The accepted-options list of each verb is exactly what its help usage
/// lists (csr.sign is not reachable from the command line and has no usage).
#[test]
fn accepted_options_match_the_help_usage() {
    for verb in args::VERBS.iter().filter(|v| **v != "csr.sign") {
        let detail = CERT_HELP
            .verbs
            .iter()
            .find(|v| v.name == *verb)
            .and_then(|v| v.detail.as_ref())
            .unwrap();
        let mut in_usage: Vec<String> = Vec::new();
        for word in detail
            .usage
            .split(|c: char| c.is_whitespace() || c == '[' || c == '|' || c == '(')
        {
            if let Some((key, _)) = word.split_once('=') {
                let key = key.to_string();
                if !key.is_empty() && !in_usage.contains(&key) {
                    in_usage.push(key);
                }
            }
        }
        let mut accepted: Vec<String> = args::verb_args(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        in_usage.sort();
        accepted.sort();
        assert_eq!(in_usage, accepted, "{verb}");
    }
}

#[test]
fn every_error_code_is_valid_and_documented() {
    let doc = include_str!("../../../../docs/Security_Secrets/cert.md");
    for (code, exit) in ERROR_CODES {
        assert!(is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
        assert!([1, 2, 124].contains(exit));
    }
    for code in CHECK_CODES {
        assert!(is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
    }
    // Every code in the sources is listed.
    let sources = [
        include_str!("../certh.rs"),
        include_str!("verbs.rs"),
        include_str!("trust.rs"),
        include_str!("chain.rs"),
        include_str!("keys.rs"),
        include_str!("keyenc.rs"),
        include_str!("fileio.rs"),
        include_str!("args.rs"),
        include_str!("errors.rs"),
    ];
    let known: Vec<&str> = ERROR_CODES
        .iter()
        .map(|(c, _)| *c)
        .chain(CHECK_CODES.iter().copied())
        .collect();
    for src in sources {
        for (i, _) in src.match_indices("\"cert.") {
            let rest = &src[i + 1..];
            let code: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '.' || *c == '_')
                .collect();
            // File names such as "cert.der" in test fixtures are not codes.
            let file = ["cert.pem", "cert.der", "cert.csr", "cert.crt"].contains(&code.as_str());
            if file || code.ends_with('.') || !rest[code.len()..].starts_with('"') {
                continue;
            }
            assert!(known.contains(&code.as_str()), "{code} is not listed");
        }
    }
}

#[test]
fn unknown_arguments_and_bad_values_are_refused_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    let t = p(dir.path(), "x");
    for verb in args::VERBS {
        let r = call(&t, verb, &[("formt", "json")]);
        r.fails(2, "cert.invalid_argument");
        assert!(
            r.reason.contains("did you mean `format`"),
            "{verb}: {}",
            r.reason
        );
        call(&t, verb, &[("dry_run", "true")]).fails(2, "cert.invalid_argument");
        call(&t, verb, &[("format", "yaml")]).fails(2, "cert.invalid_argument");
    }
    for verb in ["info", "verify", "chain.info", "csr.sign"] {
        let r = call(&t, verb, &[("timeout_ms", "100")]);
        r.fails(2, "cert.invalid_argument");
        assert!(r.reason.contains("timeout_ms"), "{}", r.reason);
    }
    call(&t, "info", &[("include_pem", "maybe")]).fails(2, "cert.invalid_argument");
    call(&t, "generate", &[("overwrite", "y")]).fails(2, "cert.invalid_argument");
    call(&t, "generate", &[("timeout_ms", "0")]).fails(2, "cert.invalid_argument");
    // Nothing was written by any refusal.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn text_failures_print_nothing_on_stdout() {
    let r = call("/nonexistent/x.pem", "info", &[("format", "text")]);
    r.fails(1, "cert.not_found");
    assert!(r.stdout.is_empty());
}

#[test]
fn help_verb_and_in_url_help_render() {
    let r = call("help", "help", &[]);
    assert_eq!(r.exit, 0);
    assert!(r.stdout.contains("chain.info"));
    let r = call("help", "--help=renew", &[]);
    assert!(r.stdout.contains("key_strategy"), "{}", r.stdout);
}

#[test]
fn from_url_keeps_paths() {
    let h = CertHandle::from_url(Url::parse("cert:///etc/ssl/a.pem").unwrap()).unwrap();
    assert_eq!(h.target_path, "/etc/ssl/a.pem");
    let h = CertHandle::from_url(Url::parse("cert://./a-h.pem").unwrap()).unwrap();
    assert_eq!(h.target_path, "./a-h.pem");
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

#[test]
fn info_reports_certificates_bundles_csrs_and_keys() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let v = call(
        &p(d, "leaf.pem"),
        "info",
        &[
            ("fingerprint_algs", "sha1,sha256,sha384,sha512"),
            ("include_raw", "true"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["type"], "certificatechain");
    let o = &v["objects"][0];
    assert_eq!(o["public_key"]["algorithm"], "ECDSA");
    assert_eq!(o["public_key"]["curve"], "P-256");
    assert_eq!(o["is_ca"], false);
    assert_eq!(v["objects"][1]["is_ca"], true);
    assert_eq!(o["extensions"]["subject_alt_names"][0], "DNS:web.test");
    assert_eq!(o["extensions"]["extended_key_usage"][0], "serverAuth");
    // Fingerprints are digests of the whole DER certificate.
    let der = BASE64_STANDARD
        .decode(o["raw_der_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        o["fingerprints"]["sha512"],
        colon_hex(&sha2::Sha512::digest(&der))
    );
    assert_eq!(
        o["fingerprints"]["sha256"],
        colon_hex(&sha2::Sha256::digest(&der))
    );

    // DER certificate, private key, encrypted key, CSR, public key.
    fs::write(d.join("leaf.der"), &der).unwrap();
    let v = call(&p(d, "leaf.der"), "info", &[]).ok().clone();
    assert_eq!(
        (v["type"].as_str(), v["encoding"].as_str()),
        (Some("certificate"), Some("der"))
    );
    let v = call(&p(d, "leaf-key.pem"), "info", &[]).ok().clone();
    assert_eq!(v["objects"][0]["kind"], "private_key");
    assert_eq!(v["objects"][0]["is_encrypted"], false);
    call(
        &p(d, "k"),
        "generate",
        &[("algorithm", "ed25519"), ("key_passphrase", "pw-123456")],
    )
    .ok();
    let v = call(&p(d, "k-key.pem"), "info", &[("format", "json")])
        .ok()
        .clone();
    assert_eq!(v["objects"][0]["is_encrypted"], true);
    call(
        &p(d, "req.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"csr.test"}"#),
            ("existing_key_path", &p(d, "leaf-key.pem")),
        ],
    )
    .ok();
    let v = call(&p(d, "req.csr"), "info", &[]).ok().clone();
    assert_eq!(v["objects"][0]["kind"], "csr");
    assert_eq!(v["objects"][0]["public_key"]["signature_valid"], true);
    let text = call(&p(d, "leaf.pem"), "info", &[("format", "text")]).stdout;
    assert!(text.contains("Subject: CN=web.test"), "{text}");
}

#[test]
fn info_errors() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    call(&p(d, "none.pem"), "info", &[]).fails(1, "cert.not_found");
    fs::write(d.join("junk"), b"\x01\x02junk").unwrap();
    call(&p(d, "junk"), "info", &[]).fails(1, "cert.parse_failed");
    fs::write(
        d.join("junk.pem"),
        "-----BEGIN THING-----\nAAAA\n-----END THING-----\n",
    )
    .unwrap();
    call(&p(d, "junk.pem"), "info", &[]).fails(1, "cert.parse_failed");
    call(&p(d, "junk"), "info", &[("fingerprint_algs", "md5")]).fails(2, "cert.invalid_argument");
    call(d.to_str().unwrap(), "info", &[]).fails(1, "cert.read_failed");
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn check<'a>(v: &'a Value, name: &str) -> &'a Value {
    &v["checks"][name]
}

#[test]
fn verify_validates_a_chain_with_webpki() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let root = p(d, "root.pem");
    for trust in [
        vec![("trust_paths", root.as_str())],
        vec![("ca_file", root.as_str())],
        vec![("trust", "mount"), ("ca_file", root.as_str())],
    ] {
        let mut a = trust.clone();
        a.extend([
            ("hostname", "web.test"),
            ("purpose", "server_auth"),
            (
                "keypair_target",
                &*Box::leak(p(d, "leaf-key.pem").into_boxed_str()),
            ),
        ]);
        let v = call(&p(d, "leaf.pem"), "verify", &a).ok().clone();
        assert_eq!(v["ok"], true);
        assert_eq!(check(&v, "chain")["status"], "passed", "{v}");
        assert_eq!(v["chain_report"].as_array().unwrap().len(), 3);
        assert_eq!(v["chain_report"][2]["is_trust_anchor"], true);
        assert_eq!(check(&v, "keypair")["status"], "passed");
        assert_eq!(check(&v, "usage")["status"], "passed");
    }
    // trust_pem, and an IP address.
    let pem_text = fs::read_to_string(&root).unwrap();
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[
            ("trust", "inline"),
            ("trust_pem", &pem_text),
            ("hostname", "127.0.0.1"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(check(&v, "hostname")["status"], "passed");
}

#[test]
fn verify_failures_are_reported_and_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let pk = pki(d);
    let root = p(d, "root.pem");
    // No path to an anchor (the intermediate is missing).
    let v = call(&p(d, "leaf-only.pem"), "verify", &[("ca_file", &root)])
        .fails(1, "cert.verification_failed")
        .clone();
    assert_eq!(check(&v, "chain")["error_code"], "cert.issuer_not_found");
    // Wrong anchor.
    fs::write(
        d.join("other.pem"),
        pem(&ca("Other").serialize_der().unwrap()),
    )
    .unwrap();
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &p(d, "other.pem"))],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(check(&v, "chain")["status"], "failed");
    // Hostname and keypair mismatches.
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[
            ("ca_file", &root),
            ("hostname", "evil.test"),
            ("keypair_target", &p(d, "root-key.pem")),
        ],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(
        check(&v, "hostname")["error_code"],
        "cert.hostname_mismatch"
    );
    assert_eq!(check(&v, "keypair")["error_code"], "cert.keypair_mismatch");
    assert_eq!(check(&v, "chain")["status"], "passed");
    // Purpose not allowed by the extended key usage.
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &root), ("purpose", "client_auth")],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(check(&v, "usage")["error_code"], "cert.eku_mismatch");
    // Revocation is never a pass.
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &root), ("check_revocation", "hard")],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(check(&v, "revocation")["status"], "unsupported");
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &root), ("check_revocation", "soft")],
    )
    .ok()
    .clone();
    assert_eq!(check(&v, "revocation")["status"], "not_checked");
    // max_chain_depth.
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &root), ("max_chain_depth", "2")],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(check(&v, "chain")["error_code"], "cert.chain_too_long");
    // An expired leaf: the time check fails; allow_expired accepts it.
    let mut lp = leaf_params("old.test", &["old.test"]);
    lp.not_before = ::time::OffsetDateTime::now_utc() - ::time::Duration::days(20);
    lp.not_after = ::time::OffsetDateTime::now_utc() - ::time::Duration::days(2);
    let old = Certificate::from_params(lp).unwrap();
    fs::write(
        d.join("old.pem"),
        pem(&old.serialize_der_with_signer(&pk.root).unwrap()),
    )
    .unwrap();
    let v = call(&p(d, "old.pem"), "verify", &[("ca_file", &root)])
        .fails(1, "cert.verification_failed")
        .clone();
    assert_eq!(check(&v, "time")["error_code"], "cert.expired");
    let v = call(
        &p(d, "old.pem"),
        "verify",
        &[("ca_file", &root), ("allow_expired", "true")],
    )
    .ok()
    .clone();
    assert_eq!(check(&v, "chain")["status"], "passed", "{v}");
    // Text output still reports, and exits 1.
    let r = call(
        &p(d, "leaf-only.pem"),
        "verify",
        &[("ca_file", &root), ("format", "text")],
    );
    assert_eq!(r.exit, 1);
    assert!(r.stdout.contains("Overall: FAILED"), "{}", r.stdout);
}

#[test]
fn verify_self_signed_policy_and_object_types() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    gen_ca(d, "ss");
    let none: &[(&str, &str)] = &[("trust", "mount"), ("trust_paths", "/dev/null")];
    let _ = none;
    // A self-signed certificate that is not an anchor.
    fs::write(
        d.join("empty-anchor.pem"),
        pem(&ca("Unrelated").serialize_der().unwrap()),
    )
    .unwrap();
    let a = p(d, "empty-anchor.pem");
    let v = call(
        &p(d, "ss.pem"),
        "verify",
        &[("trust", "mount"), ("ca_file", &a)],
    )
    .fails(1, "cert.verification_failed")
    .clone();
    assert_eq!(
        check(&v, "chain")["error_code"],
        "cert.self_signed_not_allowed"
    );
    let v = call(
        &p(d, "ss.pem"),
        "verify",
        &[
            ("trust", "mount"),
            ("ca_file", &a),
            ("allow_self_signed", "true"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(check(&v, "chain")["status"], "passed");
    // Itself an anchor.
    let v = call(&p(d, "ss.pem"), "verify", &[("ca_file", &p(d, "ss.pem"))])
        .ok()
        .clone();
    assert!(
        check(&v, "chain")["message"]
            .as_str()
            .unwrap()
            .contains("itself")
    );
    // A private key, an encrypted key, a CSR.
    let v = call(
        &p(d, "ss-key.pem"),
        "verify",
        &[("trust", "mount"), ("ca_file", &a)],
    )
    .ok()
    .clone();
    assert_eq!(v["type"], "private_key");
    call(
        &p(d, "r.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"r"}"#),
            ("existing_key_path", &p(d, "ss-key.pem")),
        ],
    )
    .ok();
    call(&p(d, "r.csr"), "verify", &[("ca_file", &a)]).fails(1, "cert.unsupported_type");
    // Usage errors before anything is read.
    call(&p(d, "ss.pem"), "verify", &[("trust", "mount")]).fails(2, "cert.invalid_argument");
    call(&p(d, "ss.pem"), "verify", &[("trust", "inline")]).fails(2, "cert.invalid_argument");
    call(&p(d, "ss.pem"), "verify", &[("min_rsa_bits", "1024")]).fails(2, "cert.invalid_argument");
    call(
        &p(d, "ss.pem"),
        "verify",
        &[("ca_file", &p(d, "missing.pem"))],
    )
    .fails(1, "cert.trust_load_failed");
    call(
        &p(d, "ss.pem"),
        "verify",
        &[("trust", "inline"), ("trust_pem", "nope")],
    )
    .fails(2, "cert.invalid_argument");
}

// ---------------------------------------------------------------------------
// chain.info
// ---------------------------------------------------------------------------

#[test]
fn chain_info_links_issuers_and_validates_trusted_paths() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    pki(d);
    let root = p(d, "root.pem");
    // leaf + intermediate, root as anchor: one trusted chain of 3.
    let v = call(&p(d, "leaf.pem"), "chain.info", &[("trust_paths", &root)])
        .ok()
        .clone();
    assert_eq!(v["leaf_candidates"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["leaf_candidates"][0]["subject"]["common_name"],
        "web.test"
    );
    let c = &v["chains"][0];
    assert_eq!(c["trust_status"], "trusted", "{v}");
    assert_eq!(c["length"], 3);
    assert_eq!(c["hops"][1]["role"], "intermediate");
    assert_eq!(c["hops"][2]["role"], "root");
    assert_eq!(c["root"]["trust_source"], "mount");
    assert_eq!(
        c["hops"][0]["cert_ref"],
        format!("cert://{}#0", p(d, "leaf.pem"))
    );
    // Without anchors the chain is incomplete (the root is missing).
    let v = call(&p(d, "leaf.pem"), "chain.info", &[]).ok().clone();
    assert_eq!(v["chains"][0]["trust_status"], "incomplete");
    // With the root in the bundle but not trusted: untrusted_root.
    let bundle =
        fs::read_to_string(d.join("leaf.pem")).unwrap() + &fs::read_to_string(&root).unwrap();
    fs::write(d.join("full.pem"), bundle).unwrap();
    let v = call(
        &p(d, "full.pem"),
        "chain.info",
        &[("include_raw_subjects", "true")],
    )
    .ok()
    .clone();
    assert_eq!(v["chains"][0]["trust_status"], "untrusted_root");
    assert_eq!(
        v["chains"][0]["hops"][0]["subject"]["raw_dn"],
        "CN=web.test"
    );
    // max_depth cuts the path.
    let v = call(&p(d, "full.pem"), "chain.info", &[("max_depth", "2")])
        .ok()
        .clone();
    assert_eq!(v["chains"][0]["trust_status"], "incomplete");
    // A lone self-signed certificate.
    let v = call(&root, "chain.info", &[("format", "text")]);
    assert!(v.stdout.contains("self_signed_untrusted"), "{}", v.stdout);
    // Errors.
    call(&root, "chain.info", &[("trust", "mount")]).fails(2, "cert.invalid_argument");
    call(&root, "chain.info", &[("max_paths", "0")]).fails(2, "cert.invalid_argument");
    call(&p(d, "leaf-key.pem"), "chain.info", &[]).fails(1, "cert.parse_failed");
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

#[test]
fn generate_every_mode_and_algorithm() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for (alg, extra) in [
        ("rsa", None),
        ("ecdsa", Some(("ecdsa_curve", "P-384"))),
        ("ed25519", None),
    ] {
        let t = p(d, &format!("k-{alg}"));
        let mut a = vec![("algorithm", alg)];
        a.extend(extra);
        let v = call(&t, "generate", &a).ok().clone();
        assert_eq!(v["mode"], "key");
        let key = keys::load_key("k", &format!("{t}-key.pem"), None, "").unwrap();
        assert_eq!(key.algorithm, alg);
        let mode = fs::metadata(format!("{t}-key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let v = call(
        &p(d, "ss"),
        "generate",
        &[
            ("mode", "self_signed"),
            ("algorithm", "ecdsa"),
            (
                "subject",
                r#"{"common_name":"ss.test","organization":"Org","country":"US"}"#,
            ),
            ("sans", r#"["DNS:ss.test","IP:10.0.0.1","EMAIL:a@b.c"]"#),
            ("not_before", "2030-01-01T00:00:00Z"),
            ("not_after", "2031-06-01T00:00:00Z"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["mode"], "self_signed");
    assert_eq!(v["validity"]["not_before"], "2030-01-01T00:00:00+00:00");
    assert_eq!(v["validity"]["not_after"], "2031-06-01T00:00:00+00:00");
    assert_eq!(v["subject"]["raw_dn"], "CN=ss.test, O=Org, C=US");
    // mode=csr writes the CSR by default.
    let v = call(
        &p(d, "c"),
        "generate",
        &[
            ("mode", "csr"),
            ("algorithm", "ed25519"),
            ("subject", r#"{"common_name":"c"}"#),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["csr"]["stored_at"], format!("{}.csr", p(d, "c")));
    assert!(d.join("c.csr").exists());
    // leaf_cert signed by a CA, valid offset.
    gen_ca(d, "ca");
    let v = call(
        &p(d, "leaf"),
        "generate",
        &[
            ("mode", "leaf_cert"),
            ("algorithm", "ecdsa"),
            ("subject", r#"{"common_name":"leaf.test"}"#),
            ("sans", "DNS:leaf.test"),
            ("signer_ca", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
            ("not_after_offset_days", "10"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["is_ca"], false);
    let v = call(
        &p(d, "leaf.pem"),
        "verify",
        &[("ca_file", &p(d, "ca.pem")), ("hostname", "leaf.test")],
    )
    .ok()
    .clone();
    assert_eq!(v["ok"], true);
}

#[test]
fn generate_key_formats_encodings_and_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for (alg, format, encoding, label) in [
        ("rsa", "pkcs1", "pem", "RSA PRIVATE KEY"),
        ("ecdsa", "sec1", "pem", "EC PRIVATE KEY"),
        ("ecdsa", "sec1", "der", ""),
        ("ed25519", "pkcs8", "der", ""),
    ] {
        let t = p(d, &format!("{alg}-{format}-{encoding}"));
        call(
            &t,
            "generate",
            &[
                ("algorithm", alg),
                ("key_format", format),
                ("key_encoding", encoding),
            ],
        )
        .ok();
        let data = fs::read(format!("{t}-key.pem")).unwrap();
        if !label.is_empty() {
            assert!(String::from_utf8_lossy(&data).contains(label), "{t}");
        }
        let k = keys::parse_key(&data, &t, None, "").unwrap();
        assert_eq!(k.format, format, "{t}");
    }
    // Encrypted PKCS#8, PEM and DER, read back with the passphrase.
    for enc in ["pem", "der"] {
        let t = p(d, &format!("enc-{enc}"));
        let v = call(
            &t,
            "generate",
            &[
                ("algorithm", "ecdsa"),
                ("key_encoding", enc),
                ("key_passphrase", "correct horse"),
                ("key_kdf", "pbkdf2"),
                ("key_kdf_iterations", "20000"),
                ("output", r#"{"return_key":true}"#),
            ],
        )
        .ok()
        .clone();
        assert_eq!(v["key"]["encrypted"], true);
        assert!(!v.to_string().contains("correct horse"));
        let data = fs::read(format!("{t}-key.pem")).unwrap();
        assert!(keyenc::is_encrypted(&data));
        let e = keys::parse_key(&data, "k", None, "key_passphrase")
            .err()
            .unwrap();
        assert_eq!(e.code, "cert.passphrase_required");
        assert!(
            keys::parse_key(&data, "k", Some("correct horse"), "x")
                .unwrap()
                .encrypted
        );
    }
    if openssl() {
        openssl_ok(
            d,
            &[
                "pkey",
                "-in",
                "enc-pem-key.pem",
                "-passin",
                "pass:correct horse",
                "-noout",
            ],
        );
        openssl_ok(
            d,
            &["rsa", "-in", "rsa-pkcs1-pem-key.pem", "-check", "-noout"],
        );
        openssl_ok(
            d,
            &["ec", "-in", "ecdsa-sec1-pem-key.pem", "-check", "-noout"],
        );
    }
}

#[test]
fn generate_refusals_and_file_safety() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let t = p(d, "g");
    for bad in [
        vec![("ecdsa_curve", "P-521"), ("algorithm", "ecdsa")],
        vec![("ecdsa_curve", "secp256k1"), ("algorithm", "ecdsa")],
        vec![("rsa_bits", "1024")],
        vec![("rsa_bits", "2048"), ("algorithm", "ecdsa")],
        vec![("subject", r#"{"common_name":"x"}"#)],
        vec![("mode", "self_signed")],
        vec![("mode", "self_signed"), ("subject", r#"{"cn":"x"}"#)],
        vec![("mode", "leaf_cert"), ("subject", r#"{"common_name":"x"}"#)],
        vec![("key_format", "pkcs1"), ("algorithm", "ecdsa")],
        vec![("key_passphrase", "pw"), ("key_format", "pkcs1")],
        vec![("key_passphrase", "pw"), ("key_kdf", "argon2id")],
        vec![("key_kdf_iterations", "20000")],
        vec![("output", r#"{"write_key":false}"#)],
        vec![("output", r#"{"write_cert":false}"#)],
        vec![
            ("mode", "self_signed"),
            ("subject", r#"{"common_name":"x"}"#),
            ("path_len", "1"),
        ],
        vec![
            ("mode", "self_signed"),
            ("subject", r#"{"common_name":"x"}"#),
            ("not_after", "2001-01-01T00:00:00Z"),
        ],
        vec![
            ("mode", "self_signed"),
            ("subject", r#"{"common_name":"x","organization":["a","b"]}"#),
        ],
        vec![("sans", "FTP:x")],
    ] {
        call(&t, "generate", &bad).fails(2, "cert.invalid_argument");
    }
    assert_eq!(fs::read_dir(d).unwrap().count(), 0);

    // Existing output and planted symlinks.
    call(&t, "generate", &[("algorithm", "ed25519")]).ok();
    call(&t, "generate", &[("algorithm", "ed25519")]).fails(1, "cert.target_exists");
    call(
        &t,
        "generate",
        &[("algorithm", "ed25519"), ("overwrite", "true")],
    )
    .ok();
    fs::write(d.join("victim"), "keep").unwrap();
    std::os::unix::fs::symlink(d.join("victim"), d.join("s-key.pem")).unwrap();
    for ow in ["false", "true"] {
        call(
            &p(d, "s"),
            "generate",
            &[("algorithm", "ed25519"), ("overwrite", ow)],
        )
        .fails(
            1,
            if ow == "true" {
                "cert.symlink_refused"
            } else {
                "cert.symlink_refused"
            },
        );
    }
    assert_eq!(fs::read_to_string(d.join("victim")).unwrap(), "keep");
    // The signer of a leaf must exist and match.
    gen_ca(d, "ca");
    gen_ca(d, "ca2");
    let base = [
        ("mode", "leaf_cert"),
        ("subject", r#"{"common_name":"l"}"#),
        ("algorithm", "ed25519"),
    ];
    let mut a = base.to_vec();
    a.extend([
        ("signer_ca", "/nonexistent.pem"),
        ("signer_key", "/nonexistent.pem"),
    ]);
    call(&p(d, "l"), "generate", &a).fails(1, "cert.signer_load_failed");
    let (ca, k2) = (p(d, "ca.pem"), p(d, "ca2-key.pem"));
    let mut a = base.to_vec();
    a.extend([("signer_ca", ca.as_str()), ("signer_key", k2.as_str())]);
    call(&p(d, "l"), "generate", &a).fails(1, "cert.keypair_mismatch");
    assert!(!d.join("l.pem").exists() && !d.join("l-key.pem").exists());
}

#[test]
fn generate_timeout_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let t = p(dir.path(), "slow");
    call(&t, "generate", &[("rsa_bits", "4096"), ("timeout_ms", "1")]).fails(124, "cert.timeout");
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!Path::new(&format!("{t}-key.pem")).exists());
}

#[test]
fn encrypted_signer_keys_are_used_with_their_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    call(
        &p(d, "ca"),
        "generate",
        &[
            ("mode", "self_signed"),
            ("algorithm", "ecdsa"),
            ("is_ca", "true"),
            ("subject", r#"{"common_name":"Enc CA"}"#),
            ("key_passphrase", "ca-pass"),
        ],
    )
    .ok();
    let base = [
        ("mode", "leaf_cert"),
        ("subject", r#"{"common_name":"l"}"#),
        ("algorithm", "ed25519"),
    ];
    let (ca, key) = (p(d, "ca.pem"), p(d, "ca-key.pem"));
    let mut a = base.to_vec();
    a.extend([("signer_ca", ca.as_str()), ("signer_key", key.as_str())]);
    call(&p(d, "l"), "generate", &a).fails(2, "cert.passphrase_required");
    let mut w = a.clone();
    w.push(("signer_key_passphrase", "wrong-pass"));
    let r = call(&p(d, "l"), "generate", &w);
    r.fails(1, "cert.key_decrypt_failed");
    assert!(!r.stdout.contains("wrong-pass") && !r.reason.contains("wrong-pass"));
    a.push(("signer_key_passphrase", "ca-pass"));
    call(&p(d, "l"), "generate", &a).ok();
    call(&p(d, "l.pem"), "verify", &[("ca_file", &ca)]).ok();
}

// ---------------------------------------------------------------------------
// csr.create
// ---------------------------------------------------------------------------

#[test]
fn csr_create_reuse_and_generate() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // Reuse keys of every kind; the algorithm is read from the key.
    for (alg, format) in [("rsa", "pkcs1"), ("ecdsa", "sec1"), ("ed25519", "pkcs8")] {
        let t = p(d, alg);
        call(
            &t,
            "generate",
            &[("algorithm", alg), ("key_format", format)],
        )
        .ok();
        let v = call(
            &format!("{t}.csr"),
            "csr.create",
            &[
                ("subject", r#"{"common_name":"reuse.test"}"#),
                ("existing_key_path", &format!("{t}-key.pem")),
                ("sans", r#"["DNS:reuse.test"]"#),
                ("key_usage", r#"["digitalSignature","keyEncipherment"]"#),
                ("extended_key_usage", "serverAuth,clientAuth"),
                ("include_csr_pem", "true"),
            ],
        )
        .ok()
        .clone();
        assert_eq!(v["key"]["algorithm"], alg);
        assert_eq!(v["key"]["key_format"], format);
        assert_eq!(v["csr"]["subject"]["raw_dn"], "CN=reuse.test");
        assert!(
            v["returned"]["csr_pem"]
                .as_str()
                .unwrap()
                .contains("REQUEST")
        );
        let info = call(&format!("{t}.csr"), "info", &[]).ok().clone();
        assert_eq!(info["objects"][0]["public_key"]["signature_valid"], true);
    }
    // algorithm= must match a reused key.
    call(
        &p(d, "m.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"m"}"#),
            ("existing_key_path", &p(d, "rsa-key.pem")),
            ("algorithm", "ecdsa"),
        ],
    )
    .fails(1, "cert.keypair_mismatch");
    // Generate a new, encrypted key.
    let v = call(
        &p(d, "g.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"g"}"#),
            ("key_strategy", "generate"),
            ("algorithm", "ecdsa"),
            ("ecdsa_curve", "P-384"),
            ("new_key_output_path", &p(d, "g-key.pem")),
            ("new_key_passphrase", "new-pass"),
            ("csr_encoding", "der"),
            ("include_new_key_pem", "true"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["key"]["encrypted"], true);
    assert!(
        v["returned"]["new_key_pem"]
            .as_str()
            .unwrap()
            .contains("ENCRYPTED")
    );
    let key = keys::load_key("k", &p(d, "g-key.pem"), Some("new-pass"), "x").unwrap();
    assert_eq!(key.curve, Some("P-384"));
    let mode = fs::metadata(d.join("g-key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    // Reuse the encrypted key.
    let e = p(d, "g-key.pem");
    let base = [
        ("subject", r#"{"common_name":"g2"}"#),
        ("existing_key_path", e.as_str()),
    ];
    call(&p(d, "g2.csr"), "csr.create", &base).fails(2, "cert.passphrase_required");
    let mut a = base.to_vec();
    a.push(("existing_key_passphrase", "new-pass"));
    let v = call(&p(d, "g2.csr"), "csr.create", &a).ok().clone();
    assert_eq!(v["key"]["encrypted"], true);
    if openssl() {
        let out = openssl_ok(d, &["req", "-in", "rsa.csr", "-noout", "-verify", "-text"]);
        assert!(out.contains("Key Encipherment"), "{out}");
        assert!(out.contains("TLS Web Client Authentication"), "{out}");
        openssl_ok(
            d,
            &["req", "-in", "g.csr", "-inform", "DER", "-noout", "-verify"],
        );
    }
}

#[test]
fn csr_create_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let t = p(d, "r.csr");
    let s = ("subject", r#"{"common_name":"r"}"#);
    for bad in [
        vec![],
        vec![s],
        vec![s, ("key_strategy", "generate")],
        vec![s, ("existing_key_path", "k"), ("new_key_output_path", "n")],
        vec![
            s,
            ("key_strategy", "generate"),
            ("new_key_output_path", "n"),
            ("existing_key_path", "k"),
        ],
        vec![s, ("existing_key_path", "k"), ("key_usage", "flying")],
        vec![s, ("existing_key_path", "k"), ("extended_key_usage", "[1]")],
        vec![("subject", "{}"), ("existing_key_path", "k")],
        vec![s, ("key_strategy", "generate"), ("new_key_output_path", &t)],
    ] {
        call(&t, "csr.create", &bad).fails(2, "cert.invalid_argument");
    }
    call(&t, "csr.create", &[s, ("existing_key_path", &p(d, "none"))]).fails(1, "cert.not_found");
    fs::write(d.join("bad-key"), "not a key").unwrap();
    call(
        &t,
        "csr.create",
        &[s, ("existing_key_path", &p(d, "bad-key"))],
    )
    .fails(1, "cert.key_load_failed");
    fs::write(&t, "x").unwrap();
    call(
        &t,
        "csr.create",
        &[
            s,
            ("key_strategy", "generate"),
            ("new_key_output_path", &p(d, "n.pem")),
        ],
    )
    .fails(1, "cert.target_exists");
    assert!(!d.join("n.pem").exists());
}

// ---------------------------------------------------------------------------
// sign (mode=csr) and csr.sign
// ---------------------------------------------------------------------------

#[test]
fn sign_mode_csr_issues_from_a_csr_with_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    gen_ca(d, "ca");
    call(
        &p(d, "w.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"w.test"}"#),
            ("key_strategy", "generate"),
            ("algorithm", "ecdsa"),
            ("new_key_output_path", &p(d, "w-key.pem")),
            ("sans", "DNS:w.test"),
            ("key_usage", "digitalSignature"),
            ("extended_key_usage", "clientAuth"),
        ],
    )
    .ok();
    let v = call(
        &p(d, "ca"),
        "sign",
        &[
            ("mode", "csr"),
            ("csr_source", &p(d, "w.csr")),
            ("signer_cert", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
            ("cert_output_path", &p(d, "w.pem")),
            ("not_after_offset_days", "30"),
            ("include_cert_pem", "true"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["cert"]["subject"]["common_name"], "w.test");
    assert_eq!(v["cert"]["sans"][0], "DNS:w.test");
    assert_eq!(v["cert"]["extended_key_usage"][0], "serverAuth");
    assert!(v["warnings"].to_string().contains("clientAuth"), "{v}");
    call(
        &p(d, "w.pem"),
        "verify",
        &[
            ("ca_file", &p(d, "ca.pem")),
            ("hostname", "w.test"),
            ("keypair_target", &p(d, "w-key.pem")),
        ],
    )
    .ok();
    // Options of the other mode, missing options.
    let base = [("mode", "csr"), ("signer_key", "k")];
    let mut a = base.to_vec();
    a.push(("data_source", "x"));
    call(&p(d, "ca"), "sign", &a).fails(2, "cert.invalid_argument");
    call(&p(d, "ca"), "sign", &base).fails(2, "cert.invalid_argument");
    call(
        &p(d, "ca"),
        "sign",
        &[
            ("signer_key", "k"),
            ("csr_source", "x"),
            ("data_source", "d"),
        ],
    )
    .fails(2, "cert.invalid_argument");
    call(
        &p(d, "ca"),
        "sign",
        &[
            ("signer_key", "k"),
            ("data_source", "d"),
            ("data_bytes_base64", "aGk="),
        ],
    )
    .fails(2, "cert.invalid_argument");
    call(
        &p(d, "ca"),
        "sign",
        &[("signer_key", "k"), ("data_bytes_base64", "!!")],
    )
    .fails(2, "cert.invalid_argument");
    call(
        &p(d, "ca"),
        "sign",
        &[
            ("signer_key", "k"),
            ("data_source", "d"),
            ("overwrite", "true"),
        ],
    )
    .fails(2, "cert.invalid_argument");
    // A tampered CSR is refused.
    let mut csr = fs::read(d.join("w.csr")).unwrap();
    let pos = csr.len() / 2;
    csr[pos] = if csr[pos] == b'A' { b'B' } else { b'A' };
    fs::write(d.join("bad.csr"), csr).unwrap();
    call(
        &p(d, "ca"),
        "sign",
        &[
            ("mode", "csr"),
            ("csr_source", &p(d, "bad.csr")),
            ("signer_cert", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
            ("cert_output_path", &p(d, "bad.pem")),
        ],
    )
    .fails(1, "cert.csr_invalid");
    assert!(!d.join("bad.pem").exists());
}

#[test]
fn sign_data_with_an_encrypted_key_and_a_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    call(
        &p(d, "s"),
        "generate",
        &[("algorithm", "ed25519"), ("key_passphrase", "sig-pass")],
    )
    .ok();
    fs::write(d.join("data"), b"payload").unwrap();
    let k = p(d, "s-key.pem");
    let v = call(
        &p(d, "s"),
        "sign",
        &[
            ("signer_key", &k),
            ("signer_key_passphrase", "sig-pass"),
            ("data_source", &p(d, "data")),
            ("signature_output_path", &p(d, "data.sig")),
            ("timeout_ms", "60000"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["algorithm"], "Ed25519");
    assert_eq!(v["data"]["length_bytes"], 7);
    call(
        &p(d, "s"),
        "sign",
        &[("signer_key", &k), ("data_source", &p(d, "data"))],
    )
    .fails(2, "cert.passphrase_required");
    call(
        &p(d, "s"),
        "sign",
        &[
            ("signer_key", &p(d, "none")),
            ("data_source", &p(d, "data")),
        ],
    )
    .fails(1, "cert.signer_load_failed");
    call(
        &p(d, "s"),
        "sign",
        &[
            ("signer_key", &k),
            ("signer_key_passphrase", "sig-pass"),
            ("data_source", &p(d, "none")),
        ],
    )
    .fails(1, "cert.not_found");
}

#[test]
fn csr_sign_programmatic_issuing() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    gen_ca(d, "ca");
    call(
        &p(d, "r.csr"),
        "csr.create",
        &[
            ("subject", r#"{"common_name":"r.test"}"#),
            ("key_strategy", "generate"),
            ("algorithm", "ed25519"),
            ("new_key_output_path", &p(d, "r-key.pem")),
            ("sans", "DNS:r.test"),
            ("key_usage", "digitalSignature"),
            ("extended_key_usage", "clientAuth"),
        ],
    )
    .ok();
    let (ca, key) = (p(d, "ca.pem"), p(d, "ca-key.pem"));
    let base = vec![("signer_ca", ca.as_str()), ("signer_key", key.as_str())];
    let mut a = base.clone();
    let out = p(d, "r.pem");
    a.extend([
        ("cert_output_path", out.as_str()),
        ("serial_override", "0x0A0B0C"),
    ]);
    let v = call(&p(d, "r.csr"), "csr.sign", &a).ok().clone();
    assert_eq!(v["certificate"]["serial_number"], "0A0B0C");
    assert_eq!(v["certificate"]["key_usage"][0], "digitalSignature");
    assert_eq!(v["certificate"]["extended_key_usage"][0], "clientAuth");
    call(
        &out,
        "verify",
        &[("ca_file", &ca), ("purpose", "client_auth")],
    )
    .ok();
    let mut a = base.clone();
    let out2 = p(d, "r2.pem");
    a.extend([
        ("cert_output_path", out2.as_str()),
        ("serial_strategy", "uuid"),
        ("copy_subject", "false"),
        ("subject_common_name", "renamed.test"),
        ("copy_sans", "false"),
        ("copy_extended_key_usage", "false"),
        ("include_cert_pem", "true"),
    ]);
    let v = call(&p(d, "r.csr"), "csr.sign", &a).ok().clone();
    assert_eq!(v["certificate"]["subject"]["raw_dn"], "CN=renamed.test");
    assert_eq!(v["certificate"]["sans"].as_array().unwrap().len(), 0);
    assert_eq!(
        v["certificate"]["serial_number"].as_str().unwrap().len(),
        32
    );
    assert!(v["returned"]["cert_pem"].is_string());
    for bad in [
        vec![("serial_strategy", "increment"), ("cert_output_path", "x")],
        vec![("copy_subject", "false"), ("cert_output_path", "x")],
        vec![("serial_override", "zz"), ("cert_output_path", "x")],
        vec![],
    ] {
        let mut a = base.clone();
        a.extend(bad);
        call(&p(d, "r.csr"), "csr.sign", &a).fails(2, "cert.invalid_argument");
    }
    let mut a = base.clone();
    a.push(("cert_output_path", out.as_str()));
    call(&p(d, "r.csr"), "csr.sign", &a).fails(1, "cert.target_exists");
}

// ---------------------------------------------------------------------------
// renew
// ---------------------------------------------------------------------------

#[test]
fn renew_self_signed_and_ca_signed() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    call(
        &p(d, "ss"),
        "generate",
        &[
            ("mode", "self_signed"),
            ("algorithm", "ecdsa"),
            ("subject", r#"{"common_name":"ss.test"}"#),
            ("sans", "DNS:ss.test"),
            ("not_after_offset_days", "5"),
        ],
    )
    .ok();
    // reuse: same key, subject and SANs, new validity.
    let v = call(
        &p(d, "ss.pem"),
        "renew",
        &[
            ("not_after_offset_days", "100"),
            ("include_cert_pem", "true"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["new_cert"]["subject"]["common_name"], "ss.test");
    assert_eq!(v["new_cert"]["sans"][0], "DNS:ss.test");
    assert_eq!(v["key"]["reused"], true);
    assert!(v["returned"]["cert_pem"].is_string());
    let renewed = call(
        &p(d, "ss-renewed.pem"),
        "verify",
        &[
            ("ca_file", &p(d, "ss-renewed.pem")),
            ("keypair_target", &p(d, "ss-key.pem")),
        ],
    )
    .ok()
    .clone();
    assert_eq!(renewed["ok"], true);
    // rekey with an encrypted new key.
    let v = call(
        &p(d, "ss.pem"),
        "renew",
        &[
            ("key_strategy", "rekey"),
            ("algorithm", "rsa"),
            ("key_passphrase", "renew-pass"),
            ("new_cert_output_path", &p(d, "rk.pem")),
            ("not_before", "carry_over_start"),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["key"]["algorithm"], "rsa");
    assert_eq!(v["key"]["encrypted"], true);
    assert_eq!(v["key"]["stored_at"], p(d, "rk-key.pem"));
    assert_eq!(
        v["new_cert"]["validity"]["not_before"],
        v["old_cert"]["validity"]["not_before"]
    );
    let k = keys::load_key("k", &p(d, "rk-key.pem"), Some("renew-pass"), "x").unwrap();
    assert_eq!(k.algorithm, "rsa");
    call(
        &p(d, "rk.pem"),
        "verify",
        &[
            ("ca_file", &p(d, "rk.pem")),
            ("keypair_target", &p(d, "rk-key.pem")),
        ],
    )
    .fails(1, "cert.verification_failed");

    // A CA-signed certificate needs its signer.
    gen_ca(d, "ca");
    call(
        &p(d, "leaf"),
        "generate",
        &[
            ("mode", "leaf_cert"),
            ("algorithm", "ecdsa"),
            ("subject", r#"{"common_name":"leaf.test"}"#),
            ("signer_ca", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
        ],
    )
    .ok();
    call(&p(d, "leaf.pem"), "renew", &[]).fails(2, "cert.signer_required");
    let v = call(
        &p(d, "leaf.pem"),
        "renew",
        &[
            ("signer_ca", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
        ],
    )
    .ok()
    .clone();
    assert_eq!(v["new_cert"]["issuer"]["common_name"], "Gen CA");
    call(
        &p(d, "leaf-renewed.pem"),
        "verify",
        &[("ca_file", &p(d, "ca.pem"))],
    )
    .ok();
    // Existing output.
    call(
        &p(d, "leaf.pem"),
        "renew",
        &[
            ("signer_ca", &p(d, "ca.pem")),
            ("signer_key", &p(d, "ca-key.pem")),
        ],
    )
    .fails(1, "cert.target_exists");
}

#[test]
fn renew_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let t = p(d, "x.pem");
    for bad in [
        vec![("algorithm", "rsa")],
        vec![("key_strategy", "rekey"), ("existing_key_path", "k")],
        vec![("renewal_mode", "self_signed"), ("signer_ca", "c")],
        vec![("renewal_mode", "explicit_signer")],
        vec![("signer_ca", "c")],
        vec![("not_before", "yesterday")],
        vec![
            ("not_after", "2030-01-01T00:00:00Z"),
            ("not_after_offset_days", "3"),
        ],
        vec![("copy_subject", "false")],
        vec![("key_strategy", "rekey"), ("key_kdf_iterations", "10")],
    ] {
        call(&t, "renew", &bad).fails(2, "cert.invalid_argument");
    }
    call(&t, "renew", &[]).fails(1, "cert.not_found");
}
