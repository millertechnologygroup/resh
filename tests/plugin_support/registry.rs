//! An in-process HTTPS plugin registry for tests (127.0.0.1 only), with a
//! private CA made by rcgen. Shared by the plugin unit tests
//! (`src/handles/pluginh/tests.rs`) and `tests/plugin_verbs.rs`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
enum Route {
    Body(u16, Vec<u8>),
    /// Sends headers promising `len` bytes, then one byte every 50 ms.
    Slow(u64),
    Redirect(String),
}

/// A fake registry/index server.
pub struct FakeRegistry {
    pub port: u16,
    pub ca_pem: String,
    routes: Arc<Mutex<HashMap<String, Route>>>,
    hits: Arc<Mutex<Vec<String>>>,
    entries: Mutex<HashMap<String, serde_json::Value>>,
}

/// The platform key of this machine (`linux-x86_64`).
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

/// A `.tar.gz` built by `f`.
pub fn tar_gz(f: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    f(&mut b);
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Appends a regular file with `mode`.
pub fn add_file(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8], mode: u32) {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    b.append_data(&mut h, path, data).unwrap();
}

/// A plugin artifact with an executable `bin/plugin` and a manifest.
pub fn plugin_tar_gz(tag: &str) -> Vec<u8> {
    tar_gz(|b| {
        add_file(
            b,
            "bin/plugin",
            format!("#!/bin/sh\necho {tag}\n").as_bytes(),
            0o755,
        );
        add_file(
            b,
            "manifest.json",
            br#"{"description":"demo plugin","tags":["demo"],"capabilities":["x"]}"#,
            0o644,
        );
    })
}

/// A tar.gz whose entry name is written raw into the header (so `..` and
/// absolute paths survive), for traversal tests.
pub fn raw_tar_gz(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = tar::Header::new_old();
    {
        let bytes = h.as_mut_bytes();
        bytes[..name.len()].copy_from_slice(name.as_bytes());
    }
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    let mut tar = h.as_bytes().to_vec();
    tar.extend_from_slice(data);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    tar.extend_from_slice(&[0u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn certs() -> (String, Vec<u8>, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::new(vec![]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "resh plugin test CA");
    let ca = rcgen::Certificate::from_params(ca_params).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    leaf.subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let leaf = rcgen::Certificate::from_params(leaf).unwrap();
    (
        ca.serialize_pem().unwrap(),
        leaf.serialize_der_with_signer(&ca).unwrap(),
        leaf.serialize_private_key_der(),
    )
}

impl FakeRegistry {
    pub fn start() -> Self {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let (ca_pem, leaf, key) = certs();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Arc<Mutex<HashMap<String, Route>>> = Arc::default();
        let hits: Arc<Mutex<Vec<String>>> = Arc::default();
        let (r, h) = (routes.clone(), hits.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (config, routes, hits) = (config.clone(), r.clone(), h.clone());
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let conn = match rustls::ServerConnection::new(config) {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let mut tls = rustls::StreamOwned::new(conn, stream);
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => return,
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    hits.lock().unwrap().push(path.clone());
                    let route = routes.lock().unwrap().get(&path).cloned();
                    match route {
                        None => respond(&mut tls, 404, b"not found", &[]),
                        Some(Route::Body(code, body)) => respond(&mut tls, code, &body, &[]),
                        Some(Route::Redirect(loc)) => {
                            respond(&mut tls, 302, b"", &[("Location", loc.as_str())])
                        }
                        Some(Route::Slow(len)) => {
                            let h = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nContent-Type: application/octet-stream\r\n\r\n"
                            );
                            if tls.write_all(h.as_bytes()).is_err() {
                                return;
                            }
                            for _ in 0..len {
                                if tls.write_all(b"x").and_then(|()| tls.flush()).is_err() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                    }
                });
            }
        });
        FakeRegistry {
            port,
            ca_pem,
            routes,
            hits,
            entries: Mutex::default(),
        }
    }

    /// `https://127.0.0.1:<port>`.
    pub fn base(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    pub fn set(&self, path: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_string(), Route::Body(status, body.into()));
    }

    pub fn slow(&self, path: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_string(), Route::Slow(1_000_000));
    }

    pub fn redirect(&self, path: &str, location: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_string(), Route::Redirect(location.to_string()));
    }

    /// Request paths served so far.
    pub fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }

    /// Publishes `version` of plugin `id`: the registry entry (with every
    /// version published so far) and the artifact `bin` with `data`. `sha`
    /// is the checksum the registry gives (`None`: none at all).
    pub fn publish(&self, id: &str, version: &str, bin: &str, data: &[u8], sha: Option<&str>) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .entry(id.to_string())
            .or_insert_with(|| serde_json::json!({"plugin_id": id, "versions": {}}));
        let mut spec = serde_json::json!({"os": std::env::consts::OS, "arch": std::env::consts::ARCH, "bin": bin});
        if let Some(s) = sha {
            spec["sha256"] = serde_json::json!(s);
        }
        entry["versions"][version] = serde_json::json!({
            "name": id,
            "version": version,
            "platforms": { platform(): spec },
        });
        let body = serde_json::to_vec(entry).unwrap();
        drop(entries);
        self.set(&format!("/v1/plugins/{id}"), 200, body);
        self.set(
            &format!("/v1/artifacts/{id}/{version}/{bin}"),
            200,
            data.to_vec(),
        );
    }

    /// Publishes a correct, checksummed `.tar.gz` of `id` `version`.
    pub fn publish_ok(&self, id: &str, version: &str) -> Vec<u8> {
        let data = plugin_tar_gz(version);
        let sha = sha256_hex(&data);
        self.publish(id, version, "plugin.tar.gz", &data, Some(&sha));
        data
    }
}

fn respond<S: Write>(s: &mut S, code: u16, body: &[u8], headers: &[(&str, &str)]) {
    let reason = match code {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        _ => "Status",
    };
    let mut h = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}
