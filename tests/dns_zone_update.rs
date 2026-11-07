//! `dns://.zone.update` through the built `resh` binary, against a fake DNS
//! server on 127.0.0.1 that records each request and answers with a fixed
//! RCODE.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command;
use tempfile::TempDir;

fn resh(dir: &std::path::Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("resh");
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_CACHE_HOME", dir.join("cache"));
    cmd
}

/// Starts a UDP server that answers every request with a header-only reply
/// carrying `rcode`. Returns the port and the captured requests.
fn fake_udp_server(rcode: u8) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = captured.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf) {
            let req = buf[..len].to_vec();
            sink.lock().unwrap().push(req.clone());
            // ID, QR + request opcode, RCODE, all counts zero
            let reply = [
                req[0],
                req[1],
                0x80 | (req[2] & 0x78),
                rcode & 0x0F,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            let _ = socket.send_to(&reply, peer);
        }
    });
    (port, captured)
}

const ADDS: &str =
    r#"[{"name":"www.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]"#;

#[test]
fn zone_update_sends_update_and_reports_noerror() {
    let tmp = TempDir::new().unwrap();
    let (port, captured) = fake_udp_server(0);
    let out = resh(tmp.path())
        .args([
            "dns://.zone.update",
            "zone=example.com",
            "servers=127.0.0.1",
            &format!("port={port}"),
            "use_tcp=false",
            &format!("adds={ADDS}"),
        ])
        .timeout(Duration::from_secs(20))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["summary"]["rcode"], "NOERROR");
    assert_eq!(v["summary"]["applied_adds"], 1);

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!((req[2] >> 3) & 0x0F, 5, "opcode UPDATE");
    // ZOCOUNT 1, PRCOUNT 0, UPCOUNT 1, ADCOUNT 0
    assert_eq!(&req[4..12], &[0, 1, 0, 0, 0, 1, 0, 0]);
    // The added A record's RDATA is on the wire
    assert!(req.windows(4).any(|w| w == [203, 0, 113, 10]));
}

#[test]
fn zone_update_reports_refused_and_exits_1() {
    let tmp = TempDir::new().unwrap();
    let (port, captured) = fake_udp_server(5);
    let out = resh(tmp.path())
        .args([
            "dns://.zone.update",
            "zone=example.com",
            "servers=127.0.0.1",
            &format!("port={port}"),
            "use_tcp=false",
            &format!("adds={ADDS}"),
        ])
        .timeout(Duration::from_secs(20))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["summary"]["rcode"], "REFUSED");
    assert_eq!(v["error"][0], "dns.zone_update_refused");
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[test]
fn zone_update_dry_run_sends_nothing() {
    let tmp = TempDir::new().unwrap();
    let (port, captured) = fake_udp_server(0);
    let out = resh(tmp.path())
        .args([
            "dns://.zone.update",
            "zone=example.com",
            "servers=127.0.0.1",
            &format!("port={port}"),
            "use_tcp=false",
            "dry_run=true",
            &format!("adds={ADDS}"),
        ])
        .timeout(Duration::from_secs(20))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["summary"]["dry_run"], true);
    std::thread::sleep(Duration::from_millis(100));
    assert!(captured.lock().unwrap().is_empty());
}

#[test]
fn zone_update_invalid_input_exits_1_with_code() {
    let tmp = TempDir::new().unwrap();
    let out = resh(tmp.path())
        .args([
            "dns://.zone.update",
            "zone=example.com",
            r#"adds=[{"name":"a.example.com","rtype":"BOGUS","ttl":1,"data":{}}]"#,
        ])
        .timeout(Duration::from_secs(20))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("[dns.zone_update_invalid_record_type]"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
