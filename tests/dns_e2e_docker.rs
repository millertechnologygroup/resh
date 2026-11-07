//! `dns://` against a real BIND 9 server in a throwaway Docker container
//! (published on 127.0.0.1 only; nothing on the internet is contacted).
//! Run with `cargo test --features e2e-docker --test dns_e2e_docker`.
//!
//! The container serves `example.com.` (transfers and updates need the TSIG
//! key `xfr-key`; about 2000 records, so AXFR spans many signed messages)
//! and `open.test.` (unsigned transfers allowed). The host-built `resh`
//! binary queries it: lookup, zone.fetch (unsigned, signed, IXFR after an
//! update) and a signed zone.update.
#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::process::Command;
use std::time::{Duration, Instant};

const IMAGE: &str = "internetsystemsconsortium/bind9:9.20";
const SECRET: &str = "c2VjcmV0LWtleS1ieXRlcy0xMjM0NTY3ODkwYWJjZGVm";

struct Bind {
    name: String,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Bind {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

fn free_port() -> u16 {
    loop {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = t.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

fn write(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
}

fn start_bind() -> Bind {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    write(
        &dir.path().join("named.conf"),
        &format!(
            r#"options {{
    directory "/zones";
    listen-on {{ any; }};
    listen-on-v6 {{ none; }};
    recursion no;
    allow-query {{ any; }};
    dnssec-validation no;
}};
key "xfr-key" {{ algorithm hmac-sha256; secret "{SECRET}"; }};
zone "example.com" {{
    type primary;
    file "/zones/example.com.db";
    allow-transfer {{ key xfr-key; }};
    allow-update {{ key xfr-key; }};
}};
zone "open.test" {{
    type primary;
    file "/zones/open.test.db";
    allow-transfer {{ any; }};
}};
"#
        ),
    );
    let mut zone = String::from(
        "$TTL 300\n@ IN SOA ns1.example.com. hostmaster.example.com. 100 7200 3600 1209600 300\n\
         @ IN NS ns1.example.com.\nns1 IN A 192.0.2.53\nwww IN A 192.0.2.10\n\
         @ IN MX 10 mail.example.com.\nmail IN A 192.0.2.25\n",
    );
    for i in 0..2000 {
        zone.push_str(&format!(
            "h{i} IN TXT \"record number {i} with some padding text\"\n"
        ));
    }
    write(&dir.path().join("example.com.db"), &zone);
    write(
        &dir.path().join("open.test.db"),
        "$TTL 300\n@ IN SOA ns1.open.test. hostmaster.open.test. 7 7200 3600 1209600 300\n\
         @ IN NS ns1.open.test.\nns1 IN A 192.0.2.54\na IN A 192.0.2.1\nb IN A 192.0.2.2\n",
    );
    let port = free_port();
    let name = format!("resh-dns-e2e-{}-{port}", std::process::id());
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "-p",
            &format!("127.0.0.1:{port}:53/tcp"),
            "-p",
            &format!("127.0.0.1:{port}:53/udp"),
            "-v",
            &format!("{}:/zones", dir.path().display()),
            IMAGE,
            // The image's entrypoint is `named -u bind`.
            "-g",
            "-c",
            "/zones/named.conf",
        ])
        .output()
        .expect("docker is required for e2e-docker tests");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bind = Bind {
        name,
        port,
        _dir: dir,
    };
    // Wait until BIND answers.
    let started = Instant::now();
    loop {
        let (code, _, _) = resh(
            &bind,
            &[
                "dns://.lookup",
                "name=www.example.com",
                "timeout_ms=300",
                "retries=0",
            ],
        );
        if code == 0 {
            break;
        }
        if started.elapsed() > Duration::from_secs(30) {
            let logs = Command::new("docker")
                .args(["logs", &bind.name])
                .output()
                .unwrap();
            panic!(
                "BIND did not start: {}",
                String::from_utf8_lossy(&logs.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bind
}

/// Runs the host binary with `servers=127.0.0.1 port=<bind port>` added.
fn resh(bind: &Bind, args: &[&str]) -> (i32, Value, String) {
    let port = format!("port={}", bind.port);
    let out = Command::new(env!("CARGO_BIN_EXE_resh"))
        .args(args)
        .args(["servers=127.0.0.1", &port])
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const KEY: [&str; 2] = [
    "tsig_key_name=xfr-key",
    "tsig_secret=c2VjcmV0LWtleS1ieXRlcy0xMjM0NTY3ODkwYWJjZGVm",
];

#[test]
fn lookup_transfer_and_update_against_bind() {
    let bind = start_bind();

    // lookup: authoritative answer with the additional glue.
    let (code, v, err) = resh(&bind, &["dns://.lookup", "name=example.com", "rtype=MX"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(v["response"]["authoritative"], true);
    assert_eq!(v["answers"][0]["data"]["exchange"], "mail.example.com.");
    assert_eq!(v["additional"][0]["data"]["address"], "192.0.2.25");
    let (code, v, _) = resh(&bind, &["dns://.lookup", "name=nope.example.com"]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "dns.lookup_nxdomain");
    assert_eq!(v["authority"][0]["rtype"], "SOA");
    let (code, v, _) = resh(
        &bind,
        &["dns://.resolve", "name=www.example.com", "family=ipv4"],
    );
    assert_eq!(code, 0);
    assert_eq!(v["resolution"]["addresses"][0]["ip"], "192.0.2.10");

    // Unsigned AXFR where allowed.
    let (code, v, err) = resh(&bind, &["dns://.zone.fetch", "zone=open.test"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(v["zone"]["serial"], 7);
    assert_eq!(v["zone"]["record_count"], 5);

    // example.com needs the key.
    let (code, v, _) = resh(&bind, &["dns://.zone.fetch", "zone=example.com"]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "dns.zone_fetch_refused", "{v}");

    // Signed multi-message AXFR, every signature verified.
    let mut args = vec!["dns://.zone.fetch", "zone=example.com", "include_raw=true"];
    args.extend(KEY);
    let (code, v, err) = resh(&bind, &args);
    assert_eq!(code, 0, "{err}\n{}", v["error"]);
    assert_eq!(v["zone"]["record_count"], 2006);
    assert!(
        v["raw"]["response_hex"].as_array().unwrap().len() > 1,
        "expected several messages"
    );
    let serial0 = v["zone"]["serial"].as_u64().unwrap();

    // Wrong secret: BIND rejects the signature.
    let (code, v, _) = resh(
        &bind,
        &[
            "dns://.zone.fetch",
            "zone=example.com",
            "tsig_key_name=xfr-key",
            "tsig_secret=b3RoZXIta2V5LWJ5dGVz",
        ],
    );
    assert_eq!(code, 1);
    let ecode = v["error"]["code"].as_str().unwrap();
    assert!(
        ecode == "dns.zone_fetch_tsig_failed" || ecode == "dns.zone_fetch_rcode_error",
        "{v}"
    );

    // Unsigned update: refused.
    let adds = r#"adds=[{"name":"new.example.com","rtype":"A","ttl":300,"data":{"address":"203.0.113.10"}}]"#;
    let (code, v, _) = resh(&bind, &["dns://.zone.update", "zone=example.com", adds]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "dns.zone_update_refused", "{v}");

    // Signed update over UDP and TCP.
    let mut args = vec![
        "dns://.zone.update",
        "zone=example.com",
        adds,
        "use_tcp=false",
    ];
    args.extend(KEY);
    let (code, v, err) = resh(&bind, &args);
    assert_eq!(code, 0, "{err}\n{v}");
    assert_eq!(v["summary"]["rcode"], "NOERROR");
    assert_eq!(v["summary"]["tsig_used"], true);
    let prereq =
        r#"prerequisites=[{"kind":"record_not_exists","name":"new.example.com","rtype":"A"}]"#;
    let mut args = vec!["dns://.zone.update", "zone=example.com", adds, prereq];
    args.extend(KEY);
    let (code, v, _) = resh(&bind, &args);
    assert_eq!(code, 1);
    assert_eq!(
        v["error"]["code"], "dns.zone_update_precondition_failed",
        "{v}"
    );

    let (code, v, _) = resh(&bind, &["dns://.lookup", "name=new.example.com"]);
    assert_eq!(code, 0);
    assert_eq!(v["answers"][0]["data"]["address"], "203.0.113.10");

    // IXFR from the old serial: the change only.
    let serial_arg = format!("serial={serial0}");
    let mut args = vec![
        "dns://.zone.fetch",
        "zone=example.com",
        "transfer=IXFR",
        serial_arg.as_str(),
    ];
    args.extend(KEY);
    let (code, v, err) = resh(&bind, &args);
    assert_eq!(code, 0, "{err}\n{v}");
    assert_eq!(v["zone"]["transfer_used"], "IXFR", "{v}");
    assert_eq!(v["changes"]["old_serial"], serial0);
    let added = v["changes"]["added"].as_array().unwrap();
    assert!(
        added
            .iter()
            .any(|r| r["name"] == "new.example.com." && r["data"]["address"] == "203.0.113.10"),
        "{v}"
    );
}
