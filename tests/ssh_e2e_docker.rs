//! End-to-end tests for `ssh://` against a real OpenSSH server in a
//! throwaway `debian:13-slim` container, reached on a mapped 127.0.0.1 port.
//! The client side runs the host's ssh with a temporary HOME and explicit
//! known_hosts and key files; the user's ~/.ssh is never used for keys or
//! known hosts. Password logins need sshpass, so those runs execute the
//! host-built resh inside the container against its own sshd.
//!
//! Run with `cargo test --features e2e-docker --test ssh_e2e_docker`.

#![cfg(feature = "e2e-docker")]

use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const IMAGE: &str = "resh-ssh-e2e:1";
const DOCKERFILE: &str = "FROM debian:13-slim\n\
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
openssh-client sshpass socat procps && rm -rf /var/lib/apt/lists/*\n";

const SETUP: &str = r#"
useradd -m -s /bin/bash alice && echo alice:alicepw | chpasswd
useradd -m -s /bin/sh bob
for h in /home/alice /root; do mkdir -p $h/.ssh && chmod 700 $h/.ssh; done
chown alice:alice /home/alice/.ssh
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
socat TCP-LISTEN:7000,fork,reuseaddr EXEC:cat &
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes \
  -o PermitRootLogin=prohibit-password -o AllowTcpForwarding=yes -o MaxStartups=100
"#;

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("docker is required for e2e-docker tests")
}

fn ensure_image() {
    if docker(&["image", "inspect", IMAGE]).status.success() {
        return;
    }
    let mut child = Command::new("docker")
        .args(["build", "-q", "-t", IMAGE, "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(DOCKERFILE.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "image build failed");
}

/// A running sshd container plus the client-side files.
struct Server {
    id: String,
    port: u16,
    dir: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.id]);
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    json: Value,
}

fn keygen(path: &Path, kind: &str, pass: &str) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", kind, "-N", pass, "-C", kind, "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success());
}

impl Server {
    fn start() -> Server {
        ensure_image();
        let bin = env!("CARGO_BIN_EXE_resh");
        let mount = format!("{bin}:/usr/local/bin/resh:ro");
        let out = docker(&[
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::22",
            "-v",
            &mount,
            IMAGE,
            "sh",
            "-c",
            SETUP,
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let id = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let port_out = docker(&["port", &id, "22/tcp"]);
        let mapped = String::from_utf8(port_out.stdout).unwrap();
        let port: u16 = mapped
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("mapped port");
        let dir = TempDir::new().unwrap();
        let s = Server { id, port, dir };
        for d in ["home", "keys"] {
            std::fs::create_dir(s.path(d)).unwrap();
        }
        keygen(&s.path("keys/ed"), "ed25519", "");
        keygen(&s.path("keys/rsa"), "rsa", "");
        keygen(&s.path("keys/enc"), "ed25519", "secret-pp");
        // Wait until the setup script has started sshd.
        let start = Instant::now();
        while !docker(&["exec", &s.id, "pgrep", "-x", "sshd"])
            .status
            .success()
        {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "sshd did not start"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut auth = String::new();
        for k in ["ed", "rsa", "enc"] {
            auth.push_str(&std::fs::read_to_string(s.path(&format!("keys/{k}.pub"))).unwrap());
        }
        s.exec_in(&format!(
            "printf '%s' '{auth}' > /home/alice/.ssh/authorized_keys && \
             chown alice:alice /home/alice/.ssh/authorized_keys && chmod 600 /home/alice/.ssh/authorized_keys && \
             printf '%s' '{auth}' > /root/.ssh/authorized_keys"
        ));
        // Wait for sshd, then pin its host key in our known_hosts.
        let start = Instant::now();
        let hostkey = loop {
            let k = s.exec_in("cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null; true");
            if !k.trim().is_empty() && std::net::TcpStream::connect(("127.0.0.1", s.port)).is_ok() {
                break k;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "sshd did not start"
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        let line = format!("[127.0.0.1]:{} {}", s.port, hostkey.trim());
        std::fs::write(s.path("known_hosts"), format!("{line}\n")).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        s
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn exec_in(&self, script: &str) -> String {
        let out = docker(&["exec", &self.id, "sh", "-c", script]);
        assert!(
            out.status.success(),
            "{}: {}",
            script.chars().take(60).collect::<String>(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn url(&self, user: &str, verb: &str) -> String {
        format!("ssh://{user}@127.0.0.1:{}.{verb}", self.port)
    }

    /// Common arguments: strict host keys with our known_hosts, the ed25519 key.
    fn key_args(&self) -> Vec<String> {
        vec![
            format!("known_hosts_path={}", self.path("known_hosts").display()),
            format!("identity_path={}", self.path("keys/ed").display()),
        ]
    }

    fn resh(&self, args: &[String]) -> Run {
        let out = Command::new(env!("CARGO_BIN_EXE_resh"))
            .current_dir(self.dir.path())
            .env("HOME", self.path("home"))
            .env_remove("SSH_AUTH_SOCK")
            .args(args)
            .output()
            .unwrap();
        to_run(out)
    }

    fn run(&self, user: &str, verb: &str, extra: &[&str]) -> Run {
        let mut a = vec![self.url(user, verb)];
        a.extend(self.key_args());
        a.extend(extra.iter().map(|s| s.to_string()));
        self.resh(&a)
    }

    /// resh inside the container (for sshpass), against its own sshd.
    fn resh_inside(&self, args: &[&str]) -> Run {
        let mut a = vec!["exec", &self.id, "resh"];
        a.extend_from_slice(args);
        to_run(docker(&a))
    }
}

fn to_run(out: std::process::Output) -> Run {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let last = stdout
        .find("\n{")
        .filter(|_| stdout.starts_with("{\"event\""))
        .map(|i| &stdout[i + 1..])
        .unwrap_or(&stdout);
    Run {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(last).unwrap_or(Value::Null),
        stdout: stdout.clone(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn ok(r: &Run) -> &Value {
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["ok"], true, "{}", r.stdout);
    &r.json
}

fn fails(r: &Run, exit: i32, code: &str) {
    assert_eq!(r.code, exit, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(r.json["error"]["code"], code, "{}", r.stdout);
}

#[test]
fn exec_with_every_kind_of_key() {
    let s = Server::start();
    let r = s.run(
        "alice",
        "exec",
        &["command=id -un; echo err >&2; pwd", "cwd=/tmp"],
    );
    let j = ok(&r);
    assert_eq!(j["result"]["stdout"], "alice\n/tmp");
    assert_eq!(j["result"]["stderr"], "err");
    let r = s.run("alice", "exec", &["command=exit 42"]);
    fails(&r, 1, "ssh.remote_exit_nonzero");
    assert_eq!(r.json["result"]["exit_code"], 42);
    let r = s.run("alice", "exec", &["command=cat; echo done"]);
    assert_eq!(ok(&r)["result"]["stdout"], "done", "stdin is empty");
    let r = s.run(
        "alice",
        "exec",
        &[
            "command=printf '%s|' \"$A\" ",
            "command_args=x y,$(id)",
            "env=A=v a l",
        ],
    );
    assert_eq!(ok(&r)["result"]["stdout"], "v a l|x y|$(id)|");

    let kh = format!("known_hosts_path={}", s.path("known_hosts").display());
    let rsa = format!("identity_path={}", s.path("keys/rsa").display());
    let r = s.resh(&[
        s.url("alice", "exec"),
        kh.clone(),
        rsa,
        "command=echo rsa".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "rsa");
    let enc = format!("identity_path={}", s.path("keys/enc").display());
    let r = s.resh(&[
        s.url("alice", "exec"),
        kh.clone(),
        enc.clone(),
        "identity_passphrase=secret-pp".into(),
        "command=echo enc".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "enc", "{}", r.stderr);
    let r = s.resh(&[
        s.url("alice", "exec"),
        kh.clone(),
        enc,
        "identity_passphrase=wrong".into(),
        "command=echo enc".into(),
    ]);
    assert_eq!(r.code, 1);
    let key = std::fs::read_to_string(s.path("keys/ed")).unwrap();
    let r = s.resh(&[
        s.url("alice", "exec"),
        kh.clone(),
        format!("identity_data={key}"),
        "command=echo data".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "data");
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&key);
    let r = s.resh(&[
        s.url("alice", "exec"),
        kh,
        format!("identity_data={b64}"),
        "command=echo b64".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "b64");
}

#[test]
fn exec_timeout_kills_the_remote_command() {
    let s = Server::start();
    let start = Instant::now();
    let r = s.run(
        "alice",
        "exec",
        &[
            "command=sleep 7; touch /tmp/late",
            "command_timeout_ms=1500",
        ],
    );
    fails(&r, 124, "ssh.exec_timeout");
    assert!(start.elapsed() < Duration::from_secs(7));
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("was stopped"),
        "{}",
        r.stdout
    );
    std::thread::sleep(Duration::from_secs(7));
    assert_eq!(
        s.exec_in("pgrep -x sleep || true; test -e /tmp/late && echo late || true")
            .trim(),
        ""
    );
}

#[test]
fn password_agent_and_host_key_modes() {
    let s = Server::start();
    // Password logins run inside the container, where sshpass is installed.
    let r = s.resh_inside(&[
        "ssh://alice:alicepw@127.0.0.1.exec",
        "known_hosts_mode=accept-new",
        "command=id -un",
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "alice");
    let r = s.resh_inside(&[
        "ssh://alice:wrong@127.0.0.1.exec",
        "known_hosts_mode=accept-new",
        "command=id -un",
    ]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let r = s.resh_inside(&[
        "ssh://alice@127.0.0.1.test",
        "password=alicepw",
        "known_hosts_mode=accept-new",
        "tests=connect,auth,exec,sftp",
    ]);
    assert_eq!(ok(&r)["summary"]["tests_passed"], 4);

    // Agent.
    let sock = s.path("agent.sock");
    let agent = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&sock)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _agent = Kill(agent);
    let start = Instant::now();
    while !sock.exists() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    let added = Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", &sock)
        .arg(s.path("keys/rsa"))
        .output()
        .unwrap();
    assert!(added.status.success());
    let r = s.resh(&[
        s.url("alice", "exec"),
        format!("known_hosts_path={}", s.path("known_hosts").display()),
        "auth_method=agent".into(),
        format!("agent_socket={}", sock.display()),
        "command=echo agent".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "agent");

    // Host keys: strict with an empty file fails; accept-new records it.
    let empty = s.path("empty_known_hosts");
    std::fs::write(&empty, "").unwrap();
    let id = format!("identity_path={}", s.path("keys/ed").display());
    let r = s.resh(&[
        s.url("alice", "download"),
        id.clone(),
        format!("known_hosts_path={}", empty.display()),
        "source=/etc/hostname".into(),
        "dest_mode=none".into(),
    ]);
    fails(&r, 1, "ssh.hostkey_verification_failed");
    let r = s.resh(&[
        s.url("alice", "exec"),
        id.clone(),
        format!("known_hosts_path={}", empty.display()),
        "known_hosts_mode=accept-new".into(),
        "command=true".into(),
    ]);
    ok(&r);
    assert!(std::fs::read_to_string(&empty).unwrap().contains("ssh-"));
    // A wrong key in known_hosts is refused.
    let wrong = s.path("wrong_known_hosts");
    let fake = std::fs::read_to_string(s.path("keys/ed.pub")).unwrap();
    let mut it = fake.split_whitespace();
    std::fs::write(
        &wrong,
        format!(
            "[127.0.0.1]:{} {} {}\n",
            s.port,
            it.next().unwrap(),
            it.next().unwrap()
        ),
    )
    .unwrap();
    let r = s.resh(&[
        s.url("alice", "test"),
        id,
        format!("known_hosts_path={}", wrong.display()),
        "tests=hostkey".into(),
    ]);
    fails(&r, 1, "ssh.test_failed");
    assert_eq!(
        r.json["tests"][0]["error"]["code"],
        "ssh.test_hostkey_failed"
    );
}

#[test]
fn file_transfer_both_ways() {
    let s = Server::start();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(s.path("blob.bin"), &data).unwrap();
    let src = format!("source={}", s.path("blob.bin").display());
    let r = s.run(
        "alice",
        "upload",
        &[
            &src,
            "dest=~/in/blob.bin",
            "file_mode=0600",
            "verify_checksum=true",
        ],
    );
    assert_eq!(ok(&r)["result"]["checksum_verified"], true);
    assert_eq!(
        s.exec_in("stat -c '%a %U %s' /home/alice/in/blob.bin")
            .trim(),
        "600 alice 200000"
    );
    let r = s.run("alice", "upload", &[&src, "dest=~/in/blob.bin"]);
    fails(&r, 1, "ssh.upload_dest_exists");
    let r = s.run("alice", "upload", &[&src, "dest=/root/x"]);
    fails(&r, 1, "ssh.upload_remote_write_failed");
    let dest = s.path("back/blob.bin");
    let r = s.run(
        "alice",
        "download",
        &[
            "source=in/blob.bin",
            &format!("dest={}", dest.display()),
            "verify_checksum=true",
            "checksum_algorithm=sha1",
            "return_content=false",
        ],
    );
    ok(&r);
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    let r = s.run(
        "alice",
        "download",
        &[
            "source=in/blob.bin",
            "dest_mode=none",
            "max_size_bytes=1000",
        ],
    );
    fails(&r, 1, "ssh.download_too_large");
    let r = s.run(
        "alice",
        "download",
        &["source=/etc/shadow", "dest_mode=none"],
    );
    fails(&r, 1, "ssh.download_remote_read_failed");
    let r = s.run("alice", "download", &["source=/nope", "dest_mode=none"]);
    fails(&r, 1, "ssh.download_source_not_found");
}

#[test]
fn tunnels_forward_to_container_services() {
    let s = Server::start();
    // Local forward to the echo service on the container's loopback.
    let mut a = vec![s.url("alice", "tunnel")];
    a.extend(s.key_args());
    a.extend(
        [
            "mode=local",
            "remote_dest_host=127.0.0.1",
            "remote_dest_port=7000",
            "max_connections=1",
        ]
        .map(String::from),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_resh"))
        .env("HOME", s.path("home"))
        .env_remove("SSH_AUTH_SOCK")
        .args(&a)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut first = Vec::new();
    let mut b = [0u8; 1];
    while out.read(&mut b).unwrap() == 1 && b[0] != b'\n' {
        first.push(b[0]);
    }
    let ready: Value = serde_json::from_slice(&first).unwrap();
    let mut c = std::net::TcpStream::connect(ready["listen"].as_str().unwrap()).unwrap();
    c.write_all(b"through ssh").unwrap();
    let mut buf = [0u8; 11];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"through ssh");
    drop(c);
    let mut rest = String::new();
    out.read_to_string(&mut rest).unwrap();
    assert!(child.wait().unwrap().success(), "{rest}");
    let report: Value = serde_json::from_str(&rest).unwrap();
    assert_eq!(report["lifetime"]["closed_reason"], "max_connections");
    assert_eq!(report["stats"]["bytes_in"], 11);
    assert_eq!(report["stats"]["bytes_out"], 11);

    // Dynamic (SOCKS5) forward.
    let mut a = vec![s.url("alice", "tunnel")];
    a.extend(s.key_args());
    a.extend(["mode=dynamic", "max_connections=1"].map(String::from));
    let mut child = Command::new(env!("CARGO_BIN_EXE_resh"))
        .env("HOME", s.path("home"))
        .env_remove("SSH_AUTH_SOCK")
        .args(&a)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut first = Vec::new();
    while out.read(&mut b).unwrap() == 1 && b[0] != b'\n' {
        first.push(b[0]);
    }
    let ready: Value = serde_json::from_slice(&first).unwrap();
    let mut c = std::net::TcpStream::connect(ready["listen"].as_str().unwrap()).unwrap();
    c.write_all(&[5, 1, 0]).unwrap();
    let mut hello = [0u8; 2];
    c.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [5, 0]);
    c.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1b, 0x58])
        .unwrap(); // port 7000
    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "SOCKS connect refused");
    c.write_all(b"socks").unwrap();
    let mut buf = [0u8; 5];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"socks");
    drop(c);
    let mut rest = String::new();
    out.read_to_string(&mut rest).unwrap();
    assert!(child.wait().unwrap().success(), "{rest}");

    // Remote forward: the container connects back to an echo server here.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in echo.incoming().flatten() {
            let mut r = c.try_clone().unwrap();
            let mut w = c;
            let _ = std::io::copy(&mut r, &mut w);
        }
    });
    let mut a = vec![s.url("alice", "tunnel")];
    a.extend(s.key_args());
    a.extend([
        "mode=remote".to_string(),
        "remote_bind_port=9000".into(),
        "local_dest_host=127.0.0.1".into(),
        format!("local_dest_port={echo_port}"),
        "max_connections=1".into(),
    ]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_resh"))
        .env("HOME", s.path("home"))
        .env_remove("SSH_AUTH_SOCK")
        .args(&a)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut first = Vec::new();
    while out.read(&mut b).unwrap() == 1 && b[0] != b'\n' {
        first.push(b[0]);
    }
    let ready: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(ready["mode"], "remote");
    let echoed = s.exec_in("printf back | socat -t 2 - TCP:127.0.0.1:9000");
    assert_eq!(echoed, "back");
    let mut rest = String::new();
    out.read_to_string(&mut rest).unwrap();
    assert!(child.wait().unwrap().success(), "{rest}");
    let report: Value = serde_json::from_str(&rest).unwrap();
    assert_eq!(report["stats"]["connections_accepted"], 1);

    // A port the server cannot bind is a forward failure.
    let mut a = vec![s.url("alice", "tunnel")];
    a.extend(s.key_args());
    a.extend(
        [
            "mode=remote",
            "remote_bind_port=22",
            "local_dest_host=127.0.0.1",
            "local_dest_port=1",
        ]
        .map(String::from),
    );
    let r = s.resh(&a);
    fails(&r, 1, "ssh.tunnel_forward_failed");
}

#[test]
fn keys_and_connection_checks() {
    let s = Server::start();
    let r = s.run("alice", "keys.list", &[]);
    let j = ok(&r);
    assert_eq!(j["files"][0]["path"], "/home/alice/.ssh/authorized_keys");
    assert_eq!(j["summary"]["total_keys"], 3);
    assert_eq!(j["files"][1]["exists"], false);
    let r = s.run("root", "keys.list", &["scope=host", "key_types=ed25519"]);
    assert_eq!(ok(&r)["summary"]["matched_keys"], 1);

    // key.add as root into bob's authorized_keys: created with bob's owner.
    keygen(&s.path("keys/new"), "ed25519", "");
    let pubkey = format!("public_key_path={}", s.path("keys/new.pub").display());
    let r = s.run("root", "key.add", &[&pubkey, "authorized_user=bob"]);
    let j = ok(&r);
    assert_eq!(j["operation"]["status"], "added");
    assert_eq!(j["target_file"], "/home/bob/.ssh/authorized_keys");
    assert_eq!(
        s.exec_in("stat -c '%U %a' /home/bob/.ssh /home/bob/.ssh/authorized_keys"),
        "bob 700\nbob 600\n"
    );
    let r = s.run("root", "key.add", &[&pubkey, "authorized_user=bob"]);
    assert_eq!(ok(&r)["operation"]["status"], "already_present");
    // Added to alice's own file, then usable for login.
    let r = s.run("alice", "key.add", &[&pubkey]);
    assert_eq!(ok(&r)["operation"]["backup_created"], true);
    let r = s.resh(&[
        s.url("alice", "exec"),
        format!("known_hosts_path={}", s.path("known_hosts").display()),
        format!("identity_path={}", s.path("keys/new").display()),
        "command=echo new".into(),
    ]);
    assert_eq!(ok(&r)["result"]["stdout"], "new");
    assert_eq!(
        s.exec_in("stat -c %a /home/alice/.ssh/authorized_keys")
            .trim(),
        "600"
    );

    // test: every check, with the real host key fingerprint.
    let r = s.run(
        "alice",
        "test",
        &["tests=connect,auth,exec,sftp,hostkey", "exec_command=true"],
    );
    let j = ok(&r);
    assert_eq!(j["summary"]["tests_passed"], 5);
    let fp = s.exec_in("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub");
    let want = j["security"]["hostkey_fingerprint"].as_str().unwrap();
    assert!(fp.contains(want), "{fp} vs {want}");
    let r = s.run("alice", "test", &["tests=exec", "exec_command=exit 3"]);
    fails(&r, 1, "ssh.test_failed");
    // Wrong user: auth fails, connect passes.
    let r = s.run("bob", "test", &[]);
    fails(&r, 1, "ssh.test_failed");
    assert_eq!(r.json["tests"][0]["status"], "passed");
    assert_eq!(r.json["tests"][1]["error"]["code"], "ssh.test_auth_failed");
    // Nothing listens: connect fails.
    let r = s.resh(&[
        "ssh://alice@127.0.0.1:1.exec".into(),
        "command=true".into(),
        "connect_timeout_ms=2000".into(),
    ]);
    assert_eq!(r.code, 1, "{}", r.stderr);
}
