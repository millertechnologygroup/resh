//! A scripted SMTP server on 127.0.0.1 for the mail handle's tests (unit
//! tests include it with `#[path]`, and so does tests/mail_verbs.rs). It
//! speaks just enough ESMTP for lettre: EHLO/HELO, STARTTLS (advertised and
//! accepted, then the handshake fails because the server has no TLS), AUTH
//! PLAIN and AUTH LOGIN, MAIL, RCPT, DATA (dot-unstuffed), RSET, NOOP and
//! QUIT. Every session is recorded for assertions.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the server does. The default accepts everything without AUTH.
#[derive(Clone, Debug)]
pub struct Behavior {
    /// Advertise AUTH with these mechanisms (for example "PLAIN LOGIN").
    pub auth_mechs: Option<&'static str>,
    /// The credentials AUTH accepts; anything else gets 535.
    pub credentials: Option<(String, String)>,
    /// Advertise STARTTLS. The server answers 220 and then writes plain
    /// text, so the client's TLS handshake fails.
    pub starttls: bool,
    /// Recipients answered with `550 5.1.1 no such user`.
    pub reject_rcpt: Vec<String>,
    /// Reply to MAIL FROM in the first `n` sessions (then 250).
    pub mail_reply: Option<(usize, &'static str)>,
    /// Reply after the message data instead of 250.
    pub data_reply: Option<&'static str>,
    /// Wait this long before the greeting.
    pub greeting_delay: Duration,
    /// Wait this long before answering the end of DATA.
    pub data_delay: Duration,
    /// Send this instead of the normal greeting (for example a 554).
    pub greeting: Option<&'static str>,
    /// Answer NOOP with this instead of 250.
    pub noop_reply: Option<&'static str>,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            auth_mechs: None,
            credentials: None,
            starttls: false,
            reject_rcpt: Vec::new(),
            mail_reply: None,
            data_reply: None,
            greeting_delay: Duration::ZERO,
            data_delay: Duration::ZERO,
            greeting: None,
            noop_reply: None,
        }
    }
}

/// One SMTP session as the server saw it.
#[derive(Clone, Debug, Default)]
pub struct Session {
    pub commands: Vec<String>,
    /// (mechanism, user, password) of an AUTH exchange.
    pub auth: Option<(String, String, String)>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    /// The message as received (CRLF line ends, dot-unstuffed).
    pub data: Option<String>,
}

pub struct FakeSmtp {
    pub port: u16,
    sessions: Arc<Mutex<Vec<Session>>>,
}

impl FakeSmtp {
    pub fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake SMTP server");
        let port = listener.local_addr().unwrap().port();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&sessions);
        std::thread::spawn(move || {
            let mut count = 0usize;
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                count += 1;
                let b = behavior.clone();
                let rec = Arc::clone(&recorded);
                let index = {
                    let mut all = rec.lock().unwrap();
                    all.push(Session::default());
                    all.len() - 1
                };
                let n = count;
                std::thread::spawn(move || {
                    let _ = serve(stream, &b, n, &rec, index);
                });
            }
        });
        Self { port, sessions }
    }

    pub fn port_arg(&self) -> String {
        format!("smtp_port={}", self.port)
    }

    pub fn sessions(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().clone()
    }

    /// Sessions that delivered a message.
    pub fn messages(&self) -> Vec<Session> {
        self.sessions()
            .into_iter()
            .filter(|s| s.data.is_some())
            .collect()
    }

    /// Waits up to two seconds for `n` sessions to be recorded and to end
    /// their exchange (the client may close after the reply arrives).
    pub fn wait_sessions(&self, n: usize) -> Vec<Session> {
        for _ in 0..200 {
            let s = self.sessions();
            if s.len() >= n {
                return s;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.sessions()
    }
}

fn update(rec: &Arc<Mutex<Vec<Session>>>, index: usize, f: impl FnOnce(&mut Session)) {
    f(&mut rec.lock().unwrap()[index]);
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_default()
}

fn serve(
    stream: TcpStream,
    b: &Behavior,
    session_number: usize,
    rec: &Arc<Mutex<Vec<Session>>>,
    index: usize,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut out = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut send = |out: &mut TcpStream, line: &str| -> std::io::Result<()> {
        out.write_all(line.as_bytes())?;
        out.write_all(b"\r\n")?;
        out.flush()
    };
    std::thread::sleep(b.greeting_delay);
    if let Some(g) = b.greeting {
        send(&mut out, g)?;
    } else {
        send(&mut out, "220 fake.test ESMTP ready")?;
    }

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let cmd = line.trim_end_matches(['\r', '\n']).to_string();
        update(rec, index, |s| s.commands.push(cmd.clone()));
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let mut lines = vec!["250-fake.test".to_string()];
            if b.starttls {
                lines.push("250-STARTTLS".to_string());
            }
            if let Some(m) = b.auth_mechs {
                lines.push(format!("250-AUTH {m}"));
            }
            lines.push("250 8BITMIME".to_string());
            send(&mut out, &lines.join("\r\n"))?;
        } else if upper.starts_with("HELO") {
            send(&mut out, "250 fake.test")?;
        } else if upper == "STARTTLS" {
            send(&mut out, "220 2.0.0 go ahead")?;
            // No TLS here: wait for the ClientHello, answer it with plain
            // text, and close.
            let mut hello = [0u8; 512];
            let _ = std::io::Read::read(reader.get_mut(), &mut hello);
            send(&mut out, "this is not TLS")?;
            return Ok(());
        } else if upper.starts_with("AUTH PLAIN") {
            let encoded = cmd.get(11..).unwrap_or("").to_string();
            let encoded = if encoded.trim().is_empty() {
                send(&mut out, "334 ")?;
                line.clear();
                reader.read_line(&mut line)?;
                line.trim().to_string()
            } else {
                encoded
            };
            let decoded = b64(&encoded);
            let mut parts = decoded.split('\0').skip(1);
            let user = parts.next().unwrap_or("").to_string();
            let pass = parts.next().unwrap_or("").to_string();
            auth_reply(&mut out, &mut send, b, rec, index, "PLAIN", user, pass)?;
        } else if upper.starts_with("AUTH LOGIN") {
            send(&mut out, "334 VXNlcm5hbWU6")?;
            line.clear();
            reader.read_line(&mut line)?;
            let user = b64(&line);
            send(&mut out, "334 UGFzc3dvcmQ6")?;
            line.clear();
            reader.read_line(&mut line)?;
            let pass = b64(&line);
            auth_reply(&mut out, &mut send, b, rec, index, "LOGIN", user, pass)?;
        } else if upper.starts_with("MAIL FROM:") {
            match b.mail_reply {
                Some((n, reply)) if session_number <= n => send(&mut out, reply)?,
                _ => {
                    let from = cmd[10..].trim().to_string();
                    update(rec, index, |s| s.mail_from = Some(from));
                    send(&mut out, "250 2.1.0 ok")?;
                }
            }
        } else if upper.starts_with("RCPT TO:") {
            let to = cmd[8..]
                .trim()
                .trim_start_matches('<')
                .split('>')
                .next()
                .unwrap_or("")
                .to_string();
            if b.reject_rcpt.contains(&to) {
                send(&mut out, "550 5.1.1 no such user")?;
            } else {
                update(rec, index, |s| s.rcpt_to.push(to));
                send(&mut out, "250 2.1.5 ok")?;
            }
        } else if upper == "DATA" {
            send(&mut out, "354 end with <CRLF>.<CRLF>")?;
            let mut data = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 {
                    return Ok(());
                }
                if line == ".\r\n" || line == ".\n" {
                    break;
                }
                let l = line.strip_prefix('.').unwrap_or(&line);
                data.push_str(l);
            }
            std::thread::sleep(b.data_delay);
            match b.data_reply {
                Some(reply) => send(&mut out, reply)?,
                None => {
                    update(rec, index, |s| s.data = Some(data));
                    send(&mut out, "250 2.0.0 queued as FAKE1")?;
                }
            }
        } else if upper == "RSET" {
            send(&mut out, "250 2.0.0 ok")?;
        } else if upper == "NOOP" {
            send(&mut out, b.noop_reply.unwrap_or("250 2.0.0 ok"))?;
        } else if upper == "QUIT" {
            send(&mut out, "221 2.0.0 bye")?;
            return Ok(());
        } else {
            send(&mut out, "500 5.5.1 unknown command")?;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn auth_reply(
    out: &mut TcpStream,
    send: &mut impl FnMut(&mut TcpStream, &str) -> std::io::Result<()>,
    b: &Behavior,
    rec: &Arc<Mutex<Vec<Session>>>,
    index: usize,
    mech: &str,
    user: String,
    pass: String,
) -> std::io::Result<()> {
    let ok = b
        .credentials
        .as_ref()
        .is_none_or(|(u, p)| *u == user && *p == pass);
    update(rec, index, |s| {
        s.auth = Some((mech.to_string(), user, pass))
    });
    if ok {
        send(out, "235 2.7.0 authenticated")
    } else {
        send(out, "535 5.7.8 authentication credentials invalid")
    }
}

/// Headers of a received message, unfolded, up to the first blank line.
pub fn headers(data: &str) -> Vec<(String, String)> {
    let head = data.split("\r\n\r\n").next().unwrap_or("");
    let mut out: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.push((k.to_string(), v.trim().to_string()));
        }
    }
    out
}

/// The value of header `name` (case-insensitive), if present.
pub fn header(data: &str, name: &str) -> Option<String> {
    headers(data)
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}
