//! A small in-process stand-in for HashiCorp Vault's KV version 2 API on
//! 127.0.0.1, for `secret://vault` tests (unit tests and the binary tests
//! include this file). It implements what resh uses: read/write a secret
//! (`/v1/<mount>/data/<path>`, with check-and-set), soft-delete the latest
//! version (`DELETE .../data/<path>`), read/delete/list
//! metadata (`/v1/<mount>/metadata/<path>`, `?list=true`), the
//! `X-Vault-Token` check, and Vault's error bodies (`{"errors": [...]}`;
//! a missing secret is a 404 with an empty list). The real server is
//! tested in `tests/secret_e2e_docker.rs`.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct State {
    /// Secret path -> (version, data) per mount.
    secrets: BTreeMap<String, (u64, serde_json::Map<String, Value>)>,
    /// Paths whose latest version is soft-deleted (`DELETE .../data/...`).
    deleted: std::collections::BTreeSet<String>,
    /// Requests seen: "METHOD path?query[ ns=<namespace>]".
    log: Vec<String>,
    delay: Option<Duration>,
}

pub struct FakeVault {
    addr: String,
    token: String,
    mount: String,
    state: Arc<Mutex<State>>,
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FakeVault {
    /// A server accepting `token`, with one KV v2 engine at `mount`.
    pub fn start(token: &str, mount: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let (st, tok, mnt) = (state.clone(), token.to_string(), mount.to_string());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (st, tok, mnt) = (st.clone(), tok.clone(), mnt.clone());
                std::thread::spawn(move || {
                    let _ = serve(stream, &st, &tok, &mnt);
                });
            }
        });
        Self {
            addr,
            token: token.into(),
            mount: mount.into(),
            state,
        }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Delays every response (timeout tests).
    pub fn set_delay(&self, d: Option<Duration>) {
        self.state.lock().unwrap().delay = d;
    }

    /// The stored fields of `path`, if it exists.
    pub fn secret(&self, path: &str) -> Option<serde_json::Map<String, Value>> {
        self.state
            .lock()
            .unwrap()
            .secrets
            .get(path)
            .map(|(_, d)| d.clone())
    }

    /// True if the latest version of `path` is soft-deleted (its data and
    /// metadata are kept).
    pub fn is_soft_deleted(&self, path: &str) -> bool {
        self.state.lock().unwrap().deleted.contains(path)
    }

    /// The current version number of `path`.
    pub fn version(&self, path: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .secrets
            .get(path)
            .map(|(v, _)| *v)
    }

    /// Stores `fields` at `path` as a new version.
    pub fn put(&self, path: &str, fields: Value) {
        let mut st = self.state.lock().unwrap();
        let v = st.secrets.get(path).map(|(v, _)| *v).unwrap_or(0) + 1;
        st.secrets
            .insert(path.into(), (v, fields.as_object().unwrap().clone()));
        st.deleted.remove(path);
    }

    /// The requests seen so far, as "METHOD path?query[ ns=<namespace>]".
    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut r = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((target.clone(), String::new()));
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        r.read_line(&mut h)?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0usize);
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: u16, body: Option<Value>) -> std::io::Result<()> {
    let text = body.map(|b| b.to_string()).unwrap_or_default();
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )?;
    stream.flush()
}

fn decode(seg: &str) -> String {
    percent_encoding::percent_decode_str(seg)
        .decode_utf8_lossy()
        .into_owned()
}

fn serve(
    mut stream: TcpStream,
    st: &Mutex<State>,
    token: &str,
    mount: &str,
) -> std::io::Result<()> {
    let req = read_request(&mut stream)?;
    let delay = {
        let mut s = st.lock().unwrap();
        let ns = req
            .headers
            .iter()
            .find(|(k, _)| k == "x-vault-namespace")
            .map(|(_, v)| format!(" ns={v}"))
            .unwrap_or_default();
        s.log
            .push(format!("{} {}?{}{ns}", req.method, req.path, req.query));
        s.delay
    };
    if let Some(d) = delay {
        std::thread::sleep(d);
    }
    let tok = req
        .headers
        .iter()
        .find(|(k, _)| k == "x-vault-token")
        .map(|(_, v)| v.as_str());
    if tok != Some(token) {
        return respond(
            &mut stream,
            403,
            Some(json!({"errors": ["permission denied"]})),
        );
    }
    let segs: Vec<String> = req
        .path
        .trim_start_matches('/')
        .split('/')
        .map(decode)
        .collect();
    let mount_segs: Vec<&str> = mount.split('/').collect();
    let n = mount_segs.len();
    let route_ok = segs.len() >= n + 2
        && segs[0] == "v1"
        && segs[1..=n] == mount_segs[..]
        && (segs[n + 1] == "data" || segs[n + 1] == "metadata");
    if !route_ok {
        return respond(
            &mut stream,
            404,
            Some(
                json!({"errors": [format!("no handler for route \"{}\". route entry not found.", req.path)]}),
            ),
        );
    }
    let kind = segs[n + 1].clone();
    let path = segs[n + 2..].join("/");
    let list = req.query.split('&').any(|p| p == "list=true") || req.method == "LIST";
    let mut s = st.lock().unwrap();
    match (req.method.as_str(), kind.as_str()) {
        ("GET", "data") => match s.secrets.get(&path).filter(|_| !s.deleted.contains(&path)) {
            Some((v, d)) => respond(
                &mut stream,
                200,
                Some(json!({"data": {"data": d, "metadata": {"version": v}}})),
            ),
            None => respond(&mut stream, 404, Some(json!({"errors": []}))),
        },
        ("POST" | "PUT", "data") => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let Some(data) = body["data"].as_object().cloned() else {
                return respond(
                    &mut stream,
                    400,
                    Some(json!({"errors": ["no data provided"]})),
                );
            };
            let current = s.secrets.get(&path).map(|(v, _)| *v).unwrap_or(0);
            if let Some(cas) = body["options"]["cas"].as_u64()
                && cas != current
            {
                return respond(
                    &mut stream,
                    400,
                    Some(
                        json!({"errors": ["check-and-set parameter did not match the current version"]}),
                    ),
                );
            }
            s.deleted.remove(&path);
            s.secrets.insert(path, (current + 1, data));
            respond(
                &mut stream,
                200,
                Some(json!({"data": {"version": current + 1}})),
            )
        }
        ("GET" | "LIST", "metadata") if list => {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{}/", path.trim_end_matches('/'))
            };
            let mut keys: Vec<String> = s
                .secrets
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix))
                .map(|rest| match rest.split_once('/') {
                    Some((dir, _)) => format!("{dir}/"),
                    None => rest.to_string(),
                })
                .collect();
            keys.sort();
            keys.dedup();
            if keys.is_empty() {
                respond(&mut stream, 404, Some(json!({"errors": []})))
            } else {
                respond(&mut stream, 200, Some(json!({"data": {"keys": keys}})))
            }
        }
        ("GET", "metadata") => match s.secrets.get(&path) {
            Some((v, _)) => respond(
                &mut stream,
                200,
                Some(json!({"data": {"current_version": v}})),
            ),
            None => respond(&mut stream, 404, Some(json!({"errors": []}))),
        },
        ("DELETE", "data") => {
            if s.secrets.contains_key(&path) {
                s.deleted.insert(path);
            }
            respond(&mut stream, 204, None)
        }
        ("DELETE", "metadata") => {
            s.secrets.remove(&path);
            s.deleted.remove(&path);
            respond(&mut stream, 204, None)
        }
        _ => respond(
            &mut stream,
            405,
            Some(json!({"errors": ["unsupported operation"]})),
        ),
    }
}
