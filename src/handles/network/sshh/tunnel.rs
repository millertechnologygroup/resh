//! `tunnel`: a local, remote or dynamic (SOCKS) forward through the system
//! ssh client. resh accepts the connections itself and relays them to ssh's
//! forward (a Unix socket in a private directory, or a loopback port for
//! SOCKS), so it can count connections and bytes and enforce the limits.

use super::args::{ArgReader, check_known};
use super::conn::{ConnOptions, SshTarget, UserRule, check_host, connection_error, parse_conn};
use super::runner::{InterruptGuard, ProcessOutput, SshCommandLine, spawn_ssh, stop_child};
use super::types::*;
use super::{Out, coded, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
const POLL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone)]
pub struct TunnelOptions {
    pub conn: ConnOptions,
    pub mode: TunnelMode,
    pub local_bind_host: String,
    pub local_bind_port: u16,
    pub remote_bind_host: String,
    pub remote_bind_port: u16,
    pub remote_dest_host: Option<String>,
    pub remote_dest_port: Option<u16>,
    pub local_dest_host: Option<String>,
    pub local_dest_port: Option<u16>,
    pub socks_version: SocksVersion,
    pub tunnel_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub max_connections: Option<u64>,
    pub max_bytes_in: Option<u64>,
    pub max_bytes_out: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub dry_run: bool,
}

fn is_wildcard(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]" | "*")
}

fn positive(r: &ArgReader, key: &str) -> Result<Option<u64>, SshError> {
    match r.u64(key)? {
        Some(0) => Err(SshError::InvalidArgument(format!(
            "{key} must be at least 1 (leave it out for no limit)"
        ))),
        v => Ok(v),
    }
}

pub fn parse(r: &ArgReader, target: &SshTarget) -> Result<TunnelOptions, SshError> {
    let conn = parse_conn(r, target, UserRule::Required)?;
    let mode = r
        .choice("mode", TunnelMode::VALUES)?
        .ok_or(SshError::TunnelModeRequired)?;
    let not_for: &[&str] = match mode {
        TunnelMode::Local => &[
            "remote_bind_host",
            "remote_bind_port",
            "local_dest_host",
            "local_dest_port",
            "socks_version",
        ],
        TunnelMode::Remote => &[
            "local_bind_host",
            "local_bind_port",
            "remote_dest_host",
            "remote_dest_port",
            "socks_version",
        ],
        TunnelMode::Dynamic => &[
            "remote_bind_host",
            "remote_bind_port",
            "remote_dest_host",
            "remote_dest_port",
            "local_dest_host",
            "local_dest_port",
        ],
    };
    for key in not_for {
        if r.has(key) {
            return Err(SshError::InvalidArgument(format!(
                "{key} is not used with mode={}",
                mode.as_str()
            )));
        }
    }
    let host_arg = |key: &str, default: Option<&str>| -> Result<Option<String>, SshError> {
        match r.text(key)?.or(default.map(str::to_string)) {
            Some(h) => {
                if !is_wildcard(&h) {
                    check_host(&h)
                        .map_err(|_| SshError::InvalidArgument(format!("invalid {key} {h:?}")))?;
                }
                Ok(Some(
                    h.trim_start_matches('[').trim_end_matches(']').to_string(),
                ))
            }
            None => Ok(None),
        }
    };
    let local_bind_host = host_arg("local_bind_host", Some("127.0.0.1"))?.unwrap_or_default();
    let remote_bind_host = host_arg("remote_bind_host", Some("127.0.0.1"))?.unwrap_or_default();
    let remote_dest_host = host_arg("remote_dest_host", None)?;
    let local_dest_host = host_arg("local_dest_host", None)?;
    let remote_dest_port = r.port("remote_dest_port", false)?;
    let local_dest_port = r.port("local_dest_port", false)?;
    match mode {
        TunnelMode::Local if remote_dest_host.is_none() || remote_dest_port.is_none() => {
            return Err(SshError::TunnelMissingRemoteDest);
        }
        TunnelMode::Remote if local_dest_host.is_none() || local_dest_port.is_none() => {
            return Err(SshError::TunnelMissingLocalDest);
        }
        _ => {}
    }
    let bind = if mode == TunnelMode::Remote {
        &remote_bind_host
    } else {
        &local_bind_host
    };
    let allow_wildcard_binds = r.bool("allow_wildcard_binds", false)?;
    if is_wildcard(bind) && !allow_wildcard_binds {
        return Err(SshError::TunnelWildcardBindForbidden(bind.clone()));
    }
    if allow_wildcard_binds && !is_wildcard(bind) {
        return Err(SshError::InvalidArgument(
            "allow_wildcard_binds only applies with a wildcard bind address".into(),
        ));
    }
    let idle = r.u64_or("idle_timeout_ms", DEFAULT_IDLE_TIMEOUT_MS)?;
    Ok(TunnelOptions {
        conn,
        mode,
        local_bind_host: if local_bind_host == "*" {
            "0.0.0.0".into()
        } else {
            local_bind_host
        },
        local_bind_port: r.port("local_bind_port", true)?.unwrap_or(0),
        remote_bind_host,
        remote_bind_port: r.port("remote_bind_port", true)?.unwrap_or(0),
        remote_dest_host,
        remote_dest_port,
        local_dest_host,
        local_dest_port,
        socks_version: r
            .choice("socks_version", SocksVersion::VALUES)?
            .unwrap_or_default(),
        tunnel_timeout_ms: positive(r, "tunnel_timeout_ms")?,
        idle_timeout_ms: (idle > 0).then_some(idle),
        max_connections: positive(r, "max_connections")?,
        max_bytes_in: positive(r, "max_bytes_in")?,
        max_bytes_out: positive(r, "max_bytes_out")?,
        timeout_ms: r.u64("timeout_ms")?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// `host:port` with brackets around an IPv6 address.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The ssh forwarding arguments for each mode.
pub fn forward_args(o: &TunnelOptions, socket: &Path, socks_port: u16) -> Vec<String> {
    let mut args = vec![
        "-N".to_string(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
    ];
    match o.mode {
        TunnelMode::Local => {
            args.push("-L".into());
            args.push(format!(
                "{}:{}",
                socket.display(),
                host_port(
                    o.remote_dest_host.as_deref().unwrap_or_default(),
                    o.remote_dest_port.unwrap_or_default()
                )
            ));
        }
        TunnelMode::Dynamic => {
            args.push("-D".into());
            args.push(format!("127.0.0.1:{socks_port}"));
        }
        TunnelMode::Remote => {
            args.push("-v".into());
            args.push("-R".into());
            args.push(format!(
                "{}:{}",
                host_port(&o.remote_bind_host, o.remote_bind_port),
                socket.display()
            ));
        }
    }
    args
}

pub fn tunnel_info(o: &TunnelOptions, local_port: u16, remote_port: u16) -> SshTunnelInfo {
    let local = matches!(o.mode, TunnelMode::Local | TunnelMode::Dynamic);
    SshTunnelInfo {
        mode: o.mode.as_str().into(),
        local_bind_host: local.then(|| o.local_bind_host.clone()),
        local_bind_port: local.then_some(local_port),
        remote_bind_host: (o.mode == TunnelMode::Remote).then(|| o.remote_bind_host.clone()),
        remote_bind_port: (o.mode == TunnelMode::Remote).then_some(remote_port),
        remote_dest_host: o.remote_dest_host.clone(),
        remote_dest_port: o.remote_dest_port,
        local_dest_host: o.local_dest_host.clone(),
        local_dest_port: o.local_dest_port,
        socks_version: (o.mode == TunnelMode::Dynamic).then(|| o.socks_version.as_str().into()),
    }
}

fn lifetime(o: &TunnelOptions, reason: Option<&str>) -> SshTunnelLifetimeConfig {
    SshTunnelLifetimeConfig {
        connect_timeout_ms: o.conn.connect_timeout_ms,
        tunnel_timeout_ms: o.tunnel_timeout_ms,
        idle_timeout_ms: o.idle_timeout_ms,
        max_connections: o.max_connections,
        max_bytes_in: o.max_bytes_in,
        max_bytes_out: o.max_bytes_out,
        closed_reason: reason.map(str::to_string),
    }
}

// ----------------------------------------------------------------- relay --

/// A TCP or Unix stream.
enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn try_clone(&self) -> std::io::Result<Stream> {
        Ok(match self {
            Stream::Tcp(s) => Stream::Tcp(s.try_clone()?),
            Stream::Unix(s) => Stream::Unix(s.try_clone()?),
        })
    }
    fn shutdown(&self, how: Shutdown) {
        let _ = match self {
            Stream::Tcp(s) => s.shutdown(how),
            Stream::Unix(s) => s.shutdown(how),
        };
    }
    fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            Stream::Tcp(s) => s.set_read_timeout(d),
            Stream::Unix(s) => s.set_read_timeout(d),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Shared state of a running tunnel.
#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    reason: Mutex<Option<&'static str>>,
    accepted: AtomicU64,
    active: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Milliseconds since `epoch` of the last accepted connection or byte.
    last_activity: AtomicU64,
    refused: AtomicU64,
    open: Mutex<Vec<Stream>>,
}

impl Shared {
    fn stop_with(&self, reason: &'static str) {
        if let Ok(mut r) = self.reason.lock() {
            r.get_or_insert(reason);
        }
        self.stop.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn touch(&self, epoch: Instant) {
        self.last_activity
            .store(epoch.elapsed().as_millis() as u64, Ordering::SeqCst);
    }

    fn close_all(&self) {
        if let Ok(open) = self.open.lock() {
            for s in open.iter() {
                s.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Copies `from` to `to`, counting into `counter` up to `limit`.
fn pump(
    mut from: Stream,
    mut to: Stream,
    shared: Arc<Shared>,
    inbound: bool,
    limit: Option<u64>,
    epoch: Instant,
) {
    let _ = from.set_read_timeout(Some(Duration::from_millis(200)));
    let counter = if inbound {
        &shared.bytes_in
    } else {
        &shared.bytes_out
    };
    let mut buf = [0u8; 16 * 1024];
    while !shared.stopped() {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        let mut allowed = n;
        if let Some(max) = limit {
            let used = counter.load(Ordering::SeqCst);
            allowed = n.min(max.saturating_sub(used) as usize);
        }
        if allowed > 0 && to.write_all(&buf[..allowed]).is_err() {
            break;
        }
        counter.fetch_add(allowed as u64, Ordering::SeqCst);
        shared.touch(epoch);
        if let Some(max) = limit {
            if counter.load(Ordering::SeqCst) >= max {
                shared.stop_with(if inbound {
                    "max_bytes_in"
                } else {
                    "max_bytes_out"
                });
                break;
            }
        }
    }
    to.shutdown(Shutdown::Write);
}

/// Relays one accepted connection to `upstream` in two threads.
fn relay(client: Stream, upstream: Stream, shared: Arc<Shared>, o: &TunnelOptions, epoch: Instant) {
    let (Ok(c2), Ok(u2), Ok(c3), Ok(u3)) = (
        client.try_clone(),
        upstream.try_clone(),
        client.try_clone(),
        upstream.try_clone(),
    ) else {
        client.shutdown(Shutdown::Both);
        upstream.shutdown(Shutdown::Both);
        return;
    };
    if let Ok(mut open) = shared.open.lock() {
        open.push(c3);
        open.push(u3);
    }
    shared.active.fetch_add(1, Ordering::SeqCst);
    let (max_in, max_out) = (o.max_bytes_in, o.max_bytes_out);
    let s1 = shared.clone();
    let inbound = std::thread::spawn(move || pump(client, u2, s1, true, max_in, epoch));
    let s2 = shared.clone();
    std::thread::spawn(move || {
        pump(upstream, c2, s2.clone(), false, max_out, epoch);
        let _ = inbound.join();
        s2.active.fetch_sub(1, Ordering::SeqCst);
        s2.touch(epoch);
    });
}

enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

/// Accepts connections until stopped, relaying each to its upstream.
fn accept_loop(
    listener: Listener,
    upstream: Arc<dyn Fn() -> std::io::Result<Stream> + Send + Sync>,
    shared: Arc<Shared>,
    o: TunnelOptions,
    epoch: Instant,
) {
    let _ = match &listener {
        Listener::Tcp(l) => l.set_nonblocking(true),
        Listener::Unix(l) => l.set_nonblocking(true),
    };
    while !shared.stopped() {
        let accepted = match &listener {
            Listener::Tcp(l) => l.accept().map(|(s, _)| Stream::Tcp(s)),
            Listener::Unix(l) => l.accept().map(|(s, _)| Stream::Unix(s)),
        };
        let client = match accepted {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
                continue;
            }
            Err(_) => {
                std::thread::sleep(POLL);
                continue;
            }
        };
        let _ = match &client {
            Stream::Tcp(s) => s.set_nonblocking(false),
            Stream::Unix(s) => s.set_nonblocking(false),
        };
        if o.max_connections
            .is_some_and(|m| shared.accepted.load(Ordering::SeqCst) >= m)
        {
            client.shutdown(Shutdown::Both);
            shared.refused.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        if o.mode == TunnelMode::Dynamic {
            let mut first = [0u8; 1];
            let ok = match &client {
                Stream::Tcp(s) => {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let r = s.peek(&mut first);
                    let _ = s.set_read_timeout(None);
                    matches!(r, Ok(1)) && first[0] == o.socks_version.first_byte()
                }
                Stream::Unix(_) => false,
            };
            if !ok {
                client.shutdown(Shutdown::Both);
                shared.refused.fetch_add(1, Ordering::SeqCst);
                continue;
            }
        }
        shared.accepted.fetch_add(1, Ordering::SeqCst);
        shared.touch(epoch);
        match upstream() {
            Ok(up) => relay(client, up, shared.clone(), &o, epoch),
            Err(_) => client.shutdown(Shutdown::Both),
        }
    }
}

// ------------------------------------------------------------------- run --

/// A running ssh: its stderr is collected (bounded) by a thread.
struct SshProc {
    child: std::process::Child,
    program: String,
    stderr: Arc<Mutex<Vec<u8>>>,
}

impl SshProc {
    fn start(cmd: &SshCommandLine) -> Result<Self, SshError> {
        let mut child =
            spawn_ssh(cmd).map_err(|e| super::conn::run_error(e, SshError::Interrupted))?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = stderr.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut s) = sink.lock() {
                        if s.len() < 256 * 1024 {
                            s.extend_from_slice(&buf[..n]);
                        }
                    }
                }
            });
        }
        if let Some(mut out) = child.stdout.take() {
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut out, &mut std::io::sink());
            });
        }
        Ok(SshProc {
            child,
            program: cmd.program.clone(),
            stderr,
        })
    }

    fn stderr_text(&self) -> String {
        self.stderr
            .lock()
            .map(|s| String::from_utf8_lossy(&s).into_owned())
            .unwrap_or_default()
    }

    /// The exit status once ssh has ended.
    fn exited(&mut self) -> Option<ProcessOutput> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                use std::os::unix::process::ExitStatusExt;
                std::thread::sleep(Duration::from_millis(50));
                Some(ProcessOutput {
                    exit_code: status.code(),
                    signal: status.signal(),
                    stderr: self.stderr_text().into_bytes(),
                    ..Default::default()
                })
            }
            _ => None,
        }
    }

    fn stop(&mut self) {
        stop_child(&self.program, &mut self.child);
    }
}

/// Why ssh ended before or while forwarding.
fn ssh_failure(cmd: &SshCommandLine, out: &ProcessOutput) -> SshError {
    let text = out.stderr_text();
    let detail: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with("debug") && !l.starts_with("Authenticated to"))
        .collect();
    let detail = detail.join("; ");
    if text.contains("forwarding failed")
        || text.contains("Could not request local forwarding")
        || text.contains("cannot listen")
        || text.contains("Address already in use")
    {
        return SshError::TunnelForwardFailed(detail);
    }
    connection_error(cmd, out).unwrap_or(SshError::ConnectFailed(if detail.is_empty() {
        format!("ssh exited with {:?}", out.exit_code)
    } else {
        detail
    }))
}

/// The port the server allocated for `-R` with port 0 (from `ssh -v`).
pub fn allocated_port(stderr: &str) -> Option<u16> {
    stderr.lines().find_map(|l| {
        l.split("Allocated port ")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

pub fn run(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshTunnelResponse {
        ok: false,
        dry_run: out.dry_run,
        connection: None,
        tunnel: None,
        lifetime: None,
        stats: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshTunnelResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_text).map(|_| status)
    };
    let o = match check_known("tunnel", args).and_then(|_| parse(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.connection = Some(SshConnectionInfo::new(
        &o.conn.host,
        o.conn.port,
        &o.conn.username,
    ));
    response.tunnel = Some(tunnel_info(&o, o.local_bind_port, o.remote_bind_port));
    response.lifetime = Some(lifetime(&o, None));
    let bind = if o.mode == TunnelMode::Remote {
        &o.remote_bind_host
    } else {
        &o.local_bind_host
    };
    if is_wildcard(bind) {
        response.warnings.push(format!(
            "WARNING: binding to {bind} exposes the tunnel to all network interfaces"
        ));
    }
    if o.conn.known_hosts_mode == KnownHostsMode::Insecure {
        response
            .warnings
            .push("WARNING: Host key verification disabled (insecure mode)".into());
    }
    let prep = match o.conn.prepare() {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };
    if o.dry_run {
        response.ok = true;
        response.stats = Some(SshTunnelStats::default());
        response
            .warnings
            .push("Dry run: no SSH connection was made and no tunnel was created.".into());
        write_response(io, out.format, &response, format_text)?;
        return Ok(Status::ok());
    }

    let dir = match super::conn::private_dir("resh-tunnel-") {
        Ok(d) => d,
        Err(e) => return fail(&mut response, io, e),
    };
    let socket: PathBuf = dir.path().join("fwd.sock");
    // resh's own listener, opened before ssh so a busy port fails fast.
    let mut socks_port = 0u16;
    let (listener, local_port) = match o.mode {
        TunnelMode::Local | TunnelMode::Dynamic => {
            match TcpListener::bind((o.local_bind_host.as_str(), o.local_bind_port)) {
                Ok(l) => {
                    let port = l
                        .local_addr()
                        .map(|a| a.port())
                        .unwrap_or(o.local_bind_port);
                    (Listener::Tcp(l), port)
                }
                Err(e) => {
                    return fail(
                        &mut response,
                        io,
                        SshError::TunnelBindFailed(
                            o.local_bind_port,
                            o.local_bind_host.clone(),
                            e.to_string(),
                        ),
                    );
                }
            }
        }
        TunnelMode::Remote => match UnixListener::bind(&socket) {
            Ok(l) => (Listener::Unix(l), 0),
            Err(e) => return fail(&mut response, io, SshError::IoError(e.to_string())),
        },
    };
    if o.mode == TunnelMode::Dynamic {
        socks_port = match TcpListener::bind(("127.0.0.1", 0)).and_then(|l| l.local_addr()) {
            Ok(a) => a.port(),
            Err(e) => return fail(&mut response, io, SshError::IoError(e.to_string())),
        };
    }

    let _guard = InterruptGuard::install();
    let deadline = super::runner::Deadline::new(o.timeout_ms);
    let cmd = o
        .conn
        .command_line(&prep, &forward_args(&o, &socket, socks_port), None, false);
    let mut ssh = match SshProc::start(&cmd) {
        Ok(p) => p,
        Err(e) => return fail(&mut response, io, e),
    };

    // Wait until the forward is up.
    let ready_limit = Duration::from_millis(o.conn.connect_timeout_ms.max(1000) * 2 + 10_000);
    let started = Instant::now();
    let mut remote_port = o.remote_bind_port;
    loop {
        if let Some(done) = ssh.exited() {
            return fail(&mut response, io, ssh_failure(&cmd, &done));
        }
        let ready = match o.mode {
            TunnelMode::Local => socket.exists(),
            TunnelMode::Dynamic => TcpStream::connect(("127.0.0.1", socks_port)).is_ok(),
            TunnelMode::Remote => {
                let text = ssh.stderr_text();
                if let Some(p) = allocated_port(&text) {
                    remote_port = p;
                }
                text.contains("remote forward success") || allocated_port(&text).is_some()
            }
        };
        if ready {
            break;
        }
        let stop = if InterruptGuard::interrupted() {
            Some(SshError::Interrupted)
        } else if deadline.expired() {
            Some(SshError::TunnelTimeout(o.timeout_ms.unwrap_or(0)))
        } else if started.elapsed() >= ready_limit {
            Some(SshError::ConnectFailed(
                "timed out waiting for ssh to set up the forward".into(),
            ))
        } else {
            None
        };
        if let Some(e) = stop {
            ssh.stop();
            return fail(&mut response, io, e);
        }
        std::thread::sleep(POLL);
    }

    // Ready: report it at once, then relay until something ends the tunnel.
    let (listen, to) = match o.mode {
        TunnelMode::Local => (
            host_port(&o.local_bind_host, local_port),
            host_port(
                o.remote_dest_host.as_deref().unwrap_or_default(),
                o.remote_dest_port.unwrap_or_default(),
            ),
        ),
        TunnelMode::Dynamic => (
            host_port(&o.local_bind_host, local_port),
            format!("{} proxy", o.socks_version.as_str()),
        ),
        TunnelMode::Remote => (
            format!("{} (remote)", host_port(&o.remote_bind_host, remote_port)),
            host_port(
                o.local_dest_host.as_deref().unwrap_or_default(),
                o.local_dest_port.unwrap_or_default(),
            ),
        ),
    };
    match out.format {
        OutputFormat::Json => writeln!(
            io.stdout,
            "{}",
            serde_json::json!({"event": "ready", "mode": o.mode.as_str(), "listen": listen, "forward_to": to})
        )?,
        OutputFormat::Text => writeln!(
            io.stdout,
            "Tunnel ready: listening on {listen}, forwarding to {to}"
        )?,
    }
    io.stdout.flush()?;

    let epoch = Instant::now();
    let shared = Arc::new(Shared::default());
    let upstream: Arc<dyn Fn() -> std::io::Result<Stream> + Send + Sync> = match o.mode {
        TunnelMode::Local => {
            let s = socket.clone();
            Arc::new(move || UnixStream::connect(&s).map(Stream::Unix))
        }
        TunnelMode::Dynamic => {
            Arc::new(move || TcpStream::connect(("127.0.0.1", socks_port)).map(Stream::Tcp))
        }
        TunnelMode::Remote => {
            let host = o.local_dest_host.clone().unwrap_or_default();
            let port = o.local_dest_port.unwrap_or_default();
            Arc::new(move || TcpStream::connect((host.as_str(), port)).map(Stream::Tcp))
        }
    };
    let acceptor = {
        let (shared, o) = (shared.clone(), o.clone());
        std::thread::spawn(move || accept_loop(listener, upstream, shared, o, epoch))
    };

    let mut failure: Option<SshError> = None;
    loop {
        if shared.stopped() {
            break;
        }
        if let Some(done) = ssh.exited() {
            failure = Some(SshError::TunnelClosed(match ssh_failure(&cmd, &done) {
                SshError::ConnectFailed(m) => m,
                e => e.to_string(),
            }));
            shared.stop_with("ssh_exited");
            break;
        }
        let now = epoch.elapsed().as_millis() as u64;
        let idle_for = now.saturating_sub(shared.last_activity.load(Ordering::SeqCst));
        let reason = if InterruptGuard::interrupted() {
            Some("interrupted")
        } else if deadline.expired() {
            failure = Some(SshError::TunnelTimeout(o.timeout_ms.unwrap_or(0)));
            Some("timeout_ms")
        } else if o.tunnel_timeout_ms.is_some_and(|t| now >= t) {
            Some("tunnel_timeout")
        } else if o
            .max_connections
            .is_some_and(|m| shared.accepted.load(Ordering::SeqCst) >= m)
            && shared.active.load(Ordering::SeqCst) == 0
        {
            Some("max_connections")
        } else if o.idle_timeout_ms.is_some_and(|t| idle_for >= t)
            && shared.active.load(Ordering::SeqCst) == 0
        {
            Some("idle_timeout")
        } else {
            None
        };
        if let Some(reason) = reason {
            shared.stop_with(reason);
            break;
        }
        std::thread::sleep(POLL);
    }
    shared.close_all();
    ssh.stop();
    let _ = acceptor.join();
    // Relay threads poll the stop flag every 200 ms.
    let wait_until = Instant::now() + Duration::from_secs(2);
    while shared.active.load(Ordering::SeqCst) > 0 && Instant::now() < wait_until {
        std::thread::sleep(POLL);
    }
    drop(dir);

    let reason = shared
        .reason
        .lock()
        .ok()
        .and_then(|r| *r)
        .unwrap_or("closed");
    let refused = shared.refused.load(Ordering::SeqCst);
    if refused > 0 {
        response.warnings.push(format!(
            "{refused} connection(s) were refused (over max_connections or wrong SOCKS version)"
        ));
    }
    response.tunnel = Some(tunnel_info(&o, local_port, remote_port));
    response.lifetime = Some(lifetime(&o, Some(reason)));
    response.stats = Some(SshTunnelStats {
        connections_accepted: shared.accepted.load(Ordering::SeqCst),
        bytes_in: shared.bytes_in.load(Ordering::SeqCst),
        bytes_out: shared.bytes_out.load(Ordering::SeqCst),
        uptime_ms: epoch.elapsed().as_millis() as u64,
    });
    if let Some(e) = failure {
        return fail(&mut response, io, e);
    }
    response.ok = true;
    write_response(io, out.format, &response, format_text)?;
    Ok(Status::ok())
}

pub fn format_text(response: &SshTunnelResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Tunnel\n==========\n\n");
    if let Some(conn) = &response.connection {
        output.push_str(&format!("Host     : {}\n", conn.host));
        output.push_str(&format!("Port     : {}\n", conn.port));
        output.push_str(&format!("User     : {}\n", conn.username));
    }
    output.push_str(&format!("Dry Run  : {}\n\n", response.dry_run));
    if let Some(t) = &response.tunnel {
        output.push_str(&format!("Mode     : {}\n", t.mode));
        if let Some(host) = &t.local_bind_host {
            output.push_str(&format!(
                "Local    : {}\n",
                host_port(host, t.local_bind_port.unwrap_or(0))
            ));
        }
        if let Some(host) = &t.remote_bind_host {
            output.push_str(&format!(
                "Remote Bind : {}\n",
                host_port(host, t.remote_bind_port.unwrap_or(0))
            ));
        }
        if let Some(host) = &t.remote_dest_host {
            output.push_str(&format!(
                "Remote Dest : {}\n",
                host_port(host, t.remote_dest_port.unwrap_or(0))
            ));
        }
        if let Some(host) = &t.local_dest_host {
            output.push_str(&format!(
                "Local Dest  : {}\n",
                host_port(host, t.local_dest_port.unwrap_or(0))
            ));
        }
        if let Some(socks) = &t.socks_version {
            output.push_str(&format!("SOCKS    : {socks}\n"));
        }
        output.push('\n');
    }
    if let Some(l) = &response.lifetime {
        let opt = |v: Option<u64>, unit: &str| {
            v.map(|v| format!("{v}{unit}"))
                .unwrap_or_else(|| "(none)".into())
        };
        output.push_str("Lifetime :\n");
        output.push_str(&format!(
            "  Connect Timeout : {} ms\n",
            l.connect_timeout_ms
        ));
        output.push_str(&format!(
            "  Tunnel Timeout  : {}\n",
            opt(l.tunnel_timeout_ms, " ms")
        ));
        output.push_str(&format!(
            "  Idle Timeout    : {}\n",
            opt(l.idle_timeout_ms, " ms")
        ));
        output.push_str(&format!(
            "  Max Connections : {}\n",
            opt(l.max_connections, "")
        ));
        output.push_str(&format!(
            "  Max Bytes In    : {}\n",
            opt(l.max_bytes_in, "")
        ));
        output.push_str(&format!(
            "  Max Bytes Out   : {}\n",
            opt(l.max_bytes_out, "")
        ));
        if let Some(reason) = &l.closed_reason {
            output.push_str(&format!("  Closed Reason   : {reason}\n"));
        }
        output.push('\n');
    }
    if let Some(stats) = &response.stats {
        output.push_str("Stats    :\n");
        output.push_str(&format!("  Connections : {}\n", stats.connections_accepted));
        output.push_str(&format!("  Bytes In    : {}\n", stats.bytes_in));
        output.push_str(&format!("  Bytes Out   : {}\n", stats.bytes_out));
        output.push_str(&format!("  Uptime      : {} ms\n", stats.uptime_ms));
        output.push('\n');
    }
    super::transfer::push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}
