//! A small async client for the memcached text protocol: the commands the
//! `cache` handle uses, with every server reply told apart (`STORED` and
//! `NOT_STORED`, `DELETED` and `NOT_FOUND`, `CLIENT_ERROR`, `SERVER_ERROR`,
//! `ERROR` for an unknown command), plus `mg` (meta get, memcached 1.6+)
//! and `lru_crawler metadump` (memcached 1.4.31+) for TTLs and key listing.
//!
//! Keys are checked by the caller ([`check_key`]) before they reach a
//! command line, so a key can never inject a second command.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Longest key memcached accepts, in bytes.
pub const MAX_KEY_LEN: usize = 250;

/// Relative expiry times above this many seconds are read by memcached as
/// absolute Unix times, so longer TTLs are sent as absolute times.
const MAX_RELATIVE_EXPTIME: u64 = 60 * 60 * 24 * 30;

/// Keys sent in one `get` command.
const GET_BATCH: usize = 100;

/// Why a memcached command failed.
#[derive(Debug)]
pub enum McError {
    /// Reading or writing the socket failed, or the connection closed.
    Io(std::io::Error),
    /// The server does not know the command (`ERROR`).
    UnknownCommand,
    /// `CLIENT_ERROR <msg>`: the server refused the request.
    Client(String),
    /// `SERVER_ERROR <msg>`, or a reply this client does not understand.
    Server(String),
}

impl std::fmt::Display for McError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McError::Io(e) => write!(f, "connection error: {e}"),
            McError::UnknownCommand => write!(f, "the server does not support this command"),
            McError::Client(m) => write!(f, "CLIENT_ERROR {m}"),
            McError::Server(m) => write!(f, "{m}"),
        }
    }
}

impl From<std::io::Error> for McError {
    fn from(e: std::io::Error) -> Self {
        McError::Io(e)
    }
}

/// Why `key` cannot be sent to memcached, or `None` when it can: memcached
/// keys are 1-250 bytes without spaces or control characters.
pub fn check_key(key: &str) -> Option<String> {
    if key.is_empty() {
        return Some("a key cannot be empty".into());
    }
    if key.len() > MAX_KEY_LEN {
        return Some(format!(
            "memcached keys are at most {MAX_KEY_LEN} bytes; {key:?} is {} bytes",
            key.len()
        ));
    }
    if key.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Some(format!(
            "memcached keys cannot contain spaces or control characters: {key:?}"
        ));
    }
    None
}

/// The memcached expiry for a TTL in milliseconds: 0 (never) for none,
/// otherwise whole seconds rounded up (so a TTL below one second still
/// expires), as an absolute Unix time beyond memcached's 30-day limit for
/// relative times.
pub fn exptime(ttl_ms: Option<u64>) -> u64 {
    let Some(ms) = ttl_ms else { return 0 };
    let secs = ms.div_ceil(1000).max(1);
    if secs > MAX_RELATIVE_EXPTIME {
        now_unix().saturating_add(secs)
    } else {
        secs
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The result of `mg <key> [t]`.
#[derive(Debug, Clone, PartialEq)]
pub enum Meta {
    /// The server has no meta commands (older than 1.6).
    Unsupported,
    Miss,
    /// A hit, with the remaining TTL in seconds when asked for (`None`
    /// means the item never expires).
    Hit {
        ttl_secs: Option<u64>,
    },
}

/// One item from `lru_crawler metadump`.
#[derive(Debug, Clone, PartialEq)]
pub struct DumpedKey {
    pub key: String,
    /// Absolute expiry (Unix seconds), `None` when the item never expires.
    pub exp: Option<u64>,
}

/// The result of `lru_crawler metadump all`.
#[derive(Debug)]
pub enum Dump {
    Keys(Vec<DumpedKey>),
    /// Another crawl is running; try again.
    Busy,
    /// The server cannot dump keys (too old, or the LRU crawler is off).
    Unsupported(String),
}

/// One connection to a memcached server.
pub struct Memcached {
    stream: BufReader<TcpStream>,
}

impl Memcached {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    async fn send(&mut self, line: &str, data: Option<&[u8]>) -> Result<(), McError> {
        let s = self.stream.get_mut();
        let mut buf = Vec::with_capacity(line.len() + 2 + data.map_or(0, |d| d.len() + 2));
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"\r\n");
        if let Some(d) = data {
            buf.extend_from_slice(d);
            buf.extend_from_slice(b"\r\n");
        }
        s.write_all(&buf).await?;
        s.flush().await?;
        Ok(())
    }

    /// One reply line without its line ending. `ERROR`, `CLIENT_ERROR` and
    /// `SERVER_ERROR` lines become errors.
    async fn line(&mut self) -> Result<String, McError> {
        let mut raw = Vec::new();
        let n = self.stream.read_until(b'\n', &mut raw).await?;
        if n == 0 {
            return Err(McError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the server closed the connection",
            )));
        }
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        let line = String::from_utf8_lossy(&raw).into_owned();
        if line == "ERROR" || line.starts_with("ERROR ") {
            return Err(McError::UnknownCommand);
        }
        if let Some(m) = line.strip_prefix("CLIENT_ERROR ") {
            return Err(McError::Client(m.to_string()));
        }
        if line.starts_with("SERVER_ERROR") {
            return Err(McError::Server(line));
        }
        Ok(line)
    }

    fn unexpected(cmd: &str, line: &str) -> McError {
        McError::Server(format!("unexpected reply to {cmd}: {line:?}"))
    }

    /// `version`: the server version string.
    pub async fn version(&mut self) -> Result<String, McError> {
        self.send("version", None).await?;
        let line = self.line().await?;
        line.strip_prefix("VERSION ")
            .map(str::to_string)
            .ok_or_else(|| Self::unexpected("version", &line))
    }

    /// `get`: the stored bytes of each key found.
    pub async fn get_many(&mut self, keys: &[String]) -> Result<HashMap<String, Vec<u8>>, McError> {
        let mut found = HashMap::new();
        for chunk in keys.chunks(GET_BATCH) {
            self.send(&format!("get {}", chunk.join(" ")), None).await?;
            loop {
                let line = self.line().await?;
                if line == "END" {
                    break;
                }
                // VALUE <key> <flags> <bytes> [<cas>]
                let parts: Vec<&str> = line.split(' ').collect();
                let len = match parts.as_slice() {
                    ["VALUE", _, _, len, ..] => len.parse::<usize>().ok(),
                    _ => None,
                }
                .ok_or_else(|| Self::unexpected("get", &line))?;
                let mut data = vec![0u8; len + 2];
                self.stream.read_exact(&mut data).await?;
                if !data.ends_with(b"\r\n") {
                    return Err(Self::unexpected("get", "value without a line ending"));
                }
                data.truncate(len);
                found.insert(parts[1].to_string(), data);
            }
        }
        Ok(found)
    }

    /// `set`, `add` or `replace`: true when stored, false for `NOT_STORED`
    /// (the add or replace condition was not met).
    pub async fn store(
        &mut self,
        cmd: &str,
        key: &str,
        data: &[u8],
        exptime: u64,
    ) -> Result<bool, McError> {
        debug_assert!(matches!(cmd, "set" | "add" | "replace"));
        self.send(
            &format!("{cmd} {key} 0 {exptime} {}", data.len()),
            Some(data),
        )
        .await?;
        match self.line().await?.as_str() {
            "STORED" => Ok(true),
            "NOT_STORED" => Ok(false),
            other => Err(Self::unexpected(cmd, other)),
        }
    }

    /// `delete`: true when the key existed.
    pub async fn delete(&mut self, key: &str) -> Result<bool, McError> {
        self.send(&format!("delete {key}"), None).await?;
        match self.line().await?.as_str() {
            "DELETED" => Ok(true),
            "NOT_FOUND" => Ok(false),
            other => Err(Self::unexpected("delete", other)),
        }
    }

    /// `incr` or `decr`: the new value, or `None` when the key is missing.
    /// A non-numeric value is `McError::Client`.
    pub async fn incr_decr(
        &mut self,
        cmd: &str,
        key: &str,
        by: u64,
    ) -> Result<Option<u64>, McError> {
        debug_assert!(matches!(cmd, "incr" | "decr"));
        self.send(&format!("{cmd} {key} {by}"), None).await?;
        let line = self.line().await?;
        if line == "NOT_FOUND" {
            return Ok(None);
        }
        line.trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Self::unexpected(cmd, &line))
    }

    /// `touch`: true when the key existed.
    pub async fn touch(&mut self, key: &str, exptime: u64) -> Result<bool, McError> {
        self.send(&format!("touch {key} {exptime}"), None).await?;
        match self.line().await?.as_str() {
            "TOUCHED" => Ok(true),
            "NOT_FOUND" => Ok(false),
            other => Err(Self::unexpected("touch", other)),
        }
    }

    /// `mg <key> [t]`: whether the key exists, and its remaining TTL when
    /// `ttl` is set, without fetching the value.
    pub async fn meta_get(&mut self, key: &str, ttl: bool) -> Result<Meta, McError> {
        let cmd = if ttl {
            format!("mg {key} t")
        } else {
            format!("mg {key}")
        };
        self.send(&cmd, None).await?;
        let line = match self.line().await {
            Err(McError::UnknownCommand) => return Ok(Meta::Unsupported),
            other => other?,
        };
        if line == "EN" {
            return Ok(Meta::Miss);
        }
        // "HD <flags>" (1.6.10+) or "OK <flags>" (earlier 1.6 releases).
        let mut words = line.split(' ');
        if !matches!(words.next(), Some("HD" | "OK")) {
            return Err(Self::unexpected("mg", &line));
        }
        let mut ttl_secs = None;
        for w in words {
            if let Some(t) = w.strip_prefix('t') {
                let t: i64 = t.parse().map_err(|_| Self::unexpected("mg", &line))?;
                ttl_secs = u64::try_from(t).ok();
            }
        }
        if ttl && !line.split(' ').any(|w| w.starts_with('t')) {
            return Err(Self::unexpected("mg", &line));
        }
        Ok(Meta::Hit { ttl_secs })
    }

    /// `lru_crawler metadump all`: every key in the cache with its expiry.
    /// memcached 1.6 answers `OK`, then one `key=<url-encoded> exp=<unix|-1>
    /// ...` line per item (ending in a bare `\n`), then `END`.
    pub async fn metadump(&mut self) -> Result<Dump, McError> {
        self.send("lru_crawler metadump all", None).await?;
        let mut keys = Vec::new();
        loop {
            let line = match self.line().await {
                Ok(l) => l,
                Err(McError::UnknownCommand) => {
                    return Ok(Dump::Unsupported(
                        "the server has no `lru_crawler metadump` (memcached 1.4.31 or later \
                         is needed)"
                            .into(),
                    ));
                }
                Err(McError::Client(m)) | Err(McError::Server(m)) if keys.is_empty() => {
                    return Ok(Dump::Unsupported(format!(
                        "the server refused `lru_crawler metadump`: {m}"
                    )));
                }
                Err(e) => return Err(e),
            };
            if line == "END" {
                return Ok(Dump::Keys(keys));
            }
            // memcached 1.6 starts the dump with "OK".
            if line == "OK" && keys.is_empty() {
                continue;
            }
            if line.starts_with("BUSY") {
                return Ok(Dump::Busy);
            }
            let mut key = None;
            let mut exp = None;
            for field in line.split(' ') {
                if let Some(k) = field.strip_prefix("key=") {
                    key = Some(
                        percent_encoding::percent_decode_str(k)
                            .decode_utf8_lossy()
                            .into_owned(),
                    );
                } else if let Some(e) = field.strip_prefix("exp=") {
                    exp = e.parse::<i64>().ok().and_then(|e| u64::try_from(e).ok());
                }
            }
            match key {
                Some(key) => keys.push(DumpedKey { key, exp }),
                None => return Err(Self::unexpected("lru_crawler metadump", &line)),
            }
        }
    }
}

/// Redis-style glob match (`*`, `?`, `[abc]`, `[^a]`, `[a-z]`, `\x`), the
/// syntax `keys` uses on both backends.
pub fn glob_match(pattern: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    // Backtrack point for the last `*`: (pattern index after it, text index).
    let mut star: Option<(usize, usize)> = None;
    while i < s.len() {
        let step = if p < pattern.len() {
            match pattern[p] {
                b'*' => {
                    star = Some((p + 1, i));
                    p += 1;
                    continue;
                }
                b'?' => Some(p + 1),
                b'[' => match_class(pattern, p, s[i]),
                b'\\' if p + 1 < pattern.len() => (pattern[p + 1] == s[i]).then_some(p + 2),
                c => (c == s[i]).then_some(p + 1),
            }
        } else {
            None
        };
        match step {
            Some(next) => {
                p = next;
                i += 1;
            }
            None => match star {
                Some((sp, si)) => {
                    p = sp;
                    i = si + 1;
                    star = Some((sp, si + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Matches `c` against the class starting at `pattern[open] == b'['`; the
/// pattern index after the class when it matches. An unterminated class
/// is matched literally as `[`.
fn match_class(pattern: &[u8], open: usize, c: u8) -> Option<usize> {
    let mut j = open + 1;
    let negate = matches!(pattern.get(j), Some(b'^'));
    if negate {
        j += 1;
    }
    let mut hit = false;
    let mut first = true;
    loop {
        let Some(&pc) = pattern.get(j) else {
            // No closing bracket: a literal '['.
            return (c == b'[').then_some(open + 1);
        };
        if pc == b']' && !first {
            break;
        }
        first = false;
        if pc == b'\\' && j + 1 < pattern.len() {
            hit |= pattern[j + 1] == c;
            j += 2;
        } else if j + 2 < pattern.len() && pattern[j + 1] == b'-' && pattern[j + 2] != b']' {
            let (lo, hi) = (pc.min(pattern[j + 2]), pc.max(pattern[j + 2]));
            hit |= (lo..=hi).contains(&c);
            j += 3;
        } else {
            hit |= pc == c;
            j += 1;
        }
    }
    (hit != negate).then_some(j + 1)
}

/// `s` with the glob special characters escaped, so it matches only itself.
pub fn glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_like_redis() {
        let m = |p: &str, s: &str| glob_match(p.as_bytes(), s.as_bytes());
        assert!(m("*", ""));
        assert!(m("*", "anything"));
        assert!(m("user:*", "user:1"));
        assert!(!m("user:*", "users:1"));
        assert!(m("*:42", "user:42"));
        assert!(m("a*b*c", "aXXbYYc"));
        assert!(!m("a*b*c", "aXXbYY"));
        assert!(m("h?llo", "hello"));
        assert!(!m("h?llo", "hllo"));
        assert!(m("h[ae]llo", "hallo"));
        assert!(!m("h[ae]llo", "hillo"));
        assert!(m("h[^e]llo", "hallo"));
        assert!(!m("h[^e]llo", "hello"));
        assert!(m("h[a-c]llo", "hbllo"));
        assert!(!m("h[a-c]llo", "hdllo"));
        assert!(m("a\\*b", "a*b"));
        assert!(!m("a\\*b", "aXb"));
        assert!(m("[]]x", "]x"));
        assert!(m("ab[", "ab["));
        assert!(m("**x", "x"));
        assert!(!m("x", "xy"));
    }

    #[test]
    fn glob_escape_matches_only_itself() {
        let ns = "a*[b]?\\";
        let pat = format!("{}:*", glob_escape(ns));
        assert!(glob_match(pat.as_bytes(), format!("{ns}:k").as_bytes()));
        assert!(!glob_match(pat.as_bytes(), b"aXbY:k"));
    }

    #[test]
    fn keys_are_checked() {
        assert!(check_key("user:1").is_none());
        assert!(check_key(&"k".repeat(250)).is_none());
        assert!(check_key("").is_some());
        assert!(check_key(&"k".repeat(251)).is_some());
        for bad in ["a b", "a\r\nflush_all", "a\tb", "a\u{7f}"] {
            assert!(check_key(bad).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn exptime_rounds_up_and_switches_to_absolute() {
        assert_eq!(exptime(None), 0);
        assert_eq!(exptime(Some(1)), 1);
        assert_eq!(exptime(Some(999)), 1);
        assert_eq!(exptime(Some(1000)), 1);
        assert_eq!(exptime(Some(1001)), 2);
        assert_eq!(
            exptime(Some(MAX_RELATIVE_EXPTIME * 1000)),
            MAX_RELATIVE_EXPTIME
        );
        let abs = exptime(Some((MAX_RELATIVE_EXPTIME + 1) * 1000));
        assert!(abs > now_unix(), "{abs}");
    }
}
