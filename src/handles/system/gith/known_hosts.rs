//! OpenSSH `known_hosts` parsing and strict host-key matching for the git
//! handle's `known_hosts_path` option.
//!
//! Supported line forms (see sshd(8), "SSH_KNOWN_HOSTS FILE FORMAT"):
//!
//! * `hostpatterns keytype base64-key [comment]`
//! * `@revoked hostpatterns keytype base64-key [comment]`
//! * `@cert-authority hostpatterns keytype base64-key [comment]` (parsed so
//!   it can be reported, but never used to accept a key)
//!
//! `hostpatterns` is either a comma-separated list of patterns (`*` and `?`
//! wildcards, `!` negation, `[host]:port` for ports other than 22) or one
//! hashed entry `|1|base64(salt)|base64(HMAC-SHA1(salt, name))`. Host names
//! are compared case-insensitively. Blank lines, `#` comments, lines with an
//! unknown `@` marker and malformed lines are skipped, never fatal.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The line marker of a known_hosts entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    None,
    Revoked,
    CertAuthority,
}

/// The host field of an entry.
#[derive(Debug, Clone)]
enum HostField {
    /// `|1|salt|hash`: HMAC-SHA1 of the lookup name keyed with `salt`.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    /// Comma-separated patterns, lowercased, `!` kept as a prefix.
    Patterns(Vec<String>),
}

#[derive(Debug, Clone)]
struct Entry {
    marker: Marker,
    host: HostField,
    key_type: String,
    blob: Vec<u8>,
}

/// A host key presented by a server. libgit2 normally reports the raw key
/// blob and its type; when only a fingerprint is available, the SHA-256 of
/// the blob is compared instead.
#[derive(Debug, Clone, Default)]
pub struct PresentedKey {
    /// OpenSSH key type name, such as `ssh-ed25519`.
    pub key_type: Option<String>,
    /// The raw SSH wire-format public key blob.
    pub blob: Option<Vec<u8>>,
    /// SHA-256 of the key blob.
    pub sha256: Option<[u8; 32]>,
}

impl PresentedKey {
    fn sha256(&self) -> Option<[u8; 32]> {
        match &self.blob {
            Some(blob) => Some(Sha256::digest(blob).into()),
            None => self.sha256,
        }
    }

    fn type_name(&self) -> String {
        self.key_type
            .clone()
            .or_else(|| self.blob.as_deref().and_then(blob_key_type))
            .unwrap_or_else(|| "unknown key type".to_string())
    }

    /// `<type> SHA256:<fingerprint>` as printed by OpenSSH.
    fn describe(&self) -> String {
        match self.sha256() {
            Some(h) => format!("{} SHA256:{}", self.type_name(), STANDARD_NO_PAD.encode(h)),
            None => self.type_name(),
        }
    }

    /// True when this key is the key of `entry` (type and blob).
    fn matches(&self, entry: &Entry) -> bool {
        if let Some(t) = &self.key_type {
            if *t != entry.key_type {
                return false;
            }
        }
        match (&self.blob, self.sha256) {
            (Some(blob), _) => *blob == entry.blob,
            (None, Some(h)) => <[u8; 32]>::from(Sha256::digest(&entry.blob)) == h,
            (None, None) => false,
        }
    }
}

/// A parsed known_hosts file.
#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
    entries: Vec<Entry>,
    skipped: usize,
}

/// The name a host is looked up under: `host` on port 22, else `[host]:port`.
pub fn lookup_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{}]:{}", host, port)
    }
}

impl KnownHosts {
    /// Reads and parses `path`. An unreadable or missing file is an error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read known_hosts file '{}': {}", path.display(), e))?;
        Ok(Self::parse(path, &text))
    }

    /// Parses known_hosts text; `path` is only used in messages.
    pub fn parse(path: &Path, text: &str) -> Self {
        let mut entries = Vec::new();
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_line(line) {
                Some(entry) => entries.push(entry),
                None => {
                    log::debug!("known_hosts: skipping malformed or unsupported line: {line}");
                    skipped += 1;
                }
            }
        }
        KnownHosts {
            path: path.to_path_buf(),
            entries,
            skipped,
        }
    }

    /// Number of non-comment lines that were skipped as malformed or unsupported.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    fn entries_for<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
        self.entries
            .iter()
            .filter(move |e| host_matches(&e.host, name))
    }

    /// Checks, before connecting, that the host has at least one plain key
    /// entry to verify against.
    pub fn preflight(&self, host: &str, port: u16) -> Result<(), String> {
        let name = lookup_name(host, port);
        let (plain, ca) = self
            .entries_for(&name)
            .fold((0, 0), |(p, c), e| match e.marker {
                Marker::None => (p + 1, c),
                Marker::CertAuthority => (p, c + 1),
                Marker::Revoked => (p, c),
            });
        if plain > 0 {
            Ok(())
        } else if ca > 0 {
            Err(format!(
                "known_hosts file '{}' lists '{}' only under @cert-authority; CA-signed host keys \
                 are not supported by known_hosts_path checking. Add the host's own key \
                 (for example from ssh-keyscan) to the file",
                self.path.display(),
                name
            ))
        } else {
            Err(format!(
                "host '{}' is not listed in known_hosts file '{}'",
                name,
                self.path.display()
            ))
        }
    }

    /// Accepts `key` for `host:port` only when it matches a plain entry for
    /// that host and no `@revoked` entry for that host lists it.
    pub fn verify(&self, host: &str, port: u16, key: &PresentedKey) -> Result<(), String> {
        let name = lookup_name(host, port);
        if key.blob.is_none() && key.sha256.is_none() {
            return Err(format!(
                "the SSH server for '{}' did not expose its host key, so it cannot be checked \
                 against '{}'",
                name,
                self.path.display()
            ));
        }
        let entries: Vec<&Entry> = self.entries_for(&name).collect();
        if entries
            .iter()
            .any(|e| e.marker == Marker::Revoked && key.matches(e))
        {
            return Err(format!(
                "the host key presented by '{}' ({}) is marked @revoked in '{}'",
                name,
                key.describe(),
                self.path.display()
            ));
        }
        let plain: Vec<&&Entry> = entries
            .iter()
            .filter(|e| e.marker == Marker::None)
            .collect();
        if plain.iter().any(|e| key.matches(e)) {
            return Ok(());
        }
        if plain.is_empty() {
            // Unknown host, or only @cert-authority lines.
            self.preflight(host, port)?;
        }
        let mut types: Vec<&str> = plain.iter().map(|e| e.key_type.as_str()).collect();
        types.sort_unstable();
        types.dedup();
        Err(format!(
            "the host key presented by '{}' ({}) does not match the key(s) recorded for it in \
             '{}' (recorded key types: {}). The host key may have changed, or the connection \
             may be intercepted",
            name,
            key.describe(),
            self.path.display(),
            types.join(", ")
        ))
    }
}

/// Parses one non-empty, non-comment line.
fn parse_line(line: &str) -> Option<Entry> {
    let mut fields = line.split_whitespace();
    let mut first = fields.next()?;
    let marker = if let Some(m) = first.strip_prefix('@') {
        let marker = match m {
            "revoked" => Marker::Revoked,
            "cert-authority" => Marker::CertAuthority,
            _ => return None,
        };
        first = fields.next()?;
        marker
    } else {
        Marker::None
    };
    let key_type = fields.next()?.to_string();
    let blob = STANDARD.decode(fields.next()?).ok()?;
    // The type field must agree with the type inside the key blob.
    if blob_key_type(&blob)? != key_type {
        return None;
    }
    let host = parse_host_field(first)?;
    Some(Entry {
        marker,
        host,
        key_type,
        blob,
    })
}

fn parse_host_field(field: &str) -> Option<HostField> {
    if let Some(rest) = field.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|')?;
        let salt = STANDARD.decode(salt).ok()?;
        let hash = STANDARD.decode(hash).ok()?;
        if salt.is_empty() || hash.len() != 20 {
            return None;
        }
        return Some(HostField::Hashed { salt, hash });
    }
    if field.starts_with('|') {
        // An unknown hash format.
        return None;
    }
    let patterns: Vec<String> = field
        .split(',')
        .filter(|p| !p.is_empty() && *p != "!")
        .map(|p| p.to_ascii_lowercase())
        .collect();
    if patterns.is_empty() {
        None
    } else {
        Some(HostField::Patterns(patterns))
    }
}

/// Reads the key type string at the start of an SSH wire-format key blob.
fn blob_key_type(blob: &[u8]) -> Option<String> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    let name = blob.get(4..4usize.checked_add(len)?)?;
    let name = std::str::from_utf8(name).ok()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// HMAC-SHA1 of `name` keyed with `salt`, as used by hashed known_hosts entries.
pub fn hash_host(salt: &[u8], name: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn host_matches(field: &HostField, name: &str) -> bool {
    match field {
        HostField::Hashed { salt, hash } => hash_host(salt, name) == *hash,
        HostField::Patterns(patterns) => {
            // As in OpenSSH match_hostname(): a matching negated pattern
            // excludes the host even when a positive pattern matches.
            let mut matched = false;
            for p in patterns {
                if let Some(neg) = p.strip_prefix('!') {
                    if wildcard_match(neg, name) {
                        return false;
                    }
                } else if wildcard_match(p, name) {
                    matched = true;
                }
            }
            matched
        }
    }
}

/// Glob match with `*` (any run) and `?` (one character).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Returns the host and port of an SSH remote URL, or None when the URL does
/// not use SSH (https, http, git, file, a local path).
///
/// Accepts `ssh://[user@]host[:port]/path`, `git+ssh://`, `ssh+git://` and
/// the scp-like `[user@]host:path` form (port 22).
pub fn ssh_endpoint(url: &str) -> Option<(String, u16)> {
    if let Some(idx) = url.find("://") {
        let scheme = url[..idx].to_ascii_lowercase();
        if !matches!(scheme.as_str(), "ssh" | "git+ssh" | "ssh+git") {
            return None;
        }
        // Normalise the scheme so the url crate parses the authority.
        let parsed = url::Url::parse(&format!("ssh://{}", &url[idx + 3..])).ok()?;
        let host = parsed.host_str()?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return None;
        }
        return Some((host.to_string(), parsed.port().unwrap_or(22)));
    }
    // scp-like syntax: a ':' before any '/'.
    let colon = url.find(':')?;
    if url[..colon].contains('/') {
        return None;
    }
    let authority = &url[..colon];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    // A single letter is a Windows drive (C:\repo), not a host.
    if host.is_empty() || (host.len() == 1 && url[colon + 1..].starts_with(['\\', '/'])) {
        return None;
    }
    Some((host.to_string(), 22))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fabricated SSH wire-format key blob: string(type) || string(data).
    fn blob(key_type: &str, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        b.extend_from_slice(key_type.as_bytes());
        b.extend_from_slice(&(data.len() as u32).to_be_bytes());
        b.extend_from_slice(data);
        b
    }

    fn b64(key_type: &str, data: &[u8]) -> String {
        STANDARD.encode(blob(key_type, data))
    }

    fn key(key_type: &str, data: &[u8]) -> PresentedKey {
        PresentedKey {
            key_type: Some(key_type.to_string()),
            blob: Some(blob(key_type, data)),
            sha256: None,
        }
    }

    fn hashed(name: &str, salt: &[u8]) -> String {
        format!(
            "|1|{}|{}",
            STANDARD.encode(salt),
            STANDARD.encode(hash_host(salt, name))
        )
    }

    fn kh(text: &str) -> KnownHosts {
        KnownHosts::parse(Path::new("/test/known_hosts"), text)
    }

    const ED: &str = "ssh-ed25519";
    const RSA: &str = "ssh-rsa";

    #[test]
    fn plain_entry_accepts_matching_key_only() {
        let k = kh(&format!("example.com {ED} {}\n", b64(ED, b"good")));
        assert!(k.verify("example.com", 22, &key(ED, b"good")).is_ok());
        assert!(k.verify("EXAMPLE.com", 22, &key(ED, b"good")).is_ok());
        let err = k.verify("example.com", 22, &key(ED, b"evil")).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        assert!(err.contains("SHA256:"), "{err}");
        assert!(err.contains("ssh-ed25519"), "{err}");
    }

    #[test]
    fn key_type_must_match_too() {
        let k = kh(&format!("h {ED} {}\n", b64(ED, b"same")));
        // Same data under another type is a different key.
        let err = k.verify("h", 22, &key(RSA, b"same")).unwrap_err();
        assert!(err.contains("recorded key types: ssh-ed25519"), "{err}");
    }

    #[test]
    fn unknown_host_is_refused() {
        let k = kh(&format!("example.com {ED} {}\n", b64(ED, b"k")));
        let err = k.verify("other.com", 22, &key(ED, b"k")).unwrap_err();
        assert!(err.contains("not listed"), "{err}");
        assert!(k.preflight("other.com", 22).is_err());
        assert!(k.preflight("example.com", 22).is_ok());
    }

    #[test]
    fn comma_separated_host_list() {
        let k = kh(&format!("a.com,b.com,10.0.0.1 {ED} {}\n", b64(ED, b"k")));
        for h in ["a.com", "b.com", "10.0.0.1"] {
            assert!(k.verify(h, 22, &key(ED, b"k")).is_ok(), "{h}");
        }
        assert!(k.verify("c.com", 22, &key(ED, b"k")).is_err());
    }

    #[test]
    fn non_default_port_uses_bracket_form() {
        let k = kh(&format!(
            "[git.example.com]:2222 {ED} {}\ngit.example.com {ED} {}\n",
            b64(ED, b"port2222"),
            b64(ED, b"port22")
        ));
        assert!(
            k.verify("git.example.com", 2222, &key(ED, b"port2222"))
                .is_ok()
        );
        assert!(k.verify("git.example.com", 22, &key(ED, b"port22")).is_ok());
        // The port-22 key is not valid on 2222 and vice versa.
        assert!(
            k.verify("git.example.com", 2222, &key(ED, b"port22"))
                .is_err()
        );
        assert!(
            k.verify("git.example.com", 22, &key(ED, b"port2222"))
                .is_err()
        );
        // A plain entry does not cover other ports.
        let only22 = kh(&format!("h {ED} {}\n", b64(ED, b"k")));
        let err = only22.verify("h", 2200, &key(ED, b"k")).unwrap_err();
        assert!(err.contains("[h]:2200"), "{err}");
    }

    #[test]
    fn hashed_entries() {
        let k = kh(&format!(
            "{} {ED} {}\n{} {ED} {}\n",
            hashed("hashed.example", b"0123456789abcdefghij"),
            b64(ED, b"k1"),
            hashed("[hashed.example]:2222", b"saltsaltsaltsaltsalt"),
            b64(ED, b"k2")
        ));
        assert!(k.verify("hashed.example", 22, &key(ED, b"k1")).is_ok());
        assert!(k.verify("Hashed.Example", 22, &key(ED, b"k1")).is_ok());
        assert!(k.verify("hashed.example", 2222, &key(ED, b"k2")).is_ok());
        assert!(k.verify("hashed.example", 2222, &key(ED, b"k1")).is_err());
        assert!(k.verify("other.example", 22, &key(ED, b"k1")).is_err());
    }

    #[test]
    fn wildcard_patterns() {
        let k = kh(&format!(
            "*.example.com {ED} {}\nhost?.lan {ED} {}\n",
            b64(ED, b"wild"),
            b64(ED, b"q")
        ));
        assert!(k.verify("git.example.com", 22, &key(ED, b"wild")).is_ok());
        assert!(k.verify("a.b.example.com", 22, &key(ED, b"wild")).is_ok());
        assert!(k.verify("example.com", 22, &key(ED, b"wild")).is_err());
        assert!(k.verify("host1.lan", 22, &key(ED, b"q")).is_ok());
        assert!(k.verify("host12.lan", 22, &key(ED, b"q")).is_err());
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*b*c", "aXXbYYc"));
        assert!(!wildcard_match("a*b*c", "aXXbYY"));
        assert!(wildcard_match("[h]:*", "[h]:2222"));
    }

    #[test]
    fn negated_pattern_excludes_host() {
        let k = kh(&format!(
            "*.example.com,!evil.example.com {ED} {}\n",
            b64(ED, b"k")
        ));
        assert!(k.verify("good.example.com", 22, &key(ED, b"k")).is_ok());
        let err = k
            .verify("evil.example.com", 22, &key(ED, b"k"))
            .unwrap_err();
        assert!(err.contains("not listed"), "{err}");
        // A negation alone never matches anything.
        let neg_only = kh(&format!("!x {ED} {}\n", b64(ED, b"k")));
        assert!(neg_only.verify("y", 22, &key(ED, b"k")).is_err());
    }

    #[test]
    fn revoked_key_is_refused_even_if_also_listed() {
        let k = kh(&format!(
            "h {ED} {good}\nh {ED} {bad}\n@revoked h {ED} {bad}\n",
            good = b64(ED, b"good"),
            bad = b64(ED, b"bad")
        ));
        assert!(k.verify("h", 22, &key(ED, b"good")).is_ok());
        let err = k.verify("h", 22, &key(ED, b"bad")).unwrap_err();
        assert!(err.contains("@revoked"), "{err}");
        // A revocation for another host does not apply.
        let other = kh(&format!(
            "h {ED} {k}\n@revoked other {ED} {k}\n",
            k = b64(ED, b"k")
        ));
        assert!(other.verify("h", 22, &key(ED, b"k")).is_ok());
    }

    #[test]
    fn cert_authority_lines_are_not_used_for_matching() {
        let ca_only = kh(&format!("@cert-authority *.corp {ED} {}\n", b64(ED, b"ca")));
        let err = ca_only.verify("git.corp", 22, &key(ED, b"ca")).unwrap_err();
        assert!(err.contains("CA-signed host keys"), "{err}");
        assert!(
            ca_only
                .preflight("git.corp", 22)
                .unwrap_err()
                .contains("CA-signed")
        );

        // With a plain entry as well, the plain entry decides.
        let mixed = kh(&format!(
            "@cert-authority *.corp {ED} {}\ngit.corp {ED} {}\n",
            b64(ED, b"ca"),
            b64(ED, b"host")
        ));
        assert!(mixed.verify("git.corp", 22, &key(ED, b"host")).is_ok());
        let err = mixed.verify("git.corp", 22, &key(ED, b"ca")).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let text = format!(
            "# comment\n\
             \n\
             justonefield\n\
             host-without-key ssh-ed25519\n\
             bad ssh-ed25519 !!!notbase64!!!\n\
             typemismatch ssh-rsa {ed}\n\
             |1|bad|hash {ED} {ed}\n\
             |2|x|y {ED} {ed}\n\
             @unknown-marker h {ED} {ed}\n\
             @revoked\n\
             , {ED} {ed}\n\
             \tgood.example {ED} {ed} trailing comment words\n",
            ed = b64(ED, b"k")
        );
        let k = kh(&text);
        assert_eq!(k.skipped(), 9);
        assert!(k.verify("good.example", 22, &key(ED, b"k")).is_ok());
        assert!(k.verify("typemismatch", 22, &key(RSA, b"k")).is_err());
    }

    #[test]
    fn fingerprint_only_keys_are_compared_by_sha256() {
        let k = kh(&format!("h {ED} {}\n", b64(ED, b"k")));
        let good = PresentedKey {
            key_type: None,
            blob: None,
            sha256: Some(Sha256::digest(blob(ED, b"k")).into()),
        };
        assert!(k.verify("h", 22, &good).is_ok());
        let bad = PresentedKey {
            key_type: None,
            blob: None,
            sha256: Some([0u8; 32]),
        };
        assert!(k.verify("h", 22, &bad).is_err());
        let nothing = PresentedKey::default();
        assert!(
            k.verify("h", 22, &nothing)
                .unwrap_err()
                .contains("did not expose")
        );
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = KnownHosts::load(Path::new("/nonexistent/known_hosts")).unwrap_err();
        assert!(err.contains("cannot read known_hosts file"), "{err}");
        let dir = tempfile::TempDir::new().unwrap();
        assert!(KnownHosts::load(dir.path()).is_err());
    }

    #[test]
    fn ssh_endpoint_parsing() {
        assert_eq!(
            ssh_endpoint("ssh://git@example.com/repo.git"),
            Some(("example.com".into(), 22))
        );
        assert_eq!(
            ssh_endpoint("ssh://git@example.com:2222/repo.git"),
            Some(("example.com".into(), 2222))
        );
        assert_eq!(
            ssh_endpoint("git+ssh://example.com:7999/r"),
            Some(("example.com".into(), 7999))
        );
        assert_eq!(
            ssh_endpoint("ssh+git://example.com/r"),
            Some(("example.com".into(), 22))
        );
        assert_eq!(
            ssh_endpoint("ssh://[::1]:2222/r"),
            Some(("::1".into(), 2222))
        );
        assert_eq!(
            ssh_endpoint("git@github.com:owner/repo.git"),
            Some(("github.com".into(), 22))
        );
        assert_eq!(ssh_endpoint("host:repo.git"), Some(("host".into(), 22)));
        for not_ssh in [
            "https://example.com/r.git",
            "http://example.com/r.git",
            "git://example.com/r.git",
            "file:///tmp/r",
            "/tmp/r",
            "./relative/path",
            "relative/with:colon",
            "C:\\repo",
            "C:/repo",
        ] {
            assert_eq!(ssh_endpoint(not_ssh), None, "{not_ssh}");
        }
    }

    /// Hashed entries written by the real `ssh-keygen -H` match. Skips when
    /// ssh-keygen is not installed.
    #[test]
    fn real_ssh_keygen_hashed_file() {
        use std::process::Command;
        let dir = tempfile::TempDir::new().unwrap();
        let keyfile = dir.path().join("hostkey");
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&keyfile)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let pubkey = std::fs::read_to_string(keyfile.with_extension("pub")).unwrap();
        let mut parts = pubkey.split_whitespace();
        let (ktype, kb64) = (parts.next().unwrap(), parts.next().unwrap());
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            format!("git.example.org {ktype} {kb64}\n[git.example.org]:2222 {ktype} {kb64}\n"),
        )
        .unwrap();
        let hashed = Command::new("ssh-keygen")
            .arg("-H")
            .arg("-f")
            .arg(&kh_path)
            .output()
            .unwrap();
        assert!(hashed.status.success());
        let text = std::fs::read_to_string(&kh_path).unwrap();
        assert!(text.starts_with("|1|"), "{text}");

        let k = KnownHosts::load(&kh_path).unwrap();
        assert_eq!(k.skipped(), 0);
        let presented = PresentedKey {
            key_type: Some(ktype.to_string()),
            blob: Some(STANDARD.decode(kb64).unwrap()),
            sha256: None,
        };
        assert!(k.verify("git.example.org", 22, &presented).is_ok());
        assert!(k.verify("git.example.org", 2222, &presented).is_ok());
        assert!(k.verify("git.example.org", 2200, &presented).is_err());
        assert!(k.verify("other.example.org", 22, &presented).is_err());
    }
}
