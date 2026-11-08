//! HTTPS downloads for the plugin verbs.
//!
//! Only `https://` URLs with a host are fetched; certificates are always
//! verified (the built-in roots plus `ca_file=`), and a redirect to anything
//! but HTTPS is refused. Every request ends at the verb's deadline, body
//! reading included, and bodies larger than the caller's limit are refused
//! while they are read.

use std::io::Read;
use std::time::Duration;

use url::Url;

use super::common::{CaFile, DOWNLOAD_FAILED, Deadline, NOT_FOUND, PResult, PluginError};

/// Checks a user-supplied registry, index or artifact URL: `https`, a host,
/// no user name or password. Usage error (exit 2) otherwise.
pub fn parse_https_url(key: &str, value: &str) -> PResult<Url> {
    let bad =
        |why: &str| PluginError::usage(format!("invalid {key} {value:?}: {why}; nothing was done"));
    let url = Url::parse(value).map_err(|e| bad(&e.to_string()))?;
    if url.scheme() != "https" {
        return Err(bad(&format!(
            "scheme {:?} is not allowed, plugin registries, indexes and artifacts must use https://",
            url.scheme()
        )));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(bad("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("credentials in the URL are not allowed"));
    }
    if url.fragment().is_some() {
        return Err(bad("a #fragment is not allowed"));
    }
    Ok(url)
}

/// A verifying HTTPS client bound to one verb's deadline.
pub struct Fetcher {
    client: reqwest::blocking::Client,
    deadline: Deadline,
}

impl Fetcher {
    pub fn new(ca: Option<&CaFile>, deadline: Deadline) -> PResult<Self> {
        let mut builder = reqwest::blocking::Client::builder()
            .user_agent(concat!("resh-plugin/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_millis(deadline.ms.max(1)));
        if let Some(ca) = ca {
            for cert in &ca.certs {
                builder = builder.add_root_certificate(cert.clone());
            }
        }
        let client = builder.build().map_err(|e| {
            PluginError::failed(
                DOWNLOAD_FAILED,
                format!("cannot create the HTTPS client: {e}"),
            )
        })?;
        Ok(Self { client, deadline })
    }

    /// GETs `url` and returns its body, at most `max_bytes`. HTTP 404 is
    /// `plugin.not_found`; other failures are `plugin.download_failed`, and
    /// reaching the deadline is `plugin.timeout` (exit 124).
    pub fn get(&self, url: &Url, max_bytes: u64, what: &str) -> PResult<Vec<u8>> {
        if url.scheme() != "https" {
            return Err(PluginError::failed(
                DOWNLOAD_FAILED,
                format!("refusing to fetch {what} from {url}: only https:// is allowed"),
            ));
        }
        let timed_out = || {
            self.deadline
                .error(&format!("while fetching {what} from {url}"))
        };
        let remaining = self.deadline.remaining();
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut resp = match self.client.get(url.clone()).timeout(remaining).send() {
            Ok(r) => r,
            Err(e) if e.is_timeout() || self.deadline.expired() => return Err(timed_out()),
            Err(e) => {
                return Err(PluginError::failed(
                    DOWNLOAD_FAILED,
                    format!("cannot fetch {what} from {url}: {}", error_chain(&e)),
                ));
            }
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(PluginError::failed(
                NOT_FOUND,
                format!("{what} not found: {url} answered HTTP 404"),
            ));
        }
        if !status.is_success() {
            return Err(PluginError::failed(
                DOWNLOAD_FAILED,
                format!("cannot fetch {what} from {url}: HTTP {status}"),
            ));
        }
        if let Some(len) = resp.content_length()
            && len > max_bytes
        {
            return Err(too_large(what, url, max_bytes));
        }
        let mut body = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            if self.deadline.expired() {
                return Err(timed_out());
            }
            match resp.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if body.len() as u64 + n as u64 > max_bytes {
                        return Err(too_large(what, url, max_bytes));
                    }
                    body.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) if self.deadline.expired() => return Err(timed_out()),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(timed_out()),
                Err(e) => {
                    return Err(PluginError::failed(
                        DOWNLOAD_FAILED,
                        format!("cannot read {what} from {url}: {e}"),
                    ));
                }
            }
        }
        Ok(body)
    }
}

fn too_large(what: &str, url: &Url, max: u64) -> PluginError {
    PluginError::failed(
        DOWNLOAD_FAILED,
        format!("{what} at {url} is larger than the {max}-byte limit"),
    )
}

/// The error and its sources, so TLS failures say why.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        let t = c.to_string();
        if !s.contains(&t) {
            s.push_str(": ");
            s.push_str(&t);
        }
        cur = c.source();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_with_a_host_are_accepted() {
        assert!(parse_https_url("registry", "https://plugins.example.org/base").is_ok());
        for bad in [
            "http://plugins.example.org",
            "ftp://x",
            "file:///etc/passwd",
            "https://user:pw@example.org",
            "https://example.org/#frag",
            "/srv/registry.json",
            "",
        ] {
            let e = parse_https_url("registry", bad).unwrap_err();
            assert_eq!(e.exit, 2, "{bad}");
        }
    }
}
