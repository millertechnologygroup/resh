use anyhow::{Result, bail};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

pub use super::status::Status;

// Function to preprocess URL strings to handle backslash escapes
fn preprocess_url_escapes(url: &str) -> String {
    let mut result = String::with_capacity(url.len() * 2); // Pre-allocate some extra space
    let mut chars = url.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some(' ') => {
                    chars.next(); // consume the space
                    result.push_str("%20"); // URL-encode the space
                }
                Some('\\') => {
                    chars.next(); // consume the second backslash
                    result.push_str("%5C"); // URL-encode the backslash
                }
                Some('t') => {
                    chars.next(); // consume the 't'
                    result.push_str("%09"); // URL-encode tab
                }
                Some('n') => {
                    chars.next(); // consume the 'n'
                    result.push_str("%0A"); // URL-encode newline
                }
                _ => result.push(c), // just a backslash, keep it
            }
        } else {
            result.push(c);
        }
    }

    result
}

pub type Args = HashMap<String, String>;

pub struct IoStreams<'a> {
    #[allow(dead_code)]
    pub stdin: &'a mut dyn Read,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

impl<'a> IoStreams<'a> {
    pub fn new(
        stdin: &'a mut dyn Read,
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
        }
    }
}

pub trait Handle: Send + Sync {
    #[allow(dead_code)]
    fn verbs(&self) -> &'static [&'static str];
    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status>;

    /// Descriptive metadata for `resh <handle> --help`. Handles without
    /// metadata keep the default CLI help behavior.
    fn help(&self) -> Option<&'static super::help::HandleHelp> {
        None
    }
}

pub struct Registry {
    schemes: HashMap<String, Arc<dyn Fn(&url::Url) -> Result<Box<dyn Handle>>>>,
    /// Placeholder URLs for handles whose constructor needs a specific
    /// URL shape; see `instantiate`.
    probe_urls: HashMap<String, String>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            schemes: HashMap::new(),
            probe_urls: HashMap::new(),
        }
    }
}

impl Registry {
    pub fn list_schemes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.schemes.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn register_scheme<F>(&mut self, scheme: &str, ctor: F)
    where
        F: Fn(&url::Url) -> Result<Box<dyn Handle>> + 'static + Send + Sync,
    {
        self.schemes.insert(scheme.to_string(), Arc::new(ctor));
    }

    /// Sets the placeholder URL `instantiate` uses for `scheme`, for
    /// constructors that reject the default `<scheme>://resh-help-probe`.
    /// The constructor must not perform I/O for this URL.
    pub fn set_probe_url(&mut self, scheme: &str, url: &str) {
        self.probe_urls.insert(scheme.to_string(), url.to_string());
    }

    /// Constructs the handle registered for `scheme` from a placeholder URL,
    /// for reading metadata such as `verbs()` and `help()`.
    /// Returns `None` if the scheme is not registered.
    pub fn instantiate(&self, scheme: &str) -> Option<Result<Box<dyn Handle>>> {
        let ctor = self.schemes.get(scheme)?;
        let probe = self
            .probe_urls
            .get(scheme)
            .cloned()
            .unwrap_or_else(|| format!("{scheme}://resh-help-probe"));
        Some(
            url::Url::parse(&probe)
                .map_err(Into::into)
                .and_then(|u| ctor(&u)),
        )
    }

    pub fn resolve(&self, target: &str) -> Result<Box<dyn Handle>> {
        // Pre-process the target to handle backslash escapes in URLs
        let processed_target = preprocess_url_escapes(target);
        let u = url::Url::parse(&processed_target)?;
        let scheme = u.scheme();
        if let Some(ctor) = self.schemes.get(scheme) {
            ctor(&u)
        } else {
            bail!("Unknown scheme: {}", scheme);
        }
    }
}
