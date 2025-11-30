use anyhow::{Result, bail};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use super::status::Status;

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

pub trait Handle: Send + Sync {
    #[allow(dead_code)]
    fn verbs(&self) -> &'static [&'static str];
    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status>;
}

pub struct Registry {
    schemes: HashMap<String, Arc<dyn Fn(&url::Url) -> Result<Box<dyn Handle>>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            schemes: HashMap::new(),
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
