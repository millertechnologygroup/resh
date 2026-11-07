//! `config.get`: the OpenSSH client settings that apply to a host, from the
//! local config files, with OpenSSH's first-obtained-value rule.

use super::args::{ArgReader, check_known};
use super::conn::{SshTarget, check_host};
use super::types::*;
use super::{Out, coded, write_response};
use crate::core::registry::{Args, IoStreams};
use crate::core::status::Status;
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_USER_CONFIG: &str = "~/.ssh/config";
pub const DEFAULT_SYSTEM_CONFIG: &str = "/etc/ssh/ssh_config";
pub const DEFAULT_MAX_CONFIG_BYTES: u64 = 1_048_576;
pub const DEFAULT_MAX_INCLUDES: u64 = 64;
pub const DEFAULT_MAX_HOSTS: u64 = 1024;

/// Options that may be given several times; every value is kept, in order.
const MULTI_VALUED: &[&str] = &[
    "identityfile",
    "certificatefile",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "sendenv",
];

#[derive(Debug, Clone)]
pub struct ConfigGetOptions {
    pub host: String,
    pub user: Option<String>,
    pub user_home: Option<String>,
    pub user_config_path: String,
    pub user_config_given: bool,
    pub system_config_path: String,
    pub system_config_given: bool,
    pub extra_config_paths: Vec<String>,
    pub follow_includes: bool,
    pub include_raw_entries: bool,
    pub include_origin: bool,
    pub max_config_bytes: u64,
    pub max_includes: u64,
    pub max_hosts: u64,
    pub dry_run: bool,
}

pub fn parse(r: &ArgReader, target: &SshTarget) -> Result<ConfigGetOptions, SshError> {
    if target.port.is_some() || target.password.is_some() {
        return Err(SshError::InvalidArgument(
            "config.get uses only the host and user of the URL; remove the port and password"
                .into(),
        ));
    }
    let host = match (target.host.clone(), r.text("host")?) {
        (Some(u), Some(a)) if u != a => {
            return Err(SshError::TargetConflict(format!(
                "the URL host is {u:?} but host= is {a:?}"
            )));
        }
        (u, a) => u.or(a).ok_or(SshError::ConfigGetHostRequired)?,
    };
    check_host(&host)?;
    let user_config = r.text("user_config_path")?;
    let system_config = r.text("system_config_path")?;
    Ok(ConfigGetOptions {
        host,
        user: target.username.clone(),
        user_home: r.text("user_home")?,
        user_config_given: user_config.is_some(),
        user_config_path: user_config.unwrap_or_else(|| DEFAULT_USER_CONFIG.into()),
        system_config_given: system_config.is_some(),
        system_config_path: system_config.unwrap_or_else(|| DEFAULT_SYSTEM_CONFIG.into()),
        extra_config_paths: r.list("extra_config_paths")?.unwrap_or_default(),
        follow_includes: r.bool("follow_includes", true)?,
        include_raw_entries: r.bool("include_raw_entries", true)?,
        include_origin: r.bool("include_origin", true)?,
        max_config_bytes: r.u64_or("max_config_bytes", DEFAULT_MAX_CONFIG_BYTES)?,
        max_includes: r.u64_or("max_includes", DEFAULT_MAX_INCLUDES)?,
        max_hosts: r.u64_or("max_hosts", DEFAULT_MAX_HOSTS)?,
        dry_run: r.bool("dry_run", false)?,
    })
}

/// A Host or Match block (or the global section, `kind` "Global").
#[derive(Debug, Clone, PartialEq)]
struct Block {
    kind: String,
    pattern: Option<String>,
    file: String,
    line: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    raw: SshConfigRawEntry,
    block: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    User,
    System,
}

struct Parser<'a> {
    o: &'a ConfigGetOptions,
    home: PathBuf,
    blocks: Vec<Block>,
    entries: Vec<Entry>,
    files: usize,
    bytes: u64,
    includes: u64,
    hosts: u64,
}

/// Splits a config line into keyword and value (`Key value`, `Key=value`,
/// `Key = value`).
fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let keyword = line[..end].to_string();
    let mut rest = line[end..].trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    Some((keyword, rest.trim().to_string()))
}

/// Whitespace-separated words, honoring double quotes.
fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in value.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// ssh_config glob: `*` any run of characters, `?` one character.
pub fn glob_match(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// OpenSSH pattern-list rule: any matching negated pattern rejects; else at
/// least one positive pattern must match. Host names compare
/// case-insensitively.
pub fn match_list<'a>(text: &str, patterns: impl IntoIterator<Item = &'a str>) -> bool {
    let text = text.to_lowercase();
    let mut positive = false;
    for pat in patterns {
        let pat = pat.to_lowercase();
        if let Some(neg) = pat.strip_prefix('!') {
            if glob_match(&text, neg) {
                return false;
            }
        } else if glob_match(&text, &pat) {
            positive = true;
        }
    }
    positive
}

impl<'a> Parser<'a> {
    fn expand(&self, path: &str) -> PathBuf {
        if path == "~" {
            return self.home.clone();
        }
        match path.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None => PathBuf::from(path),
        }
    }

    fn read(&mut self, path: &Path) -> Result<String, SshError> {
        let text = std::fs::read(path)
            .map_err(|e| SshError::ConfigGetReadFailed(format!("{}: {e}", path.display())))?;
        self.bytes += text.len() as u64;
        if self.bytes > self.o.max_config_bytes {
            return Err(SshError::ConfigGetTooLarge(self.o.max_config_bytes));
        }
        self.files += 1;
        Ok(String::from_utf8_lossy(&text).into_owned())
    }

    /// Parses `path`; lines before its first Host/Match belong to `block`.
    fn parse_file(&mut self, path: &Path, origin: Origin, block: usize) -> Result<(), SshError> {
        let text = self.read(path)?;
        let file = path.display().to_string();
        let mut current = block;
        for (i, line) in text.lines().enumerate() {
            let Some((keyword, value)) = split_line(line) else {
                continue;
            };
            let lower = keyword.to_lowercase();
            if lower == "host" || lower == "match" {
                self.hosts += 1;
                if self.hosts > self.o.max_hosts {
                    return Err(SshError::ConfigGetTooManyHosts(self.o.max_hosts));
                }
                self.blocks.push(Block {
                    kind: if lower == "host" { "Host" } else { "Match" }.into(),
                    pattern: Some(value.clone()),
                    file: file.clone(),
                    line: i + 1,
                });
                current = self.blocks.len() - 1;
                continue;
            }
            if lower == "include" {
                if self.o.follow_includes {
                    for pattern in words(&value) {
                        self.include(&pattern, origin, current)?;
                    }
                }
                continue;
            }
            let b = &self.blocks[current];
            self.entries.push(Entry {
                raw: SshConfigRawEntry {
                    file: file.clone(),
                    line: i + 1,
                    block_type: b.kind.clone(),
                    block_pattern: b.pattern.clone(),
                    option: keyword,
                    value,
                },
                block: current,
            });
        }
        Ok(())
    }

    fn include(&mut self, pattern: &str, origin: Origin, block: usize) -> Result<(), SshError> {
        let expanded = self.expand(pattern);
        let full = if expanded.is_absolute() {
            expanded
        } else if origin == Origin::System {
            Path::new("/etc/ssh").join(expanded)
        } else {
            self.home.join(".ssh").join(expanded)
        };
        let mut matches: Vec<PathBuf> = match glob::glob(&full.to_string_lossy()) {
            Ok(paths) => paths.filter_map(|p| p.ok()).collect(),
            Err(_) => vec![full],
        };
        matches.sort();
        for path in matches.into_iter().filter(|p| p.is_file()) {
            self.includes += 1;
            if self.includes > self.o.max_includes {
                return Err(SshError::ConfigGetTooManyIncludes(self.o.max_includes));
            }
            self.parse_file(&path, origin, block)?;
        }
        Ok(())
    }
}

/// Whether a Match line applies; `None` when it uses a criterion resh
/// cannot evaluate (exec, localnetwork, tagged, ...).
fn match_applies(spec: &str, host: &str, user: &str, local_user: &str) -> Option<bool> {
    let w = words(spec);
    let mut i = 0;
    let mut result = true;
    while i < w.len() {
        let (neg, crit) = match w[i].strip_prefix('!') {
            Some(c) => (true, c.to_lowercase()),
            None => (false, w[i].to_lowercase()),
        };
        i += 1;
        let hit = match crit.as_str() {
            "all" => true,
            "final" => true,
            "canonical" => false,
            "host" | "originalhost" | "user" | "localuser" => {
                let arg = w.get(i)?;
                i += 1;
                let subject = match crit.as_str() {
                    "host" | "originalhost" => host,
                    "user" => user,
                    _ => local_user,
                };
                match_list(subject, arg.split(','))
            }
            _ => return None,
        };
        if hit == neg {
            result = false;
        }
    }
    Some(result)
}

#[derive(Debug)]
pub struct Resolved {
    pub effective: BTreeMap<String, SshConfigSetting>,
    pub raw: Vec<SshConfigRawEntry>,
    pub summary: SshConfigSummary,
    pub warnings: Vec<String>,
}

pub fn resolve(o: &ConfigGetOptions) -> Result<Resolved, SshError> {
    let home = o
        .user_home
        .clone()
        .or_else(|| std::env::var("HOME").ok())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut p = Parser {
        o,
        home,
        blocks: vec![Block {
            kind: "Global".into(),
            pattern: None,
            file: String::new(),
            line: 0,
        }],
        entries: vec![],
        files: 0,
        bytes: 0,
        includes: 0,
        hosts: 0,
    };
    // OpenSSH reads the user file first, then the system file; extra files
    // come last. The first value obtained for an option wins.
    let mut sources: Vec<(String, bool, Origin)> = vec![
        (
            o.user_config_path.clone(),
            o.user_config_given,
            Origin::User,
        ),
        (
            o.system_config_path.clone(),
            o.system_config_given,
            Origin::System,
        ),
    ];
    sources.extend(
        o.extra_config_paths
            .iter()
            .map(|e| (e.clone(), true, Origin::User)),
    );
    for (path, given, origin) in sources {
        let full = p.expand(&path);
        if !given && !full.exists() {
            continue;
        }
        // Each file starts in the global section.
        p.parse_file(&full, origin, 0)?;
    }

    let local_user = std::env::var("USER").unwrap_or_default();
    let mut warnings = Vec::new();
    let mut applies: Vec<Option<bool>> = Vec::with_capacity(p.blocks.len());
    let mut effective: BTreeMap<String, SshConfigSetting> = BTreeMap::new();
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    let mut matched: Vec<String> = Vec::new();
    for (i, b) in p.blocks.iter().enumerate() {
        let a = match b.kind.as_str() {
            "Global" => Some(true),
            "Host" => Some(match_list(
                &o.host,
                words(b.pattern.as_deref().unwrap_or(""))
                    .iter()
                    .map(String::as_str),
            )),
            _ => None, // Match: evaluated when reached, as User may change.
        };
        applies.push(a);
        let _ = i;
    }
    for e in &p.entries {
        let b = &p.blocks[e.block];
        let on = match applies[e.block] {
            Some(v) => v,
            None => {
                let user = o
                    .user
                    .clone()
                    .or_else(|| {
                        keys.get("user")
                            .and_then(|k| effective.get(k))
                            .map(|s| s.value.clone())
                    })
                    .unwrap_or_else(|| local_user.clone());
                let v = match_applies(
                    b.pattern.as_deref().unwrap_or(""),
                    &o.host,
                    &user,
                    &local_user,
                );
                if v.is_none() {
                    warnings.push(format!(
                        "Match {} ({}:{}) uses a criterion resh does not evaluate; its settings were skipped",
                        b.pattern.as_deref().unwrap_or(""),
                        b.file,
                        b.line
                    ));
                }
                applies[e.block] = Some(v.unwrap_or(false));
                v.unwrap_or(false)
            }
        };
        if !on {
            continue;
        }
        if b.kind != "Global" {
            let desc = format!(
                "{} {} ({}:{})",
                b.kind,
                b.pattern.as_deref().unwrap_or(""),
                b.file,
                b.line
            );
            if !matched.contains(&desc) {
                matched.push(desc);
            }
        }
        let lower = e.raw.option.to_lowercase();
        let origin = o.include_origin.then(|| SshConfigSettingOrigin {
            file: Some(e.raw.file.clone()),
            line: Some(e.raw.line),
            block: Some(match &b.pattern {
                Some(p) => format!("{} {}", b.kind, p),
                None => b.kind.clone(),
            }),
        });
        match keys.get(&lower) {
            None => {
                keys.insert(lower, e.raw.option.clone());
                effective.insert(
                    e.raw.option.clone(),
                    SshConfigSetting {
                        value: e.raw.value.clone(),
                        origin,
                    },
                );
            }
            Some(name) if MULTI_VALUED.contains(&lower.as_str()) => {
                if let Some(s) = effective.get_mut(name) {
                    s.value.push('\n');
                    s.value.push_str(&e.raw.value);
                }
            }
            Some(_) => {}
        }
    }
    let raw: Vec<SshConfigRawEntry> = p.entries.into_iter().map(|e| e.raw).collect();
    Ok(Resolved {
        summary: SshConfigSummary {
            total_files: p.files,
            total_entries: raw.len(),
            matched_blocks: matched,
            truncated: false,
        },
        effective,
        raw,
        warnings,
    })
}

fn sources_json(o: &ConfigGetOptions) -> serde_json::Value {
    serde_json::json!({
        "system_config_path": o.system_config_path,
        "user_config_path": o.user_config_path,
        "extra_config_paths": o.extra_config_paths,
        "follow_includes": o.follow_includes,
    })
}

pub fn run(target: &SshTarget, args: &Args, out: &Out, io: &mut IoStreams) -> Result<Status> {
    let r = ArgReader::new(args);
    let mut response = SshConfigGetResponse {
        ok: false,
        dry_run: out.dry_run,
        host: target.host.clone().unwrap_or_default(),
        sources: serde_json::json!({}),
        effective: None,
        raw_entries: None,
        summary: None,
        error: None,
        warnings: vec![],
    };
    let fail = |response: &mut SshConfigGetResponse, io: &mut IoStreams, e: SshError| {
        let status = coded(e.exit_code(), e.code(), &e.to_string());
        response.error = Some(e.to_json());
        write_response(io, out.format, response, format_text).map(|_| status)
    };
    let o = match check_known("config.get", args).and_then(|_| parse(&r, target)) {
        Ok(o) => o,
        Err(e) => return fail(&mut response, io, e),
    };
    response.host = o.host.clone();
    response.sources = sources_json(&o);
    if o.dry_run {
        response.ok = true;
        response
            .warnings
            .push("Dry run: config files were not read or parsed.".into());
        write_response(io, out.format, &response, format_text)?;
        return Ok(Status::ok());
    }
    match resolve(&o) {
        Ok(res) => {
            response.ok = true;
            response.effective = Some(res.effective);
            response.raw_entries = o.include_raw_entries.then_some(res.raw);
            response.summary = Some(res.summary);
            response.warnings = res.warnings;
            write_response(io, out.format, &response, format_text)?;
            Ok(Status::ok())
        }
        Err(e) => fail(&mut response, io, e),
    }
}

pub fn format_text(response: &SshConfigGetResponse) -> String {
    let mut output = String::new();
    output.push_str("SSH Config Get\n==============\n\n");
    output.push_str(&format!("Host   : {}\n", response.host));
    output.push_str(&format!("Dry Run: {}\n\n", response.dry_run));
    let s = |k: &str| {
        response
            .sources
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    if response.sources.is_object() && response.sources.get("user_config_path").is_some() {
        output.push_str("Sources:\n");
        output.push_str(&format!("  User  : {}\n", s("user_config_path")));
        output.push_str(&format!("  System: {}\n", s("system_config_path")));
        let extra: Vec<String> = response
            .sources
            .get("extra_config_paths")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if extra.is_empty() {
            output.push_str("  Extra : (none)\n");
        }
        for e in extra {
            output.push_str(&format!("  Extra : {e}\n"));
        }
        let follow = response
            .sources
            .get("follow_includes")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        output.push_str(&format!(
            "  Includes: {}\n\n",
            if follow { "followed" } else { "ignored" }
        ));
    }
    if let Some(effective) = &response.effective {
        output.push_str("Effective Settings:\n");
        if effective.is_empty() {
            output.push_str("  (none)\n");
        }
        for (key, setting) in effective {
            let origin = match &setting.origin {
                Some(SshConfigSettingOrigin {
                    file: Some(f),
                    line: Some(l),
                    block: Some(b),
                }) => format!(" (from {f}:{l}, {b})"),
                _ => String::new(),
            };
            for (i, value) in setting.value.split('\n').enumerate() {
                let name = if i == 0 { key.as_str() } else { "" };
                output.push_str(&format!(
                    "  {name:<20} = {value}{}\n",
                    if i == 0 { origin.as_str() } else { "" }
                ));
            }
        }
        output.push('\n');
    }
    if let Some(summary) = &response.summary {
        output.push_str("Matched Blocks:\n");
        if summary.matched_blocks.is_empty() {
            output.push_str("  (none)\n");
        }
        for block in &summary.matched_blocks {
            output.push_str(&format!("  - {block}\n"));
        }
        output.push('\n');
    }
    super::transfer::push_error_and_warnings(&mut output, &response.error, &response.warnings);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(dir: &Path, user_cfg: &str, system_cfg: &str) -> ConfigGetOptions {
        std::fs::write(dir.join("user"), user_cfg).unwrap();
        std::fs::write(dir.join("system"), system_cfg).unwrap();
        ConfigGetOptions {
            host: "web01".into(),
            user: None,
            user_home: Some(dir.display().to_string()),
            user_config_path: dir.join("user").display().to_string(),
            user_config_given: true,
            system_config_path: dir.join("system").display().to_string(),
            system_config_given: true,
            extra_config_paths: vec![],
            follow_includes: true,
            include_raw_entries: true,
            include_origin: true,
            max_config_bytes: DEFAULT_MAX_CONFIG_BYTES,
            max_includes: DEFAULT_MAX_INCLUDES,
            max_hosts: DEFAULT_MAX_HOSTS,
            dry_run: false,
        }
    }

    fn value(r: &Resolved, k: &str) -> Option<String> {
        r.effective.get(k).map(|s| s.value.clone())
    }

    #[test]
    fn first_obtained_value_wins_user_before_system() {
        let d = tempfile::tempdir().unwrap();
        let o = opts(
            d.path(),
            "Host web01\n  User alice\nHost *\n  User nobody\n  Port 2222\n",
            "Host *\n  Port 22\n  User root\n  ForwardAgent no\n",
        );
        let r = resolve(&o).unwrap();
        assert_eq!(value(&r, "User").as_deref(), Some("alice"));
        assert_eq!(value(&r, "Port").as_deref(), Some("2222"));
        assert_eq!(value(&r, "ForwardAgent").as_deref(), Some("no"));
        assert_eq!(r.summary.total_files, 2);
        assert_eq!(r.summary.matched_blocks.len(), 3);
    }

    #[test]
    fn negated_patterns_and_case_insensitive_keywords() {
        let d = tempfile::tempdir().unwrap();
        let o = opts(
            d.path(),
            "Host * !web01\n  User other\nhost=web0?\n  user=bob\nHOST \"web*\"\n  USER x\n  identityfile ~/a\n  IdentityFile ~/b\n",
            "",
        );
        let r = resolve(&o).unwrap();
        assert_eq!(value(&r, "user").as_deref(), Some("bob"));
        assert_eq!(value(&r, "identityfile").as_deref(), Some("~/a\n~/b"));
        assert!(!r.effective.contains_key("USER"));
    }

    #[test]
    fn match_blocks_and_includes() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join(".ssh")).unwrap();
        std::fs::write(
            d.path().join(".ssh/inc1"),
            "Compression yes\nHost web01\n  Port 7\n",
        )
        .unwrap();
        let o = opts(
            d.path(),
            "Match host web*,!db* user alice\n  HostName m.example\nMatch exec \"true\"\n  Port 1\nHost web01\n  Include inc*\n  LogLevel ERROR\n",
            "",
        );
        let mut o2 = o.clone();
        o2.user = Some("alice".into());
        let r = resolve(&o2).unwrap();
        assert_eq!(value(&r, "HostName").as_deref(), Some("m.example"));
        assert_eq!(value(&r, "Compression").as_deref(), Some("yes"));
        assert_eq!(value(&r, "Port").as_deref(), Some("7"));
        assert_eq!(value(&r, "LogLevel").as_deref(), Some("ERROR"));
        assert!(
            r.warnings.iter().any(|w| w.contains("exec")),
            "{:?}",
            r.warnings
        );
        let r = resolve(&o).unwrap();
        // Without a URL user, $USER decides `Match user`.
        if std::env::var("USER").ok().as_deref() != Some("alice") {
            assert_eq!(value(&r, "HostName"), None);
        }
        let mut o3 = o.clone();
        o3.follow_includes = false;
        assert_eq!(value(&resolve(&o3).unwrap(), "Compression"), None);
    }

    #[test]
    fn limits_and_missing_files() {
        let d = tempfile::tempdir().unwrap();
        let mut o = opts(d.path(), "Host a\nHost b\nHost c\n", "");
        o.max_hosts = 2;
        assert_eq!(resolve(&o).unwrap_err(), SshError::ConfigGetTooManyHosts(2));
        let mut o = opts(d.path(), "User x\n", "");
        o.max_config_bytes = 3;
        assert_eq!(resolve(&o).unwrap_err(), SshError::ConfigGetTooLarge(3));
        let mut o = opts(d.path(), "Include user\n", "");
        o.user_config_path = d.path().join("user").display().to_string();
        std::fs::write(
            d.path().join("user"),
            format!("Include {}\n", d.path().join("user").display()),
        )
        .unwrap();
        assert_eq!(
            resolve(&o).unwrap_err(),
            SshError::ConfigGetTooManyIncludes(64)
        );
        let mut o = opts(d.path(), "", "");
        o.extra_config_paths = vec![d.path().join("missing").display().to_string()];
        assert!(matches!(resolve(&o), Err(SshError::ConfigGetReadFailed(_))));
        let mut o = opts(d.path(), "", "");
        o.user_config_given = false;
        o.user_config_path = d.path().join("missing").display().to_string();
        assert!(resolve(&o).is_ok());
    }

    #[test]
    fn glob_rules() {
        assert!(glob_match("web01.example.com", "*.example.com"));
        assert!(glob_match("a", "?"));
        assert!(!glob_match("ab", "?"));
        assert!(glob_match("", "*"));
        assert!(!match_list("web01", ["*", "!web01"]));
        assert!(match_list("WEB01", ["web01"]));
        assert!(!match_list("x", ["!y"]));
        assert_eq!(match_applies("all", "h", "u", "l"), Some(true));
        assert_eq!(match_applies("!host h", "h", "u", "l"), Some(false));
        assert_eq!(
            match_applies("localnetwork 10.0.0.0/8", "h", "u", "l"),
            None
        );
        assert_eq!(match_applies("host", "h", "u", "l"), None);
    }
}
