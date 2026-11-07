//! Contextual command-line help for resource handles.
//!
//! Supports two request forms, recognized before normal stage dispatch:
//!
//!   resh <handle> --help
//!   resh <handle> <verb> --help
//!
//! The set of verbs a handle supports is always taken from the handle's
//! registered `Handle::verbs()`; the metadata here only adds descriptive
//! text. A handle opts in by returning `Some(&HandleHelp)` from
//! `Handle::help()`. Requests that cannot be answered from metadata return
//! `None` so the caller can fall back to its existing behavior.

use super::registry::Registry;

/// Maximum rendered line width.
const WIDTH: usize = 80;
/// Indentation for section bodies.
const INDENT: &str = "  ";

/// Verb names that handles register as help aliases rather than operations.
pub const HELP_ALIASES: &[&str] = &["help", "--help", "-h", "h"];

/// Descriptive metadata for one resource handle.
pub struct HandleHelp {
    /// Short paragraph (two or three sentences) describing the handle.
    pub description: &'static str,
    /// General command syntax for the handle.
    pub usage: &'static str,
    /// Per-verb metadata. Display order follows this slice; only verbs the
    /// handle actually registers are shown.
    pub verbs: &'static [VerbHelp],
}

/// Descriptive metadata for one verb.
pub struct VerbHelp {
    pub name: &'static str,
    /// One-sentence explanation of what the verb does.
    pub definition: &'static str,
    /// Usage and example. Verb-level help is available only when present.
    pub detail: Option<VerbDetail>,
}

pub struct VerbDetail {
    /// Command syntax. Continuation lines, if any, start with two spaces.
    pub usage: &'static str,
    /// One valid, shell-safe example command.
    pub example: &'static str,
    /// Sample output of `example`, rendered verbatim with section indentation.
    pub example_output: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HelpRequest<'a> {
    Handle(&'a str),
    Verb(&'a str, &'a str),
}

/// Command-line words that request help: `--help`, `-h` and `help`.
const HELP_WORDS: &[&str] = &["--help", "-h", "help"];

/// Recognizes the help request forms (arguments after the program name):
///
///   <handle> --help | -h | help
///   <handle> <verb> --help | -h | help
///   help <handle> [<verb>]
///
/// Anything else, including stage URLs such as `svc://nginx.status`, is not a
/// handle help request.
pub fn parse_help_request(args: &[String]) -> Option<HelpRequest<'_>> {
    let is_word = |s: &str| {
        !s.is_empty() && !s.starts_with('-') && !s.contains("://") && !HELP_WORDS.contains(&s)
    };
    let is_help = |s: &str| HELP_WORDS.contains(&s);
    match args {
        [first, handle] if first == "help" && is_word(handle) => Some(HelpRequest::Handle(handle)),
        [first, handle, verb] if first == "help" && is_word(handle) && is_word(verb) => {
            Some(HelpRequest::Verb(handle, verb))
        }
        [handle, flag] if is_help(flag) && is_word(handle) => Some(HelpRequest::Handle(handle)),
        // Help about help (`svc help --help`) is the handle's help.
        [handle, h1, h2] if is_help(h1) && is_help(h2) && is_word(handle) => {
            Some(HelpRequest::Handle(handle))
        }
        [handle, verb, flag] if is_help(flag) && is_word(handle) && is_word(verb) => {
            Some(HelpRequest::Verb(handle, verb))
        }
        _ => None,
    }
}

/// Why a help request could not be answered.
#[derive(Debug, PartialEq, Eq)]
pub enum HelpError {
    /// No handle is registered under this name.
    UnknownHandle {
        name: String,
        suggestion: Option<String>,
    },
    /// The handle exists but does not register this verb.
    UnknownVerb {
        handle: String,
        verb: String,
        verbs: Vec<String>,
        suggestion: Option<String>,
    },
    /// The handle or verb exists but has no help metadata.
    NoHelp { what: String },
}

impl HelpError {
    /// The error code for this failure (see `status::error_line`).
    pub fn code(&self) -> String {
        match self {
            HelpError::UnknownHandle { .. } => "resh.unknown_handle".to_string(),
            HelpError::UnknownVerb { handle, .. } => format!("{handle}.unknown_verb"),
            HelpError::NoHelp { .. } => "resh.no_help".to_string(),
        }
    }
}

impl std::fmt::Display for HelpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelpError::UnknownHandle { name, suggestion } => {
                write!(f, "unknown handle '{name}'.")?;
                if let Some(s) = suggestion {
                    write!(f, "\nDid you mean '{s}'?")?;
                }
                write!(
                    f,
                    "\nRun `resh --list-schemas` to list the available handles."
                )
            }
            HelpError::UnknownVerb {
                handle,
                verb,
                verbs,
                suggestion,
            } => {
                write!(f, "unknown verb '{verb}' for handle '{handle}'.")?;
                if let Some(s) = suggestion {
                    write!(f, "\nDid you mean '{s}'?")?;
                }
                // "Error: " is prepended by the caller; wrap so no line
                // exceeds the help width.
                let list = wrap(&verbs.join(", "), "Available verbs: ", INDENT);
                write!(f, "\n{}", list.trim_end())?;
                write!(f, "\nRun `resh {handle} --help` for details.")
            }
            HelpError::NoHelp { what } => write!(f, "no help is available for {what}."),
        }
    }
}

/// Renders help for `req`. Fails if the handle is unknown, the verb is not
/// registered, or there is no help metadata for it.
///
/// Only constructs the handle to read its metadata; never calls it.
pub fn render(reg: &Registry, req: &HelpRequest) -> Result<String, HelpError> {
    let handle_name = match req {
        HelpRequest::Handle(h) | HelpRequest::Verb(h, _) => *h,
    };
    let unknown_handle = || HelpError::UnknownHandle {
        name: handle_name.to_string(),
        suggestion: closest(handle_name, reg.list_schemes().iter().map(|s| s.as_ref())),
    };
    let handle = match reg.instantiate(handle_name) {
        Some(Ok(h)) => h,
        _ => return Err(unknown_handle()),
    };
    let no_help = |what: String| HelpError::NoHelp { what };
    let help = handle
        .help()
        .ok_or_else(|| no_help(format!("handle '{handle_name}'")))?;
    let registered = handle.verbs();

    match req {
        HelpRequest::Handle(_) => Ok(render_handle(handle_name, help, registered)),
        HelpRequest::Verb(_, verb) => {
            if !registered.contains(verb) || HELP_ALIASES.contains(verb) {
                let verbs: Vec<String> = listed_verbs(help, registered)
                    .iter()
                    .map(|v| v.name.to_string())
                    .collect();
                return Err(HelpError::UnknownVerb {
                    handle: handle_name.to_string(),
                    verb: verb.to_string(),
                    suggestion: closest(verb, verbs.iter().map(String::as_str)),
                    verbs,
                });
            }
            let what = || format!("verb '{verb}' of handle '{handle_name}'");
            let verb_help = help
                .verbs
                .iter()
                .find(|v| v.name == *verb)
                .ok_or_else(|| no_help(what()))?;
            render_verb(handle_name, verb_help).ok_or_else(|| no_help(what()))
        }
    }
}

/// The candidate that `input` is an unambiguous prefix of, or else the
/// candidate closest to it by edit distance when that is close enough to be
/// a likely typo (at most 2, or a third of the length for longer names).
fn closest<'a>(input: &str, candidates: impl Iterator<Item = &'a str>) -> Option<String> {
    let input_lc = input.to_lowercase();
    let mut best: Option<(usize, &str)> = None;
    let mut prefix_matches = Vec::new();
    for c in candidates {
        if c.starts_with(&input_lc) {
            prefix_matches.push(c);
        }
        let d = edit_distance(&input_lc, c);
        if best.is_none_or(|(bd, _)| d < bd) {
            best = Some((d, c));
        }
    }
    // An unambiguous prefix is the strongest hint (`fire` -> `firewall`).
    if prefix_matches.len() == 1 && input.chars().count() >= 2 {
        return Some(prefix_matches[0].to_string());
    }
    let limit = (input.chars().count() / 3).max(2);
    match best {
        Some((d, c)) if d <= limit && d < input.chars().count() => Some(c.to_string()),
        _ => None,
    }
}

/// Levenshtein distance between two strings (by `char`).
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Renders help for a handle's own in-URL help forms (for example
/// `svc://--help` or `fs://.help(verb=mount)`), so they show the same text as
/// `resh <handle> [<verb>] --help`. Falls back to handle-level help when
/// `verb` is absent, unknown, or has no verb-level detail.
pub fn render_legacy(
    handle: &str,
    help: &HandleHelp,
    registered: &[&str],
    verb: Option<&str>,
) -> String {
    verb.filter(|v| registered.contains(v))
        .and_then(|v| help.verbs.iter().find(|h| h.name == v))
        .and_then(|v| render_verb(handle, v))
        .unwrap_or_else(|| render_handle(handle, help, registered))
}

/// True if `s` is exactly a help flag (`--help` or `-h`), ignoring leading
/// slashes and dots from URL paths and hosts. Unlike a substring check, this
/// does not match targets such as `/home/x/my-hosts`.
pub fn is_help_flag(s: &str) -> bool {
    matches!(s.trim_start_matches(['/', '.']), "--help" | "-h")
}

/// Verbs that are registered and documented, in metadata order.
fn listed_verbs<'a>(help: &'a HandleHelp, registered: &[&str]) -> Vec<&'a VerbHelp> {
    help.verbs
        .iter()
        .filter(|v| registered.contains(&v.name) && !HELP_ALIASES.contains(&v.name))
        .collect()
}

pub fn render_handle(handle: &str, help: &HandleHelp, registered: &[&str]) -> String {
    let verbs = listed_verbs(help, registered);
    let col = verbs.iter().map(|v| v.name.len()).max().unwrap_or(0) + 3;

    let mut out = String::new();
    out.push_str(&format!("Handle: {handle}\n\n"));

    out.push_str("Description:\n");
    out.push_str(&wrap(help.description, INDENT, INDENT));
    out.push('\n');

    out.push_str("Available Verbs:\n");
    let hang = " ".repeat(INDENT.len() + col);
    for v in &verbs {
        let first = format!("{INDENT}{:<col$}", v.name);
        out.push_str(&wrap(v.definition, &first, &hang));
    }
    out.push('\n');

    out.push_str("Usage:\n");
    out.push_str(&format!("{INDENT}{}\n\n", help.usage));

    out.push_str("For help with a specific verb:\n");
    out.push_str(&format!("{INDENT}resh {handle} <verb> --help\n"));
    out
}

pub fn render_verb(handle: &str, verb: &VerbHelp) -> Option<String> {
    let detail = verb.detail.as_ref()?;
    let mut out = String::new();
    out.push_str(&format!("Handle: {handle}\n"));
    out.push_str(&format!("Verb: {}\n", verb.name));
    out.push_str(&wrap(verb.definition, "Definition: ", INDENT));
    out.push('\n');
    out.push_str("Usage:\n");
    out.push_str(&indent_block(detail.usage));
    out.push_str("\nExample:\n");
    out.push_str(&indent_block(detail.example));
    if let Some(sample) = detail.example_output {
        out.push_str("\nExample Output:\n");
        out.push_str(&indent_block(sample));
    }
    Some(out)
}

/// Indents each non-empty line of `text` by `INDENT`, preserving blank lines.
fn indent_block(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if !line.is_empty() {
            out.push_str(INDENT);
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Greedy word wrap to `WIDTH`. `first` prefixes the first line and `rest`
/// prefixes continuation lines. Each line ends with a newline.
fn wrap(text: &str, first: &str, rest: &str) -> String {
    let mut out = String::new();
    let mut line = first.to_string();
    let mut prefix_len = first.len();
    for word in text.split_whitespace() {
        let has_word = line.len() > prefix_len;
        if has_word && line.len() + 1 + word.len() > WIDTH {
            out.push_str(&line);
            out.push('\n');
            line = rest.to_string();
            prefix_len = rest.len();
        } else if has_word {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push_str(&line);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_handle_and_verb_requests() {
        assert_eq!(
            parse_help_request(&args(&["svc", "--help"])),
            Some(HelpRequest::Handle("svc"))
        );
        assert_eq!(
            parse_help_request(&args(&["svc", "status", "--help"])),
            Some(HelpRequest::Verb("svc", "status"))
        );
    }

    #[test]
    fn parses_every_help_spelling() {
        for flag in ["--help", "-h", "help"] {
            assert_eq!(
                parse_help_request(&args(&["svc", flag])),
                Some(HelpRequest::Handle("svc")),
                "{flag}"
            );
            assert_eq!(
                parse_help_request(&args(&["svc", "status", flag])),
                Some(HelpRequest::Verb("svc", "status")),
                "{flag}"
            );
        }
        assert_eq!(
            parse_help_request(&args(&["help", "svc"])),
            Some(HelpRequest::Handle("svc"))
        );
        assert_eq!(
            parse_help_request(&args(&["help", "svc", "status"])),
            Some(HelpRequest::Verb("svc", "status"))
        );
    }

    #[test]
    fn closest_suggests_likely_typos_only() {
        let names = ["file", "fs", "firewall", "proc", "cert"];
        let c = |s: &str| closest(s, names.iter().copied());
        assert_eq!(c("fiel").as_deref(), Some("file"));
        assert_eq!(c("firewal").as_deref(), Some("firewall"));
        assert_eq!(c("prc").as_deref(), Some("proc"));
        assert_eq!(c("fire").as_deref(), Some("firewall"));
        assert_eq!(c("zzzzzz"), None);
        assert_eq!(c("x"), None);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn ignores_non_help_invocations() {
        assert_eq!(parse_help_request(&args(&["--help"])), None);
        assert_eq!(parse_help_request(&args(&["svc"])), None);
        assert_eq!(parse_help_request(&args(&["svc://nginx.status"])), None);
        assert_eq!(
            parse_help_request(&args(&["svc://nginx.status", "--help"])),
            None
        );
        assert_eq!(parse_help_request(&args(&["help"])), None);
        assert_eq!(parse_help_request(&args(&["svc", "h"])), None);
        assert_eq!(parse_help_request(&args(&["help", "--help"])), None);
        assert_eq!(
            parse_help_request(&args(&["svc", "help", "help"])),
            Some(HelpRequest::Handle("svc"))
        );
        assert_eq!(
            parse_help_request(&args(&["help", "svc", "status", "x"])),
            None
        );
        assert_eq!(
            parse_help_request(&args(&["--json-pretty", "--help"])),
            None
        );
        assert_eq!(
            parse_help_request(&args(&["svc", "status", "x", "--help"])),
            None
        );
    }

    #[test]
    fn wrap_respects_width_and_indents() {
        let text = "word ".repeat(40);
        let out = wrap(&text, "Definition: ", INDENT);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("Definition: "));
        for l in &lines[1..] {
            assert!(l.starts_with(INDENT));
        }
        assert!(lines.iter().all(|l| l.len() <= WIDTH));
    }

    const TEST_HELP: HandleHelp = HandleHelp {
        description: "Test handle.",
        usage: "resh t://<x>.<verb>",
        verbs: &[
            VerbHelp {
                name: "a",
                definition: "Does a.",
                detail: None,
            },
            VerbHelp {
                name: "ghost",
                definition: "Not registered.",
                detail: None,
            },
            VerbHelp {
                name: "help",
                definition: "Alias.",
                detail: None,
            },
        ],
    };

    #[test]
    fn handle_lists_only_registered_non_alias_verbs() {
        let out = render_handle("t", &TEST_HELP, &["a", "help", "--help"]);
        assert!(out.contains("  a   Does a.\n"));
        assert!(!out.contains("ghost"));
        assert!(!out.contains("Alias."));
    }

    #[test]
    fn help_flag_is_exact() {
        for s in ["--help", "-h", "/--help", "/-h", ".--help", "//-h"] {
            assert!(is_help_flag(s), "{s}");
        }
        for s in [
            "/home/x/my-hosts",
            "my-httpd",
            "pre-hotfix",
            "-help",
            "--helper",
            "",
        ] {
            assert!(!is_help_flag(s), "{s}");
        }
    }

    #[test]
    fn legacy_falls_back_to_handle_help() {
        let handle = render_handle("t", &TEST_HELP, &["a"]);
        assert_eq!(render_legacy("t", &TEST_HELP, &["a"], None), handle);
        assert_eq!(render_legacy("t", &TEST_HELP, &["a"], Some("a")), handle);
        assert_eq!(render_legacy("t", &TEST_HELP, &["a"], Some("zzz")), handle);
    }

    #[test]
    fn verb_without_detail_has_no_verb_help() {
        assert!(render_verb("t", &TEST_HELP.verbs[0]).is_none());
    }

    struct PanicOnCall;

    impl crate::core::Handle for PanicOnCall {
        fn verbs(&self) -> &'static [&'static str] {
            &["a"]
        }
        fn call(
            &self,
            _: &str,
            _: &crate::core::Args,
            _: &mut crate::core::IoStreams,
        ) -> anyhow::Result<crate::core::Status> {
            panic!("help must not execute the handle");
        }
        fn help(&self) -> Option<&'static HandleHelp> {
            Some(&TEST_HELP)
        }
    }

    #[test]
    fn render_never_calls_handle() {
        let mut reg = Registry::default();
        reg.register_scheme("t", |_| Ok(Box::new(PanicOnCall)));
        assert!(render(&reg, &HelpRequest::Handle("t")).is_ok());
        assert_eq!(
            render(&reg, &HelpRequest::Verb("t", "a")),
            Err(HelpError::NoHelp {
                what: "verb 'a' of handle 't'".into()
            })
        );
        assert!(matches!(
            render(&reg, &HelpRequest::Verb("t", "ghost")),
            Err(HelpError::UnknownVerb { .. })
        ));
        assert!(matches!(
            render(&reg, &HelpRequest::Handle("missing")),
            Err(HelpError::UnknownHandle { .. })
        ));
    }

    #[test]
    fn unknown_names_explain_and_suggest() {
        let mut reg = Registry::default();
        reg.register_scheme("t", |_| Ok(Box::new(PanicOnCall)));
        let msg = render(&reg, &HelpRequest::Verb("t", "aa"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("unknown verb 'aa' for handle 't'"), "{msg}");
        assert!(msg.contains("Did you mean 'a'?"), "{msg}");
        assert!(msg.contains("Available verbs: a"), "{msg}");
        // Help aliases are not verbs, even when a handle registers them.
        assert!(matches!(
            render(&reg, &HelpRequest::Verb("t", "help")),
            Err(HelpError::UnknownVerb { .. }) | Err(HelpError::NoHelp { .. })
        ));
        let msg = render(&reg, &HelpRequest::Handle("tt"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("unknown handle 'tt'"), "{msg}");
        assert!(msg.contains("Did you mean 't'?"), "{msg}");
        assert!(msg.contains("resh --list-schemas"), "{msg}");
    }
}
