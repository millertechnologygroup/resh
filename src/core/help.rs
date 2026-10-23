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

/// Recognizes `<handle> --help` and `<handle> <verb> --help` (arguments
/// after the program name). Anything else, including stage URLs such as
/// `svc://nginx.status`, is not a handle help request.
pub fn parse_help_request(args: &[String]) -> Option<HelpRequest<'_>> {
    let is_word = |s: &str| !s.is_empty() && !s.starts_with('-') && !s.contains("://");
    match args {
        [handle, flag] if flag == "--help" && is_word(handle) => Some(HelpRequest::Handle(handle)),
        [handle, verb, flag] if flag == "--help" && is_word(handle) && is_word(verb) => {
            Some(HelpRequest::Verb(handle, verb))
        }
        _ => None,
    }
}

/// Renders help for `req`, or returns `None` if the handle is unknown, has
/// no help metadata, or the verb is not registered or not documented.
///
/// Only constructs the handle to read its metadata; never calls it.
pub fn render(reg: &Registry, req: &HelpRequest) -> Option<String> {
    let handle_name = match req {
        HelpRequest::Handle(h) | HelpRequest::Verb(h, _) => *h,
    };
    let handle = reg.instantiate(handle_name)?.ok()?;
    let help = handle.help()?;
    let registered = handle.verbs();

    match req {
        HelpRequest::Handle(_) => Some(render_handle(handle_name, help, registered)),
        HelpRequest::Verb(_, verb) => {
            if !registered.contains(verb) {
                return None;
            }
            let verb_help = help.verbs.iter().find(|v| v.name == *verb)?;
            render_verb(handle_name, verb_help)
        }
    }
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
    fn ignores_non_help_invocations() {
        assert_eq!(parse_help_request(&args(&["--help"])), None);
        assert_eq!(parse_help_request(&args(&["svc"])), None);
        assert_eq!(parse_help_request(&args(&["svc://nginx.status"])), None);
        assert_eq!(
            parse_help_request(&args(&["svc://nginx.status", "--help"])),
            None
        );
        assert_eq!(parse_help_request(&args(&["svc", "-h"])), None);
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
        assert!(render(&reg, &HelpRequest::Handle("t")).is_some());
        assert!(render(&reg, &HelpRequest::Verb("t", "a")).is_none());
        assert!(render(&reg, &HelpRequest::Verb("t", "ghost")).is_none());
        assert!(render(&reg, &HelpRequest::Handle("missing")).is_none());
    }
}
