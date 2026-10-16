//! Every registered handle must provide help metadata for every verb it
//! registers, and the rendered help must follow the approved format.
//!
//! Set HELP_COVERAGE_ONLY=svc,proc to check a subset of handles.

use resh::core::help::{self, HELP_ALIASES, HelpRequest};
use resh::core::parse::parse_stage;
use resh::{Registry, handles};

fn registry() -> Registry {
    let mut reg = Registry::default();
    handles::register_all(&mut reg);
    reg
}

/// Minimal POSIX-shell word splitting: whitespace, single and double quotes,
/// backslash escapes outside single quotes.
fn shell_words(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Err("unterminated single quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => cur.push(chars.next().ok_or("dangling backslash")?),
                        Some(c) => cur.push(c),
                        None => return Err("unterminated double quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.push(chars.next().ok_or("dangling backslash")?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '(' | ')' | ';' | '&' | '|' | '<' | '>' | '`' | '$' | '*' | '?' => {
                return Err(format!("unquoted shell metacharacter {c:?}"));
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// Checks that `example` is `resh [--global-flags] <stage> [key=value ...]`
/// and that the stage parses to `handle` and `verb`.
fn check_example(handle: &str, verb: &str, example: &str) -> Result<(), String> {
    if example.contains('\n') {
        return Err("example must be a single line".into());
    }
    let words = shell_words(example)?;
    let mut it = words.iter().map(String::as_str);
    if it.next() != Some("resh") {
        return Err("example must start with `resh`".into());
    }
    let rest: Vec<&str> = it.skip_while(|w| *w == "--json-pretty").collect();
    let (stage, args) = rest.split_first().ok_or("example has no stage")?;
    if let Some(bad) = args.iter().find(|a| !a.contains('=')) {
        return Err(format!("trailing argument {bad:?} is not key=value"));
    }
    // mail:// stages are rewritten by main.rs before parsing; accept either
    // the function-call form or trailing key=value arguments.
    let parsed = parse_stage(stage).map_err(|e| format!("stage does not parse: {e}"))?;
    if !parsed.target.starts_with(&format!("{handle}://")) {
        return Err(format!("stage target {:?} is not a {handle}:// URL", parsed.target));
    }
    let ok_verb = parsed.verb == verb
        // plugin:// encodes the verb in the host; parse_stage reports it
        // as the URL host.
        || (handle == "plugin" && parsed.target.starts_with(&format!("plugin://{verb}")));
    if !ok_verb {
        return Err(format!("stage parses to verb {:?}, expected {verb:?}", parsed.verb));
    }
    Ok(())
}

fn check_text(out: &str) -> Result<(), String> {
    if !out.is_ascii() {
        return Err("non-ASCII output".into());
    }
    if let Some(l) = out.lines().find(|l| l.len() > 80) {
        return Err(format!("line over 80 columns: {l:?}"));
    }
    if out.lines().any(|l| l.ends_with(' ')) {
        return Err("trailing whitespace".into());
    }
    Ok(())
}

/// Registered verbs the stage parser cannot reach. Their help must say so
/// and point to the alternative with `resh <handle> <verb> --help`. If the
/// parser starts reaching one, this test fails so the entry is revisited.
const UNREACHABLE: &[(&str, &str, &str)] = &[("cert", "csr.sign", "resh cert sign --help")];

fn sentences(s: &str) -> usize {
    s.split(". ").count()
}

#[test]
fn every_handle_and_verb_has_help() {
    let only: Option<Vec<String>> = std::env::var("HELP_COVERAGE_ONLY")
        .ok()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let reg = registry();
    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0;

    for scheme in reg.list_schemes() {
        if only.as_ref().is_some_and(|o| !o.contains(&scheme)) {
            continue;
        }
        let mut fail = |msg: String| problems.push(format!("{scheme}: {msg}"));

        let h = match reg.instantiate(&scheme).unwrap() {
            Ok(h) => h,
            Err(e) => {
                fail(format!("cannot instantiate from probe URL: {e}"));
                continue;
            }
        };
        let Some(meta) = h.help() else {
            fail("Handle::help() returns None".into());
            continue;
        };
        let ops: Vec<&str> =
            h.verbs().iter().copied().filter(|v| !HELP_ALIASES.contains(v)).collect();

        let n = sentences(meta.description);
        if !(2..=3).contains(&n) || !meta.description.ends_with('.') {
            fail(format!("description should be 2-3 sentences, found {n}"));
        }
        if !meta.usage.starts_with(&format!("resh {scheme}://")) {
            fail(format!("handle usage must start with `resh {scheme}://`"));
        }

        let mut seen = std::collections::HashSet::new();
        for v in meta.verbs {
            if !seen.insert(v.name) {
                fail(format!("verb {:?} documented twice", v.name));
            }
            if !ops.contains(&v.name) {
                fail(format!("verb {:?} documented but not registered", v.name));
            }
        }

        let handle_out = help::render(&reg, &HelpRequest::Handle(&scheme));
        match &handle_out {
            None => fail("handle help did not render".into()),
            Some(out) => {
                if let Err(e) = check_text(out) {
                    fail(format!("handle help: {e}"));
                }
            }
        }

        for verb in &ops {
            checked += 1;
            let mut fail = |msg: String| problems.push(format!("{scheme} {verb}: {msg}"));
            let Some(v) = meta.verbs.iter().find(|v| v.name == *verb) else {
                fail("registered verb has no VerbHelp".into());
                continue;
            };
            if sentences(v.definition) != 1 || !v.definition.ends_with('.') {
                fail("definition must be one sentence ending in a period".into());
            }
            let Some(d) = &v.detail else {
                fail("VerbHelp.detail is None".into());
                continue;
            };
            let first_usage = d.usage.lines().next().unwrap_or("");
            if !first_usage.starts_with(&format!("resh {scheme}://")) || !first_usage.contains(verb) {
                fail(format!("usage must start with `resh {scheme}://` and name the verb"));
            }
            if d.usage.lines().skip(1).any(|l| !l.starts_with("  ")) {
                fail("usage continuation lines must start with two spaces".into());
            }
            if let Some((_, _, pointer)) =
                UNREACHABLE.iter().find(|(h, v, _)| *h == scheme && v == verb)
            {
                if d.example != *pointer {
                    fail(format!("unreachable verb's example must be {pointer:?}"));
                }
                let stage = format!("{scheme}://x.{verb}");
                if parse_stage(&stage).map(|p| p.verb == *verb).unwrap_or(false) {
                    fail("verb is now reachable; remove it from UNREACHABLE".into());
                }
            } else if let Err(e) = check_example(&scheme, verb, d.example) {
                fail(format!("example {:?}: {e}", d.example));
            }
            if let Some(sample) = d.example_output {
                if sample.trim().is_empty() {
                    fail("example_output is empty; use None".into());
                }
            }
            match help::render(&reg, &HelpRequest::Verb(&scheme, verb)) {
                None => fail("verb help did not render".into()),
                Some(out) => {
                    if let Err(e) = check_text(&out) {
                        fail(format!("verb help: {e}"));
                    }
                }
            }
        }
    }

    assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
    assert!(checked > 0, "no verbs checked");
}

#[test]
fn shell_words_rejects_unquoted_parens() {
    assert!(shell_words("resh svc://a.stop(timeout=1)").is_err());
    assert_eq!(
        shell_words(r#"resh 'svc://a.stop(timeout=1)' x="a b""#).unwrap(),
        ["resh", "svc://a.stop(timeout=1)", "x=a b"]
    );
}
