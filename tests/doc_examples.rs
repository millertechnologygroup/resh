//! Every `resh` command shown in a shell code block of the Markdown
//! documentation must parse to a registered handle and verb.
//!
//! Examples are only parsed, never executed: the stage goes through the real
//! stage parser and the handle is instantiated from its help probe URL to
//! read its registered verbs. No network, filesystem or system command is
//! touched.
//!
//! Checked: fenced blocks tagged `bash`, `sh`, `shell`, `console` or untagged,
//! in `README.md`, `CONTRIBUTING.md` and `docs/**/*.md` (except
//! `docs/reviews/`). A line is an example when it starts with `resh ` (after
//! an optional `$ ` prompt). Backslash continuations are joined. The command
//! ends at an unquoted `|`, `>`, `<`, `;`, `&&`, `||` or `#` comment.
//!
//! Lines that use shell substitution (`$VAR`, `$(...)`, backticks) or globs
//! cannot be checked statically; they are counted and listed with
//! `DOC_EXAMPLES_VERBOSE=1` for manual review.

use resh::core::help::{self, HELP_ALIASES};
use resh::core::parse::{is_bare_dry_run, parse_stage};
use resh::{Registry, handles};
use std::path::{Path, PathBuf};

fn registry() -> Registry {
    let mut reg = Registry::default();
    handles::register_all(&mut reg);
    reg
}

enum Words {
    Ok(Vec<String>),
    /// Uses shell expansion; cannot be checked without a shell.
    Dynamic(&'static str),
    Err(String),
}

/// POSIX-style word splitting of one command, stopping at the first unquoted
/// pipeline, redirection, list operator or comment.
fn shell_words(s: &str) -> Words {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => cur.push(c),
                        None => return Words::Err("unterminated single quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c) => cur.push(c),
                            None => return Words::Err("dangling backslash".into()),
                        },
                        Some('$') | Some('`') => return Words::Dynamic("expansion inside quotes"),
                        Some(c) => cur.push(c),
                        None => return Words::Err("unterminated double quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(c) => cur.push(c),
                    None => return Words::Err("dangling backslash".into()),
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '#' if !in_word => break,
            '|' | ';' | '>' | '<' => break,
            '&' if chars.peek() == Some(&'&') => break,
            '2' if !in_word && chars.peek() == Some(&'>') => break,
            '$' | '`' => return Words::Dynamic("shell expansion"),
            '*' | '?' => return Words::Dynamic("glob"),
            '(' | ')' | '&' => {
                return Words::Err(format!("unquoted shell metacharacter {c:?}"));
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
    Words::Ok(words)
}

/// Words of an extracted example. A bare stage written in the function-call
/// form (`git://x.sync(\n  path=/r,\n  ...)`) is stage syntax, not shell
/// syntax: the text through the matching `)` is the stage, and only what
/// follows it is split into shell words.
fn example_words(cmd: &str) -> Words {
    let Some(stage) = cmd.strip_prefix(BARE) else {
        return shell_words(cmd);
    };
    let (head, tail) = match stage.find('(') {
        Some(open) if stage[..open].chars().all(|c| !c.is_whitespace()) => {
            let mut depth = 0;
            let mut end = None;
            for (i, c) in stage.char_indices().skip(open) {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            match end {
                Some(e) => (stage[..e].to_string(), &stage[e..]),
                None => return Words::Err("unclosed `(` in stage".into()),
            }
        }
        _ => {
            return shell_words(&format!("resh {stage}"));
        }
    };
    match shell_words(tail) {
        Words::Ok(rest) => {
            let mut w = vec!["resh".to_string(), head];
            w.extend(rest);
            Words::Ok(w)
        }
        other => other,
    }
}

const GLOBAL_FLAGS: &[&str] = &["--json-pretty"];
const STANDALONE: &[&str] = &["--list-schemas", "--help", "-h", "--version", "-V"];

/// Message-field keys that make main.rs treat `mail://...` as `send`.
const MAIL_MESSAGE_KEYS: &[&str] = &[
    "to",
    "subject",
    "text_body",
    "html_body",
    "from",
    "cc",
    "bcc",
];

fn check_command(reg: &Registry, words: &[String]) -> Result<(), String> {
    let mut it = words.iter().map(String::as_str).peekable();
    if it.next() != Some("resh") {
        return Err("does not start with `resh`".into());
    }
    // clap accepts the global flags anywhere on the command line.
    let rest: Vec<&str> = it.filter(|w| !GLOBAL_FLAGS.contains(w)).collect();
    let Some((first, args)) = rest.split_first() else {
        return Err("no stage".into());
    };
    if STANDALONE.contains(first) && args.is_empty() {
        return Ok(());
    }

    // `resh <handle> --help` and `resh <handle> <verb> --help`.
    let owned: Vec<String> = rest.iter().map(|s| s.to_string()).collect();
    if let Some(req) = help::parse_help_request(&owned) {
        return match help::render(reg, &req) {
            Some(_) => Ok(()),
            None => Err("help request names an unknown handle or verb".into()),
        };
    }
    if !first.contains("://") {
        return Err(format!("{first:?} is not a stage URL or help request"));
    }

    if let Some(bad) = args
        .iter()
        .find(|a| !a.contains('=') && !is_bare_dry_run(a))
    {
        return Err(format!("argument {bad:?} is not key=value"));
    }

    let scheme = first.split("://").next().unwrap_or("");
    let Some(handle) = reg.instantiate(scheme) else {
        return Err(format!("unknown scheme {scheme:?}"));
    };
    let handle = handle.map_err(|e| format!("cannot instantiate {scheme}: {e}"))?;
    let verbs = handle.verbs();

    let parsed = match parse_stage(first) {
        Ok(p) => p,
        Err(e) => return Err(format!("stage does not parse: {e}")),
    };

    // In-URL help (`svc://--help`, `svc://x.--help=start`).
    if HELP_ALIASES.contains(&parsed.verb.as_str()) || parsed.verb.starts_with("--help") {
        return Ok(());
    }

    let verb = parsed.verb.as_str();
    if verbs.contains(&verb) {
        return Ok(());
    }
    // plugin:// encodes some verbs in the host (plugin://available.list).
    if scheme == "plugin" {
        let host = parsed.target.trim_start_matches("plugin://");
        let host = host.split('/').next().unwrap_or(host);
        if verbs.contains(&host) || verbs.contains(&verb) {
            return Ok(());
        }
    }
    // main.rs turns `mail://<profile> to=...` into a send.
    if scheme == "mail"
        && args.iter().any(|a| {
            a.split_once('=')
                .is_some_and(|(k, _)| MAIL_MESSAGE_KEYS.contains(&k))
        })
    {
        return Ok(());
    }
    Err(format!(
        "stage parses to verb {verb:?}, which {scheme} does not register"
    ))
}

fn markdown_files(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.join("README.md"), root.join("CONTRIBUTING.md")];
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "reviews") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Prefix marking an example that was written as a bare stage, not a shell
/// command. The marker cannot occur in Markdown text.
const BARE: &str = "\u{0}bare ";

/// True if `s` starts with `<scheme>://`.
fn starts_with_stage(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once("://") else {
        return false;
    };
    let mut c = scheme.chars();
    c.next().is_some_and(|f| f.is_ascii_lowercase())
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "+.-".contains(ch))
}

/// True while `s` has an open quote or an unclosed `(` outside quotes, or
/// ends in a backslash continuation: the command continues on the next line.
fn is_incomplete(s: &str) -> bool {
    let (mut single, mut double, mut depth, mut esc) = (false, false, 0i32, false);
    for c in s.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if !single => esc = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '(' if !single && !double => depth += 1,
            ')' if !single && !double => depth -= 1,
            _ => {}
        }
    }
    single || double || depth > 0 || s.ends_with('\\')
}

/// (line number, joined command) for each example in a Markdown file.
/// A line starting with `resh ` (optionally after a `$ ` prompt) is an
/// example, and so is a bare stage (`svc://nginx.status`), which is checked
/// as `resh <stage>`.
fn examples(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_shell_block = false;
    let mut in_block = false;
    let mut pending: Option<(usize, String)> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(lang) = trimmed.strip_prefix("```") {
            if let Some(p) = pending.take() {
                out.push(p);
            }
            if in_block {
                in_block = false;
                in_shell_block = false;
            } else {
                in_block = true;
                in_shell_block = matches!(lang.trim(), "" | "bash" | "sh" | "shell" | "console");
            }
            continue;
        }
        if !in_shell_block {
            continue;
        }
        let (start, cmd) = match pending.take() {
            Some((start, mut cmd)) => {
                // Inside quotes, keep the line break; elsewhere a continuation
                // is a word break.
                match cmd.strip_suffix('\\') {
                    Some(head) => cmd = format!("{head} {trimmed}"),
                    None => {
                        cmd.push(' ');
                        cmd.push_str(trimmed);
                    }
                }
                (start, cmd)
            }
            None => {
                let cmd = trimmed.strip_prefix("$ ").unwrap_or(trimmed);
                if cmd.starts_with("resh ") {
                    (i + 1, cmd.to_string())
                } else if starts_with_stage(cmd) {
                    (i + 1, format!("{BARE}{cmd}"))
                } else {
                    continue;
                }
            }
        };
        if is_incomplete(&cmd) {
            pending = Some((start, cmd));
        } else {
            out.push((start, cmd));
        }
    }
    if let Some(p) = pending {
        out.push(p);
    }
    out
}

#[test]
fn documented_examples_parse_to_registered_verbs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let reg = registry();
    let verbose = std::env::var_os("DOC_EXAMPLES_VERBOSE").is_some();
    let (mut checked, mut dynamic) = (0, Vec::new());
    let mut problems = Vec::new();

    for file in markdown_files(root) {
        let text = std::fs::read_to_string(&file).unwrap();
        let rel = file.strip_prefix(root).unwrap().display().to_string();
        for (line, raw) in examples(&text) {
            let cmd = raw.strip_prefix(BARE).unwrap_or(&raw);
            match example_words(&raw) {
                Words::Dynamic(why) => dynamic.push(format!("{rel}:{line}: ({why}) {cmd}")),
                Words::Err(e) => problems.push(format!("{rel}:{line}: {e}: {cmd}")),
                Words::Ok(words) => {
                    checked += 1;
                    if let Err(e) = check_command(&reg, &words) {
                        problems.push(format!("{rel}:{line}: {e}: {cmd}"));
                    }
                }
            }
        }
    }

    if verbose {
        eprintln!(
            "checked {checked} examples; {} need manual review:",
            dynamic.len()
        );
        for d in &dynamic {
            eprintln!("  {d}");
        }
    }
    assert!(checked > 0, "no documentation examples found");
    assert!(
        problems.is_empty(),
        "{} of {checked} documentation example(s) do not parse to a registered verb:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn extractor_and_splitter_behave() {
    let md =
        "text\n```bash\n$ resh svc://a.status \\\n  x=1 | jq .\nls\n```\n```json\nresh nope\n```\n";
    let ex = examples(md);
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0].0, 3);
    match shell_words(&ex[0].1) {
        Words::Ok(w) => assert_eq!(w, ["resh", "svc://a.status", "x=1"]),
        _ => panic!("expected words"),
    }
    assert!(matches!(shell_words("resh 'a(b)' # c"), Words::Ok(w) if w.len() == 2));
    assert!(matches!(shell_words("resh a(b)"), Words::Err(_)));
    assert!(matches!(shell_words("resh x=$HOME"), Words::Dynamic(_)));

    let md = "```\ngit://r.sync(\n  path=/repo,\n  remote=origin\n)\n```\n";
    let ex = examples(md);
    assert_eq!(ex.len(), 1);
    match example_words(&ex[0].1) {
        Words::Ok(w) => assert_eq!(w, ["resh", "git://r.sync( path=/repo, remote=origin )"]),
        _ => panic!("expected words"),
    }
    let md = "```sh\nresh pkg://system.install input='{\n  \"manager\": \"apt\"\n}'\n```\n";
    assert!(matches!(example_words(&examples(md)[0].1), Words::Ok(w) if w.len() == 3));

    let reg = registry();
    let w = |s: &str| match shell_words(s) {
        Words::Ok(w) => w,
        _ => panic!("{s}"),
    };
    assert!(check_command(&reg, &w("resh svc://nginx.status")).is_ok());
    assert!(check_command(&reg, &w("resh svc --help")).is_ok());
    assert!(check_command(&reg, &w("resh svc://nginx.frobnicate")).is_err());
    assert!(check_command(&reg, &w("resh nosuch://x.read")).is_err());
    assert!(check_command(&reg, &w("resh svc://nginx.status loose")).is_err());
    assert!(check_command(&reg, &w("resh svc://nginx.status --json-pretty")).is_ok());
    let bare = |s: &str| match example_words(&format!("{BARE}{s}")) {
        Words::Ok(w) => w,
        _ => panic!("{s}"),
    };
    assert!(check_command(&reg, &bare("git://r.sync( path=/repo )")).is_ok());
    assert!(check_command(&reg, &bare("archive://create( format=zip )")).is_err());
}
