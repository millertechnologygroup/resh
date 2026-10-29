pub mod envelope;
pub mod help;
pub mod lenient;
pub mod parse;
pub mod registry;
pub mod secure_fs;
pub mod status;
#[cfg(test)]
pub mod test_support;

pub use envelope::{BackendInfo, BackupEnvelope, BackupError, BackupEvent, Timer};
pub use registry::{Args, Handle, IoStreams, Registry};
pub use status::Status;

use anyhow::Result;
use std::io::{Read, Write};

pub fn dispatch_stage(
    reg: &mut Registry,
    stage_str: &str,
    cli_args: &[String],
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Status> {
    let mut parsed = parse::parse_stage(stage_str)?;

    // Add CLI arguments to parsed arguments
    for arg in cli_args {
        if let Some((key, value)) = arg.split_once('=') {
            parsed
                .args
                .insert(key.trim().to_string(), value.trim().to_string());
        } else if parse::is_bare_dry_run(arg) {
            // A bare `dry_run` asks for a dry run; dropping it would run
            // the real change.
            parsed
                .args
                .insert("dry_run".to_string(), "true".to_string());
        } else {
            // Any other bare word used to be dropped silently, so a
            // misspelled `dry-run` ran the real change.
            return Ok(Status::err(
                2,
                format!("argument {arg:?} is not key=value; nothing was done"),
            ));
        }
    }

    let mut io = registry::IoStreams {
        stdin,
        stdout,
        stderr,
    };
    let h = reg.resolve(&parsed.target)?;
    if let Some(refusal) = dry_run_refusal(h.as_ref(), &parsed.target, &parsed.verb, &parsed.args) {
        return Ok(Status::err(2, refusal));
    }
    h.call(&parsed.verb, &parsed.args, &mut io)
}

/// A dry-run request must never perform the real change. Returns the reason
/// to refuse the stage, or `None` to run it:
/// - a key that is a misspelling of `dry_run` (`dry-run`, `DRY_RUN`,
///   `dryRun`), which the handle would ignore;
/// - a malformed `dry_run` value;
/// - `dry_run=true` for a verb that has no dry-run mode, which would
///   otherwise ignore it and make the change. A verb has a dry-run mode when
///   its help usage lists `dry_run` (`help_coverage` keeps every verb's
///   usage present, and the handles were checked against it).
fn dry_run_refusal(h: &dyn Handle, target: &str, verb: &str, args: &Args) -> Option<String> {
    if let Some(k) = args.keys().find(|k| {
        k.as_str() != "dry_run" && k.to_ascii_lowercase().replace(['-', '_'], "") == "dryrun"
    }) {
        return Some(format!(
            "unrecognized argument {k:?}: use dry_run; nothing was done"
        ));
    }
    if !args.contains_key("dry_run")
        || help::HELP_ALIASES.contains(&verb)
        || verb.starts_with("--help")
    {
        return None;
    }
    let scheme = target.split("://").next().unwrap_or(target);
    match lenient::dry_run(args) {
        Err(e) => Some(format!("{e}; nothing was done")),
        Ok(false) => None,
        // Handles configured by an `input=` JSON document (pkg) read
        // dry_run only from inside it and would ignore this one.
        Ok(true) if args.contains_key("input") => Some(format!(
            "{scheme} {verb} reads dry_run from its input JSON; put \"dry_run\":true inside input=; nothing was done"
        )),
        Ok(true) => {
            let detail = h
                .help()
                .and_then(|m| m.verbs.iter().find(|v| v.name == verb))
                .and_then(|v| v.detail.as_ref());
            // Fail closed: only a verb whose usage lists dry_run gets it.
            match detail {
                Some(d) if d.usage.contains("dry_run") => None,
                _ => Some(format!(
                    "{scheme} {verb} does not support dry_run; nothing was done"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records the arguments each call receives; performs nothing.
    struct Recorder(Arc<Mutex<Vec<Args>>>);

    impl Handle for Recorder {
        fn verbs(&self) -> &'static [&'static str] {
            &["delete"]
        }
        fn call(&self, _verb: &str, args: &Args, _io: &mut IoStreams) -> Result<Status> {
            self.0.lock().unwrap().push(args.clone());
            Ok(Status::ok())
        }
        fn help(&self) -> Option<&'static help::HandleHelp> {
            Some(&HELPED)
        }
    }

    fn dispatch(words: &[&str]) -> Args {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::default();
        let rec = seen.clone();
        reg.register_scheme("rec", move |_| Ok(Box::new(Recorder(rec.clone()))));
        let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        dispatch_stage(&mut reg, "rec://bob.delete", &words, &mut i, &mut o, &mut e).unwrap();
        seen.lock().unwrap().pop().unwrap()
    }

    /// Records calls; its help says only `delete` has a dry-run mode.
    struct Helped(Arc<Mutex<Vec<String>>>);
    static HELPED: help::HandleHelp = help::HandleHelp {
        description: "Test.",
        usage: "resh rec://x.<verb>",
        verbs: &[
            help::VerbHelp {
                name: "delete",
                definition: "Deletes.",
                detail: Some(help::VerbDetail {
                    usage: "resh rec://x.delete [dry_run=true|false]",
                    example: "resh rec://x.delete",
                    example_output: None,
                }),
            },
            help::VerbHelp {
                name: "wipe",
                definition: "Wipes.",
                detail: Some(help::VerbDetail {
                    usage: "resh rec://x.wipe",
                    example: "resh rec://x.wipe",
                    example_output: None,
                }),
            },
        ],
    };
    impl Handle for Helped {
        fn verbs(&self) -> &'static [&'static str] {
            &["delete", "wipe"]
        }
        fn call(&self, verb: &str, _args: &Args, _io: &mut IoStreams) -> Result<Status> {
            self.0.lock().unwrap().push(verb.to_string());
            Ok(Status::ok())
        }
        fn help(&self) -> Option<&'static help::HandleHelp> {
            Some(&HELPED)
        }
    }

    fn run_helped(stage: &str, words: &[&str]) -> (Status, Vec<String>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::default();
        let rec = seen.clone();
        reg.register_scheme("rec", move |_| Ok(Box::new(Helped(rec.clone()))));
        let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let st = dispatch_stage(&mut reg, stage, &words, &mut i, &mut o, &mut e).unwrap();
        let calls = seen.lock().unwrap().clone();
        (st, calls)
    }

    // Stage 4: a dry-run request never reaches a verb that would ignore it.
    #[test]
    fn dry_run_is_refused_where_the_verb_has_no_dry_run_mode() {
        for w in ["dry_run", "dry_run=true", "dry_run=YES", "dry_run=1"] {
            let (st, calls) = run_helped("rec://x.wipe", &[w]);
            assert!(!st.ok, "{w}");
            assert!(
                st.reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("does not support dry_run")
            );
            assert!(calls.is_empty(), "{w}: the verb ran");
            // A verb with a dry-run mode still receives it.
            let (st, calls) = run_helped("rec://x.delete", &[w]);
            assert!(st.ok, "{w}");
            assert_eq!(calls, ["delete"]);
        }
        // Explicitly false, or absent, runs normally.
        assert_eq!(run_helped("rec://x.wipe", &["dry_run=false"]).1, ["wipe"]);
        assert_eq!(run_helped("rec://x.wipe", &[]).1, ["wipe"]);
        // An input= document carries its own dry_run; a top-level one is refused.
        let (st, calls) = run_helped("rec://x.delete", &["input={}", "dry_run=true"]);
        assert!(!st.ok);
        assert!(calls.is_empty());
        // A help-looking argument does not bypass the guard: most handles do
        // not treat `help=` as a help request and would run the verb.
        for h in ["help=1", "h=1", "--help=x", "-h=1"] {
            let (st, calls) = run_helped("rec://x.wipe", &["dry_run=true", h]);
            assert!(!st.ok, "{h}");
            assert!(calls.is_empty(), "{h}: the verb ran");
        }
        // A verb without help metadata is refused too (fail closed).
        let (st, calls) = run_helped("rec://x.undocumented", &["dry_run"]);
        assert!(!st.ok);
        assert!(calls.is_empty());
        // Malformed values and misspelled keys or words are refused everywhere.
        for w in [
            "dry_run=maybe",
            "dry-run=true",
            "DRY_RUN=true",
            "dryRun=1",
            "dry-run",
            "dryrun",
            "x",
        ] {
            for stage in ["rec://x.wipe", "rec://x.delete"] {
                let (st, calls) = run_helped(stage, &[w]);
                assert!(!st.ok, "{stage} {w}");
                assert!(calls.is_empty(), "{stage} {w}: the verb ran");
            }
        }
    }

    // SEC-05: `resh user://bob.delete dry_run` must not lose the flag.
    #[test]
    fn bare_dry_run_cli_word_is_kept() {
        assert_eq!(
            dispatch(&["dry_run"]).get("dry_run").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            dispatch(&["force=true", " dry_run "])
                .get("dry_run")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            dispatch(&["dry_run=false"])
                .get("dry_run")
                .map(String::as_str),
            Some("false")
        );
        assert!(!dispatch(&[]).contains_key("dry_run"));
        // Stage 4: other bare words are refused instead of being dropped, so
        // a misspelled `dry-run` cannot run the real change.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut reg = Registry::default();
        let rec = seen.clone();
        reg.register_scheme("rec", move |_| Ok(Box::new(Recorder(rec.clone()))));
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let words = vec!["verbose".to_string()];
        let st =
            dispatch_stage(&mut reg, "rec://bob.delete", &words, &mut i, &mut o, &mut e).unwrap();
        assert!(!st.ok);
        assert!(seen.lock().unwrap().is_empty());
    }
}
