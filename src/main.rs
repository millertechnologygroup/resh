use resh::{core, handles};

use anyhow::Result;
use clap::Parser;
use core::{Registry, dispatch_stage};

/// Argument keys that make a mail:// stage a message to send.
const MAIL_MESSAGE_KEYS: &[&str] = &[
    "to",
    "subject",
    "text_body",
    "html_body",
    "from",
    "cc",
    "bcc",
];

/// The verb named in a mail:// stage (`mail://send`, `mail://smtp.test`,
/// `mail://send(...)`), if it is one of the mail verbs.
fn mail_stage_verb(stage: &str) -> Option<&str> {
    let rest = stage.strip_prefix("mail://")?;
    let head = rest.split('(').next().unwrap_or(rest);
    let last = head.rsplit(['/', '.']).next().unwrap_or(head);
    ["send", "send_template", "test", "config"]
        .into_iter()
        .find(|v| *v == last)
}

/// Rejoins the words of a `mail://` stage that the shell split.
///
/// * A function-call stage split at spaces (an unquoted
///   `mail://send(to=a@b.com, subject=Hi)`) is joined back into one stage.
/// * For `send` and `send_template`, a word without `=` (other than a bare
///   `dry_run`) continues the previous argument's value, so an unquoted
///   `text_body=Backup done` is the value `Backup done`. Only words after a
///   message argument (`MAIL_MESSAGE_KEYS`) are joined this way.
///
/// Every other `key=value` word is passed through unchanged; the handle
/// parses address lists (comma-separated or JSON) itself.
fn reconstruct_mail_command(stage: &str, args: &[String]) -> (String, Vec<String>) {
    if !stage.starts_with("mail://") {
        return (stage.to_string(), args.to_vec());
    }

    // Rejoin a function-call stage that the shell split at spaces.
    if !args.is_empty() && stage.contains('(') && !stage.ends_with(')') {
        let full_text = format!("{} {}", stage, args.join(" "));
        let reconstructed = full_text
            .replace(" =", "=")
            .replace("= ", "=")
            .replace(", ", ",")
            .replace(" ,", ",")
            .replace("  ", " ")
            .trim()
            .to_string();
        return (reconstructed, Vec::new());
    }

    // Only send and send_template take message text. Other verbs (test,
    // config) receive their words unchanged.
    if !matches!(mail_stage_verb(stage), Some("send") | Some("send_template")) {
        return (stage.to_string(), args.to_vec());
    }

    let mut out: Vec<String> = Vec::new();
    for arg in args {
        let continues_message = !arg.contains('=')
            && !core::parse::is_bare_dry_run(arg)
            && out.last().is_some_and(|last| {
                last.split_once('=')
                    .is_some_and(|(key, _)| MAIL_MESSAGE_KEYS.contains(&key.trim()))
            });
        match out.last_mut() {
            Some(last) if continues_message => {
                last.push(' ');
                last.push_str(arg);
            }
            _ => out.push(arg.clone()),
        }
    }
    (stage.to_string(), out)
}

/// Minimal OS/2-inspired shell
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// List registered URL schemes and exit
    #[arg(long)]
    list_schemas: bool,

    /// Pretty-print JSON outputs when possible
    #[arg(long)]
    json_pretty: bool,

    /// A single command stage like: file://./foo.txt.read or svc://nginx.status
    #[arg(value_name = "STAGE")]
    stage: Option<String>,

    /// Additional arguments passed to the command as key=value pairs
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

/// Recognizes help requests written with a stage URL. Returns the scheme and,
/// for verb help, the verb:
/// - `<scheme>://help`, `<scheme>://-h`, `<scheme>://--help` → handle help
///   (only when nothing else follows);
/// - `<stage> --help|-h|help`, for a stage that names a verb → that verb's
///   help, or the handle's help if the stage has no verb.
fn stage_help_request(args: &[String]) -> Option<(String, Option<String>)> {
    const HELP_WORDS: [&str; 3] = ["--help", "-h", "help"];
    let scheme_of = |stage: &str| {
        let (scheme, rest) = stage.split_once("://")?;
        (!scheme.is_empty()).then(|| (scheme.to_ascii_lowercase(), rest.to_string()))
    };
    match args {
        [stage] => {
            let (scheme, rest) = scheme_of(stage)?;
            if HELP_WORDS.contains(&rest.trim_start_matches('/')) {
                return Some((scheme, None));
            }
            // `<scheme>://<target>?help` or `?help=<verb>`, only when the
            // stage is not otherwise a valid stage (an http URL may carry a
            // real `help=` query parameter).
            if core::parse::parse_stage(stage).is_ok() {
                return None;
            }
            let (_, query) = rest.split_once('?')?;
            query
                .split('&')
                .find_map(|pair| match pair.split_once('=') {
                    Some(("help", verb)) if !verb.is_empty() => {
                        Some((scheme.clone(), Some(verb.to_string())))
                    }
                    Some(("help", _)) | None if pair == "help" || pair == "help=" => {
                        Some((scheme.clone(), None))
                    }
                    _ => None,
                })
        }
        [stage, flag] if HELP_WORDS.contains(&flag.as_str()) => {
            let (scheme, _) = scheme_of(stage)?;
            let verb = core::parse::parse_stage(stage)
                .ok()
                .map(|p| p.verb)
                .filter(|v| !v.is_empty() && !HELP_WORDS.contains(&v.as_str()));
            Some((scheme, verb))
        }
        _ => None,
    }
}

fn main() -> Result<()> {
    let mut reg = Registry::default();
    // register schemes
    handles::register_all(&mut reg);

    // Handle and verb help (`resh <handle> [<verb>] --help|-h|help` and
    // `resh help <handle> [<verb>]`): answered from handle metadata without
    // dispatching. An unknown handle or verb is an error (exit 2).
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(req) = core::help::parse_help_request(&raw_args) {
        match core::help::render(&reg, &req) {
            Ok(text) => {
                print!("{}", text);
                return Ok(());
            }
            Err(e) => {
                eprintln!("{}", core::status::error_line(&e.code(), &e.to_string()));
                std::process::exit(2);
            }
        }
    }
    // Help for a stage URL: `resh <scheme>://help` (handle help) and
    // `resh <stage> --help|-h|help` (help for the stage's verb).
    if let Some((scheme, verb)) = stage_help_request(&raw_args) {
        let req = match &verb {
            Some(v) => core::help::HelpRequest::Verb(&scheme, v),
            None => core::help::HelpRequest::Handle(&scheme),
        };
        match core::help::render(&reg, &req) {
            Ok(text) => {
                print!("{}", text);
                return Ok(());
            }
            Err(e) => {
                eprintln!("{}", core::status::error_line(&e.code(), &e.to_string()));
                std::process::exit(2);
            }
        }
    }
    // `resh help` on its own is the global help.
    if raw_args.len() == 1 && raw_args[0] == "help" {
        use clap::CommandFactory;
        // A closed stdout (e.g. `resh help | head`) is not an error.
        let _ = Cli::command().print_help();
        return Ok(());
    }

    let cli = Cli::parse();

    if cli.list_schemas {
        for s in reg.list_schemes() {
            println!("{}", s);
        }
        return Ok(());
    }

    let Some(stage) = cli.stage else {
        eprintln!("Error: no stage provided. Try `resh --help` or `resh --list-schemas`.");
        std::process::exit(2);
    };

    // A bare handle name (`resh file`, `resh file read`) is not a stage: say
    // how to write one instead of a generic parse error.
    if !stage.contains("://") && reg.list_schemes().iter().any(|s| s.as_str() == stage) {
        eprintln!(
            "Error: '{stage}' is a handle name, not a stage.\n\
             Stages are written as {stage}://<target>.<verb>; \
             run `resh {stage} --help` to see its verbs."
        );
        std::process::exit(2);
    }

    // Reconstruct mail URLs that were broken by shell parsing
    let (final_stage, final_args) = reconstruct_mail_command(&stage, &cli.args);

    // Output is streamed to stdout as the stage writes it (so long-running
    // verbs such as `config watch` show events as they happen). Only
    // --json-pretty needs the whole output first, to reformat it.
    let mut buf: Vec<u8> = Vec::new();
    let mut stdout = std::io::stdout();
    let mut stderr = core::status::TrackingWriter::new(std::io::stderr());
    let status = dispatch_stage(
        &mut reg,
        &final_stage,
        &final_args,
        &mut std::io::stdin(),
        if cli.json_pretty {
            &mut buf as &mut dyn std::io::Write
        } else {
            &mut stdout
        },
        &mut stderr,
    );

    let status = match status {
        Ok(status) => status,
        Err(e) if core::process::has_lost() => core::status::Status::err(1, e.to_string()),
        Err(e) => return Err(e),
    };

    if cli.json_pretty {
        if let Ok(text) = String::from_utf8(buf.clone()) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                // not JSON; print raw
                print!("{}", text);
            }
        } else {
            // binary; write raw
            use std::io::Write;
            let _ = std::io::stdout().write_all(&buf);
        }
    } else {
        use std::io::Write;
        let _ = stdout.flush();
    }

    // A tool lost to its deadline decides the outcome, whatever the handle
    // made of the error: what it did before it stopped is unknown.
    if let Some(lost) = core::process::take_lost() {
        let state = match lost.stopped {
            // Earlier steps of the verb may have run; handles that do several
            // steps report what was applied in their JSON result.
            core::process::Stopped::NotStarted => "was not started before the deadline",
            core::process::Stopped::Terminated => {
                "was stopped; it may already have made changes, so check before retrying"
            }
            core::process::Stopped::StillRunning => "could not be stopped and may still be running",
        };
        let scheme = final_stage
            .split("://")
            .next()
            .unwrap_or("resh")
            .to_ascii_lowercase();
        eprintln!(
            "{}",
            core::status::error_line(
                &format!("{}.timeout", core::status::error_prefix(&scheme)),
                &format!("outcome unknown: {} {state}", lost.tool)
            )
        );
        std::process::exit(core::status::exit::TIMEOUT);
    }

    if !status.ok {
        // A failure must never be silent or exit 0.
        let _ = core::status::report_failure(&status, stderr.written, &mut std::io::stderr());
        std::process::exit(status.exit_code());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_and_config_are_never_rewritten_to_send() {
        for (stage, a) in [
            ("mail://test", vec!["smtp_username=alice@example.com"]),
            (
                "mail://test",
                vec!["smtp_host=mail.example.com", "connection_only=true"],
            ),
            (
                "mail://config",
                vec!["action=set", "from_address=ops@example.com"],
            ),
            ("mail://test", vec!["note=goto"]),
        ] {
            let a = args(&a);
            assert_eq!(
                reconstruct_mail_command(stage, &a),
                (stage.to_string(), a.clone())
            );
        }
    }

    #[test]
    fn send_args_pass_through_unchanged() {
        // Values with quotes, commas and JSON reach the handle as typed.
        let a = args(&[
            "to=a@example.com,b@example.com",
            r#"subject=He said "hi", twice"#,
            r#"vars={"user_name":"Bob"}"#,
            "dry_run",
        ]);
        assert_eq!(
            reconstruct_mail_command("mail://send", &a),
            ("mail://send".to_string(), a.clone())
        );
    }

    #[test]
    fn bare_words_continue_a_message_value() {
        let (stage, rest) = reconstruct_mail_command(
            "mail://send",
            &args(&["to=a@example.com", "text_body=Backup", "done", "dry_run"]),
        );
        assert_eq!(stage, "mail://send");
        assert_eq!(
            rest,
            args(&["to=a@example.com", "text_body=Backup done", "dry_run"])
        );
        // After a non-message argument a bare word is left for the
        // dispatcher to refuse.
        let a = args(&["smtp_host=h", "stray"]);
        assert_eq!(reconstruct_mail_command("mail://send", &a).1, a);
    }

    #[test]
    fn split_function_call_is_rejoined() {
        let (stage, rest) =
            reconstruct_mail_command("mail://send(to=a@b.com,", &args(&["subject=Hi)"]));
        assert_eq!(stage, "mail://send(to=a@b.com,subject=Hi)");
        assert!(rest.is_empty());
    }

    #[test]
    fn substrings_do_not_trigger_send() {
        // "to" inside a value or key is not the `to` key.
        let a = args(&["template=onboarding_tour"]);
        assert_eq!(
            reconstruct_mail_command("mail://send_template", &a),
            ("mail://send_template".to_string(), a.clone())
        );
    }

    #[test]
    fn mail_stage_verb_detection() {
        assert_eq!(mail_stage_verb("mail://test"), Some("test"));
        assert_eq!(mail_stage_verb("mail://smtp.send"), Some("send"));
        assert_eq!(
            mail_stage_verb("mail://send_template(x=1)"),
            Some("send_template")
        );
        assert_eq!(mail_stage_verb("mail://"), None);
    }
}
