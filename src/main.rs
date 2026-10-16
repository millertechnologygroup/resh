mod core;
mod handles;

use anyhow::Result;
use clap::Parser;
use core::{Registry, dispatch_stage};

/// Argument keys that make a mail:// stage a message to send.
const MAIL_MESSAGE_KEYS: &[&str] = &["to", "subject", "text_body", "html_body", "from", "cc", "bcc"];

/// The verb named in a mail:// stage (`mail://send`, `mail://smtp.test`,
/// `mail://send(...)`), if it is one of the mail verbs.
fn mail_stage_verb(stage: &str) -> Option<&str> {
    let rest = stage.strip_prefix("mail://")?;
    let head = rest.split('(').next().unwrap_or(rest);
    let last = head.rsplit(['/', '.']).next().unwrap_or(head);
    ["send", "send_template", "test", "config"].into_iter().find(|v| *v == last)
}

/// Reconstructs mail:// commands that were broken by shell parsing
/// Reconstruct mail commands from shell-broken arguments
/// Supports multiple input formats for user convenience
fn reconstruct_mail_command(stage: &str, args: &[String]) -> (String, Vec<String>) {
    // Only process mail:// URLs
    if !stage.starts_with("mail://") {
        return (stage.to_string(), args.to_vec());
    }

    // Only send and send_template take message fields. Other verbs (test,
    // config) receive their key=value arguments unchanged.
    let verb = mail_stage_verb(stage);
    if !matches!(verb, None | Some("send") | Some("send_template")) {
        return (stage.to_string(), args.to_vec());
    }
    
    // If this is already a complete URL, return as-is
    if stage.contains('(') && stage.contains(')') && args.is_empty() {
        return (stage.to_string(), args.to_vec());
    }
    
    // Check if arguments look like key=value pairs for mail commands
    let has_mail_args = args.iter().any(|arg| {
        arg.split_once('=').is_some_and(|(key, _)| MAIL_MESSAGE_KEYS.contains(&key.trim()))
    });
    
    if has_mail_args {
        // Process the arguments to create a proper function call syntax
        let verb = if stage.ends_with("/send") || stage.ends_with("/test") || 
                      stage.ends_with("/config") || stage.ends_with("/send_template") {
            // Verb is already specified
            stage.to_string()
        } else {
            // Default to send if no verb specified
            format!("{}/send", stage)
        };
        
        // Process and clean the arguments
        let mut processed_args = Vec::new();
        for arg in args {
            if arg.contains("=") {
                // For email lists, handle comma-separated values properly
                let cleaned = if arg.starts_with("to=") || arg.starts_with("cc=") || arg.starts_with("bcc=") {
                    // Handle email list formatting
                    if arg.contains(',') {
                        // Convert comma-separated emails to proper JSON array format
                        let (key, value) = arg.split_once('=').unwrap();
                        let emails: Vec<&str> = value.split(',').map(|s| s.trim().trim_matches('"')).collect();
                        format!("{}=[{}]", key, emails.iter().map(|e| format!("\"{}\"", e)).collect::<Vec<_>>().join(","))
                    } else {
                        // Single email - format as an array for compatibility
                        let (key, value) = arg.split_once('=').unwrap();
                        format!("{}=[\"{}\"]", key, value.trim_matches('"'))
                    }
                } else {
                    // For non-email fields, just ensure proper quoting
                    if let Some((key, value)) = arg.split_once('=') {
                        format!("{}=\"{}\"", key, value.trim_matches('"'))
                    } else {
                        arg.to_string()
                    }
                };
                processed_args.push(cleaned);
            } else {
                // This might be part of a broken quoted argument, try to merge
                if let Some(last) = processed_args.last_mut() {
                    last.push(' ');
                    last.push_str(arg);
                } else {
                    processed_args.push(arg.to_string());
                }
            }
        }
        
        // Build the reconstructed command
        let reconstructed = format!("{}({})", verb, processed_args.join(","));
        
        return (reconstructed, Vec::new());
    }
    
    // Rejoin a function-call stage that the shell split at spaces, for
    // example `mail://send(to=a@b.com, subject=Hi)` passed unquoted.
    if !args.is_empty() && stage.contains('(') {
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
    
    // Return as-is if no processing needed
    (stage.to_string(), args.to_vec())
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

fn main() -> Result<()> {
    let mut reg = Registry::default();
    // register schemes
    handles::register_all(&mut reg);

    // `resh <handle> --help` and `resh <handle> <verb> --help`: answered from
    // handle metadata without dispatching. Anything not covered falls through
    // to clap unchanged.
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(req) = core::help::parse_help_request(&raw_args) {
        if let Some(text) = core::help::render(&reg, &req) {
            print!("{}", text);
            return Ok(());
        }
    }

    let cli = Cli::parse();

    if cli.list_schemas {
        for s in reg.list_schemes() {
            println!("{}", s);
        }
        return Ok(());
    }

    let stage = cli.stage.expect("No stage provided. Try --list-schemas");

    // Reconstruct mail URLs that were broken by shell parsing
    let (final_stage, final_args) = reconstruct_mail_command(&stage, &cli.args);

    // Capture output so we can optionally pretty-print JSON
    let mut buf: Vec<u8> = Vec::new();
    let status = dispatch_stage(
        &mut reg,
        &final_stage,
        &final_args,
        &mut std::io::stdin(),
        &mut buf,
        &mut std::io::stderr(),
    )?;

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
        let _ = std::io::stdout().write_all(&buf);
    }

    if !status.ok {
        std::process::exit(status.code.unwrap_or(1));
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
            ("mail://test", vec!["smtp_host=mail.example.com", "connection_only=true"]),
            ("mail://config", vec!["action=set", "from_address=ops@example.com"]),
            ("mail://test", vec!["note=goto"]),
        ] {
            let a = args(&a);
            assert_eq!(reconstruct_mail_command(stage, &a), (stage.to_string(), a.clone()));
        }
    }

    #[test]
    fn send_args_become_function_call() {
        let (stage, rest) =
            reconstruct_mail_command("mail://send", &args(&["to=a@example.com", "subject=Hi"]));
        assert_eq!(stage, r#"mail://send(to=["a@example.com"],subject="Hi")"#);
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
        assert_eq!(mail_stage_verb("mail://send_template(x=1)"), Some("send_template"));
        assert_eq!(mail_stage_verb("mail://"), None);
    }
}
