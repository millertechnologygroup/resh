mod core;
mod handles;
mod backends;

use anyhow::Result;
use clap::Parser;
use core::{Registry, dispatch_stage};

/// Reconstructs mail:// commands that were broken by shell parsing
/// Reconstruct mail commands from shell-broken arguments
/// Supports multiple input formats for user convenience
fn reconstruct_mail_command(stage: &str, args: &[String]) -> (String, Vec<String>) {
    // Only process mail:// URLs
    if !stage.starts_with("mail://") {
        return (stage.to_string(), args.to_vec());
    }
    
    // If this is already a complete URL, return as-is
    if stage.contains('(') && stage.contains(')') && args.is_empty() {
        return (stage.to_string(), args.to_vec());
    }
    
    // Check if arguments look like key=value pairs for mail commands
    let has_mail_args = args.iter().any(|arg| {
        arg.starts_with("to=") || arg.starts_with("subject=") || 
        arg.starts_with("text_body=") || arg.starts_with("html_body=") ||
        arg.starts_with("from=") || arg.starts_with("cc=") || arg.starts_with("bcc=")
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
    
    // Handle other potential shell-broken patterns
    if !args.is_empty() {
        let full_text = format!("{} {}", stage, args.join(" "));
        
        // Check if this looks like a broken mail URL with parentheses
        if full_text.contains("=") && (
            full_text.contains("@") || 
            full_text.contains("to") ||
            full_text.contains("subject")
        ) {
            // Try to reconstruct as a function call
            let reconstructed = if full_text.contains("(") {
                // Already has opening paren, just clean it up
                full_text
                    .replace(" =", "=")
                    .replace("= ", "=")
                    .replace(", ", ",")
                    .replace(" ,", ",")
                    .replace("  ", " ")
                    .trim()
                    .to_string()
            } else {
                // Need to add function call syntax
                full_text.replace("mail://", "mail://send(") + ")"
            };
            
            return (reconstructed, Vec::new());
        }
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
    let cli = Cli::parse();
    let mut reg = Registry::default();
    // register schemes
    handles::register_all(&mut reg);

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
