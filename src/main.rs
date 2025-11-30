mod core;
mod handles;

use anyhow::Result;
use clap::Parser;
use core::{Registry, dispatch_stage};

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

    // Capture output so we can optionally pretty-print JSON
    let mut buf: Vec<u8> = Vec::new();
    let status = dispatch_stage(
        &mut reg,
        &stage,
        &cli.args,
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
