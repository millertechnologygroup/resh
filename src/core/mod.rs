pub mod parse;
pub mod registry;
pub mod status;
pub mod envelope;

pub use registry::{Handle, Registry, IoStreams, Args};
pub use status::Status;
pub use envelope::{BackupEnvelope, BackendInfo, BackupError, BackupEvent, Timer};

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
            parsed.args.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    
    let mut io = registry::IoStreams {
        stdin,
        stdout,
        stderr,
    };
    let h = reg.resolve(&parsed.target)?;
    h.call(&parsed.verb, &parsed.args, &mut io)
}
