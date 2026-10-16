use anyhow::{Result, bail};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::core::{
    help::{self, HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use dirs::state_dir;

/// Metadata for `resh mq --help` and `resh mq <verb> --help`.
static MQ_HELP: HandleHelp = HandleHelp {
    description: "The mq handle provides a local, file-based FIFO message queue, storing each \
        message as a file under the user's state directory, normally \
        ~/.local/state/resh/mq/<queue>. The queue is named by the URL, such as mq://jobs, and \
        unsafe characters in the name are replaced with underscores.",
    usage: "resh mq://<queue>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "len",
            definition: "Prints the number of messages waiting in the queue.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.len",
                example: "resh mq://jobs.len",
                example_output: Some("2"),
            }),
        },
        VerbHelp {
            name: "peek",
            definition: "Prints the oldest message without removing it, exiting with status 2 \
                if the queue is empty.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.peek",
                example: "resh mq://jobs.peek",
                example_output: Some("backup-db"),
            }),
        },
        VerbHelp {
            name: "create",
            definition: "Creates the queue's storage directories if they do not already exist.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.create",
                example: "resh mq://jobs.create",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "put",
            definition: "Appends a message to the queue, taken from the data argument or, if \
                it is absent, from standard input.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.put [data=<message>]",
                example: "resh mq://jobs.put data=backup-db",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "get",
            definition: "Removes the oldest message from the queue and prints it, exiting with \
                status 2 if the queue is empty.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.get",
                example: "resh mq://jobs.get",
                example_output: Some("backup-db"),
            }),
        },
        VerbHelp {
            name: "purge",
            definition: "Deletes every message in the queue, including any left in flight.",
            detail: Some(VerbDetail {
                usage: "resh mq://<queue>.purge",
                example: "resh mq://jobs.purge",
                example_output: None,
            }),
        },
    ],
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("mq", |u| Ok(Box::new(MQHandle::from_url(u)?)));
}

fn sanitize_name(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.len() > 120 {
        out.truncate(120);
    }
    if out.is_empty() { "_".to_string() } else { out }
}

pub struct MQHandle {
    #[allow(dead_code)]
    name: String,
    dir: PathBuf,
}

impl MQHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        let name = format!("{}{}", u.host_str().unwrap_or(""), u.path());
        let safe = sanitize_name(&name);
        let base = state_dir().unwrap_or(std::path::PathBuf::from("/tmp"));
        let dir = base.join("resh").join("mq").join(safe);
        Ok(Self { name: name, dir })
    }

    fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::create_dir_all(self.dir.join("_inflight"))?;
        Ok(())
    }

    fn now_ns() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn purge_impl(&self) -> Result<()> {
        // Ensure directory structure exists (idempotent)
        self.ensure()?;
        
        // Purge .msg files from main directory
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg")) {
                    // Handle NotFound errors gracefully (file may have been deleted by concurrent operation)
                    match fs::remove_file(&path) {
                        Ok(()) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        
        // Purge .msg files from _inflight directory
        let inflight = self.dir.join("_inflight");
        if inflight.exists() {
            for entry in fs::read_dir(&inflight)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg")) {
                    // Handle NotFound errors gracefully (file may have been deleted by concurrent operation)
                    match fs::remove_file(&path) {
                        Ok(()) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Writes the approved help for `help`, `--help`, `-h`, `--help=<verb>`,
    /// `help(verb=<verb>)`, or a `help`/`h` argument; returns None otherwise.
    fn check_and_display_help(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Option<Status>> {
        let help_verb = if let Some(v) = verb.strip_prefix("--help=") {
            Some(v.to_string())
        } else if help::HELP_ALIASES.contains(&verb)
            || ["help", "h", "--help", "-h"].iter().any(|k| args.contains_key(*k))
        {
            args.get("verb").cloned().or_else(|| args.get("help").filter(|v| !v.is_empty()).cloned())
        } else {
            return Ok(None);
        };
        write!(io.stdout, "{}", help::render_legacy("mq", &MQ_HELP, self.verbs(), help_verb.as_deref()))?;
        Ok(Some(Status::ok()))
    }
}

impl Handle for MQHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "put", "get", "len", "purge", "peek", "help", "--help", "-h"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&MQ_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }

        match verb {
            "create" => {
                match self.ensure() {
                    Ok(_) => Ok(Status::ok()),
                    Err(e) => Ok(Status::err(1, format!("mq create failed: {}", e))),
                }
            }
            "put" => {
                self.ensure()?;
                
                // Get message data from args or stdin
                let data = if let Some(data_str) = args.get("data") {
                    // Use data from arguments if provided
                    data_str.as_bytes().to_vec()
                } else {
                    // Read from stdin if no data argument provided
                    let mut buf = Vec::new();
                    io.stdin.read_to_end(&mut buf)?;
                    buf
                };
                
                // Use atomic write: write to temp file then rename
                let now = Self::now_ns();
                let tmp = self.dir.join(format!("tmp-{}.msg", now));
                let final_path = self.dir.join(format!("{:020}.msg", now));
                
                // Write to temp file
                fs::write(&tmp, &data)?;
                
                // Atomically move to final location
                fs::rename(&tmp, &final_path)?;
                
                Ok(Status::ok())
            }
            "get" => {
                self.ensure()?;
                let mut entries: Vec<_> = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".msg"))
                    .collect();
                entries.sort_by_key(|e| e.path());
                if let Some(first) = entries.first() {
                    let src = first.path();
                    let inflight = self.dir.join("_inflight").join(src.file_name().unwrap());
                    // rename to inflight (atomic lock on same fs)
                    fs::rename(&src, &inflight)?;
                    let mut f = fs::File::open(&inflight)?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    io.stdout.write_all(&buf)?;
                    let _ = fs::remove_file(&inflight);
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(2, "empty"))
                }
            }
            "len" => {
                self.ensure()?;
                let count = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let path = e.path();
                        path.is_file() && path.extension() == Some(std::ffi::OsStr::new("msg"))
                    })
                    .count();
                write!(io.stdout, "{}", count)?;
                Ok(Status::ok())
            }
            "purge" => {
                match self.purge_impl() {
                    Ok(()) => Ok(Status::ok()),
                    Err(e) => Ok(Status::err(1, format!("failed to purge queue: {}", e))),
                }
            }
            "peek" => {
                self.ensure()?;
                let mut entries: Vec<_> = fs::read_dir(&self.dir)?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".msg"))
                    .collect();
                entries.sort_by_key(|e| e.path());
                if let Some(first) = entries.first() {
                    let src = first.path();
                    // Read directly without moving/renaming (non-destructive)
                    let mut f = fs::File::open(&src)?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    io.stdout.write_all(&buf)?;
                    Ok(Status::ok())
                } else {
                    Ok(Status::err(2, "empty"))
                }
            }
            _ => {
                bail!("unknown verb for mq://: {}", verb)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn help_out(verb: &str, args: &[(&str, &str)]) -> Option<String> {
        let h = MQHandle { name: "t".into(), dir: PathBuf::from("/nonexistent-resh-mq-test") };
        let args: Args = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let (mut i, mut o, mut e) = (Cursor::new(Vec::new()), Cursor::new(Vec::new()), Cursor::new(Vec::new()));
        let mut io = IoStreams { stdin: &mut i, stdout: &mut o, stderr: &mut e };
        let r = h.check_and_display_help(verb, &args, &mut io).unwrap();
        r.map(|_| String::from_utf8(o.into_inner()).unwrap())
    }

    #[test]
    fn legacy_help_forms_render_approved_help() {
        assert!(help_out("help", &[]).unwrap().starts_with("Handle: mq"));
        assert!(help_out("-h", &[]).unwrap().starts_with("Handle: mq"));
        assert!(help_out("help", &[("verb", "put")]).unwrap().contains("Verb: put"));
        assert!(help_out("--help=get", &[]).unwrap().contains("Verb: get"));
        assert!(help_out("len", &[("help", "peek")]).unwrap().contains("Verb: peek"));
    }

    #[test]
    fn normal_verbs_are_not_help() {
        assert!(help_out("put", &[("data", "my-hosts")]).is_none());
        assert!(help_out("len", &[]).is_none());
    }
}
