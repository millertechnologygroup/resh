use anyhow::{Result, bail};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use dirs::state_dir;

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
}

impl Handle for MQHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["create", "put", "get", "len", "purge", "peek"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
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
