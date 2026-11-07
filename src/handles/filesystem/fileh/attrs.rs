//! Permission, ownership, extended attribute and tag verbs: chmod, chown,
//! ea.get, ea.set, tag.add, tag.rm.

use super::FileHandle;
use super::common::{Code, Opts, emit, fail, invalid, io_code, io_fail};
use crate::core::{IoStreams, Status};
use anyhow::Result;
use base64::prelude::*;
use serde_json::{Value, json};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use walkdir::WalkDir;

/// The extended attribute that holds a file's tags.
pub(crate) const TAG_ATTR: &str = "user.resh.tags";

/// Attribute namespaces Linux knows.
const EA_NAMESPACES: &[&str] = &["user.", "trusted.", "security.", "system."];

/// One ownership change. `follow` is true for the path named in the URL
/// (a symlink there changes its target, like chown(1)) and false for
/// entries inside a recursive tree (a symlink is changed itself, so the
/// walk never changes anything outside the tree).
pub(crate) type ChownOp<'a> =
    dyn FnMut(&Path, Option<u32>, Option<u32>, bool) -> std::io::Result<()> + 'a;

/// The real ownership change.
pub(crate) fn os_chown(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    follow: bool,
) -> std::io::Result<()> {
    if follow {
        std::os::unix::fs::chown(path, uid, gid)
    } else {
        std::os::unix::fs::lchown(path, uid, gid)
    }
}

/// Changes `root` and, when `recursive`, everything below it. Stops at the
/// first failure and says how many entries were already changed. Returns the
/// number of entries changed.
pub(crate) fn chown_tree(
    root: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    recursive: bool,
    op: &mut ChownOp,
) -> Result<usize> {
    op(root, uid, gid, true).map_err(|e| io_fail(format!("chown {}", root.display()), &e))?;
    let mut done = 1usize;
    if recursive && root.is_dir() {
        for entry in WalkDir::new(root)
            .min_depth(1)
            .follow_links(false)
            .sort_by_file_name()
        {
            let partial = |code: Code, what: String| {
                fail(
                    code,
                    format!(
                        "{what} ({done} {} changed before this failure)",
                        if done == 1 {
                            "entry was"
                        } else {
                            "entries were"
                        }
                    ),
                )
            };
            let entry = entry.map_err(|e| {
                let code = e.io_error().map(io_code).unwrap_or(Code::IoError);
                partial(code, format!("chown {}: {e}", root.display()))
            })?;
            op(entry.path(), uid, gid, false).map_err(|e| {
                partial(
                    io_code(&e),
                    format!("chown {}: {e}", entry.path().display()),
                )
            })?;
            done += 1;
        }
    }
    Ok(done)
}

fn lookup_user(name: &str) -> Result<u32> {
    match nix::unistd::User::from_name(name) {
        Ok(Some(u)) => Ok(u.uid.as_raw()),
        Ok(None) => Err(invalid(format!("unknown user: {name:?}"))),
        Err(e) => Err(io_fail(
            format!("look up user {name:?}"),
            &std::io::Error::from(e),
        )),
    }
}

fn lookup_group(name: &str) -> Result<u32> {
    match nix::unistd::Group::from_name(name) {
        Ok(Some(g)) => Ok(g.gid.as_raw()),
        Ok(None) => Err(invalid(format!("unknown group: {name:?}"))),
        Err(e) => Err(io_fail(
            format!("look up group {name:?}"),
            &std::io::Error::from(e),
        )),
    }
}

/// The owner from `name_key` (a name) or `id_key` (a number); giving both is
/// a conflict.
fn owner_arg(
    o: &Opts,
    name_key: &str,
    id_key: &str,
    lookup: fn(&str) -> Result<u32>,
) -> Result<Option<u32>> {
    if o.has(name_key) && o.has(id_key) {
        return Err(invalid(format!(
            "{name_key}= and {id_key}= cannot be used together"
        )));
    }
    if let Some(id) = o.number::<u32>(id_key, 0)? {
        return Ok(Some(id));
    }
    match o.get(name_key) {
        None => Ok(None),
        Some(n) if n.is_empty() || n.starts_with('-') => {
            Err(invalid(format!("invalid value for {name_key}: {n:?}")))
        }
        Some(n) => lookup(n).map(Some),
    }
}

/// A namespaced extended attribute name such as `user.comment`.
fn attr_name<'a>(o: &Opts<'a>) -> Result<&'a str> {
    let name = o.required_nonempty("name")?;
    let ok = EA_NAMESPACES
        .iter()
        .any(|ns| name.starts_with(ns) && name.len() > ns.len())
        && name.len() <= 255
        && !name.contains('\0');
    if !ok {
        return Err(invalid(format!(
            "invalid attribute name {name:?} (expected a namespaced name such as user.comment)"
        )));
    }
    Ok(name)
}

/// A value as JSON text: UTF-8 as is, anything else base64 encoded.
fn decode_value(bytes: Vec<u8>) -> (String, &'static str) {
    match String::from_utf8(bytes) {
        Ok(s) => (s, "utf-8"),
        Err(e) => (BASE64_STANDARD.encode(e.as_bytes()), "base64"),
    }
}

fn c_path(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| {
        invalid(format!(
            "path {:?} contains a NUL byte",
            p.display().to_string()
        ))
    })
}

/// setxattr(2) with XATTR_CREATE / XATTR_REPLACE, so `mode=create` and
/// `mode=update` are checked atomically by the kernel.
fn set_attr(path: &Path, name: &str, value: &[u8], flags: libc::c_int) -> std::io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let cname =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: valid NUL-terminated strings and a buffer of the given length.
    let rc = unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Tags from `name=`: comma-separated, lowercased, `[a-z0-9_.-]+`.
fn parse_tags(raw: &str) -> Result<Vec<String>> {
    let mut tags = Vec::new();
    for t in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let lower = t.to_lowercase();
        let valid = lower
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'));
        if !valid {
            return Err(invalid(format!(
                "invalid tag {t:?} (tags use letters, digits, '_', '-' and '.')"
            )));
        }
        if !tags.contains(&lower) {
            tags.push(lower);
        }
    }
    if tags.is_empty() {
        return Err(invalid("name= must list at least one tag"));
    }
    Ok(tags)
}

fn read_tags(path: &Path, verb: &str) -> Result<Vec<String>> {
    let raw = xattr::get(path, TAG_ATTR)
        .map_err(|e| io_fail(format!("{verb} {}", path.display()), &e))?;
    let Some(bytes) = raw else {
        return Ok(Vec::new());
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        fail(
            Code::IoError,
            format!("{TAG_ATTR} on {} is not UTF-8", path.display()),
        )
    })?;
    Ok(text
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect())
}

fn write_tags(path: &Path, tags: &[String], verb: &str) -> Result<()> {
    let ctx = || format!("{verb} {}", path.display());
    if tags.is_empty() {
        match xattr::remove(path, TAG_ATTR) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENODATA) => Ok(()),
            Err(e) => Err(io_fail(ctx(), &e)),
        }
    } else {
        xattr::set(path, TAG_ATTR, tags.join(",").as_bytes()).map_err(|e| io_fail(ctx(), &e))
    }
}

impl FileHandle {
    pub(super) fn verb_chmod(&self, o: &Opts, _io: &mut IoStreams) -> Result<Status> {
        let Some(mode) = o.octal_mode("mode")? else {
            return Err(invalid("missing argument mode="));
        };
        fs::set_permissions(&self.path, fs::Permissions::from_mode(mode))
            .map_err(|e| io_fail(format!("chmod {}", self.path.display()), &e))?;
        Ok(Status::ok())
    }

    pub(super) fn verb_chown(&self, o: &Opts, _io: &mut IoStreams) -> Result<Status> {
        self.chown_with(o, &mut os_chown)
    }

    /// chown with the ownership change supplied, so tests can observe the
    /// calls without privileges.
    pub(crate) fn chown_with(&self, o: &Opts, op: &mut ChownOp) -> Result<Status> {
        let recursive = o.flag("recursive", false)?;
        if !["user", "uid", "group", "gid"].iter().any(|k| o.has(k)) {
            return Err(invalid(
                "chown needs at least one of user=, uid=, group=, gid=",
            ));
        }
        let uid = owner_arg(o, "user", "uid", lookup_user)?;
        let gid = owner_arg(o, "group", "gid", lookup_group)?;
        fs::metadata(&self.path)
            .map_err(|e| io_fail(format!("chown {}", self.path.display()), &e))?;
        chown_tree(&self.path, uid, gid, recursive, op)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_ea_get(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let name = attr_name(o)?;
        let allow_missing = o.flag("allow_missing", false)?;
        let value = xattr::get(&self.path, name)
            .map_err(|e| io_fail(format!("ea.get {name} on {}", self.path.display()), &e))?;
        let path = self.path.display().to_string();
        let out = match value {
            Some(bytes) => {
                let (value, encoding) = decode_value(bytes);
                let mut v = json!({"path": path, "name": name, "exists": true, "value": value});
                if encoding == "base64" {
                    v["encoding"] = json!(encoding);
                }
                v
            }
            None if allow_missing => {
                json!({"path": path, "name": name, "exists": false, "value": Value::Null})
            }
            None => {
                return Err(fail(
                    Code::AttrNotFound,
                    format!("extended attribute {name} not found on {path}"),
                ));
            }
        };
        emit(io, &out)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_ea_set(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let name = attr_name(o)?;
        let value = o.required("value")?;
        let mode = o
            .choice("mode", &["create", "update", "upsert"])?
            .unwrap_or("upsert");
        let path = &self.path;
        c_path(path)?;
        let ctx = || format!("ea.set {name} on {}", path.display());
        let previous = xattr::get(path, name).map_err(|e| io_fail(ctx(), &e))?;
        let flags = match mode {
            "create" => libc::XATTR_CREATE,
            "update" => libc::XATTR_REPLACE,
            _ => 0,
        };
        if let Err(e) = set_attr(path, name, value.as_bytes(), flags) {
            return Err(match e.raw_os_error() {
                Some(libc::EEXIST) => fail(
                    Code::AlreadyExists,
                    format!("{}: the attribute already exists (mode=create)", ctx()),
                ),
                Some(libc::ENODATA) => fail(
                    Code::AttrNotFound,
                    format!("{}: the attribute does not exist (mode=update)", ctx()),
                ),
                _ => io_fail(ctx(), &e),
            });
        }
        let (prev, encoding) = match previous {
            Some(b) => {
                let (v, enc) = decode_value(b);
                (json!(v), enc)
            }
            None => (Value::Null, "utf-8"),
        };
        emit(
            io,
            &json!({
                "path": path.display().to_string(),
                "name": name,
                "mode": mode,
                "previous": prev,
                "current": value,
                "encoding": encoding
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_tag_add(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let new = parse_tags(o.required("name")?)?;
        let mut tags = read_tags(&self.path, "tag.add")?;
        tags.extend(new);
        tags.sort();
        tags.dedup();
        write_tags(&self.path, &tags, "tag.add")?;
        emit(
            io,
            &json!({"path": self.path.display().to_string(), "tags": tags}),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_tag_rm(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let remove = parse_tags(o.required("name")?)?;
        let mut tags = read_tags(&self.path, "tag.rm")?;
        tags.retain(|t| !remove.contains(t));
        tags.sort();
        tags.dedup();
        write_tags(&self.path, &tags, "tag.rm")?;
        emit(
            io,
            &json!({"path": self.path.display().to_string(), "tags": tags}),
        )?;
        Ok(Status::ok())
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn tags_are_parsed_and_validated() {
        assert_eq!(parse_tags("Work, q3,,work").unwrap(), vec!["work", "q3"]);
        assert!(parse_tags("a b").is_err());
        assert!(parse_tags(" , ").is_err());
        assert!(parse_tags("ünï").is_err());
    }
}
