//! Verbs that change files: write, append, replace, copy, rename, move/mv,
//! delete/remove.

use super::FileHandle;
use super::common::{
    Code, Opts, TempGuard, create_new_file, dest_from_arg, dest_parent, emit, fail, invalid,
    io_fail, normalize_path, sync_dir, temp_name_in,
};
use super::inspect::open_for_read;
use crate::core::{IoStreams, Status};
use anyhow::{Context, Result};
use serde_json::json;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Metadata of `path` without following a final symlink, or `None` when
/// nothing is there.
fn entry_meta(path: &Path, verb: &str) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(None),
        Err(e) => Err(io_fail(format!("{verb} {}", path.display()), &e)),
    }
}

/// Metadata of the file a write would replace (following symlinks), or
/// `None` when it does not exist yet.
fn target_meta(path: &Path, verb: &str) -> Result<Option<Metadata>> {
    match fs::metadata(path) {
        Ok(m) => {
            if m.is_dir() {
                return Err(fail(
                    Code::IsADirectory,
                    format!("{} is a directory", path.display()),
                ));
            }
            if !m.is_file() {
                return Err(fail(
                    Code::NotAFile,
                    format!("{} is not a regular file", path.display()),
                ));
            }
            Ok(Some(m))
        }
        Err(e) if matches!(e.kind(), ErrorKind::NotFound) => {
            // A dangling symlink is replaced like a missing file, but a
            // missing parent directory component is reported as such.
            Ok(None)
        }
        Err(e) => Err(io_fail(format!("{verb} {}", path.display()), &e)),
    }
}

/// Replaces `path` atomically: the data goes to a new temporary file in the
/// same directory, which is synced and renamed over the target. `perm`
/// sets the permission bits (otherwise the umask default applies), and
/// `owner` (uid, gid) is restored when the process may do so.
fn atomic_replace(
    path: &Path,
    data: &[u8],
    perm: Option<u32>,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let dir = dest_parent(path);
    let tmp = temp_name_in(dir, "tmp");
    let mut guard = TempGuard::new(&tmp);
    let mut f = create_new_file(&tmp, 0o666)
        .with_context(|| format!("create a temporary file in {}", dir.display()))?;
    f.write_all(data)
        .with_context(|| format!("write {}", tmp.display()))?;
    if let Some(m) = perm {
        f.set_permissions(fs::Permissions::from_mode(m))
            .with_context(|| format!("set mode {m:04o} on {}", path.display()))?;
    }
    if let Some((uid, gid)) = owner {
        restore_owner(&f, uid, gid);
    }
    f.sync_all()
        .with_context(|| format!("sync {}", tmp.display()))?;
    drop(f);
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    guard.disarm();
    sync_dir(dir);
    Ok(())
}

/// Gives a replacement file the owner of the file it replaces. Only a
/// privileged process can do that; for others the new file keeps their own
/// ownership, which is what an unprivileged write produces anyway.
fn restore_owner(f: &File, uid: u32, gid: u32) {
    let me = f.metadata().map(|m| (m.uid(), m.gid())).ok();
    if me != Some((uid, gid)) {
        // Best effort by design: EPERM for an unprivileged process is the
        // expected outcome, not a failure of the write.
        let _ = std::os::unix::fs::fchown(f, Some(uid), Some(gid));
    }
}

/// Undoes `\n`, `\t` and `\\` in replacement text.
fn unescape_replacement(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                }
                Some('t') => {
                    chars.next();
                    out.push('\t');
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Literal replacement of at most `limit` occurrences (all when `None`).
fn literal_replace(
    content: &str,
    pattern: &str,
    rep: &str,
    limit: Option<usize>,
) -> (String, usize) {
    let mut out = String::with_capacity(content.len());
    let mut last = 0;
    let mut n = 0;
    for (start, _) in content.match_indices(pattern) {
        if limit.is_some_and(|l| n >= l) {
            break;
        }
        out.push_str(&content[last..start]);
        out.push_str(rep);
        last = start + pattern.len();
        n += 1;
    }
    out.push_str(&content[last..]);
    (out, n)
}

/// Makes `p` absolute (against the working directory) and normalized.
fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        normalize_path(p)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        normalize_path(&cwd.join(p))
    }
}

fn remove_entry(p: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) => Err(e),
    }
}

fn is_exdev(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.raw_os_error() == Some(libc::EXDEV))
}

/// rename(2) of `src` to `dest`. When `dest` exists and rename cannot
/// replace it (a directory on either side), the old destination is first
/// renamed aside, restored if the rename fails, and removed afterwards.
fn rename_replacing(
    src: &Path,
    dest: &Path,
    src_is_dir: bool,
    dest_meta: Option<&Metadata>,
) -> Result<()> {
    let ctx = || format!("rename {} to {}", src.display(), dest.display());
    let needs_aside = dest_meta.is_some_and(|d| d.is_dir() || src_is_dir);
    if !needs_aside {
        return fs::rename(src, dest).with_context(ctx);
    }
    let aside = temp_name_in(dest_parent(dest), "old");
    fs::rename(dest, &aside)
        .with_context(|| format!("set aside the existing {}", dest.display()))?;
    if let Err(e) = fs::rename(src, dest) {
        if let Err(r) = fs::rename(&aside, dest) {
            return Err(fail(
                Code::Partial,
                format!(
                    "{}: {e}; the previous destination could not be put back ({r}) and is at {}",
                    ctx(),
                    aside.display()
                ),
            ));
        }
        return Err(anyhow::Error::new(e).context(ctx()));
    }
    remove_entry(&aside).map_err(|e| {
        fail(
            Code::Partial,
            format!(
                "moved {} to {}, but the previous destination (now at {}) could not be removed: {e}",
                src.display(),
                dest.display(),
                aside.display()
            ),
        )
    })
}

/// Copies a file, symlink or directory tree to `dst` (which must not
/// exist), keeping permission bits and modification times, and ownership
/// when the process may set it. Special files cannot be copied.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("copy {}", src.display()))?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(src).with_context(|| format!("read link {}", src.display()))?;
        std::os::unix::fs::symlink(&target, dst)
            .with_context(|| format!("create link {}", dst.display()))?;
        // Best effort, as in restore_owner.
        let _ = std::os::unix::fs::lchown(dst, Some(meta.uid()), Some(meta.gid()));
        return Ok(());
    }
    if ft.is_dir() {
        fs::create_dir(dst).with_context(|| format!("create directory {}", dst.display()))?;
        for entry in
            fs::read_dir(src).with_context(|| format!("read directory {}", src.display()))?
        {
            let entry = entry.with_context(|| format!("read directory {}", src.display()))?;
            copy_tree(&entry.path(), &dst.join(entry.file_name()))?;
        }
        // Best effort, as in restore_owner.
        let _ = std::os::unix::fs::lchown(dst, Some(meta.uid()), Some(meta.gid()));
    } else if ft.is_file() {
        let mut input = File::open(src).with_context(|| format!("open {}", src.display()))?;
        let mut out =
            create_new_file(dst, 0o600).with_context(|| format!("create {}", dst.display()))?;
        std::io::copy(&mut input, &mut out)
            .with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
        restore_owner(&out, meta.uid(), meta.gid());
        out.sync_all()
            .with_context(|| format!("sync {}", dst.display()))?;
    } else {
        return Err(fail(
            Code::NotAFile,
            format!("{} is a special file and cannot be copied", src.display()),
        ));
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & 0o7777))
        .with_context(|| format!("set mode on {}", dst.display()))?;
    let times = fs::FileTimes::new()
        .set_accessed(
            meta.accessed()
                .with_context(|| format!("read times of {}", src.display()))?,
        )
        .set_modified(
            meta.modified()
                .with_context(|| format!("read times of {}", src.display()))?,
        );
    File::open(dst)
        .and_then(|f| f.set_times(times))
        .with_context(|| format!("set times on {}", dst.display()))?;
    Ok(())
}

struct Relocate<'a> {
    verb: &'a str,
    overwrite: bool,
    create_parents: bool,
    atomic: bool,
}

/// Moves `src` to `dest`. Returns whether the data had to be copied across
/// filesystems. Nothing is changed when a check fails.
fn relocate(src: &Path, dest: &Path, r: &Relocate) -> Result<bool> {
    let verb = r.verb;
    let src_meta =
        fs::symlink_metadata(src).with_context(|| format!("{verb} {}", src.display()))?;
    if src == dest {
        return Ok(false);
    }
    let src_name = src.file_name().is_some() && src != Path::new("/");
    if !src_name {
        return Err(fail(
            Code::Refused,
            format!("cannot {verb} {}", src.display()),
        ));
    }
    if src_meta.is_dir() {
        let (a, b) = (absolute(src), absolute(dest));
        if b != a && b.starts_with(&a) {
            return Err(fail(
                Code::Refused,
                format!(
                    "cannot {verb} directory {} into itself ({})",
                    src.display(),
                    dest.display()
                ),
            ));
        }
    }
    let parent = dest_parent(dest);
    let parent_is_dir = parent.is_dir();
    if !parent_is_dir {
        if fs::symlink_metadata(parent).is_ok() {
            return Err(fail(
                Code::NotFound,
                format!(
                    "destination parent is not a directory: {}",
                    parent.display()
                ),
            ));
        }
        if !r.create_parents {
            return Err(fail(
                Code::NotFound,
                format!("destination parent does not exist: {}", parent.display()),
            ));
        }
    }
    let dest_meta = entry_meta(dest, verb)?;
    if let Some(dm) = &dest_meta {
        if dm.dev() == src_meta.dev() && dm.ino() == src_meta.ino() {
            // Two names for the same file: rename(2) does nothing here.
            return Ok(false);
        }
        if !r.overwrite {
            return Err(fail(
                Code::AlreadyExists,
                format!(
                    "destination exists: {} (use overwrite=true)",
                    dest.display()
                ),
            ));
        }
    }
    if !parent_is_dir {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directories {}", parent.display()))?;
    }

    let parent_dev = fs::metadata(parent)
        .with_context(|| format!("{verb} to {}", parent.display()))?
        .dev();
    if parent_dev == src_meta.dev() {
        match rename_replacing(src, dest, src_meta.is_dir(), dest_meta.as_ref()) {
            Ok(()) => return Ok(false),
            Err(e) if is_exdev(&e) => {}
            Err(e) => return Err(e),
        }
    }

    // Across filesystems: copy, then remove the source.
    if r.atomic {
        // Copy to a temporary name next to the destination, then rename it
        // into place, so the destination appears complete or not at all.
        let tmp = temp_name_in(parent, "tmp");
        let mut guard = TempGuard::new(&tmp);
        copy_tree(src, &tmp)?;
        rename_replacing(&tmp, dest, src_meta.is_dir(), dest_meta.as_ref())?;
        guard.disarm();
    } else {
        if dest_meta.is_some() {
            remove_entry(dest)
                .with_context(|| format!("remove the existing {}", dest.display()))?;
        }
        let mut guard = TempGuard::new(dest);
        copy_tree(src, dest)?;
        guard.disarm();
    }
    sync_dir(parent);
    remove_entry(src).map_err(|e| {
        fail(
            Code::Partial,
            format!(
                "copied {} to {}, but the source could not be removed: {e}",
                src.display(),
                dest.display()
            ),
        )
    })?;
    Ok(true)
}

impl FileHandle {
    pub(super) fn verb_write(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let create = o.flag("create", true)?;
        let mode = o.octal_mode("mode")?;
        let path = &self.path;
        let existing = target_meta(path, "write")?;
        if existing.is_none() && !create {
            return Err(fail(
                Code::NotFound,
                format!("{} does not exist and create=false", path.display()),
            ));
        }
        let data = self.data_arg(o, io)?;
        let parent = dest_parent(path);
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directories {}", parent.display()))?;
        }
        let perm = mode.or(existing.as_ref().map(|m| m.mode() & 0o7777));
        let owner = existing.as_ref().map(|m| (m.uid(), m.gid()));
        atomic_replace(path, &data, perm, owner)?;
        emit(
            io,
            &json!({"written": true, "bytes": data.len(), "path": path.display().to_string()}),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_append(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let create = o.flag("create", true)?;
        let path = &self.path;
        let existing = target_meta(path, "append")?;
        if existing.is_none() && !create {
            return Err(fail(
                Code::NotFound,
                format!("{} does not exist and create=false", path.display()),
            ));
        }
        let data = self.data_arg(o, io)?;
        let parent = dest_parent(path);
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directories {}", parent.display()))?;
        }
        let mut f = OpenOptions::new()
            .append(true)
            .create(create)
            .open(path)
            .with_context(|| format!("append {}", path.display()))?;
        f.write_all(&data)
            .with_context(|| format!("append {}", path.display()))?;
        f.sync_data()
            .with_context(|| format!("sync {}", path.display()))?;
        emit(
            io,
            &json!({"appended": true, "bytes": data.len(), "path": path.display().to_string()}),
        )?;
        Ok(Status::ok())
    }

    /// `data=` or, without it, standard input until EOF.
    fn data_arg(&self, o: &Opts, io: &mut IoStreams) -> Result<Vec<u8>> {
        match o.get("data") {
            Some(d) => Ok(d.as_bytes().to_vec()),
            None => {
                let mut buf = Vec::new();
                io.stdin
                    .read_to_end(&mut buf)
                    .context("read data from standard input")?;
                Ok(buf)
            }
        }
    }

    pub(super) fn verb_replace(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let pattern = o.required_nonempty("pattern")?;
        let replacement = unescape_replacement(o.required("replacement")?);
        let use_regex = o.flag("regex", false)?;
        let count = o.number::<usize>("count", 1)?;
        let dry_run = o.flag("dry_run", false)?;
        let backup = match o.get("backup") {
            None => None,
            Some(s) if s.is_empty() || s.contains('/') || s.contains('\0') => {
                return Err(invalid(format!(
                    "invalid value for backup: {s:?} (expected a file name suffix such as .bak)"
                )));
            }
            Some(s) => Some(s),
        };
        let re = if use_regex {
            Some(
                regex::Regex::new(pattern)
                    .map_err(|e| invalid(format!("invalid regex pattern: {e}")))?,
            )
        } else {
            None
        };

        let path = &self.path;
        let (mut f, meta) = open_for_read(path, "replace")?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)
            .with_context(|| format!("read {}", path.display()))?;
        let content = String::from_utf8(bytes).map_err(|_| {
            fail(
                Code::NotUtf8,
                format!("{} is not UTF-8 text", path.display()),
            )
        })?;

        let (new_content, replacements) = match &re {
            Some(re) => {
                let found = re.find_iter(&content).count();
                let n = count.map_or(found, |c| found.min(c));
                let out = re.replacen(&content, count.unwrap_or(0), replacement.as_str());
                (out.into_owned(), n)
            }
            None => literal_replace(&content, pattern, &replacement, count),
        };

        if !dry_run && replacements > 0 {
            if let Some(suffix) = backup {
                let mut name = path.as_os_str().to_owned();
                name.push(suffix);
                let backup_path = PathBuf::from(name);
                crate::core::secure_fs::copy_no_follow(path, &backup_path)
                    .with_context(|| format!("create backup {}", backup_path.display()))?;
            }
            atomic_replace(
                path,
                new_content.as_bytes(),
                Some(meta.mode() & 0o7777),
                Some((meta.uid(), meta.gid())),
            )?;
        }
        emit(
            io,
            &json!({
                "path": path.to_string_lossy(),
                "pattern": pattern,
                "regex": use_regex,
                "count_limit": count,
                "replacements": replacements,
                "changed": replacements > 0 && !dry_run,
                "original_bytes": content.len(),
                "new_bytes": new_content.len(),
                "dry_run": dry_run
            }),
        )?;
        Ok(Status::ok())
    }

    pub(super) fn verb_copy(&self, o: &Opts, _io: &mut IoStreams) -> Result<Status> {
        let to = o.required_nonempty("to")?;
        let overwrite = o.flag("overwrite", false)?;
        let preserve_mode = o.flag("preserve_mode", true)?;
        let preserve_times = o.flag("preserve_times", false)?;

        let (mut src, meta) = open_for_read(&self.path, "copy")?;
        let dest = dest_from_arg(to);
        let parent = dest_parent(&dest);
        if !parent.is_dir() {
            return Err(fail(
                Code::NotFound,
                format!("destination parent does not exist: {}", parent.display()),
            ));
        }
        if let Some(dm) = entry_meta(&dest, "copy")? {
            if dm.is_dir() {
                return Err(fail(
                    Code::IsADirectory,
                    format!("destination {} is a directory", dest.display()),
                ));
            }
            if !overwrite {
                return Err(fail(
                    Code::AlreadyExists,
                    format!(
                        "destination exists: {} (use overwrite=true)",
                        dest.display()
                    ),
                ));
            }
        }

        let tmp = temp_name_in(parent, "tmp");
        let mut guard = TempGuard::new(&tmp);
        let mut out = create_new_file(&tmp, 0o666)
            .with_context(|| format!("create a temporary file in {}", parent.display()))?;
        std::io::copy(&mut src, &mut out)
            .with_context(|| format!("copy {} to {}", self.path.display(), dest.display()))?;
        if preserve_mode {
            out.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))
                .with_context(|| format!("preserve mode on {}", dest.display()))?;
        }
        if preserve_times {
            let times = fs::FileTimes::new()
                .set_accessed(meta.accessed().context("read access time")?)
                .set_modified(meta.modified().context("read modification time")?);
            out.set_times(times)
                .with_context(|| format!("preserve times on {}", dest.display()))?;
        }
        out.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
        drop(out);
        fs::rename(&tmp, &dest).with_context(|| format!("copy to {}", dest.display()))?;
        guard.disarm();
        sync_dir(parent);
        Ok(Status::ok())
    }

    pub(super) fn verb_rename(&self, o: &Opts, io: &mut IoStreams) -> Result<Status> {
        let to = o.required_nonempty("to")?;
        let r = Relocate {
            verb: "rename",
            overwrite: o.flag("overwrite", false)?,
            create_parents: o.flag("create_parents", false)?,
            atomic: o.flag("atomic", true)?,
        };
        let dest = dest_from_arg(to);
        let cross = relocate(&self.path, &dest, &r)?;
        let mut out = json!({
            "renamed": true,
            "from": self.path.display().to_string(),
            "to": dest.display().to_string()
        });
        if cross {
            out["cross_filesystem"] = json!(true);
        }
        emit(io, &out)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_move(&self, o: &Opts, _io: &mut IoStreams) -> Result<Status> {
        let to = o.required_nonempty("to")?;
        let r = Relocate {
            verb: o.verb(),
            overwrite: o.flag("overwrite", false)?,
            create_parents: false,
            atomic: true,
        };
        fs::symlink_metadata(&self.path)
            .with_context(|| format!("{} {}", r.verb, self.path.display()))?;
        let mut dest = dest_from_arg(to);
        if dest.is_dir() {
            let Some(name) = self.path.file_name() else {
                return Err(fail(
                    Code::Refused,
                    format!("cannot {} {}", r.verb, self.path.display()),
                ));
            };
            dest = dest.join(name);
        }
        relocate(&self.path, &dest, &r)?;
        Ok(Status::ok())
    }

    pub(super) fn verb_delete(&self, o: &Opts, _io: &mut IoStreams) -> Result<Status> {
        let recursive = o.flag("recursive", false)?;
        let force = o.flag("force", false)?;
        let missing_ok = o.flag("missing_ok", false)?;
        let path = &self.path;

        let refused = path.as_os_str().is_empty()
            || path == Path::new("/")
            || path == Path::new(".")
            || matches!(path.components().next_back(), Some(Component::ParentDir));
        if refused {
            return Err(fail(
                Code::Refused,
                format!("refusing to delete {:?}", path.display().to_string()),
            ));
        }

        let Some(meta) = entry_meta(path, o.verb())? else {
            if force || missing_ok {
                return Ok(Status::ok());
            }
            return Err(fail(
                Code::NotFound,
                format!("path not found: {}", path.display()),
            ));
        };
        if meta.is_dir() {
            if !recursive {
                return Err(fail(
                    Code::IsADirectory,
                    format!("{} is a directory; use recursive=true", path.display()),
                ));
            }
            fs::remove_dir_all(path).map_err(|e| {
                io_fail(
                    format!(
                        "delete {} (part of the tree may already be deleted)",
                        path.display()
                    ),
                    &e,
                )
            })?;
        } else {
            fs::remove_file(path).map_err(|e| io_fail(format!("delete {}", path.display()), &e))?;
        }
        Ok(Status::ok())
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn literal_replace_limits() {
        assert_eq!(literal_replace("aaa", "a", "b", None), ("bbb".into(), 3));
        assert_eq!(literal_replace("aaa", "a", "b", Some(2)), ("bba".into(), 2));
        assert_eq!(literal_replace("abc", "x", "y", None), ("abc".into(), 0));
    }

    #[test]
    fn replacement_escapes() {
        assert_eq!(unescape_replacement(r"a\nb\tc\\d\q"), "a\nb\tc\\d\\q");
    }
}
