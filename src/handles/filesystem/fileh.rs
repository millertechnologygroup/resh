//! The `file://` handle: reads, writes, inspects, hashes and searches local
//! files and directories, and manages permissions, ownership, extended
//! attributes and tags.
//!
//! The verbs live in submodules by area; this file holds the help metadata
//! (which is also the list of options each verb accepts, see
//! [`common::verb_options`]), URL parsing and dispatch.

mod attrs;
mod common;
mod digest;
mod inspect;
mod modify;
mod search;
#[cfg(test)]
mod tests;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use anyhow::Result;
use common::{Opts, invalid, normalize_path, status_of, unescape_backslashes};
use percent_encoding::percent_decode_str;
use std::path::PathBuf;
use url::Url;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("file", |u| Ok(Box::new(FileHandle::from_url(u.clone())?)));
}

/// The operation verbs, in help order (the help aliases `help` and `h` are
/// registered too).
const OPERATION_VERBS: &[&str] = &[
    "read", "exists", "stat", "preview", "summary", "analyze", "schema", "tail", "grep", "find",
    "watch", "md5", "sha1", "sha256", "sha512", "hash", "verify", "write", "append", "replace",
    "copy", "rename", "move", "mv", "delete", "remove", "chmod", "chown", "ea.get", "ea.set",
    "tag.add", "tag.rm",
];

/// Metadata for `resh file --help` and `resh file <verb> --help`.
static FILE_HELP: HandleHelp = HandleHelp {
    description: "The file handle reads, writes, inspects, hashes, and searches files and \
        directories on the local filesystem, and on Unix also manages permissions, ownership, \
        extended attributes, and tags. It uses the Rust standard library for file I/O, the \
        xattr crate for extended attributes, and the notify crate for change watching. The \
        target is the path after file://: absolute paths take three slashes, as in \
        file:///var/log/syslog, and relative paths such as file://data.txt or \
        file://./logs/app.log resolve from the current directory, except that URL parsing \
        lowercases the first segment of a relative path and drops a leading localhost, so \
        write file://./Report.txt for a mixed-case relative name.",
    usage: "resh file://<path>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "read",
            definition: "Prints the entire contents of a file to standard output.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.read [timeout_ms=<ms>]",
                example: "resh file:///etc/hostname.read",
                example_output: Some("web01"),
            }),
        },
        VerbHelp {
            name: "exists",
            definition: "Reports whether a path exists and whether it is a file, directory, \
                or symlink, as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.exists",
                example: "resh --json-pretty file:///etc/hosts.exists",
                example_output: Some(
                    r#"{
  "exists": true,
  "kind": "file",
  "path": "/etc/hosts"
}

A missing path reports exists false and kind none. Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "stat",
            definition: "Reports a path's type, size, permissions, ownership, and timestamps \
                as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.stat [nofollow=true|false]",
                example: "resh --json-pretty file:///etc/hosts.stat",
                example_output: Some(
                    r#"{
  "accessed": "2026-10-16T08:01:12.442193+00:00",
  "created": "2026-03-02T14:20:05.118374+00:00",
  "exists": true,
  "file_type": "file",
  "gid": 0,
  "mode": "0644",
  "modified": "2026-03-02T14:20:05.118374+00:00",
  "path": "/etc/hosts",
  "readonly": false,
  "size": 220,
  "uid": 0
}

Shown for a Unix host with --json-pretty. On other platforms mode, uid,
and gid are null, and created is null where the filesystem lacks it."#,
                ),
            }),
        },
        VerbHelp {
            name: "preview",
            definition: "Reads the first bytes and lines of a file and reports them as a JSON \
                object, base64 or hex encoding the sample when the content is binary.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.preview [max_bytes=<n>] [max_lines=<n>]\n  \
                    [mode=auto|text|binary] [encoding=base64|hex]\n  \
                    [include_metadata=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///etc/hosts.preview max_lines=2",
                example_output: Some(
                    r#"{
  "encoding": "utf-8",
  "file_size_bytes": 220,
  "is_truncated": false,
  "line_count": 2,
  "metadata": {
    "exists": true,
    "is_dir": false,
    "is_file": true,
    "modified": "2026-03-02T14:20:05.118374+00:00",
    "permissions": "0644"
  },
  "mode": "text",
  "path": "/etc/hosts",
  "preview_len_bytes": 220,
  "sample": "127.0.0.1 localhost\n::1 localhost"
}

Shown for a text file with --json-pretty. Binary samples report mode
binary, line_count null, and encoding base64 or hex."#,
                ),
            }),
        },
        VerbHelp {
            name: "summary",
            definition: "Summarizes a file's size, modification time, content type, and line \
                statistics, or a directory's entry count, as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.summary [max_bytes=<n>] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.summary",
                example_output: Some(
                    r#"{
  "avg_line_length": 16.0,
  "content_type": "csv",
  "exists": true,
  "is_dir": false,
  "line_count": 3,
  "modified": "2026-10-16T15:52:21.053651+00:00",
  "path": "/srv/data/users.csv",
  "sample": "id,name,joined\n1,alice,2026-01-05\n2,bob,2026-02-11\n",
  "size": 51
}

Shown for a CSV file with --json-pretty. Directories report only path,
exists, is_dir, and entry_count."#,
                ),
            }),
        },
        VerbHelp {
            name: "analyze",
            definition: "Samples a file and reports its ASCII ratio, byte entropy, line count, \
                and a json, csv, log, text, or binary classification as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.analyze [max_bytes=<n>] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///var/log/app.log.analyze",
                example_output: Some(
                    r#"{
  "ascii_ratio": 1.0,
  "classification": "text",
  "entropy": 4.004247855285173,
  "format_hints": {
    "is_csv": false,
    "is_json": false,
    "is_log_like": false
  },
  "line_count": 4,
  "null_byte_present": false,
  "path": "/var/log/app.log",
  "sample_bytes": 48,
  "size_bytes": 48
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "schema",
            definition: "Detects whether a file is JSON, NDJSON, CSV, TSV, or plain text and \
                reports its inferred structure as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.schema [format=json|ndjson|csv|tsv|text]\n  \
                    [max_bytes=<n>] [max_rows=<n>] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.schema",
                example_output: Some(
                    r#"{
  "byte_sample": 51,
  "detected": {
    "columns": [
      {
        "name": "id",
        "types": [
          "integer"
        ]
      },
      {
        "name": "joined",
        "types": [
          "datetime"
        ]
      }
    ],
    "delimiter": ",",
    "has_header": true,
    "row_count_sampled": 2
  },
  "encoding": "utf-8",
  "format": "csv",
  "path": "/srv/data/users.csv"
}

Shown for a CSV file with --json-pretty, with one column omitted. The
detected object has different fields for JSON, NDJSON, and text input."#,
                ),
            }),
        },
        VerbHelp {
            name: "tail",
            definition: "Prints the last lines or bytes of a file, defaulting to 10 lines, and \
                with follow=true keeps printing data appended to it.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.tail [lines=<n>] [bytes=<n>] \
                    [follow=true|false]\n  [timeout_ms=<ms>]",
                example: "resh file:///var/log/syslog.tail lines=2",
                example_output: Some(
                    "Oct 16 09:12:44 web01 systemd[1]: Started nginx.service.\n\
                     Oct 16 09:13:02 web01 CRON[2211]: (root) CMD (run-parts /etc/cron.hourly)",
                ),
            }),
        },
        VerbHelp {
            name: "grep",
            definition: "Searches a file line by line for a regular expression or literal \
                text and prints the matching lines with their line numbers.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.grep pattern=<pattern> [regex=true|false]\n  \
                    [ignore_case=true|false] [invert=true|false] [max=<n>]\n  \
                    [before=<n>] [after=<n>] [format=text|json]\n  \
                    [line_numbers=true|false] [timeout_ms=<ms>]",
                example: "resh file:///var/log/app.log.grep pattern=error ignore_case=true",
                example_output: Some(
                    "2:ERROR disk full\n\
                     4:error again\n\
                     \n\
                     The pattern is a regular expression unless regex=false. With\n\
                     format=json, matches print as an array of objects with path, line,\n\
                     text, and matched fields.",
                ),
            }),
        },
        VerbHelp {
            name: "find",
            definition: "Walks a directory tree and lists matching entries with their type, \
                size, mode, and modification time as a JSON array.",
            detail: Some(VerbDetail {
                usage: "resh file://<dir>.find [name=<glob>] [type=file|dir|symlink]\n  \
                    [max_depth=<n>] [limit=<n>] [include_hidden=true|false]\n  \
                    [follow_symlinks=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/www.find name='*.html' type=file",
                example_output: Some(
                    r#"[
  {
    "depth": 1,
    "is_hidden": false,
    "mode": "0644",
    "mtime": "2026-09-30T17:45:10.902113+00:00",
    "path": "/srv/www/index.html",
    "size": 5120,
    "type": "file"
  }
]

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "watch",
            definition: "Watches a path for create, modify, remove, and rename events and \
                prints each one as a line of JSON until max_events or timeout_ms is reached.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.watch [timeout_ms=<ms>] [max_events=<n>]\n  \
                    [events=create,modify,remove,rename]",
                example: "resh file:///etc/nginx/nginx.conf.watch events=modify \
                    timeout_ms=60000",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "md5",
            definition: "Computes the MD5 digest of a file and reports it with the file size \
                as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.md5 [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.md5",
                example_output: Some(
                    r#"{
  "algorithm": "md5",
  "hash": "d8dc1c6300e5fa108ffbd95730a9ac2e",
  "path": "/srv/data/users.csv",
  "size": 51
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "sha1",
            definition: "Computes the SHA-1 digest of a file and reports it with the file \
                size as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.sha1 [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.sha1",
                example_output: Some(
                    r#"{
  "algorithm": "sha1",
  "hash": "1509a8b17ac3590783ec2ee08d0a104333b6ecbd",
  "path": "/srv/data/users.csv",
  "size": 51
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "sha256",
            definition: "Computes the SHA-256 digest of a file and reports it with the file \
                size as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.sha256 [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.sha256",
                example_output: Some(
                    r#"{
  "algorithm": "sha256",
  "hash": "8ce5f37fbff5c2cf2dfe59511587fd29e7a55104ab1629ac0b646bc6bdddc049",
  "path": "/srv/data/users.csv",
  "size": 51
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "sha512",
            definition: "Computes the SHA-512 digest of a file and reports it with the file \
                size as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.sha512 [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.sha512",
                example_output: Some(
                    r#"{
  "algorithm": "sha512",
  "hash": "d7cb064f0a32ab92d3268f23...d0d7848436f4987102",
  "path": "/srv/data/users.csv",
  "size": 51
}

The 128-digit hash is shortened here to fit. Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "hash",
            definition: "Computes a SHA-256, SHA-512, SHA-1, MD5, or BLAKE3 digest of a \
                regular file, defaulting to SHA-256, and reports it as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.hash [algo=sha256|sha512|sha1|md5|blake3]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.hash algo=blake3",
                example_output: Some(
                    r#"{
  "algo": "blake3",
  "hash_hex": "148ae65478551f4df22f13b148664e39...3b50bcface7c2564",
  "path": "/srv/data/users.csv",
  "size_bytes": 51
}

The 64-digit hash is shortened here to fit. Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "verify",
            definition: "Computes a file's digest and checks it against expected values and an \
                optional size, reporting the result as JSON and failing on a mismatch.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.verify [algo=sha256|sha512|sha1|md5|blake3]\n  \
                    [expected=<hex>] [expected_any=<hex>;<hex>...] [size=<bytes>]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/users.csv.verify algo=md5 \
                    size=51",
                example_output: Some(
                    r#"{
  "algorithm": "md5",
  "digest": "d8dc1c6300e5fa108ffbd95730a9ac2e",
  "error": null,
  "expected": null,
  "expected_any": [],
  "match": true,
  "path": "/srv/data/users.csv",
  "size": 51,
  "size_match": true,
  "verified": true
}

Shown with --json-pretty. A wrong expected digest or size sets verified
to false and exits with status 1."#,
                ),
            }),
        },
        VerbHelp {
            name: "write",
            definition: "Atomically replaces a file's contents with the data argument or \
                standard input and reports the bytes written as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.write [data=<text>] [create=true|false] \
                    [mode=<octal>]\n  [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///tmp/greeting.txt.write \
                    data='hello world'",
                example_output: Some(
                    r#"{
  "bytes": 11,
  "path": "/tmp/greeting.txt",
  "written": true
}

Shown with --json-pretty. Without data, the content is read from stdin."#,
                ),
            }),
        },
        VerbHelp {
            name: "append",
            definition: "Appends the data argument or standard input to the end of a file and \
                reports the bytes appended as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.append [data=<text>] [create=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///var/tmp/jobs.log.append \
                    data='job finished'",
                example_output: Some(
                    r#"{
  "appended": true,
  "bytes": 12,
  "path": "/var/tmp/jobs.log"
}

Shown with --json-pretty. No newline is added after the data."#,
                ),
            }),
        },
        VerbHelp {
            name: "replace",
            definition: "Replaces literal text or regular expression matches in a file, \
                rewriting it atomically, and reports the replacement count as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.replace pattern=<text> replacement=<text>\n  \
                    [regex=true|false] [count=<n>] [dry_run=true|false]\n  \
                    [backup=<suffix>] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///etc/app.conf.replace pattern=8080 \
                    replacement=9090",
                example_output: Some(
                    r#"{
  "changed": true,
  "count_limit": null,
  "dry_run": false,
  "new_bytes": 412,
  "original_bytes": 412,
  "path": "/etc/app.conf",
  "pattern": "8080",
  "regex": false,
  "replacements": 2
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "copy",
            definition: "Copies a regular file to the path given by to through a temporary \
                file and prints nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.copy to=<path> [overwrite=true|false]\n  \
                    [preserve_mode=true|false] [preserve_times=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh file:///etc/nginx/nginx.conf.copy \
                    to=/etc/nginx/nginx.conf.bak",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "rename",
            definition: "Renames a file or directory to the path given by to, copying across \
                filesystems when needed, and reports the result as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.rename to=<path> [overwrite=true|false]\n  \
                    [create_parents=true|false] [atomic=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty file:///srv/data/old.csv.rename \
                    to=/srv/data/new.csv",
                example_output: Some(
                    r#"{
  "from": "/srv/data/old.csv",
  "renamed": true,
  "to": "/srv/data/new.csv"
}

Shown for a same-filesystem rename with --json-pretty. A rename across
filesystems also reports cross_filesystem as true."#,
                ),
            }),
        },
        VerbHelp {
            name: "move",
            definition: "Moves a file or directory to the path given by to, or into it when to \
                is an existing directory, and prints nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.move to=<path> [overwrite=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh file:///tmp/report.pdf.move to=/srv/reports",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "mv",
            definition: "Alias for move.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.mv to=<path> [overwrite=true|false]\n  \
                    [timeout_ms=<ms>]",
                example: "resh file:///tmp/report.pdf.mv to=/srv/reports/q3.pdf",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "delete",
            definition: "Deletes a file, or a directory tree when recursive=true, and prints \
                nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.delete [recursive=true|false] \
                    [force=true|false]\n  [missing_ok=true|false] [timeout_ms=<ms>]",
                example: "resh file:///tmp/build.cache.delete recursive=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "remove",
            definition: "Alias for delete.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.remove [recursive=true|false] \
                    [force=true|false]\n  [missing_ok=true|false] [timeout_ms=<ms>]",
                example: "resh file:///tmp/old.log.remove missing_ok=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "chmod",
            definition: "Sets a file's permission bits from an octal mode on Unix and prints \
                nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.chmod mode=<octal>",
                example: "resh file:///usr/local/bin/backup.sh.chmod mode=755",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "chown",
            definition: "Changes a path's owner and group by name or numeric ID on Unix, \
                optionally recursively, and prints nothing on success.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.chown [user=<name>] [uid=<n>] [group=<name>]\n  \
                    [gid=<n>] [recursive=true|false] [timeout_ms=<ms>]",
                example: "resh file:///srv/www.chown user=alice group=www recursive=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "ea.get",
            definition: "Reads one extended attribute of a file on Unix and reports its value \
                as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.ea.get name=<attr> [allow_missing=true|false]",
                example: "resh --json-pretty file:///srv/data/report.pdf.ea.get \
                    name=user.comment",
                example_output: Some(
                    r#"{
  "exists": true,
  "name": "user.comment",
  "path": "/srv/data/report.pdf",
  "value": "reviewed by alice"
}

Shown with --json-pretty. Non-UTF-8 values are base64 encoded and add
an encoding field."#,
                ),
            }),
        },
        VerbHelp {
            name: "ea.set",
            definition: "Writes an extended attribute on a file on Unix and reports its \
                previous and current values as a JSON object.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.ea.set name=<attr> value=<text>\n  \
                    [mode=create|update|upsert]",
                example: "resh --json-pretty file:///srv/report.pdf.ea.set \
                    name=user.comment value=final",
                example_output: Some(
                    r#"{
  "current": "final",
  "encoding": "utf-8",
  "mode": "upsert",
  "name": "user.comment",
  "path": "/srv/report.pdf",
  "previous": "reviewed by alice"
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "tag.add",
            definition: "Adds comma-separated lowercase tags to a file, stored in the \
                user.resh.tags extended attribute, and reports the full tag list as JSON.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.tag.add name=<tag>[,<tag>...]",
                example: "resh --json-pretty file:///srv/data/report.pdf.tag.add \
                    name=work,q3",
                example_output: Some(
                    r#"{
  "path": "/srv/data/report.pdf",
  "tags": [
    "q3",
    "work"
  ]
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "tag.rm",
            definition: "Removes comma-separated tags from a file's user.resh.tags extended \
                attribute and reports the remaining tag list as JSON.",
            detail: Some(VerbDetail {
                usage: "resh file://<path>.tag.rm name=<tag>[,<tag>...]",
                example: "resh --json-pretty file:///srv/data/report.pdf.tag.rm name=q3",
                example_output: Some(
                    r#"{
  "path": "/srv/data/report.pdf",
  "tags": [
    "work"
  ]
}

Shown with --json-pretty."#,
                ),
            }),
        },
    ],
};

pub struct FileHandle {
    path: PathBuf,
}

/// Placeholder path used for an in-URL help request.
const HELP_PATH: &str = "--help";

/// Joins the URL host and path into the target path, like the other handles
/// do: `file://./x` is `./x`, `file://dir/x` is `dir/x`, `file://name` is
/// `name`, and `file:///abs` is `/abs`.
///
/// The `url` crate treats `file` as a special scheme, so a relative first
/// segment in the host position is lowercased (`file://Dir/x` is `dir/x`)
/// and `localhost` is dropped (`file://localhost/x` is `/x`).
fn url_target_path(url: &Url) -> String {
    let path = url.path();
    match url.host_str().filter(|h| !h.is_empty()) {
        Some(host) if path.is_empty() || path == "/" => host.to_string(),
        Some(host) => format!("{}{}", host, path),
        None => path.to_string(),
    }
}

impl FileHandle {
    pub fn from_url(url: Url) -> Result<FileHandle, anyhow::Error> {
        let path_str = url_target_path(&url);

        // Decode URL encoding and escape sequences
        let decoded = percent_decode_str(&path_str)
            .decode_utf8_lossy()
            .to_string();
        let unescaped = unescape_backslashes(&decoded);

        // In-URL help (file://--help, file://-h). Exact match only, so a
        // target such as my-hosts or pre-hotfix.txt is a normal file.
        if crate::core::help::is_help_flag(&unescaped) {
            return Ok(FileHandle {
                path: PathBuf::from(HELP_PATH),
            });
        }

        Ok(FileHandle {
            path: normalize_path(&PathBuf::from(unescaped)),
        })
    }

    /// Writes the approved help, for one verb when `verb=<name>` is given.
    fn write_help(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let verb = args.get("verb").map(String::as_str);
        write!(
            io.stdout,
            "{}",
            crate::core::help::render_legacy("file", &FILE_HELP, self.verbs(), verb)
        )?;
        Ok(Status::ok())
    }

    /// Validates the arguments and runs one operation verb.
    fn dispatch(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if !OPERATION_VERBS.contains(&verb) {
            return Err(invalid(format!(
                "unknown verb for file://: {verb} (available: {})",
                OPERATION_VERBS.join(", ")
            )));
        }
        if self.path.as_os_str().is_empty() {
            return Err(invalid("missing path: use file://<path>.<verb>"));
        }
        let o = Opts::new(verb, args)?;
        match verb {
            "read" => self.verb_read(&o, io),
            "exists" => self.verb_exists(&o, io),
            "stat" => self.verb_stat(&o, io),
            "preview" => self.verb_preview(&o, io),
            "summary" => self.verb_summary(&o, io),
            "analyze" => self.verb_analyze(&o, io),
            "schema" => self.verb_schema(&o, io),
            "tail" => self.verb_tail(&o, io),
            "grep" => self.verb_grep(&o, io),
            "find" => self.verb_find(&o, io),
            "watch" => self.verb_watch(&o, io),
            "md5" | "sha1" | "sha256" | "sha512" => self.verb_fixed_hash(&o, io),
            "hash" => self.verb_hash(&o, io),
            "verify" => self.verb_verify(&o, io),
            "write" => self.verb_write(&o, io),
            "append" => self.verb_append(&o, io),
            "replace" => self.verb_replace(&o, io),
            "copy" => self.verb_copy(&o, io),
            "rename" => self.verb_rename(&o, io),
            "move" | "mv" => self.verb_move(&o, io),
            "delete" | "remove" => self.verb_delete(&o, io),
            "chmod" => self.verb_chmod(&o, io),
            "chown" => self.verb_chown(&o, io),
            "ea.get" => self.verb_ea_get(&o, io),
            "ea.set" => self.verb_ea_set(&o, io),
            "tag.add" => self.verb_tag_add(&o, io),
            "tag.rm" => self.verb_tag_rm(&o, io),
            _ => Err(invalid(format!("unknown verb for file://: {verb}"))),
        }
    }
}

impl Handle for FileHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "read", "exists", "stat", "preview", "summary", "analyze", "schema", "tail", "grep",
            "find", "watch", "md5", "sha1", "sha256", "sha512", "hash", "verify", "write",
            "append", "replace", "copy", "rename", "move", "mv", "delete", "remove", "chmod",
            "chown", "ea.get", "ea.set", "tag.add", "tag.rm", "help", "h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&FILE_HELP)
    }

    /// Every failure comes back as a failed status `<CODE>: <message>` with
    /// the code's exit status; nothing is returned as `Err`.
    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // In-URL help request (file://--help, file://--help=<verb>); see
        // from_url. Exact match, so ordinary paths containing "-h" run.
        if self.path.as_os_str() == HELP_PATH || matches!(verb, "help" | "h") {
            return self.write_help(args, io);
        }
        Ok(match self.dispatch(verb, args, io) {
            Ok(status) => status,
            Err(e) => status_of(&e),
        })
    }
}
