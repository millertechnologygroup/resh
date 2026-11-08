//! Strict argument checking for every `user` verb: unknown arguments,
//! options of another mode, and invalid values are refused (exit 2) before
//! anything is looked up or changed.

// The parsers fill a default options value field by field, in the order
// the checks must run (an earlier refusal wins), so a struct literal does
// not fit.
#![allow(clippy::field_reassign_with_default)]

use std::io::Read;

use super::{
    HashScheme, OutputFormat, UserAddMode, UserAddOptions, UserBackend, UserDeleteMode,
    UserDeleteOptions, UserError, UserExistsOptions, UserGroupsOptions, UserLockOptions,
    UserPasswdOptions, UserTarget, UserUnlockOptions,
};
use crate::core::Args;

/// The verbs, in help order.
pub const VERBS: &[&str] = &[
    "exists", "groups", "add", "delete", "passwd", "lock", "unlock",
];

const EXISTS_ARGS: &[&str] = &["username", "uid", "backend", "format"];
const GROUPS_ARGS: &[&str] = &[
    "username",
    "include_primary",
    "include_supplementary",
    "include_system_groups",
    "min_gid_for_system",
    "group_name_filter",
    "ignore_if_missing",
    "backend",
    "format",
];
const ADD_ARGS: &[&str] = &[
    "mode",
    "username",
    "uid",
    "primary_group",
    "supplementary_groups",
    "groups",
    "home",
    "create_home",
    "shell",
    "gecos",
    "password_hash",
    "group_name",
    "gid",
    "member",
    "ignore_if_exists",
    "force",
    "dry_run",
    "backend",
    "format",
    "timeout_ms",
];
const DELETE_ARGS: &[&str] = &[
    "mode",
    "username",
    "remove_home",
    "remove_mail",
    "remove_from_all_groups",
    "protect_system_users",
    "min_uid_for_delete",
    "group_name",
    "only_if_empty",
    "protect_system_groups",
    "min_gid_for_delete",
    "member",
    "groups",
    "all_groups",
    "ignore_if_missing",
    "force",
    "dry_run",
    "backend",
    "format",
    "timeout_ms",
];
const PASSWD_ARGS: &[&str] = &[
    "username",
    "new_password_plain",
    "new_password_env",
    "new_password_stdin",
    "new_password_hash",
    "hash_scheme",
    "require_old_password",
    "old_password_plain",
    "old_password_env",
    "ignore_if_missing",
    "force",
    "dry_run",
    "backend",
    "format",
    "timeout_ms",
];
const LOCK_ARGS: &[&str] = &[
    "username",
    "protect_system_users",
    "min_uid_for_lock",
    "force",
    "ignore_if_missing",
    "dry_run",
    "backend",
    "format",
    "timeout_ms",
];
const UNLOCK_ARGS: &[&str] = &[
    "username",
    "protect_system_users",
    "min_uid_for_unlock",
    "force",
    "ignore_if_missing",
    "dry_run",
    "backend",
    "format",
    "timeout_ms",
];

/// The arguments `verb` accepts (one list per verb; the help usage lists
/// exactly these).
pub fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "exists" => EXISTS_ARGS,
        "groups" => GROUPS_ARGS,
        "add" => ADD_ARGS,
        "delete" => DELETE_ARGS,
        "passwd" => PASSWD_ARGS,
        "lock" => LOCK_ARGS,
        "unlock" => UNLOCK_ARGS,
        _ => return None,
    })
}

/// Default deadline of the verbs that run tools.
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// The candidate closest to `bad` (edit distance at most 2, or a prefix of
/// at least three characters), for a "did you mean" hint.
pub fn suggest<'a>(bad: &str, candidates: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    candidates
        .iter()
        .map(|c| (distance(&lower, c), *c))
        .filter(|(d, c)| *d <= 2 || (lower.len() >= 3 && c.starts_with(lower.as_str())))
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// ` (did you mean `x`?)` or "".
pub fn hint(bad: &str, candidates: &[&str]) -> String {
    suggest(bad, candidates)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

fn invalid(message: impl Into<String>) -> UserError {
    UserError::InvalidArgument(format!("{}; nothing was done", message.into()))
}

/// Refuses an argument `verb` does not accept.
pub fn check_known(verb: &str, args: &Args) -> Result<(), UserError> {
    let allowed = verb_args(verb).unwrap_or(&[]);
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    for key in keys {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        let message = match key.as_str() {
            "timeout_ms" => format!(
                "user {verb} does not accept timeout_ms: it only reads the account \
                 database and runs no tool"
            ),
            "dry_run" => format!("user {verb} changes nothing and does not accept dry_run"),
            _ => format!(
                "unknown argument for user {verb}: {key}{} (accepted: {})",
                hint(key, allowed),
                allowed.join(", ")
            ),
        };
        return Err(invalid(message));
    }
    Ok(())
}

/// Typed, strict access to one verb's arguments.
pub struct Reader<'a> {
    pub args: &'a Args,
}

impl<'a> Reader<'a> {
    fn has(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    /// A text value: never empty, never a control character.
    fn text(&self, key: &str) -> Result<Option<String>, UserError> {
        let Some(v) = self.args.get(key) else {
            return Ok(None);
        };
        if v.is_empty() {
            return Err(invalid(format!("{key} must not be empty")));
        }
        if v.chars().any(char::is_control) {
            return Err(invalid(format!(
                "{key} must not contain line breaks or other control characters"
            )));
        }
        Ok(Some(v.clone()))
    }

    /// A field written into /etc/passwd: no `:` either.
    fn passwd_field(&self, key: &str) -> Result<Option<String>, UserError> {
        let v = self.text(key)?;
        if let Some(s) = &v
            && s.contains(':')
        {
            return Err(invalid(format!("{key} must not contain ':'")));
        }
        Ok(v)
    }

    /// An absolute path for /etc/passwd.
    fn path(&self, key: &str) -> Result<Option<String>, UserError> {
        let v = self.passwd_field(key)?;
        if let Some(s) = &v
            && !s.starts_with('/')
        {
            return Err(invalid(format!(
                "{key} must be an absolute path, got {s:?}"
            )));
        }
        Ok(v)
    }

    /// A boolean in the CLI spellings (`true|false|1|0|yes|no|on|off`).
    fn flag(&self, key: &str, default: bool) -> Result<bool, UserError> {
        crate::core::lenient::bool_arg(self.args, key)
            .map(|v| v.unwrap_or(default))
            .map_err(|e| invalid(e.to_string()))
    }

    /// A whole number in `min..=max`.
    fn uint(&self, key: &str, min: u64, max: u64) -> Result<Option<u64>, UserError> {
        let Some(raw) = self.args.get(key) else {
            return Ok(None);
        };
        match raw.parse::<u64>() {
            Ok(v) if (min..=max).contains(&v) && !raw.starts_with('+') => Ok(Some(v)),
            _ => Err(invalid(format!(
                "invalid value for {key}: {raw:?} (expected a whole number from {min} to {max})"
            ))),
        }
    }

    fn id(&self, key: &str) -> Result<Option<u32>, UserError> {
        Ok(self
            .uint(key, 0, u64::from(u32::MAX) - 1)?
            .map(|v| v as u32))
    }

    /// One of `allowed`.
    fn choice(
        &self,
        key: &str,
        allowed: &[&'static str],
    ) -> Result<Option<&'static str>, UserError> {
        match self.args.get(key) {
            None => Ok(None),
            Some(v) => allowed
                .iter()
                .copied()
                .find(|a| a == v)
                .map(Some)
                .ok_or_else(|| {
                    invalid(format!(
                        "invalid value for {key}: {v:?} (expected {}){}",
                        allowed.join(", "),
                        hint(v, allowed)
                    ))
                }),
        }
    }

    /// A comma-separated list of group names (each a valid reference).
    fn groups(&self, key: &str) -> Result<Option<Vec<String>>, UserError> {
        let Some(raw) = self.text(key)? else {
            return Ok(None);
        };
        let items: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).collect();
        if items.iter().any(String::is_empty) {
            return Err(invalid(format!(
                "{key} has an empty item: {raw:?} (expected <g1>,<g2>,...)"
            )));
        }
        for g in &items {
            validate_ref_name(Kind::Group, g)
                .map_err(|e| UserError::GroupNameInvalid(format!("{key}: {}", reason(e))))?;
        }
        let mut out: Vec<String> = Vec::new();
        for g in items {
            if !out.contains(&g) {
                out.push(g);
            }
        }
        Ok(Some(out))
    }

    fn mode(&self) -> Result<Option<&'static str>, UserError> {
        self.choice("mode", &["user", "group", "membership"])
            .map_err(|e| UserError::InvalidMode(e.to_string()))
    }

    fn backend(&self) -> Result<UserBackend, UserError> {
        match self.choice("backend", &["system", "mock", "file", "ldap"])? {
            None | Some("system") => Ok(UserBackend::System),
            Some("mock") => Ok(UserBackend::Mock),
            Some(other) => Err(UserError::BackendNotSupported(other.to_string())),
        }
    }

    fn format(&self) -> Result<OutputFormat, UserError> {
        Ok(match self.choice("format", &["json", "text"])? {
            Some("text") => OutputFormat::Text,
            _ => OutputFormat::Json,
        })
    }

    pub fn timeout_ms(&self) -> Result<u64, UserError> {
        Ok(self
            .uint("timeout_ms", 1, MAX_TIMEOUT_MS)?
            .unwrap_or(DEFAULT_TIMEOUT_MS))
    }

    /// Refuses the options of `others` (a mode's options given in another
    /// mode).
    fn refuse_others(&self, mode: &str, others: &[(&str, &[&str])]) -> Result<(), UserError> {
        for (other_mode, keys) in others {
            for key in *keys {
                if self.has(key) {
                    return Err(invalid(format!(
                        "{key} applies only to mode={other_mode}, not mode={mode}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Which name a rule applies to (for the error code).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    User,
    Group,
}

fn name_error(kind: Kind, msg: String) -> UserError {
    match kind {
        Kind::User => UserError::UsernameInvalid(msg),
        Kind::Group => UserError::GroupNameInvalid(msg),
    }
}

/// The rule's message, without the error's own prefix.
fn reason(e: UserError) -> String {
    match e {
        UserError::UsernameInvalid(m) | UserError::GroupNameInvalid(m) => m,
        other => other.to_string(),
    }
}

/// The shadow-utils rule for a user or group name: 1-32 characters of
/// ASCII letters, digits, `_`, `-` and `.`, optionally ending in `$`; not
/// starting with `-`; not `.`, `..` or all digits.
pub fn validate_name(kind: Kind, name: &str) -> Result<(), UserError> {
    let what = match kind {
        Kind::User => "user name",
        Kind::Group => "group name",
    };
    if name.is_empty() {
        return Err(name_error(kind, format!("{what} must not be empty")));
    }
    if name.len() > 32 {
        return Err(name_error(
            kind,
            format!("{what} {name:?} is longer than 32 characters"),
        ));
    }
    if name.starts_with('-') {
        return Err(name_error(
            kind,
            format!("{what} {name:?} must not start with '-'"),
        ));
    }
    let body = name.strip_suffix('$').unwrap_or(name);
    if body.is_empty()
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(name_error(
            kind,
            format!(
                "{what} {name:?} may contain only ASCII letters, digits, '_', '-' and '.' \
                 (and a final '$')"
            ),
        ));
    }
    if name == "." || name == ".." || name.chars().all(|c| c.is_ascii_digit()) {
        return Err(name_error(
            kind,
            format!("{what} {name:?} is not allowed ('.', '..' or all digits)"),
        ));
    }
    Ok(())
}

/// A reference to an existing group (or a group `groupadd` creates): any
/// name the system accepts, but never option-shaped and never one that
/// breaks a comma-separated list or a `/etc/group` line.
pub fn validate_ref_name(kind: Kind, name: &str) -> Result<(), UserError> {
    let what = match kind {
        Kind::User => "user name",
        Kind::Group => "group name",
    };
    if name.is_empty() {
        return Err(name_error(kind, format!("{what} must not be empty")));
    }
    if name.starts_with('-') {
        return Err(name_error(
            kind,
            format!("{what} {name:?} must not start with '-'"),
        ));
    }
    if name.len() > 256
        || name
            .chars()
            .any(|c| c == ':' || c == ',' || c == '/' || c.is_whitespace() || c.is_control())
    {
        return Err(name_error(
            kind,
            format!("{what} {name:?} must not contain ':', ',', '/', spaces or control characters"),
        ));
    }
    Ok(())
}

/// The account a user-targeted verb works on: the URL target
/// (`user://alice`) or `username=`, which must agree.
fn username(r: &Reader, target: &UserTarget, verb: &str) -> Result<Option<String>, UserError> {
    let from_arg = r.text("username")?;
    let from_target = match target.kind() {
        TargetKind::None => None,
        TargetKind::User(u) => Some(u),
        TargetKind::Group(_) | TargetKind::Member(_) => {
            return Err(UserError::InvalidTarget(format!(
                "user {verb} works on a user account (user://<name>), not user://{}",
                target.path
            )));
        }
        TargetKind::Invalid => {
            return Err(UserError::InvalidTarget(format!(
                "user://{} is not a valid target (use user://<name>, user://group/<name> \
                 or user://membership/<name>)",
                target.path
            )));
        }
    };
    let name = match (from_target, from_arg) {
        (Some(t), Some(a)) if t != a => {
            return Err(invalid(format!(
                "the target names user {t:?} but username= is {a:?}"
            )));
        }
        (Some(t), _) => Some(t),
        (None, a) => a,
    };
    if let Some(n) = &name {
        validate_name(Kind::User, n)?;
    }
    Ok(name)
}

/// What a `user://...` target names.
pub enum TargetKind {
    None,
    User(String),
    Group(String),
    Member(String),
    Invalid,
}

impl UserTarget {
    pub fn kind(&self) -> TargetKind {
        let p = self.path.as_str();
        if p.is_empty() {
            return TargetKind::None;
        }
        if let Some(g) = p.strip_prefix("group/") {
            return if g.is_empty() || g.contains('/') {
                TargetKind::Invalid
            } else {
                TargetKind::Group(g.to_string())
            };
        }
        if let Some(m) = p.strip_prefix("membership/") {
            return if m.is_empty() || m.contains('/') {
                TargetKind::Invalid
            } else {
                TargetKind::Member(m.to_string())
            };
        }
        if p.contains('/') || p == "group" || p == "membership" {
            return TargetKind::Invalid;
        }
        TargetKind::User(p.to_string())
    }
}

/// The name a mode needs from the target or its own argument.
fn mode_name(
    r: &Reader,
    target: &UserTarget,
    mode: &str,
    key: &str,
) -> Result<Option<String>, UserError> {
    let from_arg = r.text(key)?;
    let (from_target, wrong) = match (target.kind(), mode) {
        (TargetKind::None, _) => (None, false),
        (TargetKind::User(u), "user") => (Some(u), false),
        (TargetKind::Group(g), "group") => (Some(g), false),
        (TargetKind::Member(m), "membership") => (Some(m), false),
        (TargetKind::Invalid, _) => {
            return Err(UserError::InvalidTarget(format!(
                "user://{} is not a valid target (use user://<name>, user://group/<name> \
                 or user://membership/<name>)",
                target.path
            )));
        }
        _ => (None, true),
    };
    if wrong {
        let form = match mode {
            "user" => "user://<name>",
            "group" => "user://group/<name>",
            _ => "user://membership/<name>",
        };
        return Err(UserError::InvalidTarget(format!(
            "user://{} does not name what mode={mode} works on (use {form} or {key}=)",
            target.path
        )));
    }
    match (from_target, from_arg) {
        (Some(t), Some(a)) if t != a => Err(invalid(format!(
            "the target names {t:?} but {key}= is {a:?}"
        ))),
        (Some(t), _) => Ok(Some(t)),
        (None, a) => Ok(a),
    }
}

const ADD_USER_KEYS: &[&str] = &[
    "username",
    "uid",
    "primary_group",
    "supplementary_groups",
    "home",
    "create_home",
    "shell",
    "gecos",
    "password_hash",
];
const ADD_GROUP_KEYS: &[&str] = &["group_name", "gid"];
const ADD_MEMBERSHIP_KEYS: &[&str] = &["member"];

pub fn parse_add(args: &Args, target: &UserTarget) -> Result<UserAddOptions, UserError> {
    let r = Reader { args };
    let mut o = UserAddOptions::default();
    o.mode = match r.mode()? {
        Some("group") => UserAddMode::Group,
        Some("membership") => UserAddMode::Membership,
        _ => UserAddMode::User,
    };
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.dry_run = r.flag("dry_run", false)?;
    o.ignore_if_exists = r.flag("ignore_if_exists", true)?;
    o.force = r.flag("force", false)?;
    o.timeout_ms = r.timeout_ms()?;
    match o.mode {
        UserAddMode::User => {
            r.refuse_others(
                "user",
                &[
                    ("group", ADD_GROUP_KEYS),
                    ("membership", ADD_MEMBERSHIP_KEYS),
                ],
            )?;
            o.username = mode_name(&r, target, "user", "username")?;
            let name = o.username.clone().ok_or(UserError::UsernameRequired)?;
            validate_name(Kind::User, &name)?;
            o.uid = r.id("uid")?;
            if let Some(pg) = r.text("primary_group")? {
                validate_ref_name(Kind::Group, &pg).map_err(|e| {
                    UserError::GroupNameInvalid(format!("primary_group: {}", reason(e)))
                })?;
                o.primary_group = Some(pg);
            }
            o.supplementary_groups = match (r.has("supplementary_groups"), r.has("groups")) {
                (true, true) => {
                    return Err(invalid(
                        "give supplementary_groups= or groups= (another name for it), not both",
                    ));
                }
                (true, false) => r.groups("supplementary_groups")?.unwrap_or_default(),
                (false, true) => r.groups("groups")?.unwrap_or_default(),
                _ => Vec::new(),
            };
            o.home = r.path("home")?;
            o.create_home = r.flag("create_home", true)?;
            o.shell = r.path("shell")?;
            o.gecos = r.passwd_field("gecos")?;
            if let Some(h) = r.text("password_hash")? {
                if super::backend::hash_scheme_of(&h).is_none() {
                    return Err(UserError::HashParamsInvalid(
                        "password_hash is not a well-formed sha512_crypt ($6$), sha256_crypt \
                         ($5$), bcrypt ($2b$), yescrypt ($y$) or argon2id hash"
                            .to_string(),
                    ));
                }
                o.password_hash = Some(h);
            }
        }
        UserAddMode::Group => {
            r.refuse_others(
                "group",
                &[
                    ("user", ADD_USER_KEYS),
                    ("user or membership", &["groups"]),
                    ("membership", ADD_MEMBERSHIP_KEYS),
                ],
            )?;
            o.group_name = mode_name(&r, target, "group", "group_name")?;
            let name = o.group_name.clone().ok_or(UserError::GroupNameRequired)?;
            validate_name(Kind::Group, &name)?;
            o.gid = r.id("gid")?;
        }
        UserAddMode::Membership => {
            r.refuse_others(
                "membership",
                &[("user", ADD_USER_KEYS), ("group", ADD_GROUP_KEYS)],
            )?;
            if r.has("force") {
                return Err(invalid(
                    "force does not apply to mode=membership (it only allows a uid or gid \
                     below 1000)",
                ));
            }
            o.member = mode_name(&r, target, "membership", "member")?;
            let name = o.member.clone().ok_or(UserError::MemberRequired)?;
            validate_name(Kind::User, &name)?;
            o.groups = r.groups("groups")?.ok_or(UserError::GroupsRequired)?;
        }
    }
    Ok(o)
}

const DELETE_USER_KEYS: &[&str] = &[
    "username",
    "remove_home",
    "remove_mail",
    "remove_from_all_groups",
    "protect_system_users",
    "min_uid_for_delete",
];
const DELETE_GROUP_KEYS: &[&str] = &[
    "group_name",
    "only_if_empty",
    "protect_system_groups",
    "min_gid_for_delete",
];
const DELETE_MEMBERSHIP_KEYS: &[&str] = &["member", "groups", "all_groups"];

pub fn parse_delete(args: &Args, target: &UserTarget) -> Result<UserDeleteOptions, UserError> {
    let r = Reader { args };
    let mut o = UserDeleteOptions::default();
    o.mode = match r.mode()? {
        Some("group") => UserDeleteMode::Group,
        Some("membership") => UserDeleteMode::Membership,
        _ => UserDeleteMode::User,
    };
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.dry_run = r.flag("dry_run", false)?;
    o.ignore_if_missing = r.flag("ignore_if_missing", true)?;
    o.force = r.flag("force", false)?;
    o.timeout_ms = r.timeout_ms()?;
    match o.mode {
        UserDeleteMode::User => {
            r.refuse_others(
                "user",
                &[
                    ("group", DELETE_GROUP_KEYS),
                    ("membership", DELETE_MEMBERSHIP_KEYS),
                ],
            )?;
            o.username = mode_name(&r, target, "user", "username")?;
            let name = o.username.clone().ok_or(UserError::UsernameRequired)?;
            validate_name(Kind::User, &name)?;
            o.remove_home = r.flag("remove_home", false)?;
            o.remove_mail = r.flag("remove_mail", false)?;
            o.remove_from_all_groups = r.flag("remove_from_all_groups", true)?;
            if !o.remove_from_all_groups {
                return Err(invalid(
                    "remove_from_all_groups=false is not supported: userdel always removes \
                     the account from every group",
                ));
            }
            o.protect_system_users = r.flag("protect_system_users", true)?;
            o.min_uid_for_delete = r.id("min_uid_for_delete")?.unwrap_or(1000);
        }
        UserDeleteMode::Group => {
            r.refuse_others(
                "group",
                &[
                    ("user", DELETE_USER_KEYS),
                    ("membership", DELETE_MEMBERSHIP_KEYS),
                ],
            )?;
            o.group_name = mode_name(&r, target, "group", "group_name")?;
            let name = o.group_name.clone().ok_or(UserError::GroupNameRequired)?;
            validate_name(Kind::Group, &name)?;
            o.only_if_empty = r.flag("only_if_empty", true)?;
            o.protect_system_groups = r.flag("protect_system_groups", true)?;
            o.min_gid_for_delete = r.id("min_gid_for_delete")?.unwrap_or(1000);
        }
        UserDeleteMode::Membership => {
            r.refuse_others(
                "membership",
                &[("user", DELETE_USER_KEYS), ("group", DELETE_GROUP_KEYS)],
            )?;
            if r.has("force") {
                return Err(invalid(
                    "force does not apply to mode=membership (it has no protection to \
                     override)",
                ));
            }
            o.member = mode_name(&r, target, "membership", "member")?;
            let name = o.member.clone().ok_or(UserError::MemberRequired)?;
            validate_name(Kind::User, &name)?;
            o.all_groups = r.flag("all_groups", false)?;
            let groups = r.groups("groups")?;
            match (o.all_groups, groups) {
                (true, Some(_)) => {
                    return Err(invalid("give groups= or all_groups=true, not both"));
                }
                (false, None) => return Err(UserError::GroupsRequired),
                (_, g) => o.groups = g.unwrap_or_default(),
            }
        }
    }
    Ok(o)
}

/// Reads an environment variable named by `key`.
fn env_secret(r: &Reader, key: &str) -> Result<Option<String>, UserError> {
    let Some(name) = r.text(key)? else {
        return Ok(None);
    };
    if name.contains('=') || name.contains('\0') {
        return Err(invalid(format!(
            "{key}={name:?} is not an environment variable name"
        )));
    }
    match std::env::var(&name) {
        Ok(v) if v.is_empty() => Err(invalid(format!(
            "environment variable {name} ({key}) is empty"
        ))),
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotUnicode(_)) => Err(invalid(format!(
            "environment variable {name} ({key}) is not valid UTF-8"
        ))),
        Err(std::env::VarError::NotPresent) => Err(invalid(format!(
            "environment variable {name} ({key}) is not set"
        ))),
    }
}

/// A plaintext password: not empty, no line break or NUL (chpasswd and
/// crypt() read one line).
fn check_password(what: &str, pw: &str) -> Result<(), UserError> {
    if pw.is_empty() {
        return Err(invalid(format!("{what} is empty")));
    }
    if pw.contains('\n') || pw.contains('\r') || pw.contains('\0') {
        return Err(invalid(format!(
            "{what} must not contain line breaks or NUL characters"
        )));
    }
    Ok(())
}

pub fn parse_passwd(
    args: &Args,
    target: &UserTarget,
    stdin: &mut dyn Read,
) -> Result<UserPasswdOptions, UserError> {
    let r = Reader { args };
    let mut o = UserPasswdOptions::default();
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.dry_run = r.flag("dry_run", false)?;
    o.ignore_if_missing = r.flag("ignore_if_missing", true)?;
    o.force = r.flag("force", false)?;
    o.timeout_ms = r.timeout_ms()?;
    o.username = username(&r, target, "passwd")?;
    if o.username.is_none() {
        return Err(UserError::UsernameRequired);
    }
    if let Some(s) = r.choice(
        "hash_scheme",
        &["backend_default", "sha512_crypt", "bcrypt", "argon2id"],
    )? {
        o.hash_scheme = match s {
            "sha512_crypt" => HashScheme::Sha512Crypt,
            "bcrypt" => HashScheme::Bcrypt,
            "argon2id" => HashScheme::Argon2id,
            _ => HashScheme::BackendDefault,
        };
        o.hash_scheme_given = true;
    }
    let stdin_flag = r.flag("new_password_stdin", false)?;
    if r.has("new_password_stdin") && !stdin_flag {
        return Err(invalid(
            "new_password_stdin=false asks for nothing; leave it out",
        ));
    }
    let sources = [
        r.has("new_password_plain"),
        r.has("new_password_env"),
        stdin_flag,
        r.has("new_password_hash"),
    ]
    .iter()
    .filter(|g| **g)
    .count();
    if sources > 1 {
        return Err(UserError::PasswordConflictingSources);
    }
    if sources == 0 {
        return Err(UserError::PasswordMissingNewPassword);
    }
    if let Some(h) = r.text("new_password_hash")? {
        let Some(scheme) = super::backend::hash_scheme_of(&h) else {
            return Err(UserError::HashParamsInvalid(
                "new_password_hash is not a well-formed sha512_crypt ($6$), sha256_crypt \
                 ($5$), bcrypt ($2b$), yescrypt ($y$) or argon2id hash"
                    .to_string(),
            ));
        };
        if o.hash_scheme_given
            && o.hash_scheme != HashScheme::BackendDefault
            && o.hash_scheme.to_string() != scheme
        {
            return Err(invalid(format!(
                "hash_scheme={} does not match new_password_hash, which is {scheme}",
                o.hash_scheme
            )));
        }
        o.new_password_hash = Some(h);
        o.new_password_source = "hash".to_string();
    } else {
        let (pw, source) = if let Some(p) = args.get("new_password_plain") {
            (p.clone(), "plain")
        } else if let Some(p) = env_secret(&r, "new_password_env")? {
            (p, "env")
        } else {
            let mut bytes = Vec::new();
            stdin
                .take(64 * 1024)
                .read_to_end(&mut bytes)
                .map_err(|e| invalid(format!("cannot read the new password from stdin: {e}")))?;
            let mut text = String::from_utf8(bytes)
                .map_err(|_| invalid("the new password on stdin is not valid UTF-8"))?;
            // One trailing newline, as `echo` or a here-string adds.
            if text.ends_with('\n') {
                text.pop();
                if text.ends_with('\r') {
                    text.pop();
                }
            }
            (text, "stdin")
        };
        check_password("the new password", &pw)?;
        o.new_password_plain = Some(pw);
        o.new_password_source = source.to_string();
    }
    o.require_old_password = r.flag("require_old_password", false)?;
    let old = match (r.has("old_password_plain"), r.has("old_password_env")) {
        (true, true) => {
            return Err(invalid(
                "give old_password_plain= or old_password_env=, not both",
            ));
        }
        (true, false) => args.get("old_password_plain").cloned(),
        (false, true) => env_secret(&r, "old_password_env")?,
        _ => None,
    };
    match (&old, o.require_old_password) {
        (Some(_), false) => {
            return Err(invalid(
                "an old password is checked only with require_old_password=true",
            ));
        }
        (None, true) => return Err(UserError::OldPasswordRequired),
        (Some(p), true) => check_password("the old password", p)?,
        (None, false) => {}
    }
    o.old_password_plain = old;
    Ok(o)
}

pub fn parse_lock(args: &Args, target: &UserTarget) -> Result<UserLockOptions, UserError> {
    let r = Reader { args };
    let mut o = UserLockOptions::default();
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.dry_run = r.flag("dry_run", false)?;
    o.ignore_if_missing = r.flag("ignore_if_missing", true)?;
    o.force = r.flag("force", false)?;
    o.timeout_ms = r.timeout_ms()?;
    o.username = username(&r, target, "lock")?;
    if o.username.is_none() {
        return Err(UserError::UsernameRequired);
    }
    o.protect_system_users = r.flag("protect_system_users", true)?;
    o.min_uid_for_lock = r.id("min_uid_for_lock")?.unwrap_or(1000);
    Ok(o)
}

pub fn parse_unlock(args: &Args, target: &UserTarget) -> Result<UserUnlockOptions, UserError> {
    let r = Reader { args };
    let mut o = UserUnlockOptions::default();
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.dry_run = r.flag("dry_run", false)?;
    o.ignore_if_missing = r.flag("ignore_if_missing", true)?;
    o.force = r.flag("force", false)?;
    o.timeout_ms = r.timeout_ms()?;
    o.username = username(&r, target, "unlock")?;
    if o.username.is_none() {
        return Err(UserError::UsernameRequired);
    }
    o.protect_system_users = r.flag("protect_system_users", true)?;
    o.min_uid_for_unlock = r.id("min_uid_for_unlock")?.unwrap_or(1000);
    Ok(o)
}

pub fn parse_groups(args: &Args, target: &UserTarget) -> Result<UserGroupsOptions, UserError> {
    let r = Reader { args };
    let mut o = UserGroupsOptions::default();
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.ignore_if_missing = r.flag("ignore_if_missing", true)?;
    o.include_primary = r.flag("include_primary", true)?;
    o.include_supplementary = r.flag("include_supplementary", true)?;
    o.include_system_groups = r.flag("include_system_groups", true)?;
    o.min_gid_for_system = r.id("min_gid_for_system")?.unwrap_or(1000);
    if let Some(f) = r.text("group_name_filter")? {
        validate_ref_name(Kind::Group, &f).map_err(|e| {
            UserError::GroupNameInvalid(format!("group_name_filter: {}", reason(e)))
        })?;
        o.group_name_filter = Some(f);
    }
    o.username = username(&r, target, "groups")?;
    if o.username.is_none() {
        return Err(UserError::UsernameRequired);
    }
    Ok(o)
}

pub fn parse_exists(args: &Args, target: &UserTarget) -> Result<UserExistsOptions, UserError> {
    let r = Reader { args };
    let mut o = UserExistsOptions::default();
    o.backend = r.backend()?;
    o.format = r.format()?;
    o.uid = r.id("uid")?;
    o.username = username(&r, target, "exists")?;
    if o.username.is_none() && o.uid.is_none() {
        return Err(UserError::IdentityRequired);
    }
    Ok(o)
}
