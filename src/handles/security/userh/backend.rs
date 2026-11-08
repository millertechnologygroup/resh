//! The account backends: the system backend (getpwnam & co. for lookups,
//! shadow-utils tools for changes) and the in-memory mock backend, plus
//! password hashing and verification.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;

use super::exec::{self, RunError};
use super::sha_crypt;
use super::{GroupInfo, GroupRecord, HashScheme, UserError, UserInfo, UserRecord};

/// The lowest UID/GID handed out automatically and the default boundary
/// below which accounts count as system accounts.
pub const FIRST_REGULAR_ID: u32 = 1000;
/// The highest UID/GID handed out or accepted (65534 is nobody/nogroup).
pub const LAST_REGULAR_ID: u32 = 65533;

/// The account database: lookups and changes.
pub trait UserBackendProvider: Send + Sync {
    fn user_exists(&self, username: &str) -> Result<bool> {
        Ok(self.lookup_user(username)?.is_some())
    }
    fn group_exists(&self, group_name: &str) -> Result<bool> {
        Ok(self.lookup_group(group_name)?.is_some())
    }
    /// True if `username` is listed as a (supplementary) member of
    /// `group_name`. The primary group is not a listed membership.
    fn membership_exists(&self, username: &str, group_name: &str) -> Result<bool> {
        Ok(self
            .lookup_group(group_name)?
            .is_some_and(|g| g.members.iter().any(|m| m == username)))
    }
    /// The first free UID from 1000 to 65533.
    fn next_uid(&self) -> Result<u32> {
        for uid in FIRST_REGULAR_ID..=LAST_REGULAR_ID {
            if self.lookup_user_by_uid(uid)?.is_none() {
                return Ok(uid);
            }
        }
        Err(UserError::NoFreeId("uid".into()).into())
    }
    /// The first free GID from 1000 to 65533.
    fn next_gid(&self) -> Result<u32> {
        for gid in FIRST_REGULAR_ID..=LAST_REGULAR_ID {
            if !self.gid_in_use(gid)? {
                return Ok(gid);
            }
        }
        Err(UserError::NoFreeId("gid".into()).into())
    }
    fn gid_in_use(&self, gid: u32) -> Result<bool>;
    fn create_user(&mut self, info: &UserInfo, create_home: bool) -> Result<()>;
    fn create_group(&mut self, info: &GroupInfo) -> Result<()>;
    fn add_memberships(&mut self, username: &str, groups: &[String]) -> Result<()>;
    fn default_home_path(&self, username: &str) -> String {
        format!("/home/{}", username)
    }
    fn default_shell(&self) -> String {
        "/bin/bash".to_string()
    }
    fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>>;
    fn lookup_user_by_uid(&self, uid: u32) -> Result<Option<UserRecord>>;
    fn lookup_group(&self, group_name: &str) -> Result<Option<GroupRecord>>;
    fn delete_user(&mut self, username: &str, remove_home: bool, remove_mail: bool) -> Result<()>;
    fn delete_group(&mut self, group_name: &str) -> Result<()>;
    fn remove_user_from_group(&mut self, username: &str, group_name: &str) -> Result<()>;
    /// The user's groups: the primary group first, then the supplementary
    /// groups.
    fn list_groups_for_user(&self, username: &str) -> Result<Vec<String>>;
    fn list_groups_for_user_detailed(&self, username: &str) -> Result<Vec<GroupRecord>> {
        let mut out = Vec::new();
        for name in self.list_groups_for_user(username)? {
            match self.lookup_group(&name)? {
                Some(g) => out.push(g),
                None => out.push(GroupRecord {
                    gid: name.parse().ok(),
                    name,
                    members: vec![],
                }),
            }
        }
        Ok(out)
    }
    /// The stored password field (the shadow entry's second field), or
    /// `None` when the account has no entry.
    fn password_field(&self, username: &str) -> Result<Option<String>>;
    /// Stores a password hash. The hash never appears on a command line.
    fn set_password_hash(&mut self, username: &str, hash: &str) -> Result<()>;
    /// Commands a dry run reports. Backends that run no commands report none.
    fn planned_commands(&self, _op: &BackendOp) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn is_locked(&self, username: &str) -> Result<bool>;
    fn lock_user(&mut self, username: &str) -> Result<()>;
    fn unlock_user(&mut self, username: &str) -> Result<()>;
    /// True if something exists at `path` (a link counts).
    fn path_exists(&self, path: &str) -> bool;
    /// True if the backend can store argon2id hashes. The system crypt()
    /// library (and so PAM) cannot verify them.
    fn supports_argon2(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Password hashes
// ---------------------------------------------------------------------------

/// Bytes of a password bcrypt uses; longer passwords would be truncated.
pub const BCRYPT_MAX_BYTES: usize = 72;

/// Hashes `password` with `scheme` (`BackendDefault` means sha512_crypt).
pub fn hash_password(password: &str, scheme: &HashScheme) -> Result<String> {
    match scheme {
        HashScheme::BackendDefault | HashScheme::Sha512Crypt => {
            sha_crypt::hash(sha_crypt::Variant::Sha512, password)
                .map_err(|e| UserError::PasswordBackendFailure(e).into())
        }
        HashScheme::Bcrypt => {
            if password.len() > BCRYPT_MAX_BYTES {
                return Err(UserError::HashParamsInvalid(format!(
                    "bcrypt uses only the first {BCRYPT_MAX_BYTES} bytes of a password; \
                     this one is {} bytes (use sha512_crypt)",
                    password.len()
                ))
                .into());
            }
            bcrypt::hash(password, bcrypt::DEFAULT_COST)
                .map_err(|e| UserError::PasswordBackendFailure(format!("bcrypt: {e}")).into())
        }
        HashScheme::Argon2id => {
            use argon2::password_hash::{PasswordHasher as _, SaltString};
            use ring::rand::{SecureRandom, SystemRandom};
            let mut raw = [0u8; 16];
            SystemRandom::new().fill(&mut raw).map_err(|_| {
                UserError::PasswordBackendFailure("cannot generate a random salt".into())
            })?;
            let salt = SaltString::encode_b64(&raw)
                .map_err(|e| UserError::PasswordBackendFailure(format!("argon2 salt: {e}")))?;
            argon2::Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| UserError::PasswordBackendFailure(format!("argon2: {e}")).into())
        }
    }
}

/// The scheme of a stored hash, by its prefix, if it is well formed.
pub fn hash_scheme_of(hash: &str) -> Option<&'static str> {
    if hash.contains(':') || hash.chars().any(char::is_control) {
        return None;
    }
    if sha_crypt::is_sha_crypt(hash) {
        return Some(if hash.starts_with("$6$") {
            "sha512_crypt"
        } else {
            "sha256_crypt"
        });
    }
    let crypt_chars = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'/')
    };
    if ["$2a$", "$2b$", "$2y$"].iter().any(|p| hash.starts_with(p)) {
        let rest = &hash[4..];
        let ok = rest.len() == 56
            && rest[..2].bytes().all(|c| c.is_ascii_digit())
            && &rest[2..3] == "$"
            && crypt_chars(&rest[3..]);
        return ok.then_some("bcrypt");
    }
    if let Some(rest) = hash.strip_prefix("$y$") {
        let parts: Vec<&str> = rest.split('$').collect();
        let ok = parts.len() == 3 && parts.iter().all(|p| crypt_chars(p));
        return ok.then_some("yescrypt");
    }
    if hash.starts_with("$argon2id$") {
        return argon2::PasswordHash::new(hash)
            .is_ok()
            .then_some("argon2id");
    }
    None
}

/// Verifies `password` against a stored password field. A lock prefix
/// (`!`) is ignored; an account without a password never matches. Hashes
/// that cannot be checked here (yescrypt, MD5, DES) give
/// `user.old_password_verification_unsupported`.
pub fn verify_password_hash(password: &str, stored: &str) -> Result<bool> {
    let hash = stored.trim_start_matches('!');
    if hash.is_empty() || hash.starts_with('*') || password.is_empty() {
        return Ok(false);
    }
    if let Some(ok) = sha_crypt::verify(password, hash) {
        return Ok(ok);
    }
    if ["$2a$", "$2b$", "$2y$"].iter().any(|p| hash.starts_with(p)) {
        return Ok(bcrypt::verify(password, hash).unwrap_or(false));
    }
    if hash.starts_with("$argon2") {
        use argon2::{PasswordHash, PasswordVerifier};
        return Ok(PasswordHash::new(hash).is_ok_and(|h| {
            argon2::Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        }));
    }
    let scheme = if hash.starts_with("$y$") {
        "yescrypt"
    } else if hash.starts_with("$1$") {
        "md5_crypt"
    } else {
        "unrecognized"
    };
    Err(UserError::OldPasswordVerificationUnsupported(scheme.into()).into())
}

// ---------------------------------------------------------------------------
// Commands of the system backend
// ---------------------------------------------------------------------------

/// One change to the account database. Used to build the system backend's
/// command and to report planned commands in a dry run.
#[derive(Debug, Clone, Copy)]
pub enum BackendOp<'a> {
    CreateUser {
        info: &'a UserInfo,
        create_home: bool,
    },
    CreateGroup(&'a GroupInfo),
    AddMemberships {
        username: &'a str,
        groups: &'a [String],
    },
    DeleteUser {
        username: &'a str,
        remove_home: bool,
        remove_mail: bool,
    },
    DeleteGroup(&'a str),
    RemoveMembership {
        username: &'a str,
        group: &'a str,
    },
    SetPasswordHash {
        username: &'a str,
        hash: &'a str,
    },
    Lock(&'a str),
    Unlock(&'a str),
}

/// One external command run by the system backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCommand {
    /// Program and arguments. Never passed through a shell.
    pub argv: Vec<String>,
    /// Data written to the program's standard input. It holds a password
    /// hash, so it is never shown.
    pub stdin: Option<String>,
}

impl SystemCommand {
    fn new<S: AsRef<str>>(argv: &[S]) -> Self {
        Self {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            stdin: None,
        }
    }

    /// Shell-quoted form for display. Standard input is redacted.
    pub fn display(&self) -> String {
        let mut s = self
            .argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        if self.stdin.is_some() {
            s.push_str(" <<< (redacted)");
        }
        s
    }
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The mail spool `remove_mail` deletes.
pub fn mail_spool(username: &str) -> String {
    format!("/var/mail/{}", username)
}

/// Builds the external commands for `op`. Pure: it runs nothing. Every
/// name is an operand after `--`, so none can be read as an option.
pub fn system_commands(op: &BackendOp) -> Result<Vec<SystemCommand>> {
    Ok(match *op {
        BackendOp::CreateUser { info, create_home } => {
            let mut argv: Vec<String> = vec![
                "useradd".into(),
                "-u".into(),
                info.uid.to_string(),
                "-g".into(),
                info.primary_group.clone(),
            ];
            if !info.supplementary_groups.is_empty() {
                argv.push("-G".into());
                argv.push(info.supplementary_groups.join(","));
            }
            if let Some(home) = &info.home {
                argv.push("-d".into());
                argv.push(home.clone());
            }
            argv.push(if create_home { "-m" } else { "-M" }.into());
            if let Some(shell) = &info.shell {
                argv.push("-s".into());
                argv.push(shell.clone());
            }
            if let Some(gecos) = &info.gecos {
                argv.push("-c".into());
                argv.push(gecos.clone());
            }
            argv.push("--".into());
            argv.push(info.username.clone());
            vec![SystemCommand::new(&argv)]
        }
        BackendOp::CreateGroup(info) => vec![SystemCommand::new(&[
            "groupadd",
            "-g",
            info.gid.to_string().as_str(),
            "--",
            info.name.as_str(),
        ])],
        BackendOp::AddMemberships { username, groups } => vec![SystemCommand::new(&[
            "usermod",
            "-a",
            "-G",
            groups.join(",").as_str(),
            "--",
            username,
        ])],
        BackendOp::DeleteUser {
            username,
            remove_home,
            remove_mail,
        } => {
            let mut cmds = Vec::new();
            if remove_home {
                // userdel -r removes the home directory and the mail spool.
                cmds.push(SystemCommand::new(&["userdel", "-r", "--", username]));
            } else {
                cmds.push(SystemCommand::new(&["userdel", "--", username]));
                if remove_mail {
                    let spool = mail_spool(username);
                    cmds.push(SystemCommand::new(&["rm", "-f", "--", spool.as_str()]));
                }
            }
            cmds
        }
        BackendOp::DeleteGroup(group) => vec![SystemCommand::new(&["groupdel", "--", group])],
        BackendOp::RemoveMembership { username, group } => {
            vec![SystemCommand::new(&[
                "gpasswd", "-d", username, "--", group,
            ])]
        }
        BackendOp::SetPasswordHash { username, hash } => {
            if hash_scheme_of(hash).is_none() {
                return Err(UserError::HashParamsInvalid(
                    "the password hash is not a well-formed crypt hash".to_string(),
                )
                .into());
            }
            let mut cmd = SystemCommand::new(&["chpasswd", "-e"]);
            cmd.stdin = Some(format!("{}:{}\n", username, hash));
            vec![cmd]
        }
        BackendOp::Lock(username) => vec![SystemCommand::new(&["usermod", "-L", "--", username])],
        BackendOp::Unlock(username) => {
            vec![SystemCommand::new(&["usermod", "-U", "--", username])]
        }
    })
}

/// The password field of `username` in shadow-file contents.
pub fn shadow_password_field(shadow: &str, username: &str) -> Option<String> {
    shadow.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let name = parts.next()?;
        let pw = parts.next()?;
        (name == username).then(|| pw.to_string())
    })
}

/// True if a shadow password field marks the account as locked
/// (`usermod -L` prefixes the hash with `!`; `*` disables password login).
pub fn shadow_field_is_locked(field: &str) -> bool {
    field.starts_with('!') || field.starts_with('*')
}

/// Parses `passwd -S <user>` output. The second field is `L`/`LK` for a
/// locked password, `P`/`PS` for a usable one and `NP` for none.
pub fn parse_passwd_status(output: &str, username: &str) -> Option<bool> {
    let line = output
        .lines()
        .find(|l| l.split_whitespace().next() == Some(username))?;
    match line.split_whitespace().nth(1)? {
        "L" | "LK" => Some(true),
        "P" | "PS" | "NP" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// System backend
// ---------------------------------------------------------------------------

/// How the system backend applies changes.
#[derive(Debug, Clone)]
enum SystemExec {
    /// Run the commands (never from unit tests).
    Run,
    /// Record the commands without running them (tests).
    Record(Arc<Mutex<Vec<SystemCommand>>>),
}

/// System backend: reads the account database through NSS (getpwnam,
/// getgrnam, getgrouplist) and the shadow file, and changes it with useradd,
/// groupadd, usermod, userdel, groupdel, gpasswd and chpasswd.
#[derive(Debug)]
pub struct SystemBackend {
    exec: SystemExec,
    shadow_path: std::path::PathBuf,
    deadline: Instant,
}

impl SystemBackend {
    pub fn new(deadline: Instant) -> Self {
        Self {
            exec: SystemExec::Run,
            shadow_path: "/etc/shadow".into(),
            deadline,
        }
    }

    /// A backend that records the commands instead of running them.
    /// Lookups still read the real account database.
    pub fn recording(log: Arc<Mutex<Vec<SystemCommand>>>) -> Self {
        Self {
            exec: SystemExec::Record(log),
            shadow_path: "/etc/shadow".into(),
            deadline: Instant::now() + std::time::Duration::from_secs(60),
        }
    }

    /// Reads the shadow file from another path (tests).
    pub fn with_shadow_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.shadow_path = path.into();
        self
    }

    fn apply(&mut self, op: BackendOp) -> Result<()> {
        let cmds = system_commands(&op)?;
        if let SystemExec::Record(log) = &self.exec {
            if let Ok(mut log) = log.lock() {
                log.extend(cmds);
            }
            return Ok(());
        }
        if cfg!(test) {
            return Err(UserError::BackendOperationFailed(format!(
                "refusing to run '{}' from a unit test",
                cmds.first().map(SystemCommand::display).unwrap_or_default()
            ))
            .into());
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(UserError::PermissionDenied(format!(
                "changing accounts needs root; '{}' was not run",
                cmds.first().map(SystemCommand::display).unwrap_or_default()
            ))
            .into());
        }
        for cmd in cmds {
            self.run(&cmd)?;
        }
        Ok(())
    }

    fn run(&self, cmd: &SystemCommand) -> Result<String> {
        exec::run(&cmd.argv, cmd.stdin.as_deref(), self.deadline)
            .map(|r| r.stdout)
            .map_err(|e| {
                let program = cmd.argv.first().cloned().unwrap_or_default();
                match e {
                    RunError::NotFound(m) => UserError::ToolNotFound(m),
                    RunError::Spawn(m) => UserError::BackendOperationFailed(m),
                    RunError::Timeout(m) => UserError::Timeout(m),
                    RunError::Failed { code, stderr } => {
                        UserError::BackendOperationFailed(format!(
                            "{} exited with status {}: {}",
                            cmd.display(),
                            code.map_or("unknown".to_string(), |c| c.to_string()),
                            if stderr.is_empty() {
                                format!("{program} gave no reason")
                            } else {
                                stderr
                            }
                        ))
                    }
                }
                .into()
            })
    }

    fn shadow_field(&self, username: &str) -> Result<Option<String>> {
        let contents = std::fs::read_to_string(&self.shadow_path).map_err(|e| {
            UserError::BackendOperationFailed(format!(
                "cannot read {}: {}",
                self.shadow_path.display(),
                e
            ))
        })?;
        Ok(shadow_password_field(&contents, username))
    }

    fn record(user: nix::unistd::User) -> UserRecord {
        let primary_group = nix::unistd::Group::from_gid(user.gid)
            .ok()
            .flatten()
            .map(|g| g.name)
            .unwrap_or_else(|| user.gid.to_string());
        let gecos = user.gecos.to_string_lossy().into_owned();
        UserRecord {
            username: user.name,
            uid: user.uid.as_raw(),
            primary_group,
            home: Some(user.dir.to_string_lossy().into_owned()),
            shell: Some(user.shell.to_string_lossy().into_owned()),
            gecos: (!gecos.is_empty()).then_some(gecos),
        }
    }

    fn lookup_failed(what: &str, e: nix::Error) -> anyhow::Error {
        UserError::BackendOperationFailed(format!("cannot look up {what}: {e}")).into()
    }
}

impl UserBackendProvider for SystemBackend {
    fn gid_in_use(&self, gid: u32) -> Result<bool> {
        nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
            .map(|g| g.is_some())
            .map_err(|e| Self::lookup_failed(&format!("gid {gid}"), e))
    }

    fn create_user(&mut self, info: &UserInfo, create_home: bool) -> Result<()> {
        self.apply(BackendOp::CreateUser { info, create_home })
    }

    fn create_group(&mut self, info: &GroupInfo) -> Result<()> {
        self.apply(BackendOp::CreateGroup(info))
    }

    fn add_memberships(&mut self, username: &str, groups: &[String]) -> Result<()> {
        self.apply(BackendOp::AddMemberships { username, groups })
    }

    fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>> {
        nix::unistd::User::from_name(username)
            .map(|u| u.map(Self::record))
            .map_err(|e| Self::lookup_failed(&format!("user '{username}'"), e))
    }

    fn lookup_user_by_uid(&self, uid: u32) -> Result<Option<UserRecord>> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .map(|u| u.map(Self::record))
            .map_err(|e| Self::lookup_failed(&format!("uid {uid}"), e))
    }

    fn lookup_group(&self, group_name: &str) -> Result<Option<GroupRecord>> {
        nix::unistd::Group::from_name(group_name)
            .map(|g| {
                g.map(|g| GroupRecord {
                    name: g.name,
                    gid: Some(g.gid.as_raw()),
                    members: g.mem,
                })
            })
            .map_err(|e| Self::lookup_failed(&format!("group '{group_name}'"), e))
    }

    fn delete_user(&mut self, username: &str, remove_home: bool, remove_mail: bool) -> Result<()> {
        self.apply(BackendOp::DeleteUser {
            username,
            remove_home,
            remove_mail,
        })
    }

    fn delete_group(&mut self, group_name: &str) -> Result<()> {
        self.apply(BackendOp::DeleteGroup(group_name))
    }

    fn remove_user_from_group(&mut self, username: &str, group_name: &str) -> Result<()> {
        self.apply(BackendOp::RemoveMembership {
            username,
            group: group_name,
        })
    }

    fn list_groups_for_user(&self, username: &str) -> Result<Vec<String>> {
        let user = nix::unistd::User::from_name(username)
            .map_err(|e| Self::lookup_failed(&format!("user '{username}'"), e))?
            .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;
        let record = Self::record(user.clone());
        let c_user = std::ffi::CString::new(username)
            .map_err(|_| UserError::UsernameInvalid("username contains NUL".to_string()))?;
        let gids = nix::unistd::getgrouplist(&c_user, user.gid)
            .map_err(|e| UserError::GroupsBackendFailure(format!("getgrouplist failed: {e}")))?;
        // Primary group first, then supplementary groups.
        let mut groups = vec![record.primary_group];
        for gid in gids {
            let name = nix::unistd::Group::from_gid(gid)
                .ok()
                .flatten()
                .map(|g| g.name)
                .unwrap_or_else(|| gid.to_string());
            if !groups.contains(&name) {
                groups.push(name);
            }
        }
        Ok(groups)
    }

    fn password_field(&self, username: &str) -> Result<Option<String>> {
        self.shadow_field(username)
    }

    fn set_password_hash(&mut self, username: &str, hash: &str) -> Result<()> {
        self.apply(BackendOp::SetPasswordHash { username, hash })
    }

    fn planned_commands(&self, op: &BackendOp) -> Result<Vec<String>> {
        Ok(system_commands(op)?
            .iter()
            .map(SystemCommand::display)
            .collect())
    }

    fn is_locked(&self, username: &str) -> Result<bool> {
        // Prefer the shadow file (root only); fall back to `passwd -S`.
        let shadow_err = match self.shadow_field(username) {
            Ok(Some(field)) => return Ok(shadow_field_is_locked(&field)),
            Ok(None) => format!(
                "no entry for '{}' in {}",
                username,
                self.shadow_path.display()
            ),
            Err(e) => e.to_string(),
        };
        if cfg!(test) {
            return Err(UserError::BackendOperationFailed(format!(
                "cannot determine lock state of '{username}': {shadow_err}; \
                 passwd -S is not run from unit tests"
            ))
            .into());
        }
        let cmd = SystemCommand::new(&["passwd", "-S", "--", username]);
        match self.run(&cmd) {
            Ok(out) => parse_passwd_status(&out, username).ok_or_else(|| {
                UserError::BackendOperationFailed(format!(
                    "unrecognized passwd -S output for '{}'",
                    username
                ))
                .into()
            }),
            Err(e) => match e.downcast::<UserError>() {
                Ok(UserError::Timeout(m)) => Err(UserError::Timeout(m).into()),
                Ok(other) => Err(UserError::BackendOperationFailed(format!(
                    "cannot determine lock state of '{username}': {shadow_err}; {other}"
                ))
                .into()),
                Err(e) => Err(e),
            },
        }
    }

    fn lock_user(&mut self, username: &str) -> Result<()> {
        self.apply(BackendOp::Lock(username))
    }

    fn unlock_user(&mut self, username: &str) -> Result<()> {
        self.apply(BackendOp::Unlock(username))
    }

    fn path_exists(&self, path: &str) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn supports_argon2(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct MockUser {
    uid: u32,
    primary_group: String,
    home: String,
    shell: String,
    gecos: Option<String>,
    /// The shadow password field: `!` (no password yet) like useradd.
    password: String,
}

#[derive(Debug, Clone)]
struct MockGroup {
    gid: u32,
    members: Vec<String>,
}

#[derive(Debug, Default)]
struct MockState {
    users: HashMap<String, MockUser>,
    groups: HashMap<String, MockGroup>,
    homes: HashSet<String>,
    /// Every change, in order (tests check that dry runs change nothing).
    changes: Vec<String>,
}

/// In-memory backend. It models the system backend's rules (a new account
/// has the password field `!`, `unlock` refuses to leave an account without
/// a password, the primary group is not a listed membership). Clones share
/// one store.
#[derive(Debug, Clone, Default)]
pub struct MockBackend {
    state: Arc<Mutex<MockState>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn st(&self) -> std::sync::MutexGuard<'_, MockState> {
        // A test that panicked while holding the lock leaves usable data.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn change(&self, what: String) {
        self.st().changes.push(what);
    }

    /// The changes made so far.
    pub fn changes(&self) -> Vec<String> {
        self.st().changes.clone()
    }

    pub fn with_existing_user(self, username: &str, uid: u32, primary_group: &str) -> Self {
        {
            let mut st = self.st();
            st.users.insert(
                username.to_string(),
                MockUser {
                    uid,
                    primary_group: primary_group.to_string(),
                    home: format!("/home/{username}"),
                    shell: "/bin/bash".to_string(),
                    gecos: None,
                    password: "!".to_string(),
                },
            );
            st.homes.insert(format!("/home/{username}"));
            st.groups
                .entry(primary_group.to_string())
                .or_insert(MockGroup {
                    gid: uid,
                    members: vec![],
                });
        }
        self
    }

    pub fn with_existing_group(self, group_name: &str, gid: u32) -> Self {
        self.st().groups.insert(
            group_name.to_string(),
            MockGroup {
                gid,
                members: vec![],
            },
        );
        self
    }

    pub fn with_existing_membership(self, username: &str, group_name: &str) -> Self {
        if let Some(g) = self.st().groups.get_mut(group_name) {
            g.members.push(username.to_string());
        }
        self
    }

    pub fn with_password(self, username: &str, password_hash: &str) -> Self {
        if let Some(u) = self.st().users.get_mut(username) {
            u.password = password_hash.to_string();
        }
        self
    }

    pub fn with_locked_user(self, username: &str, locked: bool) -> Self {
        if let Some(u) = self.st().users.get_mut(username) {
            let bare = u.password.trim_start_matches('!').to_string();
            u.password = if locked { format!("!{bare}") } else { bare };
        }
        self
    }

    fn rec(name: &str, u: &MockUser) -> UserRecord {
        UserRecord {
            username: name.to_string(),
            uid: u.uid,
            primary_group: u.primary_group.clone(),
            home: Some(u.home.clone()),
            shell: Some(u.shell.clone()),
            gecos: u.gecos.clone(),
        }
    }

    fn missing_user(name: &str) -> anyhow::Error {
        UserError::BackendOperationFailed(format!("user '{name}' does not exist")).into()
    }
}

impl UserBackendProvider for MockBackend {
    fn gid_in_use(&self, gid: u32) -> Result<bool> {
        Ok(self.st().groups.values().any(|g| g.gid == gid))
    }

    fn create_user(&mut self, info: &UserInfo, create_home: bool) -> Result<()> {
        {
            let mut st = self.st();
            if st.users.contains_key(&info.username) {
                return Err(UserError::UsernameConflict(info.username.clone()).into());
            }
            if !st.groups.contains_key(&info.primary_group) {
                return Err(UserError::GroupNotFound(info.primary_group.clone()).into());
            }
            for g in &info.supplementary_groups {
                let group = st
                    .groups
                    .get_mut(g)
                    .ok_or_else(|| UserError::GroupNotFound(g.clone()))?;
                group.members.push(info.username.clone());
            }
            let home = info
                .home
                .clone()
                .unwrap_or_else(|| format!("/home/{}", info.username));
            if create_home {
                st.homes.insert(home.clone());
            }
            st.users.insert(
                info.username.clone(),
                MockUser {
                    uid: info.uid,
                    primary_group: info.primary_group.clone(),
                    home,
                    shell: info.shell.clone().unwrap_or_else(|| "/bin/bash".into()),
                    gecos: info.gecos.clone(),
                    password: "!".to_string(),
                },
            );
        }
        self.change(format!("create user {}", info.username));
        Ok(())
    }

    fn create_group(&mut self, info: &GroupInfo) -> Result<()> {
        {
            let mut st = self.st();
            if st.groups.contains_key(&info.name) {
                return Err(UserError::GroupConflict(info.name.clone()).into());
            }
            st.groups.insert(
                info.name.clone(),
                MockGroup {
                    gid: info.gid,
                    members: vec![],
                },
            );
        }
        self.change(format!("create group {}", info.name));
        Ok(())
    }

    fn add_memberships(&mut self, username: &str, groups: &[String]) -> Result<()> {
        {
            let mut st = self.st();
            if !st.users.contains_key(username) {
                return Err(Self::missing_user(username));
            }
            for g in groups {
                let group = st
                    .groups
                    .get_mut(g)
                    .ok_or_else(|| UserError::GroupNotFound(g.clone()))?;
                if !group.members.iter().any(|m| m == username) {
                    group.members.push(username.to_string());
                }
            }
        }
        self.change(format!("add {} to {}", username, groups.join(",")));
        Ok(())
    }

    fn lookup_user(&self, username: &str) -> Result<Option<UserRecord>> {
        Ok(self
            .st()
            .users
            .get(username)
            .map(|u| Self::rec(username, u)))
    }

    fn lookup_user_by_uid(&self, uid: u32) -> Result<Option<UserRecord>> {
        let st = self.st();
        let mut found: Vec<(&String, &MockUser)> =
            st.users.iter().filter(|(_, u)| u.uid == uid).collect();
        found.sort_by(|a, b| a.0.cmp(b.0));
        Ok(found.first().map(|(n, u)| Self::rec(n, u)))
    }

    fn lookup_group(&self, group_name: &str) -> Result<Option<GroupRecord>> {
        Ok(self.st().groups.get(group_name).map(|g| GroupRecord {
            name: group_name.to_string(),
            gid: Some(g.gid),
            members: g.members.clone(),
        }))
    }

    fn delete_user(&mut self, username: &str, remove_home: bool, _remove_mail: bool) -> Result<()> {
        {
            let mut st = self.st();
            let user = st
                .users
                .remove(username)
                .ok_or_else(|| Self::missing_user(username))?;
            for g in st.groups.values_mut() {
                g.members.retain(|m| m != username);
            }
            if remove_home {
                st.homes.remove(&user.home);
            }
        }
        self.change(format!("delete user {username}"));
        Ok(())
    }

    fn delete_group(&mut self, group_name: &str) -> Result<()> {
        {
            let mut st = self.st();
            if st.users.values().any(|u| u.primary_group == group_name) {
                return Err(UserError::BackendOperationFailed(format!(
                    "cannot remove the primary group of a user: {group_name}"
                ))
                .into());
            }
            st.groups.remove(group_name);
        }
        self.change(format!("delete group {group_name}"));
        Ok(())
    }

    fn remove_user_from_group(&mut self, username: &str, group_name: &str) -> Result<()> {
        {
            let mut st = self.st();
            let group = st
                .groups
                .get_mut(group_name)
                .ok_or_else(|| UserError::GroupNotFound(group_name.to_string()))?;
            if !group.members.iter().any(|m| m == username) {
                return Err(UserError::MembershipNotFound(
                    username.to_string(),
                    group_name.to_string(),
                )
                .into());
            }
            group.members.retain(|m| m != username);
        }
        self.change(format!("remove {username} from {group_name}"));
        Ok(())
    }

    fn list_groups_for_user(&self, username: &str) -> Result<Vec<String>> {
        let st = self.st();
        let user = st
            .users
            .get(username)
            .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;
        let mut out = vec![user.primary_group.clone()];
        let mut sup: Vec<&String> = st
            .groups
            .iter()
            .filter(|(_, g)| g.members.iter().any(|m| m == username))
            .map(|(n, _)| n)
            .collect();
        sup.sort();
        for n in sup {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        Ok(out)
    }

    fn password_field(&self, username: &str) -> Result<Option<String>> {
        Ok(self.st().users.get(username).map(|u| u.password.clone()))
    }

    fn set_password_hash(&mut self, username: &str, hash: &str) -> Result<()> {
        {
            let mut st = self.st();
            let user = st
                .users
                .get_mut(username)
                .ok_or_else(|| Self::missing_user(username))?;
            user.password = hash.to_string();
        }
        self.change(format!("set password of {username}"));
        Ok(())
    }

    fn is_locked(&self, username: &str) -> Result<bool> {
        let st = self.st();
        let user = st
            .users
            .get(username)
            .ok_or_else(|| Self::missing_user(username))?;
        Ok(shadow_field_is_locked(&user.password))
    }

    fn lock_user(&mut self, username: &str) -> Result<()> {
        {
            let mut st = self.st();
            let user = st
                .users
                .get_mut(username)
                .ok_or_else(|| Self::missing_user(username))?;
            if !user.password.starts_with('!') {
                user.password = format!("!{}", user.password);
            }
        }
        self.change(format!("lock {username}"));
        Ok(())
    }

    fn unlock_user(&mut self, username: &str) -> Result<()> {
        {
            let mut st = self.st();
            let user = st
                .users
                .get_mut(username)
                .ok_or_else(|| Self::missing_user(username))?;
            let bare = user.password.trim_start_matches('!');
            if bare.is_empty() {
                // usermod -U refuses this too.
                return Err(UserError::BackendOperationFailed(
                    "unlocking the user's password would result in a passwordless account"
                        .to_string(),
                )
                .into());
            }
            user.password = bare.to_string();
        }
        self.change(format!("unlock {username}"));
        Ok(())
    }

    fn path_exists(&self, path: &str) -> bool {
        self.st().homes.contains(path)
    }

    fn supports_argon2(&self) -> bool {
        true
    }
}
