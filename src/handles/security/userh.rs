//! `user://`: local accounts, groups and memberships.
//!
//! Every verb checks its arguments strictly before doing anything
//! (`args`), then runs against a backend (`backend`): the system backend
//! reads the account database through NSS and changes it with the
//! shadow-utils tools under the verb's deadline (`exec`); new passwords are
//! hashed here (`sha_crypt`, bcrypt, argon2) and handed to `chpasswd -e` on
//! standard input, never on a command line.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use thiserror::Error;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};

mod args;
mod backend;
mod exec;
mod libcrypt;
mod sha_crypt;
mod verbs;

pub use backend::{
    BackendOp, MockBackend, SystemBackend, SystemCommand, UserBackendProvider, hash_password,
    hash_scheme_of, parse_passwd_status, shadow_field_is_locked, shadow_password_field,
    system_commands, verify_password_hash,
};

/// Metadata for `resh user --help` and `resh user <verb> --help`.
static USER_HELP: HandleHelp = HandleHelp {
    description: "The user handle creates, deletes, and inspects local user accounts, groups, \
        and group memberships, and changes passwords and account lock state. The default \
        system backend reads the user database with getpwnam, getgrnam, and getgrouplist and \
        makes changes by running useradd, groupadd, usermod, userdel, groupdel, gpasswd, or \
        chpasswd (passwords are hashed by resh and passed to chpasswd -e on standard input), \
        which needs root, while dry_run=true only lists those commands as planned_commands \
        and backend=mock uses an empty in-memory store. Name a user as user://alice, a group \
        as user://group/admins, or a member as user://membership/alice (the three-slash forms \
        such as user:///alice also work), or pass username=, group_name=, or member=.",
    usage: "resh user://<name>.<verb>[(key=value,...)]",
    verbs: &[
        VerbHelp {
            name: "exists",
            definition: "Reports whether a user account exists, looked up by username, and \
                checks that its UID matches when uid is also given.",
            detail: Some(VerbDetail {
                usage: "resh user://<username>.exists [username=<name>] [uid=<n>]\n  \
                    [backend=system|mock] [format=json|text]",
                example: "resh --json-pretty user://root.exists",
                example_output: Some(
                    r#"{
  "backend": "system",
  "ok": true,
  "query": {
    "uid": null,
    "username": "root"
  },
  "user": {
    "exists": true,
    "uid": 0,
    "username": "root"
  }
}

Shown with --json-pretty. A missing user reports exists false with null
username and uid, plus a warnings array."#,
                ),
            }),
        },
        VerbHelp {
            name: "groups",
            definition: "Lists the groups a user belongs to, marking each as primary, \
                supplementary, or a system group.",
            detail: Some(VerbDetail {
                usage: "resh user://<username>.groups [username=<name>]\n  \
                    [include_primary=true|false] [include_supplementary=true|false]\n  \
                    [include_system_groups=true|false] [min_gid_for_system=<n>]\n  \
                    [group_name_filter=<group>] [ignore_if_missing=true|false]\n  \
                    [backend=system|mock] [format=json|text]",
                example: "resh --json-pretty user://root.groups",
                example_output: Some(
                    r#"{
  "backend": "system",
  "groups": [
    {
      "gid": 0,
      "name": "root",
      "primary": true,
      "supplementary": false,
      "system_group": true
    }
  ],
  "ok": true,
  "user": {
    "existed": true,
    "missing": false,
    "uid": 0,
    "username": "root"
  }
}

Shown for the system backend with --json-pretty. The primary group is
listed first, then the supplementary groups from getgrouplist."#,
                ),
            }),
        },
        VerbHelp {
            name: "add",
            definition: "Creates a user, a group, or a user's group memberships according to \
                mode, which defaults to user.",
            detail: Some(VerbDetail {
                usage: "resh user://<name>.add [mode=user|group|membership]\n  \
                    [username=<name>] [uid=<n>] [primary_group=<group>]\n  \
                    [supplementary_groups=<g1,g2>] [groups=<g1,g2>] [home=<path>]\n  \
                    [create_home=true|false] [shell=<path>] [gecos=<text>]\n  \
                    [password_hash=<hash>] [group_name=<group>] [gid=<n>]\n  \
                    [member=<user>] [ignore_if_exists=true|false] [force=true|false]\n  \
                    [dry_run=true|false] [backend=system|mock] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty user://alice.add mode=user shell=/bin/zsh \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "system",
  "dry_run": true,
  "groups": [
    {
      "created": false,
      "existed": false,
      "gid": 1001,
      "name": "alice"
    }
  ],
  "mode": "user",
  "ok": true,
  "planned_commands": [
    "groupadd -g 1001 -- alice",
    "useradd -u 1001 -g alice -d /home/alice -m -s /bin/zsh -- alice"
  ],
  "user": {
    "created": false,
    "existed": false,
    "gecos": null,
    "home": "/home/alice",
    "primary_group": "alice",
    "shell": "/bin/zsh",
    "supplementary_groups": [],
    "uid": 1001,
    "username": "alice"
  }
}

Shown for mode=user with --json-pretty. Without dry_run the commands are
run and need root; timeout_ms (default 60000) bounds them. In mode=user,
groups= is another name for supplementary_groups=; in mode=membership it
lists the groups to join. mode=group reports a group object, and
mode=membership reports member and memberships."#,
                ),
            }),
        },
        VerbHelp {
            name: "delete",
            definition: "Removes a user, a group, or a user's group memberships according to \
                mode, which defaults to user.",
            detail: Some(VerbDetail {
                usage: "resh user://<name>.delete [mode=user|group|membership]\n  \
                    [username=<name>] [remove_home=true|false] [remove_mail=true|false]\n  \
                    [remove_from_all_groups=true|false] [protect_system_users=true|false]\n  \
                    [min_uid_for_delete=<n>] [group_name=<group>] [only_if_empty=true|false]\n  \
                    [protect_system_groups=true|false] [min_gid_for_delete=<n>]\n  \
                    [member=<user>] [groups=<g1,g2>] [all_groups=true|false]\n  \
                    [ignore_if_missing=true|false] [force=true|false]\n  \
                    [dry_run=true|false] [backend=system|mock] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty user://alice.delete remove_home=true dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "system",
  "dry_run": true,
  "home": {
    "path": "/home/alice",
    "removed": false,
    "was_present": true
  },
  "mail": {
    "path": "/var/mail/alice",
    "removed": false,
    "was_present": false
  },
  "memberships": [
    {
      "group": "alice",
      "missing_group": false,
      "removed": false,
      "was_member": true
    }
  ],
  "mode": "user",
  "ok": true,
  "planned_commands": [
    "userdel -r -- alice"
  ],
  "user": {
    "deleted": false,
    "existed": true,
    "missing": false,
    "uid": 1001,
    "username": "alice"
  }
}

Shown for mode=user on the system backend with --json-pretty. Without
dry_run the commands are run and need root; timeout_ms (default 60000)
bounds them. userdel removes the account from every group."#,
                ),
            }),
        },
        VerbHelp {
            name: "passwd",
            definition: "Sets a user's password from a plaintext password (given inline, \
                in an environment variable, or on standard input), hashed with hash_scheme \
                or the backend default, or from a precomputed new_password_hash.",
            detail: Some(VerbDetail {
                usage: "resh user://<user>.passwd new_password_plain=<pw>|\n  \
                    new_password_env=<VAR>|new_password_stdin=true|\n  \
                    new_password_hash=<hash> [username=<name>]\n  \
                    [hash_scheme=backend_default|sha512_crypt|bcrypt|argon2id]\n  \
                    [require_old_password=true|false] [old_password_plain=<pw>]\n  \
                    [old_password_env=<VAR>] [ignore_if_missing=true|false]\n  \
                    [force=true|false] [dry_run=true|false] [backend=system|mock]\n  \
                    [format=json|text] [timeout_ms=<ms>]",
                example: "resh --json-pretty user://alice.passwd \
                    new_password_env=NEW_PW dry_run=true",
                example_output: Some(
                    r#"{
  "backend": "system",
  "dry_run": true,
  "ok": true,
  "password": {
    "changed": false,
    "old_password_verified": false,
    "scheme": "sha512_crypt",
    "source": "env"
  },
  "planned_commands": [
    "chpasswd -e <<< (redacted)"
  ],
  "user": {
    "existed": true,
    "missing": false,
    "username": "alice"
  },
  "warnings": [
    "Dry run: no password was actually changed."
  ]
}

Shown for the system backend with --json-pretty, NEW_PW holding the
password. resh hashes it (backend_default is sha512_crypt) and passes
the hash to chpasswd -e on stdin (needs root); the system backend
rejects argon2id. new_password_plain= is visible in the process list
and always prints a warning. Accounts with a UID below 1000 (root
included) need force=true. require_old_password needs read access to
/etc/shadow and checks every scheme the system crypt library knows
(yescrypt included), plus sha512_crypt, sha256_crypt, bcrypt and
argon2."#,
                ),
            }),
        },
        VerbHelp {
            name: "lock",
            definition: "Locks a user account so its password can no longer be used to log in.",
            detail: Some(VerbDetail {
                usage: "resh user://<username>.lock [username=<name>]\n  \
                    [protect_system_users=true|false] [min_uid_for_lock=<n>]\n  \
                    [force=true|false] [ignore_if_missing=true|false]\n  \
                    [dry_run=true|false] [backend=system|mock] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty user://alice.lock",
                example_output: Some(
                    r#"{
  "backend": "system",
  "dry_run": false,
  "lock": {
    "changed": true,
    "is_locked": true,
    "requested": true,
    "was_locked": false
  },
  "ok": true,
  "user": {
    "existed": true,
    "missing": false,
    "uid": 1001,
    "username": "alice"
  }
}

Shown for the system backend with --json-pretty, which runs usermod -L
and needs root, then checks the account is locked. The current state
comes from /etc/shadow or passwd -S; if neither can be read the verb
fails, except that a dry run reports was_locked null with a warning."#,
                ),
            }),
        },
        VerbHelp {
            name: "unlock",
            definition: "Unlocks a previously locked user account.",
            detail: Some(VerbDetail {
                usage: "resh user://<username>.unlock [username=<name>]\n  \
                    [protect_system_users=true|false] [min_uid_for_unlock=<n>]\n  \
                    [force=true|false] [ignore_if_missing=true|false]\n  \
                    [dry_run=true|false] [backend=system|mock] [format=json|text]\n  \
                    [timeout_ms=<ms>]",
                example: "resh --json-pretty user://alice.unlock",
                example_output: Some(
                    r#"{
  "backend": "system",
  "dry_run": false,
  "ok": true,
  "unlock": {
    "changed": true,
    "is_locked": false,
    "requested": true,
    "was_locked": true
  },
  "user": {
    "existed": true,
    "missing": false,
    "uid": 1001,
    "username": "alice"
  }
}

Shown for the system backend with --json-pretty, which runs usermod -U
and needs root, then checks the account is unlocked. An account that is
already unlocked is left unchanged with a warning; one without a
password cannot be unlocked."#,
                ),
            }),
        },
    ],
};

/// User management errors. Each has a stable code (`user.<name>`) and an
/// exit status from [`ERROR_CODES`].
#[derive(Debug, Error)]
pub enum UserError {
    #[error("{0}")]
    InvalidArgument(String),

    #[error("{0}")]
    InvalidTarget(String),

    #[error("{0}")]
    InvalidMode(String),

    #[error("backend '{0}' is not supported (use system or mock)")]
    BackendNotSupported(String),

    #[error("a user name is required (user://<name> or username=)")]
    UsernameRequired,

    #[error("a group name is required (user://group/<name> or group_name=)")]
    GroupNameRequired,

    #[error("a member is required (user://membership/<name> or member=)")]
    MemberRequired,

    #[error("groups=<g1,g2> is required")]
    GroupsRequired,

    #[error("give a user name (user://<name> or username=) or uid=")]
    IdentityRequired,

    #[error("invalid user name: {0}")]
    UsernameInvalid(String),

    #[error("invalid group name: {0}")]
    GroupNameInvalid(String),

    #[error("uid {0} is out of the allowed range (1000-65533, or 0-65533 with force=true)")]
    UidOutOfRange(u32),

    #[error("gid {0} is out of the allowed range (1000-65533, or 0-65533 with force=true)")]
    GidOutOfRange(u32),

    #[error("both a plaintext password and a password hash were given; give exactly one source")]
    PasswordConflictingSources,

    #[error(
        "a new password is required (new_password_plain=, new_password_env=, \
         new_password_stdin=true or new_password_hash=)"
    )]
    PasswordMissingNewPassword,

    #[error("hash scheme '{0}' is not supported")]
    HashSchemeUnsupported(String),

    #[error("invalid password hash: {0}")]
    HashParamsInvalid(String),

    #[error(
        "an old password (old_password_plain= or old_password_env=) is required when require_old_password=true"
    )]
    OldPasswordRequired,

    #[error("user '{0}' already exists")]
    UsernameConflict(String),

    #[error("group '{0}' already exists")]
    GroupConflict(String),

    #[error("uid {0} is already in use")]
    UidConflict(u32),

    #[error("gid {0} is already in use")]
    GidConflict(u32),

    #[error("no free {0} from 1000 to 65533")]
    NoFreeId(String),

    #[error("group '{0}' not found")]
    GroupNotFound(String),

    #[error("user '{0}' is already a member of group '{1}'")]
    MembershipExists(String, String),

    #[error("user '{0}' not found")]
    UserNotFound(String),

    #[error(
        "refusing to {2} system user '{0}' (uid={1}) because protect_system_users=true and force=false"
    )]
    SystemUserProtected(String, u32, &'static str, u32),

    #[error(
        "refusing to delete system group '{0}' (gid={1}) because protect_system_groups=true and force=false"
    )]
    SystemGroupProtected(String, u32, u32),

    #[error("group '{0}' is not empty and only_if_empty=true (force=true overrides)")]
    GroupNotEmpty(String),

    #[error("user '{0}' is not a member of group '{1}'")]
    MembershipNotFound(String, String),

    #[error(
        "group '{1}' is the primary group of user '{0}'; it is not a membership that can be removed"
    )]
    PrimaryGroupMembership(String, String),

    #[error("old password verification is not supported for {0} hashes")]
    OldPasswordVerificationUnsupported(String),

    #[error("old password did not match the stored password of user '{0}'")]
    OldPasswordMismatch(String),

    #[error("password change failed: {0}")]
    PasswordBackendFailure(String),

    #[error("lock failed: {0}")]
    LockBackendFailure(String),

    #[error("unlock failed: {0}")]
    UnlockBackendFailure(String),

    #[error("cannot list groups: {0}")]
    GroupsBackendFailure(String),

    #[error("user '{0}' exists with uid={1}, which does not match requested uid={2}")]
    ExistsMismatch(String, u32, u32),

    #[error("failed to query user in backend '{0}': {1}")]
    ExistsBackendFailure(String, String),

    #[error("{0}")]
    BackendOperationFailed(String),

    #[error("{0}")]
    PermissionDenied(String),

    #[error("{0}")]
    ToolNotFound(String),

    #[error("{0}")]
    Timeout(String),

    #[error("{0}")]
    PartialFailure(String),

    #[error(
        "refusing to change the password of system account '{0}' (uid={1}, below 1000) without force=true"
    )]
    ProtectedAccount(String, u32),
}

/// Every error code the handle reports, with its exit status: 2 for invalid
/// usage (nothing was looked up or changed), 1 for an operation that failed
/// or was refused, 124 for a deadline that passed (outcome unknown).
pub(crate) const ERROR_CODES: &[(&str, i32)] = &[
    ("user.invalid_argument", exit::USAGE),
    ("user.invalid_target", exit::USAGE),
    ("user.invalid_mode", exit::USAGE),
    ("user.backend_not_supported", exit::USAGE),
    ("user.username_required", exit::USAGE),
    ("user.group_name_required", exit::USAGE),
    ("user.member_required", exit::USAGE),
    ("user.groups_required", exit::USAGE),
    ("user.identity_required", exit::USAGE),
    ("user.username_invalid", exit::USAGE),
    ("user.group_name_invalid", exit::USAGE),
    ("user.uid_out_of_range", exit::USAGE),
    ("user.gid_out_of_range", exit::USAGE),
    ("user.passwd_conflicting_sources", exit::USAGE),
    ("user.passwd_missing_new_password", exit::USAGE),
    ("user.hash_scheme_unsupported", exit::USAGE),
    ("user.hash_params_invalid", exit::USAGE),
    ("user.old_password_required", exit::USAGE),
    ("user.protected_account", exit::USAGE),
    ("user.username_conflict", exit::FAILED),
    ("user.group_conflict", exit::FAILED),
    ("user.uid_conflict", exit::FAILED),
    ("user.gid_conflict", exit::FAILED),
    ("user.no_free_id", exit::FAILED),
    ("user.group_not_found", exit::FAILED),
    ("user.membership_exists", exit::FAILED),
    ("user.not_found", exit::FAILED),
    ("user.system_user_protected", exit::FAILED),
    ("user.group_system_protected", exit::FAILED),
    ("user.group_not_empty", exit::FAILED),
    ("user.membership_not_found", exit::FAILED),
    ("user.primary_group_membership", exit::FAILED),
    ("user.old_password_verification_unsupported", exit::FAILED),
    ("user.old_password_mismatch", exit::FAILED),
    ("user.passwd_backend_failure", exit::FAILED),
    ("user.lock_backend_failure", exit::FAILED),
    ("user.unlock_backend_failure", exit::FAILED),
    ("user.groups_backend_failure", exit::FAILED),
    ("user.exists_mismatch", exit::FAILED),
    ("user.exists_backend_failure", exit::FAILED),
    ("user.backend_operation_failed", exit::FAILED),
    ("user.permission_denied", exit::FAILED),
    ("user.tool_not_found", exit::FAILED),
    ("user.partial_failure", exit::FAILED),
    // A handle error the dispatcher reports (such as stdout closed).
    ("user.failed", exit::FAILED),
    ("user.timeout", exit::TIMEOUT),
];

impl UserError {
    pub fn code(&self) -> String {
        let c = match self {
            Self::InvalidArgument(_) => "invalid_argument",
            Self::InvalidTarget(_) => "invalid_target",
            Self::InvalidMode(_) => "invalid_mode",
            Self::BackendNotSupported(_) => "backend_not_supported",
            Self::UsernameRequired => "username_required",
            Self::GroupNameRequired => "group_name_required",
            Self::MemberRequired => "member_required",
            Self::GroupsRequired => "groups_required",
            Self::IdentityRequired => "identity_required",
            Self::UsernameInvalid(_) => "username_invalid",
            Self::GroupNameInvalid(_) => "group_name_invalid",
            Self::UidOutOfRange(_) => "uid_out_of_range",
            Self::GidOutOfRange(_) => "gid_out_of_range",
            Self::PasswordConflictingSources => "passwd_conflicting_sources",
            Self::PasswordMissingNewPassword => "passwd_missing_new_password",
            Self::HashSchemeUnsupported(_) => "hash_scheme_unsupported",
            Self::HashParamsInvalid(_) => "hash_params_invalid",
            Self::OldPasswordRequired => "old_password_required",
            Self::UsernameConflict(_) => "username_conflict",
            Self::GroupConflict(_) => "group_conflict",
            Self::UidConflict(_) => "uid_conflict",
            Self::GidConflict(_) => "gid_conflict",
            Self::NoFreeId(_) => "no_free_id",
            Self::GroupNotFound(_) => "group_not_found",
            Self::MembershipExists(_, _) => "membership_exists",
            Self::UserNotFound(_) => "not_found",
            Self::SystemUserProtected(..) => "system_user_protected",
            Self::SystemGroupProtected(..) => "group_system_protected",
            Self::GroupNotEmpty(_) => "group_not_empty",
            Self::MembershipNotFound(_, _) => "membership_not_found",
            Self::PrimaryGroupMembership(_, _) => "primary_group_membership",
            Self::OldPasswordVerificationUnsupported(_) => "old_password_verification_unsupported",
            Self::OldPasswordMismatch(_) => "old_password_mismatch",
            Self::PasswordBackendFailure(_) => "passwd_backend_failure",
            Self::LockBackendFailure(_) => "lock_backend_failure",
            Self::UnlockBackendFailure(_) => "unlock_backend_failure",
            Self::GroupsBackendFailure(_) => "groups_backend_failure",
            Self::ExistsMismatch(..) => "exists_mismatch",
            Self::ExistsBackendFailure(_, _) => "exists_backend_failure",
            Self::BackendOperationFailed(_) => "backend_operation_failed",
            Self::PermissionDenied(_) => "permission_denied",
            Self::ToolNotFound(_) => "tool_not_found",
            Self::Timeout(_) => "timeout",
            Self::PartialFailure(_) => "partial_failure",
            Self::ProtectedAccount(_, _) => "protected_account",
        };
        format!("user.{c}")
    }

    /// The exit status for this error (0/1/2/124 convention).
    pub fn exit_code(&self) -> i32 {
        exit_for(&self.code())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": false,
            "error": {
                "code": self.code(),
                "message": self.to_string(),
                "details": self.details()
            }
        })
    }

    fn details(&self) -> Value {
        match self {
            Self::UsernameConflict(username) => json!({"username": username}),
            Self::GroupConflict(group_name) => json!({"group_name": group_name}),
            Self::UidConflict(uid) | Self::UidOutOfRange(uid) => json!({"uid": uid}),
            Self::GidConflict(gid) | Self::GidOutOfRange(gid) => json!({"gid": gid}),
            Self::GroupNotFound(group_name) | Self::GroupNotEmpty(group_name) => {
                json!({"group_name": group_name})
            }
            Self::MembershipExists(username, group_name)
            | Self::MembershipNotFound(username, group_name)
            | Self::PrimaryGroupMembership(username, group_name) => {
                json!({"username": username, "group_name": group_name})
            }
            Self::UserNotFound(username) => json!({"username": username}),
            Self::SystemUserProtected(username, uid, verb, min) => {
                let key = format!("min_uid_for_{verb}");
                let mut d = json!({"username": username, "uid": uid});
                d[key] = json!(min);
                d
            }
            Self::SystemGroupProtected(group_name, gid, min) => {
                json!({"group_name": group_name, "gid": gid, "min_gid_for_delete": min})
            }
            Self::HashSchemeUnsupported(scheme) => json!({"hash_scheme": scheme}),
            Self::OldPasswordVerificationUnsupported(scheme) => json!({"hash_scheme": scheme}),
            Self::OldPasswordMismatch(username) => {
                json!({"username": username, "require_old_password": true})
            }
            Self::ExistsMismatch(username, actual_uid, requested_uid) => json!({
                "username": username,
                "actual_uid": actual_uid,
                "requested_uid": requested_uid
            }),
            Self::ExistsBackendFailure(backend, cause) => json!({
                "backend": backend,
                "cause": cause
            }),
            _ => json!({}),
        }
    }
}

/// The exit status for error `code` (1 for a code not in the table).
fn exit_for(code: &str) -> i32 {
    ERROR_CODES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or(exit::FAILED, |(_, e)| *e)
}

/// User add mode enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserAddMode {
    User,
    Group,
    Membership,
}

/// User delete mode enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserDeleteMode {
    User,
    Group,
    Membership,
}

impl fmt::Display for UserAddMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Group => write!(f, "group"),
            Self::Membership => write!(f, "membership"),
        }
    }
}

impl fmt::Display for UserDeleteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Group => write!(f, "group"),
            Self::Membership => write!(f, "membership"),
        }
    }
}

/// User backend enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserBackend {
    System,
    Mock,
    File,
    Ldap,
}

impl fmt::Display for UserBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::Mock => write!(f, "mock"),
            Self::File => write!(f, "file"),
            Self::Ldap => write!(f, "ldap"),
        }
    }
}

/// Output format enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Text,
}

/// Password source enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordSource {
    Plain,
    Hash,
}

/// Hash scheme enumeration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashScheme {
    BackendDefault,
    Sha512Crypt,
    Bcrypt,
    Argon2id,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Text => write!(f, "text"),
        }
    }
}

impl fmt::Display for PasswordSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::Hash => write!(f, "hash"),
        }
    }
}

impl fmt::Display for HashScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendDefault => write!(f, "backend_default"),
            Self::Sha512Crypt => write!(f, "sha512_crypt"),
            Self::Bcrypt => write!(f, "bcrypt"),
            Self::Argon2id => write!(f, "argon2id"),
        }
    }
}

/// User add options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserAddOptions {
    pub mode: UserAddMode,
    pub backend: UserBackend,
    pub dry_run: bool,
    pub ignore_if_exists: bool,
    pub force: bool,
    pub format: OutputFormat,
    /// Deadline of every tool the verb runs, in milliseconds.
    pub timeout_ms: u64,

    // User mode
    pub username: Option<String>,
    pub uid: Option<u32>,
    pub primary_group: Option<String>,
    pub supplementary_groups: Vec<String>,
    pub home: Option<String>,
    pub create_home: bool,
    pub shell: Option<String>,
    pub gecos: Option<String>,
    pub password_hash: Option<String>,

    // Group mode
    pub group_name: Option<String>,
    pub gid: Option<u32>,

    // Membership mode
    pub member: Option<String>,
    pub groups: Vec<String>,
}

impl Default for UserAddOptions {
    fn default() -> Self {
        Self {
            mode: UserAddMode::User,
            backend: UserBackend::System,
            dry_run: false,
            ignore_if_exists: true,
            force: false,
            format: OutputFormat::Json,
            timeout_ms: args::DEFAULT_TIMEOUT_MS,
            username: None,
            uid: None,
            primary_group: None,
            supplementary_groups: Vec::new(),
            home: None,
            create_home: true,
            shell: None,
            gecos: None,
            password_hash: None,
            group_name: None,
            gid: None,
            member: None,
            groups: Vec::new(),
        }
    }
}

/// User delete options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserDeleteOptions {
    pub mode: UserDeleteMode,
    pub backend: UserBackend,
    pub dry_run: bool,
    pub ignore_if_missing: bool,
    pub force: bool,
    pub format: OutputFormat,
    /// Deadline of every tool the verb runs, in milliseconds.
    pub timeout_ms: u64,

    // User mode
    pub username: Option<String>,
    pub remove_home: bool,
    pub remove_mail: bool,
    pub remove_from_all_groups: bool,
    pub protect_system_users: bool,
    pub min_uid_for_delete: u32,

    // Group mode
    pub group_name: Option<String>,
    pub only_if_empty: bool,
    pub protect_system_groups: bool,
    pub min_gid_for_delete: u32,

    // Membership mode
    pub member: Option<String>,
    pub groups: Vec<String>,
    pub all_groups: bool,
}

impl Default for UserDeleteOptions {
    fn default() -> Self {
        Self {
            mode: UserDeleteMode::User,
            backend: UserBackend::System,
            dry_run: false,
            ignore_if_missing: true,
            force: false,
            format: OutputFormat::Json,
            timeout_ms: args::DEFAULT_TIMEOUT_MS,
            username: None,
            remove_home: false,
            remove_mail: false,
            remove_from_all_groups: true,
            protect_system_users: true,
            min_uid_for_delete: 1000,
            group_name: None,
            only_if_empty: true,
            protect_system_groups: true,
            min_gid_for_delete: 1000,
            member: None,
            groups: Vec::new(),
            all_groups: false,
        }
    }
}

/// User password options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserPasswdOptions {
    pub backend: UserBackend,
    pub dry_run: bool,
    pub ignore_if_missing: bool,
    pub force: bool,
    pub format: OutputFormat,
    /// Deadline of every tool the verb runs, in milliseconds.
    pub timeout_ms: u64,

    pub username: Option<String>,

    // Password source (exactly one must be provided)
    pub new_password_plain: Option<String>,
    pub new_password_hash: Option<String>,

    // Hashing options (for new_password_plain)
    pub hash_scheme: HashScheme,
    /// True when hash_scheme= was given.
    pub hash_scheme_given: bool,
    /// Where the new password came from: plain, env, stdin or hash.
    pub new_password_source: String,

    // Old password verification
    pub require_old_password: bool,
    pub old_password_plain: Option<String>,
}

impl Default for UserPasswdOptions {
    fn default() -> Self {
        Self {
            backend: UserBackend::System,
            dry_run: false,
            ignore_if_missing: true,
            force: false,
            format: OutputFormat::Json,
            timeout_ms: args::DEFAULT_TIMEOUT_MS,
            username: None,
            new_password_plain: None,
            new_password_hash: None,
            hash_scheme: HashScheme::BackendDefault,
            hash_scheme_given: false,
            new_password_source: "plain".to_string(),
            require_old_password: false,
            old_password_plain: None,
        }
    }
}

/// User lock options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserLockOptions {
    pub backend: UserBackend,
    pub dry_run: bool,
    pub ignore_if_missing: bool,
    pub force: bool,
    pub format: OutputFormat,
    /// Deadline of every tool the verb runs, in milliseconds.
    pub timeout_ms: u64,

    pub username: Option<String>,

    // Safety guards
    pub protect_system_users: bool,
    pub min_uid_for_lock: u32,
}

impl Default for UserLockOptions {
    fn default() -> Self {
        Self {
            backend: UserBackend::System,
            dry_run: false,
            ignore_if_missing: true,
            force: false,
            format: OutputFormat::Json,
            timeout_ms: args::DEFAULT_TIMEOUT_MS,
            username: None,
            protect_system_users: true,
            min_uid_for_lock: 1000,
        }
    }
}

/// User information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub primary_group: String,
    pub supplementary_groups: Vec<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub gecos: Option<String>,
    pub created: bool,
    pub existed: bool,
}

/// Group information structure
#[derive(Debug, Clone, Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub gid: u32,
    pub created: bool,
    pub existed: bool,
}

/// Detailed group information for groups verb
#[derive(Debug, Clone, Serialize)]
pub struct GroupInfoDetailed {
    pub name: String,
    pub gid: Option<u32>,
    pub primary: bool,
    pub supplementary: bool,
    pub system_group: bool,
}

/// Membership operation result
#[derive(Debug, Clone, Serialize)]
pub struct MembershipInfo {
    pub group: String,
    pub added: bool,
    pub already_member: bool,
}

/// User add response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserAddResponse {
    pub ok: bool,
    pub mode: String,
    pub backend: String,
    pub dry_run: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub memberships: Vec<MembershipInfo>,

    /// Whether password_hash= was stored (only when it was given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Commands a dry run on the system backend would run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub planned_commands: Vec<String>,
}

/// User delete information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserDeleteInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub existed: bool,
    pub deleted: bool,
    pub missing: bool,
}

/// Group delete information structure
#[derive(Debug, Clone, Serialize)]
pub struct GroupDeleteInfo {
    pub name: String,
    pub gid: Option<u32>,
    pub existed: bool,
    pub deleted: bool,
    pub missing: bool,
    pub member_count_before: u32,
}

/// Home directory information structure
#[derive(Debug, Clone, Serialize)]
pub struct HomeInfo {
    pub path: String,
    pub removed: bool,
    pub was_present: bool,
}

/// Mail spool information structure
#[derive(Debug, Clone, Serialize)]
pub struct MailInfo {
    pub path: String,
    pub removed: bool,
    pub was_present: bool,
}

/// Membership delete information structure
#[derive(Debug, Clone, Serialize)]
pub struct MembershipDeleteInfo {
    pub group: String,
    pub removed: bool,
    pub was_member: bool,
    pub missing_group: bool,
}

/// User delete response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserDeleteResponse {
    pub ok: bool,
    pub mode: String,
    pub backend: String,
    pub dry_run: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDeleteInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupDeleteInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<HomeInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub memberships: Vec<MembershipDeleteInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Commands a dry run on the system backend would run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub planned_commands: Vec<String>,
}

/// User password information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserPasswordInfo {
    pub username: String,
    pub existed: bool,
    pub missing: bool,
}

/// Password change information structure
#[derive(Debug, Clone, Serialize)]
pub struct PasswordInfo {
    pub changed: bool,
    pub scheme: Option<String>,
    pub source: Option<String>,
    pub old_password_verified: bool,
}

/// User password response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserPasswdResponse {
    pub ok: bool,
    pub backend: String,
    pub dry_run: bool,
    pub user: UserPasswordInfo,
    pub password: PasswordInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Commands a dry run on the system backend would run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub planned_commands: Vec<String>,
}

/// User lock information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserLockInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub existed: bool,
    pub missing: bool,
}

/// Lock operation information structure
#[derive(Debug, Clone, Serialize)]
pub struct LockInfo {
    pub requested: bool,
    pub was_locked: Option<bool>,
    pub is_locked: Option<bool>,
    pub changed: bool,
}

/// User lock response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserLockResponse {
    pub ok: bool,
    pub backend: String,
    pub dry_run: bool,
    pub user: UserLockInfo,
    pub lock: LockInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Commands a dry run on the system backend would run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub planned_commands: Vec<String>,
}

/// User unlock options structure
#[derive(Debug, Clone)]
pub struct UserUnlockOptions {
    pub backend: UserBackend,
    pub dry_run: bool,
    pub ignore_if_missing: bool,
    pub force: bool,
    pub format: OutputFormat,
    /// Deadline of every tool the verb runs, in milliseconds.
    pub timeout_ms: u64,

    pub username: Option<String>,

    // Safety guards
    pub protect_system_users: bool,
    pub min_uid_for_unlock: u32,
}

/// User groups options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserGroupsOptions {
    pub backend: UserBackend,
    pub ignore_if_missing: bool,
    pub format: OutputFormat,

    pub username: Option<String>,

    // Group inclusion/classification
    pub include_primary: bool,
    pub include_supplementary: bool,
    pub include_system_groups: bool,
    pub min_gid_for_system: u32,

    // Filtering
    pub group_name_filter: Option<String>,
}

/// User exists options structure
#[derive(Debug, Clone, Deserialize)]
pub struct UserExistsOptions {
    pub backend: UserBackend,
    pub format: OutputFormat,

    pub username: Option<String>,
    pub uid: Option<u32>,
}

impl Default for UserUnlockOptions {
    fn default() -> Self {
        Self {
            backend: UserBackend::System,
            dry_run: false,
            ignore_if_missing: true,
            force: false,
            format: OutputFormat::Json,
            timeout_ms: args::DEFAULT_TIMEOUT_MS,
            username: None,
            protect_system_users: true,
            min_uid_for_unlock: 1000,
        }
    }
}

impl Default for UserGroupsOptions {
    fn default() -> Self {
        Self {
            backend: UserBackend::System,
            ignore_if_missing: true,
            format: OutputFormat::Json,
            username: None,
            include_primary: true,
            include_supplementary: true,
            include_system_groups: true,
            min_gid_for_system: 1000,
            group_name_filter: None,
        }
    }
}

impl Default for UserExistsOptions {
    fn default() -> Self {
        Self {
            backend: UserBackend::System,
            format: OutputFormat::Json,
            username: None,
            uid: None,
        }
    }
}

/// User unlock information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserUnlockInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub existed: bool,
    pub missing: bool,
}

/// Unlock operation information structure
#[derive(Debug, Clone, Serialize)]
pub struct UnlockInfo {
    pub requested: bool,
    pub was_locked: Option<bool>,
    pub is_locked: Option<bool>,
    pub changed: bool,
}

/// User unlock response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserUnlockResponse {
    pub ok: bool,
    pub backend: String,
    pub dry_run: bool,
    pub user: UserUnlockInfo,
    pub unlock: UnlockInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Commands a dry run on the system backend would run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub planned_commands: Vec<String>,
}

/// User groups result information structure
#[derive(Debug, Clone, Serialize)]
pub struct UserGroupsResult {
    pub username: String,
    pub uid: Option<u32>,
    pub existed: bool,
    pub missing: bool,
}

/// User groups response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserGroupsResponse {
    pub ok: bool,
    pub backend: String,
    pub user: UserGroupsResult,
    pub groups: Vec<GroupInfoDetailed>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// User exists response structure
#[derive(Debug, Clone, Serialize)]
pub struct UserExistsResponse {
    pub ok: bool,
    pub backend: String,
    pub query: UserExistsQuery,
    pub user: UserExistsResult,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Query information for exists operation
#[derive(Debug, Clone, Serialize)]
pub struct UserExistsQuery {
    pub username: Option<String>,
    pub uid: Option<u32>,
}

/// Result information for exists operation
#[derive(Debug, Clone, Serialize)]
pub struct UserExistsResult {
    pub exists: bool,
    pub username: Option<String>,
    pub uid: Option<u32>,
}

/// User record structure for backend queries
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub username: String,
    pub uid: u32,
    pub primary_group: String,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub gecos: Option<String>,
}

/// Group record structure for backend queries
#[derive(Debug, Clone)]
pub struct GroupRecord {
    pub name: String,
    pub gid: Option<u32>,
    pub members: Vec<String>,
}

/// User target structure for parsing URL paths
#[derive(Debug, Clone)]
pub struct UserTarget {
    pub path: String,
}

impl UserTarget {
    pub fn from_url(url: &Url) -> Result<Self> {
        // Handle different URL patterns:
        // user://alice -> hostname is alice, path is empty -> username is alice
        // user://group/admins -> hostname is group, path is /admins -> group is admins
        // user://membership/alice -> hostname is membership, path is /alice -> member is alice
        let hostname = url.host_str().unwrap_or("");
        let path_part = url.path().trim_start_matches('/');

        let path = if hostname.is_empty() {
            // user:///alice -> path is alice
            path_part.to_string()
        } else if hostname == "group" || hostname == "membership" {
            // user://group/admins -> path is "group/admins"
            // user://membership/alice -> path is "membership/alice"
            format!("{}/{}", hostname, path_part)
        } else if path_part.is_empty() {
            // user://alice -> path is alice (hostname becomes the path)
            hostname.to_string()
        } else {
            // user://alice/extra is kept whole and refused as a target.
            format!("{}/{}", hostname, path_part)
        };

        Ok(Self { path })
    }

    pub fn extract_username(&self) -> Option<String> {
        if !self.path.contains('/') && !self.path.is_empty() {
            Some(self.path.clone())
        } else {
            None
        }
    }

    pub fn extract_group_name(&self) -> Option<String> {
        if self.path.starts_with("group/") {
            Some(self.path.strip_prefix("group/").unwrap().to_string())
        } else {
            None
        }
    }

    pub fn extract_member_name(&self) -> Option<String> {
        if self.path.starts_with("membership/") {
            Some(self.path.strip_prefix("membership/").unwrap().to_string())
        } else {
            None
        }
    }
}

/// User handle implementation
#[derive(Debug)]
pub struct UserHandle {
    alias: String,
}

impl UserHandle {
    /// Accepts both the host form (`user://alice`, `user://group/admins`,
    /// `user://membership/alice`) and the path form (`user:///alice`,
    /// `user:///group/admins`, `user:///membership/alice`).
    pub fn from_url(url: Url) -> Result<UserHandle> {
        let target = UserTarget::from_url(&url)?;
        Ok(UserHandle {
            alias: target.path.trim_end_matches('/').to_string(),
        })
    }

    /// Format response as text
    fn format_text_response(&self, response: &UserAddResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Mode    : {}\n", response.mode));
        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("Dry Run : {}\n", response.dry_run));
        output.push('\n');

        if let Some(user) = &response.user {
            output.push_str("User:\n");
            output.push_str(&format!("  Username       : {}\n", user.username));
            output.push_str(&format!("  UID            : {}\n", user.uid));
            output.push_str(&format!("  Primary Group  : {}\n", user.primary_group));
            if !user.supplementary_groups.is_empty() {
                output.push_str(&format!(
                    "  Supplementary  : {}\n",
                    user.supplementary_groups.join(", ")
                ));
            }
            if let Some(home) = &user.home {
                output.push_str(&format!("  Home           : {}\n", home));
            }
            if let Some(shell) = &user.shell {
                output.push_str(&format!("  Shell          : {}\n", shell));
            }
            if let Some(gecos) = &user.gecos {
                output.push_str(&format!("  GECOS          : {}\n", gecos));
            }
            output.push_str(&format!(
                "  Created        : {}\n",
                if user.created { "yes" } else { "no" }
            ));
            output.push('\n');
        }

        if let Some(group) = &response.group {
            output.push_str("Group:\n");
            output.push_str(&format!("  Name           : {}\n", group.name));
            output.push_str(&format!("  GID            : {}\n", group.gid));
            output.push_str(&format!(
                "  Created        : {}\n",
                if group.created { "yes" } else { "no" }
            ));
            output.push('\n');
        }

        if !response.groups.is_empty() {
            output.push_str("Groups:\n");
            for group in &response.groups {
                let status = if group.created { "created" } else { "existed" };
                output.push_str(&format!(
                    "  - {} (gid={}) {}\n",
                    group.name, group.gid, status
                ));
            }
            output.push('\n');
        }

        if !response.memberships.is_empty() {
            output.push_str("Memberships:\n");
            if let Some(member) = &response.member {
                for membership in &response.memberships {
                    let status = if membership.added {
                        "added"
                    } else if membership.already_member {
                        "already member"
                    } else {
                        "would add"
                    };
                    output.push_str(&format!(
                        "  - {} -> {} : {}\n",
                        member, membership.group, status
                    ));
                }
            }
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Format delete response as text
    fn format_delete_text_response(&self, response: &UserDeleteResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Mode    : {}\n", response.mode));
        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("Dry Run : {}\n", response.dry_run));
        output.push('\n');

        if let Some(user) = &response.user {
            output.push_str("User:\n");
            output.push_str(&format!("  Username  : {}\n", user.username));
            if let Some(uid) = user.uid {
                output.push_str(&format!("  UID       : {}\n", uid));
            }
            output.push_str(&format!(
                "  Existed   : {}\n",
                if user.existed { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Deleted   : {}\n",
                if user.deleted { "yes" } else { "no" }
            ));
            output.push('\n');
        }

        if let Some(group) = &response.group {
            output.push_str("Group:\n");
            output.push_str(&format!("  Name              : {}\n", group.name));
            if let Some(gid) = group.gid {
                output.push_str(&format!("  GID               : {}\n", gid));
            }
            output.push_str(&format!(
                "  Existed           : {}\n",
                if group.existed { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Deleted           : {}\n",
                if group.deleted { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "  Member Count      : {}\n",
                group.member_count_before
            ));
            output.push('\n');
        }

        if let Some(home) = &response.home {
            output.push_str("Home:\n");
            output.push_str(&format!("  Path      : {}\n", home.path));
            output.push_str(&format!(
                "  Removed   : {}\n",
                if home.removed { "yes" } else { "no" }
            ));
            output.push('\n');
        }

        if let Some(mail) = &response.mail {
            output.push_str("Mail:\n");
            output.push_str(&format!("  Path      : {}\n", mail.path));
            output.push_str(&format!(
                "  Removed   : {}\n",
                if mail.removed { "yes" } else { "no" }
            ));
            output.push('\n');
        }

        if !response.memberships.is_empty() {
            output.push_str("Memberships:\n");
            for membership in &response.memberships {
                let status = if membership.missing_group {
                    "missing group"
                } else if !membership.was_member {
                    "not member"
                } else if membership.removed {
                    "removed (was member)"
                } else {
                    "would remove"
                };
                output.push_str(&format!("  - {} : {}\n", membership.group, status));
            }
            output.push('\n');
        }

        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        }

        output
    }

    /// Format password response as text
    fn format_passwd_text_response(&self, response: &UserPasswdResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("User    : {}\n", response.user.username));
        output.push_str(&format!("Dry Run : {}\n", response.dry_run));
        output.push('\n');

        output.push_str("Status:\n");
        output.push_str(&format!(
            "  Existed        : {}\n",
            if response.user.existed { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Missing        : {}\n",
            if response.user.missing { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Password Changed : {}\n",
            if response.password.changed {
                "yes"
            } else {
                "no"
            }
        ));

        if let Some(scheme) = &response.password.scheme {
            output.push_str(&format!("  Password Scheme  : {}\n", scheme));
        }

        output.push_str(&format!(
            "  Old Password Verified : {}\n",
            if response.password.old_password_verified {
                "yes"
            } else {
                "no"
            }
        ));
        output.push('\n');

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    /// Format lock response as text
    fn format_lock_text_response(&self, response: &UserLockResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("User    : {}\n", response.user.username));
        output.push_str(&format!("Dry Run : {}\n", response.dry_run));
        output.push('\n');

        output.push_str("Status:\n");
        output.push_str(&format!(
            "  Existed    : {}\n",
            if response.user.existed { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Missing    : {}\n",
            if response.user.missing { "yes" } else { "no" }
        ));

        if let Some(was_locked) = response.lock.was_locked {
            output.push_str(&format!(
                "  Was Locked : {}\n",
                if was_locked { "yes" } else { "no" }
            ));
        }

        if let Some(is_locked) = response.lock.is_locked {
            output.push_str(&format!(
                "  Is Locked  : {}\n",
                if is_locked { "yes" } else { "no" }
            ));
        }

        output.push_str(&format!(
            "  Changed    : {}\n",
            if response.lock.changed { "yes" } else { "no" }
        ));
        output.push('\n');

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    /// Format unlock response as text
    fn format_unlock_text_response(&self, response: &UserUnlockResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("User    : {}\n", response.user.username));
        output.push_str(&format!("Dry Run : {}\n", response.dry_run));
        output.push('\n');

        output.push_str("Status:\n");
        output.push_str(&format!(
            "  Existed    : {}\n",
            if response.user.existed { "yes" } else { "no" }
        ));
        output.push_str(&format!(
            "  Missing    : {}\n",
            if response.user.missing { "yes" } else { "no" }
        ));

        if let Some(was_locked) = response.unlock.was_locked {
            output.push_str(&format!(
                "  Was Locked : {}\n",
                if was_locked { "yes" } else { "no" }
            ));
        }

        if let Some(is_locked) = response.unlock.is_locked {
            output.push_str(&format!(
                "  Is Locked  : {}\n",
                if is_locked { "yes" } else { "no" }
            ));
        }

        output.push_str(&format!(
            "  Changed    : {}\n",
            if response.unlock.changed { "yes" } else { "no" }
        ));
        output.push('\n');

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    /// Format groups response as text
    fn format_groups_text_response(&self, response: &UserGroupsResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Backend : {}\n", response.backend));
        output.push_str(&format!("User    : {}", response.user.username));

        if let Some(uid) = response.user.uid {
            output.push_str(&format!(" (uid={})", uid));
        }
        output.push('\n');
        output.push('\n');

        output.push_str("Groups:\n");
        if response.groups.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for group in &response.groups {
                output.push_str(&format!("  - {}", group.name));

                if let Some(gid) = group.gid {
                    output.push_str(&format!(" (gid={})", gid));
                }

                let mut labels = Vec::new();
                if group.primary {
                    labels.push("primary");
                }
                if group.supplementary {
                    labels.push("supplementary");
                }
                if group.system_group {
                    labels.push("system");
                }

                if !labels.is_empty() {
                    output.push_str(&format!(" [{}]", labels.join(", ")));
                }

                output.push('\n');
            }
        }
        output.push('\n');

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }

    /// Format exists response as text
    fn format_exists_text_response(&self, response: &UserExistsResponse) -> String {
        let mut output = String::new();

        output.push_str(&format!("Backend : {}\n", response.backend));

        // Query information
        output.push_str("Query   : ");
        let mut query_parts = Vec::new();
        if let Some(ref username) = response.query.username {
            query_parts.push(format!("username={}", username));
        } else {
            query_parts.push("username=(none)".to_string());
        }
        if let Some(uid) = response.query.uid {
            query_parts.push(format!("uid={}", uid));
        } else {
            query_parts.push("uid=(none)".to_string());
        }
        output.push_str(&query_parts.join(", "));
        output.push_str("\n\n");

        // Result
        output.push_str("Result:\n");

        if response.user.exists {
            output.push_str("  Exists   : yes\n");
            if let Some(ref username) = response.user.username {
                output.push_str(&format!("  Username : {}\n", username));
            } else {
                output.push_str("  Username : (unknown)\n");
            }
            if let Some(uid) = response.user.uid {
                output.push_str(&format!("  UID      : {}\n", uid));
            } else {
                output.push_str("  UID      : (unknown)\n");
            }
        } else {
            output.push_str("  Exists   : no\n");
            output.push_str("  Username : (none)\n");
            output.push_str("  UID      : (none)\n");
        }
        output.push('\n');

        // Warnings
        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  - {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        output
    }
}

/// `Some(verb)` when the call asks for help (`None` inside means the
/// handle's help).
fn help_request(method: &str, args: &Args) -> Option<Option<String>> {
    let named = |v: Option<&String>| {
        v.map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "true")
    };
    if let Some(v) = method.strip_prefix("--help=") {
        return Some(Some(v.to_string()).filter(|v| !v.is_empty()));
    }
    if crate::core::help::HELP_ALIASES.contains(&method) || crate::core::help::is_help_flag(method)
    {
        return Some(named(args.get("verb")).or_else(|| named(args.get("help"))));
    }
    if args.contains_key("help") || args.contains_key("--help") || args.contains_key("-h") {
        return Some(
            named(args.get("help"))
                .or_else(|| named(args.get("--help")))
                .or_else(|| Some(method.to_string()).filter(|m| !m.is_empty())),
        );
    }
    None
}

#[cfg(test)]
thread_local! {
    /// Unit tests: the mock store `backend=mock` uses (shared by clones).
    pub(crate) static TEST_MOCK: std::cell::RefCell<Option<MockBackend>> =
        const { std::cell::RefCell::new(None) };
    /// Unit tests: when set, `backend=system` records its commands here
    /// instead of running them (lookups read the real database).
    pub(crate) static TEST_RECORD: std::cell::RefCell<Option<Arc<Mutex<Vec<SystemCommand>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// A verb's checked options.
enum Parsed {
    Exists(UserExistsOptions),
    Groups(UserGroupsOptions),
    Add(UserAddOptions),
    Delete(UserDeleteOptions),
    Passwd(UserPasswdOptions),
    Lock(UserLockOptions),
    Unlock(UserUnlockOptions),
}

impl Parsed {
    fn format(&self) -> &OutputFormat {
        match self {
            Parsed::Exists(o) => &o.format,
            Parsed::Groups(o) => &o.format,
            Parsed::Add(o) => &o.format,
            Parsed::Delete(o) => &o.format,
            Parsed::Passwd(o) => &o.format,
            Parsed::Lock(o) => &o.format,
            Parsed::Unlock(o) => &o.format,
        }
    }

    fn backend(&self) -> &UserBackend {
        match self {
            Parsed::Exists(o) => &o.backend,
            Parsed::Groups(o) => &o.backend,
            Parsed::Add(o) => &o.backend,
            Parsed::Delete(o) => &o.backend,
            Parsed::Passwd(o) => &o.backend,
            Parsed::Lock(o) => &o.backend,
            Parsed::Unlock(o) => &o.backend,
        }
    }

    fn timeout_ms(&self) -> u64 {
        match self {
            Parsed::Exists(_) | Parsed::Groups(_) => args::DEFAULT_TIMEOUT_MS,
            Parsed::Add(o) => o.timeout_ms,
            Parsed::Delete(o) => o.timeout_ms,
            Parsed::Passwd(o) => o.timeout_ms,
            Parsed::Lock(o) => o.timeout_ms,
            Parsed::Unlock(o) => o.timeout_ms,
        }
    }
}

/// Prints a failure (the JSON error object on stdout for format=json) and
/// returns its status; `main` prints `Error: [<code>] <message>`, unless
/// the handle already wrote to stderr (`warned`): then it is written here.
fn report(io: &mut IoStreams, json: bool, warned: bool, err: &UserError) -> Result<Status> {
    if json {
        writeln!(
            io.stdout,
            "{}",
            serde_json::to_string_pretty(&err.to_json())?
        )?;
        io.stdout.flush()?;
    }
    if warned {
        writeln!(
            io.stderr,
            "{}",
            crate::core::status::error_line(&err.code(), &err.to_string())
        )?;
    }
    Ok(Status::coded(err.exit_code(), &err.code(), err.to_string()))
}

/// Printed on stderr whenever `new_password_plain=` is used.
const PLAIN_PASSWORD_WARNING: &str = "Warning: new_password_plain= puts the password on the \
    command line, where the process list and shell history can show it; use \
    new_password_env=<VAR> or new_password_stdin=true instead.";

impl UserHandle {
    fn backend_for(
        &self,
        kind: &UserBackend,
        timeout_ms: u64,
    ) -> Result<Box<dyn UserBackendProvider>, UserError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        match kind {
            UserBackend::System => {
                #[cfg(test)]
                if let Some(log) = TEST_RECORD.with(|r| r.borrow().clone()) {
                    return Ok(Box::new(SystemBackend::recording(log)));
                }
                Ok(Box::new(SystemBackend::new(deadline)))
            }
            UserBackend::Mock => {
                #[cfg(test)]
                if let Some(m) = TEST_MOCK.with(|m| m.borrow().clone()) {
                    return Ok(Box::new(m));
                }
                Ok(Box::new(MockBackend::new()))
            }
            UserBackend::File | UserBackend::Ldap => {
                Err(UserError::BackendNotSupported(kind.to_string()))
            }
        }
    }

    fn parse(
        &self,
        verb: &str,
        args: &Args,
        stdin: &mut dyn std::io::Read,
    ) -> Result<Parsed, UserError> {
        args::check_known(verb, args)?;
        let target = UserTarget {
            path: self.alias.clone(),
        };
        Ok(match verb {
            "exists" => Parsed::Exists(args::parse_exists(args, &target)?),
            "groups" => Parsed::Groups(args::parse_groups(args, &target)?),
            "add" => Parsed::Add(args::parse_add(args, &target)?),
            "delete" => Parsed::Delete(args::parse_delete(args, &target)?),
            "passwd" => Parsed::Passwd(args::parse_passwd(args, &target, stdin)?),
            "lock" => Parsed::Lock(args::parse_lock(args, &target)?),
            _ => Parsed::Unlock(args::parse_unlock(args, &target)?),
        })
    }

    /// Runs the verb and renders its result.
    fn run(&self, parsed: &Parsed, backend: &mut dyn UserBackendProvider) -> Result<String> {
        let text = matches!(parsed.format(), OutputFormat::Text);
        let json = |v: &dyn erased::Json| v.pretty();
        Ok(match parsed {
            Parsed::Exists(o) => {
                let r = self.exists_user(o, backend)?;
                if text {
                    self.format_exists_text_response(&r)
                } else {
                    json(&r)?
                }
            }
            Parsed::Groups(o) => {
                let r = self.groups_user(o, backend)?;
                if text {
                    self.format_groups_text_response(&r)
                } else {
                    json(&r)?
                }
            }
            Parsed::Add(o) => {
                let r = match o.mode {
                    UserAddMode::User => self.add_user(o, backend)?,
                    UserAddMode::Group => self.add_group(o, backend)?,
                    UserAddMode::Membership => self.add_membership(o, backend)?,
                };
                if text {
                    self.format_text_response(&r) + &planned_text(&r.planned_commands)
                } else {
                    json(&r)?
                }
            }
            Parsed::Delete(o) => {
                let r = match o.mode {
                    UserDeleteMode::User => self.delete_user(o, backend)?,
                    UserDeleteMode::Group => self.delete_group(o, backend)?,
                    UserDeleteMode::Membership => self.delete_membership(o, backend)?,
                };
                if text {
                    self.format_delete_text_response(&r) + &planned_text(&r.planned_commands)
                } else {
                    json(&r)?
                }
            }
            Parsed::Passwd(o) => {
                let r = self.passwd_user(o, backend)?;
                if text {
                    self.format_passwd_text_response(&r) + &planned_text(&r.planned_commands)
                } else {
                    json(&r)?
                }
            }
            Parsed::Lock(o) => {
                let r = self.lock_user(o, backend)?;
                if text {
                    self.format_lock_text_response(&r) + &planned_text(&r.planned_commands)
                } else {
                    json(&r)?
                }
            }
            Parsed::Unlock(o) => {
                let r = self.unlock_user(o, backend)?;
                if text {
                    self.format_unlock_text_response(&r) + &planned_text(&r.planned_commands)
                } else {
                    json(&r)?
                }
            }
        })
    }
}

/// Serializing any response to pretty JSON.
mod erased {
    pub trait Json {
        fn pretty(&self) -> anyhow::Result<String>;
    }
    impl<T: serde::Serialize> Json for T {
        fn pretty(&self) -> anyhow::Result<String> {
            Ok(serde_json::to_string_pretty(self)?)
        }
    }
}

impl Handle for UserHandle {
    fn verbs(&self) -> &'static [&'static str] {
        args::VERBS
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&USER_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(topic) = help_request(verb, args) {
            let text = crate::core::help::render_legacy(
                "user",
                &USER_HELP,
                self.verbs(),
                topic.as_deref(),
            );
            write!(io.stdout, "{}", text)?;
            if !text.ends_with('\n') {
                writeln!(io.stdout)?;
            }
            return Ok(Status::ok());
        }
        // format=json is the default; a failure before the format is known
        // is reported as JSON too unless format=text was asked for.
        let json = args.get("format").map(String::as_str) != Some("text");
        if !args::VERBS.contains(&verb) {
            let err = UserError::InvalidArgument(format!(
                "unknown verb for user: {verb:?}{} (verbs: {}); nothing was done",
                args::hint(verb, args::VERBS),
                args::VERBS.join(", ")
            ));
            return report(io, json, false, &err);
        }
        // Warned before anything else, even when the call is refused.
        let warned = verb == "passwd" && args.contains_key("new_password_plain");
        if warned {
            writeln!(io.stderr, "{PLAIN_PASSWORD_WARNING}")?;
        }
        let parsed = match self.parse(verb, args, io.stdin) {
            Ok(p) => p,
            Err(e) => return report(io, json, warned, &e),
        };
        let json = matches!(parsed.format(), OutputFormat::Json);
        let mut backend = match self.backend_for(parsed.backend(), parsed.timeout_ms()) {
            Ok(b) => b,
            Err(e) => return report(io, json, warned, &e),
        };
        match self.run(&parsed, backend.as_mut()) {
            Ok(out) => {
                write!(io.stdout, "{}", out)?;
                if !out.ends_with('\n') {
                    writeln!(io.stdout)?;
                }
                io.stdout.flush()?;
                Ok(Status::ok())
            }
            Err(e) => {
                let err = match e.downcast::<UserError>() {
                    Ok(u) => u,
                    Err(other) => UserError::BackendOperationFailed(format!("{other:#}")),
                };
                report(io, json, warned, &err)
            }
        }
    }
}

/// A dry run's planned commands, for text output.
fn planned_text(planned: &[String]) -> String {
    let mut s = String::new();
    if !planned.is_empty() {
        s.push_str("Planned commands:\n");
        for cmd in planned {
            s.push_str(&format!("  {}\n", cmd));
        }
    }
    s
}

/// Register user:// scheme with the registry
pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("user", |u| Ok(Box::new(UserHandle::from_url(u.clone())?)));
}

#[cfg(test)]
mod tests;
