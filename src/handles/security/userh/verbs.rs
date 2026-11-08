//! The verbs. Each one checks everything it can before its first change,
//! then applies the changes in order; a failure after a change is reported
//! as such (`user.partial_failure`) or undone when that is safe.

use anyhow::Result;

use super::args::{Kind, validate_name};
use super::backend::{
    BackendOp, FIRST_REGULAR_ID, LAST_REGULAR_ID, UserBackendProvider, hash_password,
    hash_scheme_of, mail_spool, verify_password_hash,
};
use super::*;

/// Keeps the errors that say what went wrong in the environment (timeout,
/// permission, missing tool) and wraps every other one with `wrap`.
fn keep_or(e: anyhow::Error, wrap: impl FnOnce(String) -> UserError) -> anyhow::Error {
    match e.downcast::<UserError>() {
        Ok(
            u @ (UserError::Timeout(_)
            | UserError::PermissionDenied(_)
            | UserError::ToolNotFound(_)
            | UserError::PartialFailure(_)),
        ) => u.into(),
        Ok(other) => wrap(other.to_string()).into(),
        Err(e) => wrap(format!("{e:#}")).into(),
    }
}

fn is_timeout(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<UserError>(), Some(UserError::Timeout(_)))
}

fn check_id_range(id: u32, force: bool, uid: bool) -> Result<(), UserError> {
    let ok = id <= LAST_REGULAR_ID && (force || id >= FIRST_REGULAR_ID);
    match (ok, uid) {
        (true, _) => Ok(()),
        (false, true) => Err(UserError::UidOutOfRange(id)),
        (false, false) => Err(UserError::GidOutOfRange(id)),
    }
}

/// Top-level directories `remove_home` never removes.
fn is_top_level(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    parts.len() < 2 || parts.iter().any(|p| *p == "." || *p == "..")
}

impl UserHandle {
    pub(super) fn add_user(
        &self,
        options: &UserAddOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserAddResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let mut warnings = Vec::new();

        if let Some(rec) = backend.lookup_user(&username)? {
            if !options.ignore_if_exists {
                return Err(UserError::UsernameConflict(username).into());
            }
            let groups = backend.list_groups_for_user(&username)?;
            warnings.push(format!(
                "User {username} already exists; nothing was changed."
            ));
            return Ok(UserAddResponse {
                planned_commands: Vec::new(),
                ok: true,
                mode: options.mode.to_string(),
                backend: options.backend.to_string(),
                dry_run: options.dry_run,
                user: Some(UserInfo {
                    username: username.clone(),
                    uid: rec.uid,
                    supplementary_groups: groups
                        .into_iter()
                        .filter(|g| *g != rec.primary_group)
                        .collect(),
                    primary_group: rec.primary_group,
                    home: rec.home,
                    shell: rec.shell,
                    gecos: rec.gecos,
                    created: false,
                    existed: true,
                }),
                group: None,
                groups: vec![],
                member: None,
                memberships: vec![],
                password_set: None,
                warnings,
            });
        }

        let uid = match options.uid {
            Some(uid) => {
                check_id_range(uid, options.force, true)?;
                if backend.lookup_user_by_uid(uid)?.is_some() {
                    return Err(UserError::UidConflict(uid).into());
                }
                uid
            }
            None => backend.next_uid()?,
        };
        if uid < FIRST_REGULAR_ID {
            warnings.push(format!(
                "Creating {username} with uid {uid}, below {FIRST_REGULAR_ID}, because force=true."
            ));
        }

        for g in &options.supplementary_groups {
            if !backend.group_exists(g)? {
                return Err(UserError::GroupNotFound(g.clone()).into());
            }
        }

        let primary_group = options
            .primary_group
            .clone()
            .unwrap_or_else(|| username.clone());
        let mut new_group = None;
        if !backend.group_exists(&primary_group)? {
            validate_name(Kind::Group, &primary_group).map_err(|e| {
                UserError::GroupNameInvalid(format!(
                    "primary_group {primary_group:?} does not exist and cannot be created: {e}"
                ))
            })?;
            let gid = if primary_group == username && !backend.gid_in_use(uid)? {
                uid
            } else {
                backend.next_gid()?
            };
            new_group = Some(GroupInfo {
                name: primary_group.clone(),
                gid,
                created: !options.dry_run,
                existed: false,
            });
        }

        let home = options
            .home
            .clone()
            .unwrap_or_else(|| backend.default_home_path(&username));
        if options.create_home && backend.path_exists(&home) {
            warnings.push(format!(
                "Home directory {home} already exists; useradd keeps it and copies no \
                 skeleton files into it."
            ));
        }
        let user_info = UserInfo {
            username: username.clone(),
            uid,
            primary_group: primary_group.clone(),
            supplementary_groups: options.supplementary_groups.clone(),
            home: Some(home),
            shell: Some(
                options
                    .shell
                    .clone()
                    .unwrap_or_else(|| backend.default_shell()),
            ),
            gecos: options.gecos.clone(),
            created: !options.dry_run,
            existed: false,
        };
        let create_user = BackendOp::CreateUser {
            info: &user_info,
            create_home: options.create_home,
        };

        let mut planned = Vec::new();
        let mut password_set = options.password_hash.as_ref().map(|_| false);
        if options.dry_run {
            if let Some(g) = &new_group {
                planned.extend(backend.planned_commands(&BackendOp::CreateGroup(g))?);
            }
            planned.extend(backend.planned_commands(&create_user)?);
            if let Some(h) = &options.password_hash {
                planned.extend(backend.planned_commands(&BackendOp::SetPasswordHash {
                    username: &username,
                    hash: h,
                })?);
            }
        } else {
            if let Some(g) = &new_group {
                backend.create_group(g)?;
            }
            if let Err(e) = backend.create_user(&user_info, options.create_home) {
                if let (Some(g), false) = (&new_group, is_timeout(&e)) {
                    // The group was made for this account only; take it back.
                    if let Err(e2) = backend.delete_group(&g.name) {
                        return Err(UserError::PartialFailure(format!(
                            "creating user {username} failed ({e}); group {} was created for \
                             it and could not be removed again ({e2})",
                            g.name
                        ))
                        .into());
                    }
                }
                return Err(e);
            }
            if let Some(h) = &options.password_hash {
                backend.set_password_hash(&username, h).map_err(|e| {
                    UserError::PartialFailure(format!(
                        "user {username} was created, but its password was not set: {e}"
                    ))
                })?;
                password_set = Some(true);
            }
        }

        let memberships = options
            .supplementary_groups
            .iter()
            .map(|g| MembershipInfo {
                group: g.clone(),
                added: !options.dry_run,
                already_member: false,
            })
            .collect();
        Ok(UserAddResponse {
            planned_commands: planned,
            ok: true,
            mode: options.mode.to_string(),
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: Some(user_info),
            group: None,
            groups: new_group.into_iter().collect(),
            member: None,
            memberships,
            password_set,
            warnings,
        })
    }

    pub(super) fn add_group(
        &self,
        options: &UserAddOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserAddResponse> {
        let group_name = options
            .group_name
            .clone()
            .ok_or(UserError::GroupNameRequired)?;
        let mut warnings = Vec::new();
        let mut response = UserAddResponse {
            planned_commands: Vec::new(),
            ok: true,
            mode: options.mode.to_string(),
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: None,
            group: None,
            groups: vec![],
            member: None,
            memberships: vec![],
            password_set: None,
            warnings: vec![],
        };
        if let Some(rec) = backend.lookup_group(&group_name)? {
            if !options.ignore_if_exists {
                return Err(UserError::GroupConflict(group_name).into());
            }
            warnings.push(format!(
                "Group {group_name} already exists; nothing was changed."
            ));
            response.group = Some(GroupInfo {
                name: group_name,
                gid: rec.gid.unwrap_or(0),
                created: false,
                existed: true,
            });
            response.warnings = warnings;
            return Ok(response);
        }
        let gid = match options.gid {
            Some(gid) => {
                check_id_range(gid, options.force, false)?;
                if backend.gid_in_use(gid)? {
                    return Err(UserError::GidConflict(gid).into());
                }
                gid
            }
            None => backend.next_gid()?,
        };
        if gid < FIRST_REGULAR_ID {
            warnings.push(format!(
                "Creating {group_name} with gid {gid}, below {FIRST_REGULAR_ID}, because force=true."
            ));
        }
        let info = GroupInfo {
            name: group_name,
            gid,
            created: !options.dry_run,
            existed: false,
        };
        if options.dry_run {
            response.planned_commands = backend.planned_commands(&BackendOp::CreateGroup(&info))?;
        } else {
            backend.create_group(&info)?;
        }
        response.group = Some(info);
        response.warnings = warnings;
        Ok(response)
    }

    pub(super) fn add_membership(
        &self,
        options: &UserAddOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserAddResponse> {
        let member = options.member.clone().ok_or(UserError::MemberRequired)?;
        if options.groups.is_empty() {
            return Err(UserError::GroupsRequired.into());
        }
        let rec = backend
            .lookup_user(&member)?
            .ok_or_else(|| UserError::UserNotFound(member.clone()))?;
        let mut memberships = Vec::new();
        let mut warnings = Vec::new();
        let mut to_add = Vec::new();
        for g in &options.groups {
            if !backend.group_exists(g)? {
                return Err(UserError::GroupNotFound(g.clone()).into());
            }
            let primary = *g == rec.primary_group;
            if primary || backend.membership_exists(&member, g)? {
                if !options.ignore_if_exists {
                    return Err(UserError::MembershipExists(member, g.clone()).into());
                }
                warnings.push(if primary {
                    format!("Group {g} is the primary group of {member}.")
                } else {
                    format!("User {member} was already a member of group {g}")
                });
                memberships.push(MembershipInfo {
                    group: g.clone(),
                    added: false,
                    already_member: true,
                });
            } else {
                to_add.push(g.clone());
                memberships.push(MembershipInfo {
                    group: g.clone(),
                    added: !options.dry_run,
                    already_member: false,
                });
            }
        }
        let mut planned = Vec::new();
        if !to_add.is_empty() {
            if options.dry_run {
                planned = backend.planned_commands(&BackendOp::AddMemberships {
                    username: &member,
                    groups: &to_add,
                })?;
            } else {
                backend.add_memberships(&member, &to_add)?;
            }
        }
        Ok(UserAddResponse {
            planned_commands: planned,
            ok: true,
            mode: options.mode.to_string(),
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: None,
            group: None,
            groups: vec![],
            member: Some(member),
            memberships,
            password_set: None,
            warnings,
        })
    }

    fn delete_response(options: &UserDeleteOptions) -> UserDeleteResponse {
        UserDeleteResponse {
            planned_commands: Vec::new(),
            ok: true,
            mode: options.mode.to_string(),
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: None,
            group: None,
            home: None,
            mail: None,
            member: None,
            memberships: vec![],
            warnings: vec![],
        }
    }

    pub(super) fn delete_user(
        &self,
        options: &UserDeleteOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserDeleteResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let mut out = Self::delete_response(options);
        let Some(rec) = backend.lookup_user(&username)? else {
            if !options.ignore_if_missing {
                return Err(UserError::UserNotFound(username).into());
            }
            out.user = Some(UserDeleteInfo {
                username: username.clone(),
                uid: None,
                existed: false,
                deleted: false,
                missing: true,
            });
            out.warnings
                .push(format!("User {username} did not exist; nothing to delete."));
            return Ok(out);
        };
        let protected = options.protect_system_users && rec.uid < options.min_uid_for_delete;
        if protected && !options.force {
            return Err(UserError::SystemUserProtected(
                username,
                rec.uid,
                "delete",
                options.min_uid_for_delete,
            )
            .into());
        }
        if protected {
            out.warnings.push(format!(
                "Warning: Deleting system user {} (uid={}) with force=true",
                username, rec.uid
            ));
        }
        let home_path = rec
            .home
            .clone()
            .unwrap_or_else(|| backend.default_home_path(&username));
        if options.remove_home && is_top_level(&home_path) {
            return Err(UserError::InvalidArgument(format!(
                "remove_home=true would remove {home_path}, which is not below a parent \
                 directory such as /home; nothing was done"
            ))
            .into());
        }
        let home_present = backend.path_exists(&home_path);
        let spool = mail_spool(&username);
        let spool_present = backend.path_exists(&spool);

        // userdel removes the account from every group; report them.
        let groups = backend.list_groups_for_user(&username)?;
        out.memberships = groups
            .into_iter()
            .map(|g| MembershipDeleteInfo {
                group: g,
                removed: !options.dry_run,
                was_member: true,
                missing_group: false,
            })
            .collect();

        let op = BackendOp::DeleteUser {
            username: &username,
            remove_home: options.remove_home,
            remove_mail: options.remove_mail,
        };
        if options.dry_run {
            out.planned_commands = backend.planned_commands(&op)?;
        } else if let Err(e) =
            backend.delete_user(&username, options.remove_home, options.remove_mail)
        {
            if !is_timeout(&e) && !backend.user_exists(&username).unwrap_or(true) {
                return Err(UserError::PartialFailure(format!(
                    "user {username} was deleted, but not everything was removed: {e}"
                ))
                .into());
            }
            return Err(e);
        }
        let gone = |p: &str| !options.dry_run && !backend.path_exists(p);
        if options.remove_home {
            out.home = Some(HomeInfo {
                path: home_path.clone(),
                removed: home_present && gone(&home_path),
                was_present: home_present,
            });
        }
        if options.remove_mail || options.remove_home {
            out.mail = Some(MailInfo {
                path: spool.clone(),
                removed: spool_present && gone(&spool),
                was_present: spool_present,
            });
        }
        out.user = Some(UserDeleteInfo {
            username,
            uid: Some(rec.uid),
            existed: true,
            deleted: !options.dry_run,
            missing: false,
        });
        Ok(out)
    }

    pub(super) fn delete_group(
        &self,
        options: &UserDeleteOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserDeleteResponse> {
        let group_name = options
            .group_name
            .clone()
            .ok_or(UserError::GroupNameRequired)?;
        let mut out = Self::delete_response(options);
        let Some(rec) = backend.lookup_group(&group_name)? else {
            if !options.ignore_if_missing {
                return Err(UserError::GroupNotFound(group_name).into());
            }
            out.group = Some(GroupDeleteInfo {
                name: group_name.clone(),
                gid: None,
                existed: false,
                deleted: false,
                missing: true,
                member_count_before: 0,
            });
            out.warnings.push(format!(
                "Group {group_name} did not exist; nothing to delete."
            ));
            return Ok(out);
        };
        let system = options.protect_system_groups
            && rec.gid.is_some_and(|gid| gid < options.min_gid_for_delete);
        if system && !options.force {
            return Err(UserError::SystemGroupProtected(
                group_name,
                rec.gid.unwrap_or(0),
                options.min_gid_for_delete,
            )
            .into());
        }
        let members = rec.members.len();
        if options.only_if_empty && members > 0 && !options.force {
            return Err(UserError::GroupNotEmpty(group_name).into());
        }
        if system {
            out.warnings.push(format!(
                "Warning: Deleting system group {} (gid={}) with force=true",
                group_name,
                rec.gid.unwrap_or(0)
            ));
        }
        if members > 0 && options.only_if_empty {
            out.warnings.push(format!(
                "Warning: Deleting non-empty group {group_name} with force=true"
            ));
        }
        if options.dry_run {
            out.planned_commands =
                backend.planned_commands(&BackendOp::DeleteGroup(&group_name))?;
        } else {
            backend.delete_group(&group_name)?;
        }
        out.group = Some(GroupDeleteInfo {
            name: group_name,
            gid: rec.gid,
            existed: true,
            deleted: !options.dry_run,
            missing: false,
            member_count_before: members as u32,
        });
        Ok(out)
    }

    pub(super) fn delete_membership(
        &self,
        options: &UserDeleteOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserDeleteResponse> {
        let member = options.member.clone().ok_or(UserError::MemberRequired)?;
        let mut out = Self::delete_response(options);
        out.member = Some(member.clone());
        let Some(rec) = backend.lookup_user(&member)? else {
            if !options.ignore_if_missing {
                return Err(UserError::UserNotFound(member).into());
            }
            out.warnings
                .push(format!("User {member} does not exist; nothing to delete."));
            return Ok(out);
        };
        let groups: Vec<String> = if options.all_groups {
            backend
                .list_groups_for_user(&member)?
                .into_iter()
                .filter(|g| *g != rec.primary_group)
                .collect()
        } else if options.groups.is_empty() {
            return Err(UserError::GroupsRequired.into());
        } else {
            options.groups.clone()
        };
        // Check every group before changing anything.
        let mut to_remove = Vec::new();
        for g in &groups {
            if *g == rec.primary_group {
                return Err(UserError::PrimaryGroupMembership(member, g.clone()).into());
            }
            if !backend.group_exists(g)? {
                if !options.ignore_if_missing {
                    return Err(UserError::GroupNotFound(g.clone()).into());
                }
                out.warnings.push(format!("Group {g} does not exist"));
                out.memberships.push(MembershipDeleteInfo {
                    group: g.clone(),
                    removed: false,
                    was_member: false,
                    missing_group: true,
                });
                continue;
            }
            if !backend.membership_exists(&member, g)? {
                if !options.ignore_if_missing {
                    return Err(UserError::MembershipNotFound(member, g.clone()).into());
                }
                out.warnings
                    .push(format!("User {member} was not a member of group {g}"));
                out.memberships.push(MembershipDeleteInfo {
                    group: g.clone(),
                    removed: false,
                    was_member: false,
                    missing_group: false,
                });
                continue;
            }
            to_remove.push(g.clone());
        }
        let mut done: Vec<String> = Vec::new();
        for g in &to_remove {
            let op = BackendOp::RemoveMembership {
                username: &member,
                group: g,
            };
            if options.dry_run {
                out.planned_commands.extend(backend.planned_commands(&op)?);
            } else if let Err(e) = backend.remove_user_from_group(&member, g) {
                if done.is_empty() || is_timeout(&e) {
                    return Err(e);
                }
                return Err(UserError::PartialFailure(format!(
                    "removed {member} from {}, but not from {g}: {e}",
                    done.join(", ")
                ))
                .into());
            }
            done.push(g.clone());
            out.memberships.push(MembershipDeleteInfo {
                group: g.clone(),
                removed: !options.dry_run,
                was_member: true,
                missing_group: false,
            });
        }
        Ok(out)
    }

    pub(super) fn passwd_user(
        &self,
        options: &UserPasswdOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserPasswdResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let argon2 = options.hash_scheme == HashScheme::Argon2id
            || options
                .new_password_hash
                .as_deref()
                .is_some_and(|h| hash_scheme_of(h) == Some("argon2id"));
        if argon2 && !backend.supports_argon2() {
            return Err(UserError::HashSchemeUnsupported(
                "argon2id (the system crypt() library and PAM cannot verify it; use \
                 sha512_crypt or bcrypt)"
                    .to_string(),
            )
            .into());
        }
        let mut warnings = Vec::new();
        if backend.lookup_user(&username)?.is_none() {
            if !options.ignore_if_missing {
                return Err(UserError::UserNotFound(username).into());
            }
            return Ok(UserPasswdResponse {
                planned_commands: Vec::new(),
                ok: true,
                backend: options.backend.to_string(),
                dry_run: options.dry_run,
                user: UserPasswordInfo {
                    username: username.clone(),
                    existed: false,
                    missing: true,
                },
                password: PasswordInfo {
                    changed: false,
                    scheme: None,
                    source: None,
                    old_password_verified: false,
                },
                warnings: vec![format!(
                    "User {username} did not exist; password was not changed."
                )],
            });
        }

        let mut old_password_verified = false;
        if let (true, Some(old)) = (options.require_old_password, &options.old_password_plain) {
            let field = backend
                .password_field(&username)
                .map_err(|e| keep_or(e, UserError::PasswordBackendFailure))?
                .ok_or_else(|| {
                    UserError::PasswordBackendFailure(format!(
                        "no shadow entry for user '{username}'"
                    ))
                })?;
            if !verify_password_hash(old, &field)? {
                return Err(UserError::OldPasswordMismatch(username).into());
            }
            old_password_verified = true;
        }

        let (hash, scheme) = match (&options.new_password_hash, &options.new_password_plain) {
            (Some(h), _) => (
                h.clone(),
                hash_scheme_of(h).unwrap_or("unknown").to_string(),
            ),
            (None, Some(plain)) => {
                let scheme = match options.hash_scheme {
                    HashScheme::BackendDefault => HashScheme::Sha512Crypt,
                    ref s => s.clone(),
                };
                (hash_password(plain, &scheme)?, scheme.to_string())
            }
            (None, None) => return Err(UserError::PasswordMissingNewPassword.into()),
        };
        let mut planned = Vec::new();
        if options.dry_run {
            planned = backend.planned_commands(&BackendOp::SetPasswordHash {
                username: &username,
                hash: &hash,
            })?;
            warnings.push("Dry run: no password was actually changed.".to_string());
        } else {
            backend
                .set_password_hash(&username, &hash)
                .map_err(|e| keep_or(e, UserError::PasswordBackendFailure))?;
            if let Ok(Some(stored)) = backend.password_field(&username) {
                if stored != hash {
                    return Err(UserError::PasswordBackendFailure(format!(
                        "the stored password of {username} is not the new one after the change"
                    ))
                    .into());
                }
            }
        }
        Ok(UserPasswdResponse {
            planned_commands: planned,
            ok: true,
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: UserPasswordInfo {
                username,
                existed: true,
                missing: false,
            },
            password: PasswordInfo {
                changed: !options.dry_run,
                scheme: Some(scheme),
                source: Some(options.new_password_source.clone()),
                old_password_verified,
            },
            warnings,
        })
    }

    /// Shared by lock and unlock: `lock=true` locks.
    #[allow(clippy::too_many_arguments)]
    fn set_lock(
        &self,
        lock: bool,
        username: &str,
        dry_run: bool,
        ignore_if_missing: bool,
        protect: bool,
        min_uid: u32,
        force: bool,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<(Option<u32>, LockInfo, Vec<String>, Vec<String>)> {
        let verb = if lock { "lock" } else { "unlock" };
        let fail = |m: String| {
            if lock {
                UserError::LockBackendFailure(m)
            } else {
                UserError::UnlockBackendFailure(m)
            }
        };
        let mut warnings = Vec::new();
        let Some(rec) = backend.lookup_user(username)? else {
            if !ignore_if_missing {
                return Err(UserError::UserNotFound(username.to_string()).into());
            }
            warnings.push(format!("User {username} did not exist; nothing to {verb}."));
            if dry_run {
                warnings.push("Dry run: no changes were made.".to_string());
            }
            let info = LockInfo {
                requested: true,
                was_locked: None,
                is_locked: None,
                changed: false,
            };
            return Ok((None, info, warnings, Vec::new()));
        };
        let protected = protect && rec.uid < min_uid;
        if protected && !force {
            return Err(UserError::SystemUserProtected(
                username.to_string(),
                rec.uid,
                verb,
                min_uid,
            )
            .into());
        }
        if protected {
            let v = if lock { "Locking" } else { "Unlocking" };
            warnings.push(format!(
                "Warning: {v} system user {username} (uid={}) with force=true.",
                rec.uid
            ));
        }
        let was_locked = match backend.is_locked(username) {
            Ok(v) => Some(v),
            Err(e) if dry_run && !is_timeout(&e) => {
                warnings.push(format!(
                    "Could not determine whether {username} is locked: {e}"
                ));
                None
            }
            Err(e) => return Err(keep_or(e, fail)),
        };
        if was_locked == Some(lock) {
            let state = if lock { "locked" } else { "unlocked" };
            warnings.push(format!("User {username} was already {state}."));
        }
        let op = if lock {
            BackendOp::Lock(username)
        } else {
            BackendOp::Unlock(username)
        };
        let mut planned = Vec::new();
        let (is_locked, changed) = if dry_run {
            warnings.push(format!(
                "Dry run: account would be {verb}ed, but no changes were made."
            ));
            if was_locked != Some(lock) {
                planned = backend.planned_commands(&op)?;
            }
            (was_locked, false)
        } else if was_locked == Some(lock) {
            (Some(lock), false)
        } else {
            let r = if lock {
                backend.lock_user(username)
            } else {
                backend.unlock_user(username)
            };
            r.map_err(|e| keep_or(e, fail))?;
            match backend.is_locked(username) {
                Ok(now) if now == lock => {}
                Ok(_) => {
                    return Err(fail(format!(
                        "the account of {username} is still {} after the change",
                        if lock { "unlocked" } else { "locked" }
                    ))
                    .into());
                }
                Err(e) => return Err(keep_or(e, fail)),
            }
            (Some(lock), true)
        };
        let info = LockInfo {
            requested: true,
            was_locked,
            is_locked,
            changed,
        };
        Ok((Some(rec.uid), info, warnings, planned))
    }

    pub(super) fn lock_user(
        &self,
        options: &UserLockOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserLockResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let (uid, lock, warnings, planned) = self.set_lock(
            true,
            &username,
            options.dry_run,
            options.ignore_if_missing,
            options.protect_system_users,
            options.min_uid_for_lock,
            options.force,
            backend,
        )?;
        Ok(UserLockResponse {
            planned_commands: planned,
            ok: true,
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: UserLockInfo {
                username,
                uid,
                existed: uid.is_some(),
                missing: uid.is_none(),
            },
            lock,
            warnings,
        })
    }

    pub(super) fn unlock_user(
        &self,
        options: &UserUnlockOptions,
        backend: &mut dyn UserBackendProvider,
    ) -> Result<UserUnlockResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let (uid, lock, warnings, planned) = self.set_lock(
            false,
            &username,
            options.dry_run,
            options.ignore_if_missing,
            options.protect_system_users,
            options.min_uid_for_unlock,
            options.force,
            backend,
        )?;
        Ok(UserUnlockResponse {
            planned_commands: planned,
            ok: true,
            backend: options.backend.to_string(),
            dry_run: options.dry_run,
            user: UserUnlockInfo {
                username,
                uid,
                existed: uid.is_some(),
                missing: uid.is_none(),
            },
            unlock: UnlockInfo {
                requested: lock.requested,
                was_locked: lock.was_locked,
                is_locked: lock.is_locked,
                changed: lock.changed,
            },
            warnings,
        })
    }

    pub(super) fn groups_user(
        &self,
        options: &UserGroupsOptions,
        backend: &dyn UserBackendProvider,
    ) -> Result<UserGroupsResponse> {
        let username = options
            .username
            .clone()
            .ok_or(UserError::UsernameRequired)?;
        let Some(rec) = backend
            .lookup_user(&username)
            .map_err(|e| keep_or(e, UserError::GroupsBackendFailure))?
        else {
            if !options.ignore_if_missing {
                return Err(UserError::UserNotFound(username).into());
            }
            return Ok(UserGroupsResponse {
                ok: true,
                backend: options.backend.to_string(),
                user: UserGroupsResult {
                    username: username.clone(),
                    uid: None,
                    existed: false,
                    missing: true,
                },
                groups: vec![],
                warnings: vec![format!("User {username} did not exist; no groups to list.")],
            });
        };
        let records = backend
            .list_groups_for_user_detailed(&username)
            .map_err(|e| keep_or(e, UserError::GroupsBackendFailure))?;
        let mut groups = Vec::new();
        for g in records {
            let primary = g.name == rec.primary_group;
            let system_group = g.gid.is_some_and(|gid| gid < options.min_gid_for_system);
            if (primary && !options.include_primary)
                || (!primary && !options.include_supplementary)
                || (system_group && !options.include_system_groups)
                || options
                    .group_name_filter
                    .as_ref()
                    .is_some_and(|f| *f != g.name)
            {
                continue;
            }
            groups.push(GroupInfoDetailed {
                name: g.name,
                gid: g.gid,
                primary,
                supplementary: !primary,
                system_group,
            });
        }
        let mut warnings = Vec::new();
        if groups.is_empty() {
            warnings.push(format!(
                "User {username} has no groups matching the current filters."
            ));
        }
        Ok(UserGroupsResponse {
            ok: true,
            backend: options.backend.to_string(),
            user: UserGroupsResult {
                username,
                uid: Some(rec.uid),
                existed: true,
                missing: false,
            },
            groups,
            warnings,
        })
    }

    pub(super) fn exists_user(
        &self,
        options: &UserExistsOptions,
        backend: &dyn UserBackendProvider,
    ) -> Result<UserExistsResponse> {
        let backend_name = options.backend.to_string();
        let lookup_failed = |what: String, e: anyhow::Error| {
            UserError::ExistsBackendFailure(backend_name.clone(), format!("{what}: {e:#}"))
        };
        let record = match (&options.username, options.uid) {
            (Some(name), _) => backend
                .lookup_user(name)
                .map_err(|e| lookup_failed(format!("cannot look up user '{name}'"), e))?,
            (None, Some(uid)) => backend
                .lookup_user_by_uid(uid)
                .map_err(|e| lookup_failed(format!("cannot look up uid {uid}"), e))?,
            (None, None) => return Err(UserError::IdentityRequired.into()),
        };
        if let (Some(name), Some(uid), Some(rec)) = (&options.username, options.uid, &record) {
            if rec.uid != uid {
                return Err(UserError::ExistsMismatch(name.clone(), rec.uid, uid).into());
            }
        }
        let mut warnings = Vec::new();
        if record.is_none() {
            warnings.push(match (&options.username, options.uid) {
                (Some(name), _) => {
                    format!("User {name} does not exist in backend {}.", options.backend)
                }
                (None, Some(uid)) => format!(
                    "User with uid {uid} does not exist in backend {}.",
                    options.backend
                ),
                (None, None) => String::new(),
            });
        }
        Ok(UserExistsResponse {
            ok: true,
            backend: options.backend.to_string(),
            query: UserExistsQuery {
                username: options.username.clone(),
                uid: options.uid,
            },
            user: UserExistsResult {
                exists: record.is_some(),
                username: record.as_ref().map(|r| r.username.clone()),
                uid: record.as_ref().map(|r| r.uid),
            },
            warnings,
        })
    }
}
