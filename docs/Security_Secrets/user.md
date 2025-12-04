# User Handle Documentation

The user handle manages user accounts, groups, and user passwords in Resource Shell. It provides simple commands to create, delete, and modify users and their settings.

## Available Actions (Verbs)

The user handle supports these actions:
- **add** - Create new users, groups, or group memberships
- **delete** - Remove users, groups, or group memberships  
- **passwd** - Change user passwords
- **lock** - Lock user accounts to prevent login
- **unlock** - Unlock user accounts to allow login
- **groups** - List groups that a user belongs to
- **exists** - Check if a user exists

## Basic Usage

All user handle commands use this format:
```
user://[target] [verb] [options]
```

Where:
- `[target]` is the user, group, or membership to work with
- `[verb]` is one of the actions listed above
- `[options]` are settings that control how the action works

## Target Types

The user handle works with different types of targets:

### User Targets
- `user://alice` - Work with user "alice"
- `user://bob` - Work with user "bob"

### Group Targets  
- `user://group/admins` - Work with group "admins"
- `user://group/dev` - Work with group "dev"

### Membership Targets
- `user://membership/alice` - Work with alice's group memberships

## The Add Action

Use `add` to create new users, groups, or group memberships.

### Creating a New User

**Example from tests:**
```bash
# Create a basic user
user://alice add --mode=user --backend=mock --username=alice
```

**Expected output:**
```json
{
  "ok": true,
  "mode": "user",
  "backend": "mock",
  "dry_run": false,
  "user": {
    "username": "alice",
    "uid": 1001,
    "primary_group": "alice", 
    "supplementary_groups": ["dev"],
    "home": "/home/alice",
    "shell": "/bin/bash",
    "gecos": "Alice Example",
    "created": true,
    "existed": false
  },
  "warnings": []
}
```

**Text format output:**
```
Mode    : user
Backend : mock
Dry Run : false

User Details:
Username       : alice
UID            : 1001
Primary Group  : alice
Supplementary  : dev
Home Directory : /home/alice
Shell          : /bin/bash
Full Name      : Alice Example
Created        : yes
Existed        : no

Warnings:
  (none)
```

### Creating a New Group

**Example from tests:**
```bash
# Create a new group
user://group/admins add --mode=group --backend=mock --group_name=admins
```

**Expected output:**
```json
{
  "ok": true,
  "mode": "group", 
  "backend": "mock",
  "dry_run": false,
  "group": {
    "name": "admins",
    "gid": 1001,
    "created": true,
    "existed": false
  },
  "warnings": []
}
```

### Adding User to Groups (Membership)

**Example from tests:**
```bash
# Add alice to admins and dev groups
user://membership/alice add --mode=membership --backend=mock --member=alice --groups=admins,dev
```

### Dry Run Mode

**Example from tests:**
```bash
# Test what would happen without making changes
user://alice add --mode=user --backend=mock --username=alice --dry_run=true
```

**Expected output:**
```json
{
  "ok": true,
  "mode": "user",
  "backend": "mock", 
  "dry_run": true,
  "user": {
    "username": "alice",
    "created": false
  },
  "warnings": []
}
```

### Handling Existing Users

**Example from tests:**
```bash
# Don't fail if user already exists
user://alice add --mode=user --backend=mock --username=alice --ignore_if_exists=true
```

## The Delete Action

Use `delete` to remove users, groups, or group memberships.

### Deleting a User

**Example from tests:**
```bash
# Delete user and remove home directory
user://alice delete --mode=user --backend=mock --username=alice --remove_home=true --remove_from_all_groups=true
```

### Handling Missing Users

**Example from tests:**
```bash
# Don't fail if user doesn't exist
user://bob delete --mode=user --backend=mock --username=bob --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "mode": "user",
  "backend": "mock",
  "user": {
    "username": "bob",
    "existed": false,
    "deleted": false, 
    "missing": true
  },
  "warnings": ["User bob did not exist in backend mock, skipping deletion."]
}
```

### System User Protection

**Example from tests:**
```bash
# Protect system users from deletion
user://root delete --mode=user --backend=system --username=root --protect_system_users=true --min_uid_for_delete=1000 --force=false
```

This will fail with an error because root (uid=0) is below the minimum UID.

**Force delete system user:**
```bash
# Force delete system user (with warning)
user://root delete --mode=user --backend=system --username=root --protect_system_users=true --min_uid_for_delete=1000 --force=true
```

**Expected output includes warning:**
```json
{
  "ok": true,
  "warnings": ["Forced deletion of system user 'root' (uid=0)"]
}
```

### Deleting Groups

**Example from tests:**
```bash
# Delete group only if empty
user://group/admins delete --mode=group --backend=mock --group_name=admins --only_if_empty=true --force=false
```

### Deleting Group Memberships

**Example from tests:**
```bash
# Remove user from specific groups
user://membership/alice delete --mode=membership --backend=mock --member=alice --groups=dev
```

**Remove user from all groups:**
```bash
user://membership/alice delete --mode=membership --backend=mock --member=alice --all_groups=true
```

### Dry Run Mode for Deletes

**Example from tests:**
```bash
# Test deletion without making changes
user://alice delete --mode=user --backend=mock --username=alice --dry_run=true --remove_home=true --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "mode": "user",
  "backend": "mock",
  "dry_run": true,
  "user": {
    "username": "alice", 
    "deleted": false,
    "existed": false
  }
}
```

## The Passwd Action

Use `passwd` to change user passwords.

### Setting Password from Plain Text

**Example from tests:**
```bash
# Set password using plain text
user://alice passwd --backend=mock --username=alice --new_password_plain=Secret123!
```

**Expected output:**
```json
{
  "ok": true,
  "backend": "mock",
  "dry_run": false,
  "user": {
    "username": "alice",
    "existed": true,
    "missing": false
  },
  "password": {
    "changed": true,
    "scheme": "sha512_crypt",
    "source": "plain",
    "old_password_verified": false
  },
  "warnings": []
}
```

### Setting Password from Hash

**Example from tests:**
```bash
# Set password using pre-computed hash
user://alice passwd --backend=mock --username=alice --new_password_hash='$pbkdf2-sha512$100000$c2FsdA==$aGFzaA=='
```

**Expected output:**
```json
{
  "password": {
    "changed": true,
    "source": "hash"
  }
}
```

### Password Verification Required

**Example from tests:**
```bash
# Require old password verification
user://alice passwd --backend=mock --username=alice --new_password_plain=NewSecret123! --require_old_password=true --old_password_plain=OldSecret123!
```

### Handling Missing Users

**Example from tests:**
```bash
# Don't fail if user doesn't exist
user://bob passwd --backend=mock --username=bob --new_password_plain=Secret123! --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "user": {
    "username": "bob",
    "existed": false,
    "missing": true
  },
  "password": {
    "changed": false
  },
  "warnings": ["User bob did not exist in backend mock, password not changed."]
}
```

### Password Error Handling

**Conflicting password sources (will fail):**
```bash
user://alice passwd --backend=mock --username=alice --new_password_plain=Secret123! --new_password_hash='$pbkdf2$123$salt$hash'
```

**Missing password (will fail):**
```bash
user://alice passwd --backend=mock --username=alice
```

### Dry Run Mode for Passwords

**Example from tests:**
```bash
# Test password change without making changes
user://alice passwd --backend=mock --username=alice --new_password_plain=Secret123! --dry_run=true
```

**Expected output:**
```json
{
  "ok": true,
  "dry_run": true,
  "password": {
    "changed": false
  },
  "warnings": ["Dry run mode: password would have been changed"]
}
```

### Password Text Output

**Example text format output:**
```
Backend : mock
User    : alice
Dry Run : false

User Details:
Existed        : yes
Missing        : no

Password Details:
Password Changed : yes
Password Scheme  : sha512_crypt
Password Source  : plain
Old Password Verified : no

Warnings:
  (none)
```

## The Lock Action

Use `lock` to prevent users from logging in.

### Locking a User Account

**Example from tests:**
```bash
# Lock user account
user://alice lock --backend=mock --username=alice
```

**Expected output:**
```json
{
  "ok": true,
  "backend": "mock",
  "dry_run": false,
  "user": {
    "username": "alice",
    "uid": 1001,
    "existed": true,
    "missing": false
  },
  "lock": {
    "requested": true,
    "was_locked": false,
    "is_locked": true,
    "changed": true
  },
  "warnings": []
}
```

### Locking Already Locked User

**Example from tests:**
```bash
# Lock user that's already locked
user://alice lock --backend=mock --username=alice
```

The system handles this gracefully - no error occurs.

### Handling Missing Users

**Example from tests:**
```bash
# Don't fail if user doesn't exist  
user://bob lock --backend=mock --username=bob --ignore_if_missing=true
```

### System User Protection

**Example from tests:**
```bash
# Protect system users from being locked
user://root lock --backend=mock --username=root --protect_system_users=true --min_uid_for_lock=1000 --force=false
```

This will fail because root (uid=0) is below the minimum UID.

**Force lock system user:**
```bash
user://root lock --backend=mock --username=root --protect_system_users=true --min_uid_for_lock=1000 --force=true
```

### Dry Run Mode for Lock

**Example from tests:**
```bash
# Test locking without making changes
user://alice lock --backend=mock --username=alice --dry_run=true
```

**Expected output:**
```json
{
  "ok": true,
  "dry_run": true,
  "lock": {
    "was_locked": false,
    "is_locked": false,
    "changed": false
  },
  "warnings": ["Dry run mode: user would have been locked"]
}
```

### Lock Text Output

**Example text format output:**
```
Backend : mock
User    : alice  
Dry Run : false

User Details:
Existed    : yes
Missing    : no

Lock Details:
Was Locked : no
Is Locked  : yes
Changed    : yes

Warnings:
  (none)
```

## The Unlock Action

Use `unlock` to allow locked users to log in again.

### Unlocking a User Account

**Example from tests:**
```bash
# Unlock user account
user://alice unlock --backend=mock --username=alice
```

**Expected output:**
```json
{
  "ok": true,
  "backend": "mock", 
  "dry_run": false,
  "user": {
    "username": "alice",
    "uid": 1001,
    "existed": true,
    "missing": false
  },
  "unlock": {
    "requested": true,
    "was_locked": true,
    "is_locked": false,
    "changed": true
  },
  "warnings": []
}
```

### Unlocking Already Unlocked User

**Example from tests:**
```bash
# Unlock user that's already unlocked
user://alice unlock --backend=mock --username=alice --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "user": {
    "username": "alice",
    "existed": false,
    "missing": true
  },
  "unlock": {
    "was_locked": null,
    "is_locked": null,
    "changed": false
  },
  "warnings": ["User alice did not exist in backend mock"]
}
```

### Handling Missing Users

**Example from tests:**
```bash
# Don't fail if user doesn't exist
user://bob unlock --backend=mock --username=bob --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "user": {
    "username": "bob",
    "existed": false,
    "missing": true
  },
  "unlock": {
    "was_locked": null,
    "is_locked": null,
    "changed": false
  },
  "warnings": ["User bob did not exist in backend mock"]
}
```

### System User Protection

**Example from tests:**
```bash
# Protect system users from being unlocked
user://root unlock --backend=mock --username=root --protect_system_users=true --min_uid_for_unlock=1000 --force=false
```

**Force unlock system user:**
```bash
user://root unlock --backend=mock --username=root --protect_system_users=true --min_uid_for_unlock=1000 --force=true
```

**Expected output includes warning:**
```json
{
  "ok": true,
  "warnings": ["Forced unlock of system user 'root' (uid=0)"]
}
```

### Dry Run Mode for Unlock

**Example from tests:**
```bash
# Test unlocking without making changes
user://alice unlock --backend=mock --username=alice --dry_run=true
```

**Expected output:**
```json
{
  "ok": true,
  "dry_run": true,
  "unlock": {
    "was_locked": true,
    "is_locked": true,
    "changed": false
  },
  "warnings": ["Dry run mode: user would have been unlocked"]
}
```

### Unlock Text Output

**Example text format output:**
```
Backend : mock
User    : alice
Dry Run : false

User Details:
Existed     : yes
Missing     : no

Unlock Details:
Was Locked  : yes
Is Locked   : no  
Changed     : yes

Warnings:
  (none)
```

## The Groups Action

Use `groups` to list what groups a user belongs to.

### Listing All User Groups

**Example from tests:**
```bash
# List all groups for user
user://alice groups --backend=mock --username=alice
```

**Expected output:**
```json
{
  "ok": true,
  "backend": "mock",
  "user": {
    "username": "alice",
    "uid": 1001,
    "existed": true,
    "missing": false
  },
  "groups": [
    {
      "name": "alice",
      "gid": 1001,
      "primary": true,
      "supplementary": false,
      "system_group": false
    },
    {
      "name": "dev", 
      "gid": 1002,
      "primary": false,
      "supplementary": true,
      "system_group": false
    },
    {
      "name": "adm",
      "gid": 4,
      "primary": false, 
      "supplementary": true,
      "system_group": true
    }
  ],
  "warnings": []
}
```

### Excluding System Groups

**Example from tests:**
```bash
# Hide system groups (GID < 1000)
user://alice groups --backend=mock --username=alice --include_system_groups=false --min_gid_for_system=1000
```

**Expected output (system groups filtered):**
```json
{
  "groups": [
    {
      "name": "alice",
      "gid": 1001,
      "primary": true,
      "supplementary": false, 
      "system_group": false
    },
    {
      "name": "dev",
      "gid": 1002, 
      "primary": false,
      "supplementary": true,
      "system_group": false
    }
  ]
}
```

### Excluding Primary Group

**Example from tests:**
```bash
# Show only supplementary groups
user://alice groups --backend=mock --username=alice --include_primary=false
```

**Expected output:**
```json
{
  "groups": [
    {
      "name": "dev",
      "gid": 1002,
      "primary": false,
      "supplementary": true,
      "system_group": false
    }
  ]
}
```

### Excluding Supplementary Groups

**Example from tests:**
```bash
# Show only primary group
user://alice groups --backend=mock --username=alice --include_supplementary=false
```

**Expected output:**
```json
{
  "groups": [
    {
      "name": "alice", 
      "gid": 1001,
      "primary": true,
      "supplementary": false,
      "system_group": false
    }
  ]
}
```

### Filtering by Group Name

**Example from tests:**
```bash
# Show only groups matching name
user://alice groups --backend=mock --username=alice --group_name_filter=dev
```

**Expected output:**
```json
{
  "groups": [
    {
      "name": "dev",
      "gid": 1002,
      "primary": false,
      "supplementary": true,
      "system_group": false
    }
  ]
}
```

### Handling Missing Users

**Example from tests:**
```bash
# Don't fail if user doesn't exist
user://bob groups --backend=mock --username=bob --ignore_if_missing=true
```

**Expected output:**
```json
{
  "ok": true,
  "user": {
    "username": "bob",
    "uid": null,
    "existed": false,
    "missing": true
  },
  "groups": [],
  "warnings": ["User bob did not exist in backend mock"]
}
```

### Groups Text Output

**Example text format output:**
```
Backend : mock
User    : alice (uid=1001)

Groups:
- alice (gid=1001) [primary]
- dev (gid=1002) [supplementary]  
- adm (gid=4) [supplementary, system]

Warnings:
  (none)
```

### No Groups Warning

**Example from tests:**
```bash
# User exists but has no groups
user://alice groups --backend=mock --username=alice
```

When user has no groups, you get a warning:
```json
{
  "groups": [],
  "warnings": ["User alice has no groups matching the specified criteria"]
}
```

## The Exists Action

Use `exists` to check if a user exists in the system.

### Check User by Username

**Example from tests:**
```bash
# Check if user exists by username
user://alice exists --backend=mock --username=alice
```

**Expected output (user exists):**
```json
{
  "ok": true,
  "backend": "mock",
  "query": {
    "username": "alice",
    "uid": null
  },
  "user": {
    "exists": true,
    "username": "alice", 
    "uid": 1001
  },
  "warnings": []
}
```

**Expected output (user does not exist):**
```bash
user://bob exists --backend=mock --username=bob
```

```json
{
  "ok": true,
  "backend": "mock", 
  "query": {
    "username": "bob",
    "uid": null
  },
  "user": {
    "exists": false,
    "username": null,
    "uid": null
  },
  "warnings": ["User bob does not exist in backend mock"]
}
```

### Check User by UID

**Example from tests:**
```bash
# Check if user exists by UID
user:// exists --backend=mock --uid=1001
```

**Expected output (UID exists):**
```json
{
  "ok": true,
  "backend": "mock",
  "query": {
    "username": null,
    "uid": 1001
  },
  "user": {
    "exists": true,
    "username": "alice",
    "uid": 1001
  },
  "warnings": []
}
```

**Expected output (UID does not exist):**
```bash
user:// exists --backend=mock --uid=2000
```

```json
{
  "ok": true,
  "backend": "mock",
  "query": {
    "username": null, 
    "uid": 2000
  },
  "user": {
    "exists": false,
    "username": null,
    "uid": null
  },
  "warnings": ["UID 2000 does not exist in backend mock"]
}
```

### Check User by Both Username and UID

**Example from tests:**
```bash
# Check that username and UID match
user://alice exists --backend=mock --username=alice --uid=1001
```

**Expected output (consistent):**
```json
{
  "ok": true,
  "query": {
    "username": "alice",
    "uid": 1001
  },
  "user": {
    "exists": true,
    "username": "alice",
    "uid": 1001
  },
  "warnings": []
}
```

**Username/UID mismatch (will fail):**
```bash
user://alice exists --backend=mock --username=alice --uid=2000
```

This fails with error: "User 'alice' exists with uid=1001, which does not match requested uid=2000"

### No Identity Error

**Example from tests:**
```bash
# Must provide username or UID
user:// exists --backend=mock
```

This fails with error: "You must provide a username, uid, or a target that resolves to a username"

### Exists Text Output

**Example text format output (exists):**
```
Backend : mock
Query   : username=alice, uid=(none)

User Exists:
Exists   : yes
Username : alice
UID      : 1001

Warnings:
  (none)
```

**Example text format output (does not exist):**
```
Backend : mock  
Query   : username=bob, uid=(none)

User Exists:
Exists   : no
Username : (none)
UID      : (none)

Warnings:
- User bob does not exist in backend mock
```

## Common Options

These options work with most verbs:

### Backend Selection

- `--backend=system` - Use real system (default)
- `--backend=mock` - Use test backend (for testing)

### Output Format

- `--format=json` - JSON output (default)
- `--format=text` - Human-readable text output

### Safety Options

- `--dry_run=true` - Show what would happen without making changes
- `--ignore_if_missing=true` - Don't fail if user/group doesn't exist
- `--force=true` - Override safety checks

### System Protection

- `--protect_system_users=true` - Protect system accounts (default)
- `--min_uid_for_delete=1000` - Minimum UID for deletion
- `--min_uid_for_lock=1000` - Minimum UID for locking

## Error Handling

The user handle provides detailed error messages:

**Username validation errors:**
- Empty usernames
- Invalid characters  
- Too long usernames

**Conflict errors:**
- User already exists
- UID already in use
- Group already exists

**Not found errors:**
- User doesn't exist
- Group doesn't exist
- Membership doesn't exist

**Protection errors:**
- System user protection
- UID range violations

**Password errors:**
- Missing password
- Conflicting password sources
- Hash scheme not supported
- Old password verification failed

All errors include detailed information and suggested solutions.

## Backend Information

The user handle supports two backends:

### System Backend
- Uses real system commands (useradd, userdel, etc.)
- Modifies actual user accounts
- Requires appropriate permissions
- Default backend

### Mock Backend  
- Simulated users and groups
- Used for testing
- No real system changes
- Each operation starts with fresh state

## Username and Group Validation

**Valid usernames:**
- alice
- user_123
- test-user

**Invalid usernames:**
- Empty string
- user@domain (contains @)
- -badstart (starts with -)
- Too long names (over 32 characters)

**UID/GID Ranges:**
- System users: UID < 1000
- Regular users: UID >= 1000, UID <= 65533
- Same rules apply to groups

## Tips and Best Practices

1. **Always test first**: Use `--dry_run=true` to see what will happen
2. **Handle missing gracefully**: Use `--ignore_if_missing=true` for scripts  
3. **Protect system accounts**: Keep default protection settings
4. **Use specific UIDs**: When creating users, specify UID to avoid conflicts
5. **Verify operations**: Use `exists` verb to confirm changes
6. **Check groups**: Use `groups` verb to verify group memberships
7. **Be careful with force**: Only use `--force=true` when absolutely needed

## Examples for Common Tasks

**Create a developer user:**
```bash
user://dev1 add --mode=user --username=dev1 --groups=dev,docker
```

**Reset a user's password:**
```bash  
user://alice passwd --new_password_plain=NewPassword123!
```

**Lock a compromised account:**
```bash
user://suspicious_user lock
```

**Check if user exists before creating:**
```bash
user://newuser exists && echo "User exists" || user://newuser add --mode=user
```

**List all non-system groups for user:**
```bash
user://alice groups --include_system_groups=false
```

**Safely delete user with cleanup:**
```bash
user://olduser delete --mode=user --remove_home=true --remove_from_all_groups=true --ignore_if_missing=true
```