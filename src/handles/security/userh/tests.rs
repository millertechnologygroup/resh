//! Unit and dispatch tests. Every verb is called through `Handle::call`
//! against the shared mock store (`TEST_MOCK`) or a recording system
//! backend (`TEST_RECORD`); no account on the host is ever changed (the
//! system backend refuses to run tools from unit tests).

use super::*;
use crate::core::status::{exit, is_valid_error_code};
use serde_json::Value;

struct Out {
    status: Status,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.stdout))
    }

    #[track_caller]
    fn ok(&self) -> Value {
        assert!(
            self.status.ok,
            "expected success: {:?}\n{}",
            self.status, self.stdout
        );
        let v = self.json();
        assert_eq!(v["ok"], true);
        v
    }

    #[track_caller]
    fn fails(&self, exit_code: i32, code: &str) -> Value {
        assert!(!self.status.ok, "expected failure {code}: {}", self.stdout);
        assert_eq!(
            self.status.exit_code(),
            exit_code,
            "{code}: {:?}",
            self.status
        );
        let reason = self.status.reason.clone().unwrap_or_default();
        assert!(
            reason.starts_with(&format!("[{code}] ")),
            "{code}: {reason}"
        );
        if self.stdout.is_empty() {
            return Value::Null;
        }
        let v = self.json();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], code, "{}", self.stdout);
        v
    }

    fn reason(&self) -> String {
        self.status.reason.clone().unwrap_or_default()
    }
}

fn call_in(target: &str, verb: &str, pairs: &[(&str, &str)], stdin: &str) -> Out {
    let url = Url::parse(&format!("user://{target}")).unwrap();
    let h = UserHandle::from_url(url).unwrap();
    let args: Args = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut input = stdin.as_bytes();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = {
        let mut io = IoStreams::new(&mut input, &mut out, &mut err);
        h.call(verb, &args, &mut io).unwrap()
    };
    Out {
        status,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
    }
}

/// Calls `user://<target>.<verb>` with backend=mock on `mock`.
fn mock_call(mock: &MockBackend, target: &str, verb: &str, pairs: &[(&str, &str)]) -> Out {
    mock_call_stdin(mock, target, verb, pairs, "")
}

fn mock_call_stdin(
    mock: &MockBackend,
    target: &str,
    verb: &str,
    pairs: &[(&str, &str)],
    stdin: &str,
) -> Out {
    TEST_MOCK.with(|m| *m.borrow_mut() = Some(mock.clone()));
    let mut all = pairs.to_vec();
    if !pairs.iter().any(|(k, _)| *k == "backend") {
        all.push(("backend", "mock"));
    }
    let out = call_in(target, verb, &all, stdin);
    TEST_MOCK.with(|m| *m.borrow_mut() = None);
    out
}

/// Calls with the system backend recording its commands.
fn system_call(target: &str, verb: &str, pairs: &[(&str, &str)]) -> (Out, Vec<SystemCommand>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    TEST_RECORD.with(|r| *r.borrow_mut() = Some(log.clone()));
    let out = call_in(target, verb, pairs, "");
    TEST_RECORD.with(|r| *r.borrow_mut() = None);
    let cmds = log.lock().unwrap().clone();
    (out, cmds)
}

/// alice (1001, primary group alice, member of dev), group dev (1500),
/// group empty (1600), group sys (10), system user daemon (2).
fn world() -> MockBackend {
    MockBackend::new()
        .with_existing_group("dev", 1500)
        .with_existing_group("empty", 1600)
        .with_existing_group("sys", 10)
        .with_existing_user("alice", 1001, "alice")
        .with_existing_membership("alice", "dev")
        .with_existing_user("daemon", 2, "daemon")
}

/// A user name that does not exist on any host.
const NOBODY_HERE: &str = "resh-ut-nosuchuser";

// ---------------------------------------------------------------------------
// Targets and strict arguments
// ---------------------------------------------------------------------------

#[test]
fn targets_parse_in_host_and_path_form() {
    for (url, path) in [
        ("user://alice", "alice"),
        ("user:///alice", "alice"),
        ("user://group/admins", "group/admins"),
        ("user:///group/admins", "group/admins"),
        ("user://membership/alice", "membership/alice"),
        ("user://alice/extra", "alice/extra"),
    ] {
        let t = UserTarget::from_url(&Url::parse(url).unwrap()).unwrap();
        assert_eq!(t.path, path, "{url}");
    }
    let m = world();
    mock_call(&m, "alice/extra", "exists", &[]).fails(2, "user.invalid_target");
    mock_call(&m, "group", "add", &[("mode", "group")]).fails(2, "user.invalid_target");
    mock_call(&m, "group/dev", "lock", &[]).fails(2, "user.invalid_target");
    mock_call(&m, "alice", "add", &[("mode", "group")]).fails(2, "user.invalid_target");
    mock_call(&m, "alice", "exists", &[("username", "bob")]).fails(2, "user.invalid_argument");
    // username= alone names the account.
    let v = mock_call(&m, "", "exists", &[("username", "alice")]).ok();
    assert_eq!(v["user"]["uid"], 1001);
}

#[test]
fn every_verb_refuses_unknown_arguments_with_a_suggestion() {
    let m = world();
    for verb in args::VERBS {
        let o = mock_call(&m, "alice", verb, &[("bogus_option", "1")]);
        o.fails(2, "user.invalid_argument");
        assert!(o.reason().contains("bogus_option"), "{}", o.reason());
    }
    let o = mock_call(&m, "alice", "delete", &[("remove_hom", "true")]);
    o.fails(2, "user.invalid_argument");
    assert!(
        o.reason().contains("did you mean `remove_home`?"),
        "{}",
        o.reason()
    );
    // Lookups refuse timeout_ms and dry_run; passwd refuses force.
    for verb in ["exists", "groups"] {
        mock_call(&m, "alice", verb, &[("timeout_ms", "10")]).fails(2, "user.invalid_argument");
        mock_call(&m, "alice", verb, &[("dry_run", "true")]).fails(2, "user.invalid_argument");
    }
    // passwd: a misspelled force.
    let o = mock_call(
        &m,
        "alice",
        "passwd",
        &[("forse", "true"), ("new_password_plain", "x")],
    );
    o.fails(2, "user.invalid_argument");
    assert!(
        o.reason().contains("did you mean `force`?"),
        "{}",
        o.reason()
    );
    assert!(m.changes().is_empty());
    // An unknown verb.
    let o = mock_call(&m, "alice", "lokc", &[]);
    o.fails(2, "user.invalid_argument");
    assert!(
        o.reason().contains("did you mean `lock`?"),
        "{}",
        o.reason()
    );
}

#[test]
fn invalid_values_are_refused_before_anything_changes() {
    let m = world();
    let cases: &[(&str, &str, &[(&str, &str)], &str)] = &[
        (
            "bob",
            "add",
            &[("dry_run", "maybe")],
            "user.invalid_argument",
        ),
        ("bob", "add", &[("force", "maybe")], "user.invalid_argument"),
        (
            "bob",
            "add",
            &[("ignore_if_exists", "yes please")],
            "user.invalid_argument",
        ),
        (
            "bob",
            "add",
            &[("create_home", "")],
            "user.invalid_argument",
        ),
        ("bob", "add", &[("uid", "12x")], "user.invalid_argument"),
        ("bob", "add", &[("uid", "-1")], "user.invalid_argument"),
        (
            "bob",
            "add",
            &[("home", "relative/dir")],
            "user.invalid_argument",
        ),
        (
            "bob",
            "add",
            &[("shell", "/bin/sh:x")],
            "user.invalid_argument",
        ),
        ("bob", "add", &[("gecos", "a\nb")], "user.invalid_argument"),
        ("bob", "add", &[("mode", "users")], "user.invalid_mode"),
        ("bob", "add", &[("format", "xml")], "user.invalid_argument"),
        (
            "bob",
            "add",
            &[("timeout_ms", "0")],
            "user.invalid_argument",
        ),
        (
            "bob",
            "add",
            &[("timeout_ms", "soon")],
            "user.invalid_argument",
        ),
        (
            "bob",
            "add",
            &[("supplementary_groups", "dev,,x")],
            "user.invalid_argument",
        ),
        (
            "bob",
            "add",
            &[("supplementary_groups", "dev,-x")],
            "user.group_name_invalid",
        ),
        (
            "bob",
            "add",
            &[("groups", "dev"), ("supplementary_groups", "dev")],
            "user.invalid_argument",
        ),
        ("bob", "add", &[("gid", "5000")], "user.invalid_argument"),
        (
            "bob",
            "add",
            &[("password_hash", "plaintext")],
            "user.hash_params_invalid",
        ),
        ("-bob", "add", &[], "user.username_invalid"),
        ("", "add", &[("username", "bo:b")], "user.username_invalid"),
        ("123", "add", &[], "user.username_invalid"),
        (
            "abcdefghijklmnopqrstuvwxyz0123456",
            "add",
            &[],
            "user.username_invalid",
        ),
        (
            "group/-x",
            "add",
            &[("mode", "group")],
            "user.group_name_invalid",
        ),
        (
            "group/dev",
            "add",
            &[("mode", "group"), ("shell", "/bin/sh")],
            "user.invalid_argument",
        ),
        (
            "membership/alice",
            "add",
            &[("mode", "membership")],
            "user.groups_required",
        ),
        (
            "membership/alice",
            "add",
            &[("mode", "membership"), ("groups", "dev"), ("force", "true")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "delete",
            &[("remove_home", "yes-ish")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "delete",
            &[("remove_from_all_groups", "false")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "delete",
            &[("min_uid_for_delete", "x")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "delete",
            &[("protect_system_users", "no way")],
            "user.invalid_argument",
        ),
        (
            "membership/alice",
            "delete",
            &[
                ("mode", "membership"),
                ("groups", "dev"),
                ("all_groups", "true"),
            ],
            "user.invalid_argument",
        ),
        (
            "membership/alice",
            "delete",
            &[("mode", "membership")],
            "user.groups_required",
        ),
        (
            "alice",
            "lock",
            &[("min_uid_for_lock", "lots")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "unlock",
            &[("ignore_if_missing", "2")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "groups",
            &[("include_primary", "nah")],
            "user.invalid_argument",
        ),
        (
            "alice",
            "groups",
            &[("group_name_filter", "a b")],
            "user.group_name_invalid",
        ),
        ("alice", "exists", &[("uid", "x")], "user.invalid_argument"),
        (
            "alice",
            "exists",
            &[("backend", "ldap")],
            "user.backend_not_supported",
        ),
        (
            "alice",
            "exists",
            &[("backend", "file")],
            "user.backend_not_supported",
        ),
        (
            "alice",
            "exists",
            &[("backend", "sql")],
            "user.invalid_argument",
        ),
        ("", "exists", &[], "user.identity_required"),
        ("", "lock", &[], "user.username_required"),
        (
            "",
            "delete",
            &[("mode", "group")],
            "user.group_name_required",
        ),
        (
            "",
            "add",
            &[("mode", "membership"), ("groups", "dev")],
            "user.member_required",
        ),
    ];
    for (target, verb, pairs, code) in cases {
        let o = mock_call(&m, target, verb, pairs);
        o.fails(2, code);
    }
    assert!(m.changes().is_empty(), "{:?}", m.changes());
}

/// The accepted-options list of each verb is exactly what its help usage
/// lists.
#[test]
fn accepted_options_match_the_help_usage() {
    for verb in args::VERBS {
        let detail = USER_HELP
            .verbs
            .iter()
            .find(|v| v.name == *verb)
            .and_then(|v| v.detail.as_ref())
            .unwrap();
        let mut in_usage: Vec<String> = Vec::new();
        for word in detail
            .usage
            .split(|c: char| c.is_whitespace() || c == '[' || c == '|')
        {
            if let Some((key, _)) = word.split_once('=') {
                let key = key.trim_start_matches('[').to_string();
                if !key.is_empty() && !in_usage.contains(&key) {
                    in_usage.push(key);
                }
            }
        }
        let mut accepted: Vec<String> = args::verb_args(verb)
            .unwrap()
            .iter()
            .map(|s| s.to_string())
            .collect();
        in_usage.sort();
        accepted.sort();
        assert_eq!(in_usage, accepted, "{verb}");
    }
}

#[test]
fn every_error_code_is_valid_documented_and_has_the_right_exit() {
    let doc = include_str!("../../../../docs/Security_Secrets/user.md");
    for (code, exit_code) in ERROR_CODES {
        assert!(is_valid_error_code(code), "{code}");
        assert!(
            doc.contains(&format!("`{code}`")),
            "{code} is not documented"
        );
        assert!([1, 2, 124].contains(exit_code));
    }
    // Every variant maps to a listed code.
    let samples = [
        UserError::InvalidArgument(String::new()),
        UserError::InvalidTarget(String::new()),
        UserError::InvalidMode(String::new()),
        UserError::BackendNotSupported(String::new()),
        UserError::UsernameRequired,
        UserError::GroupNameRequired,
        UserError::MemberRequired,
        UserError::GroupsRequired,
        UserError::IdentityRequired,
        UserError::UsernameInvalid(String::new()),
        UserError::GroupNameInvalid(String::new()),
        UserError::UidOutOfRange(1),
        UserError::GidOutOfRange(1),
        UserError::PasswordConflictingSources,
        UserError::PasswordMissingNewPassword,
        UserError::HashSchemeUnsupported(String::new()),
        UserError::HashParamsInvalid(String::new()),
        UserError::OldPasswordRequired,
        UserError::UsernameConflict(String::new()),
        UserError::GroupConflict(String::new()),
        UserError::UidConflict(1),
        UserError::GidConflict(1),
        UserError::NoFreeId(String::new()),
        UserError::GroupNotFound(String::new()),
        UserError::MembershipExists(String::new(), String::new()),
        UserError::UserNotFound(String::new()),
        UserError::SystemUserProtected(String::new(), 0, "lock", 1000),
        UserError::SystemGroupProtected(String::new(), 0, 1000),
        UserError::GroupNotEmpty(String::new()),
        UserError::MembershipNotFound(String::new(), String::new()),
        UserError::PrimaryGroupMembership(String::new(), String::new()),
        UserError::OldPasswordVerificationUnsupported(String::new()),
        UserError::OldPasswordMismatch(String::new()),
        UserError::PasswordBackendFailure(String::new()),
        UserError::LockBackendFailure(String::new()),
        UserError::UnlockBackendFailure(String::new()),
        UserError::GroupsBackendFailure(String::new()),
        UserError::ExistsMismatch(String::new(), 1, 2),
        UserError::ExistsBackendFailure(String::new(), String::new()),
        UserError::BackendOperationFailed(String::new()),
        UserError::PermissionDenied(String::new()),
        UserError::ToolNotFound(String::new()),
        UserError::Timeout(String::new()),
        UserError::PartialFailure(String::new()),
        UserError::ProtectedAccount(String::new(), 0),
    ];
    for e in samples {
        let code = e.code();
        assert!(
            ERROR_CODES.iter().any(|(c, _)| *c == code),
            "{code} is missing from ERROR_CODES"
        );
    }
    assert_eq!(UserError::Timeout(String::new()).exit_code(), exit::TIMEOUT);
    assert_eq!(UserError::UsernameRequired.exit_code(), exit::USAGE);
    assert_eq!(
        UserError::UserNotFound(String::new()).exit_code(),
        exit::FAILED
    );
}

#[test]
fn help_forms_render_the_approved_help() {
    let m = world();
    let o = mock_call(&m, "alice", "help", &[]);
    assert!(o.status.ok);
    assert!(o.stdout.contains("exists") && o.stdout.contains("passwd"));
    let o = call_in("alice", "add", &[("--help", "true")], "");
    assert!(o.status.ok);
    assert!(o.stdout.contains("[timeout_ms=<ms>]"), "{}", o.stdout);
    for line in o.stdout.lines() {
        assert!(line.len() <= 80, "{line}");
    }
}

// ---------------------------------------------------------------------------
// exists / groups
// ---------------------------------------------------------------------------

#[test]
fn exists_reports_present_missing_and_uid_checks() {
    let m = world();
    let v = mock_call(&m, "alice", "exists", &[]).ok();
    assert_eq!(v["user"]["exists"], true);
    assert_eq!(v["user"]["uid"], 1001);
    let v = mock_call(&m, "bob", "exists", &[]).ok();
    assert_eq!(v["user"]["exists"], false);
    assert!(v["warnings"][0].as_str().unwrap().contains("bob"));
    mock_call(&m, "alice", "exists", &[("uid", "1001")]).ok();
    let v = mock_call(&m, "alice", "exists", &[("uid", "7")]).fails(1, "user.exists_mismatch");
    assert_eq!(v["error"]["details"]["actual_uid"], 1001);
    let v = mock_call(&m, "", "exists", &[("uid", "1001")]).ok();
    assert_eq!(v["user"]["username"], "alice");
    let v = mock_call(&m, "", "exists", &[("uid", "4242")]).ok();
    assert_eq!(v["user"]["exists"], false);
    let o = mock_call(&m, "alice", "exists", &[("format", "text")]);
    assert!(o.status.ok);
    assert!(o.stdout.contains("alice"), "{}", o.stdout);
}

#[test]
fn exists_and_groups_read_the_real_database() {
    let (o, cmds) = system_call("root", "exists", &[]);
    let v = o.ok();
    assert_eq!(v["user"]["uid"], 0);
    assert!(cmds.is_empty());
    let (o, _) = system_call(NOBODY_HERE, "exists", &[]);
    assert_eq!(o.ok()["user"]["exists"], false);
    let (o, _) = system_call("root", "groups", &[]);
    let v = o.ok();
    assert_eq!(v["groups"][0]["primary"], true);
    assert_eq!(v["groups"][0]["gid"], 0);
    assert_eq!(v["groups"][0]["system_group"], true);
    let (o, _) = system_call(NOBODY_HERE, "groups", &[("ignore_if_missing", "false")]);
    o.fails(1, "user.not_found");
}

#[test]
fn groups_filters_and_classifies() {
    let m = world();
    let v = mock_call(&m, "alice", "groups", &[]).ok();
    let names: Vec<&str> = v["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alice", "dev"]);
    assert_eq!(v["groups"][0]["primary"], true);
    assert_eq!(v["groups"][1]["supplementary"], true);
    let v = mock_call(&m, "alice", "groups", &[("include_primary", "false")]).ok();
    assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    let v = mock_call(&m, "alice", "groups", &[("include_supplementary", "0")]).ok();
    assert_eq!(v["groups"][0]["name"], "alice");
    let v = mock_call(&m, "alice", "groups", &[("min_gid_for_system", "1501")]).ok();
    assert_eq!(v["groups"][1]["system_group"], true);
    let v = mock_call(
        &m,
        "alice",
        "groups",
        &[
            ("min_gid_for_system", "1501"),
            ("include_system_groups", "off"),
        ],
    )
    .ok();
    assert_eq!(v["groups"].as_array().unwrap().len(), 0);
    assert!(v["warnings"][0].as_str().unwrap().contains("no groups"));
    let v = mock_call(&m, "alice", "groups", &[("group_name_filter", "dev")]).ok();
    assert_eq!(v["groups"][0]["name"], "dev");
    let v = mock_call(&m, "bob", "groups", &[]).ok();
    assert_eq!(v["user"]["missing"], true);
    mock_call(&m, "bob", "groups", &[("ignore_if_missing", "false")]).fails(1, "user.not_found");
    let o = mock_call(&m, "alice", "groups", &[("format", "text")]);
    assert!(o.status.ok && o.stdout.contains("dev"));
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

#[test]
fn add_user_creates_group_user_memberships_and_password() {
    let m = world();
    let hash = hash_password("pw", &HashScheme::Sha512Crypt).unwrap();
    let v = mock_call(
        &m,
        "bob",
        "add",
        &[
            ("supplementary_groups", "dev,empty"),
            ("shell", "/bin/zsh"),
            ("gecos", "Bob B"),
            ("password_hash", &hash),
        ],
    )
    .ok();
    assert_eq!(v["user"]["created"], true);
    assert_eq!(v["user"]["uid"], 1000);
    assert_eq!(v["groups"][0]["name"], "bob");
    assert_eq!(v["groups"][0]["gid"], 1000);
    assert_eq!(v["memberships"].as_array().unwrap().len(), 2);
    assert_eq!(v["password_set"], true);
    assert_eq!(
        m.changes(),
        ["create group bob", "create user bob", "set password of bob"]
    );
    assert!(m.membership_exists("bob", "empty").unwrap());
    assert_eq!(m.password_field("bob").unwrap().unwrap(), hash);
    assert!(m.path_exists("/home/bob"));
}

#[test]
fn add_user_options() {
    // create_home=false, an existing primary group, an explicit uid, and
    // the groups= alias.
    let m = world();
    let v = mock_call(
        &m,
        "carol",
        "add",
        &[
            ("create_home", "false"),
            ("primary_group", "dev"),
            ("uid", "2000"),
            ("groups", "empty"),
            ("home", "/srv/carol"),
        ],
    )
    .ok();
    assert_eq!(v["user"]["uid"], 2000);
    assert_eq!(v["user"]["home"], "/srv/carol");
    assert!(v.get("groups").is_none(), "no group was created: {v}");
    assert!(!m.path_exists("/srv/carol"));
    assert!(m.membership_exists("carol", "empty").unwrap());
    // uid conflict, out of range, and force.
    mock_call(&m, "dave", "add", &[("uid", "2000")]).fails(1, "user.uid_conflict");
    mock_call(&m, "dave", "add", &[("uid", "500")]).fails(2, "user.uid_out_of_range");
    mock_call(&m, "dave", "add", &[("uid", "65534")]).fails(2, "user.uid_out_of_range");
    let v = mock_call(&m, "dave", "add", &[("uid", "500"), ("force", "true")]).ok();
    assert!(v["warnings"][0].as_str().unwrap().contains("force=true"));
}

#[test]
fn add_user_existing_reports_the_real_account() {
    let m = world();
    let v = mock_call(&m, "alice", "add", &[("shell", "/bin/zsh")]).ok();
    assert_eq!(v["user"]["existed"], true);
    assert_eq!(v["user"]["created"], false);
    assert_eq!(v["user"]["shell"], "/bin/bash");
    assert_eq!(v["user"]["supplementary_groups"][0], "dev");
    mock_call(&m, "alice", "add", &[("ignore_if_exists", "false")])
        .fails(1, "user.username_conflict");
    assert!(m.changes().is_empty());
}

#[test]
fn add_user_checks_everything_before_the_first_change() {
    let m = world();
    // A missing supplementary group: nothing is created, not even the
    // primary group.
    mock_call(&m, "bob", "add", &[("supplementary_groups", "dev,nosuch")])
        .fails(1, "user.group_not_found");
    // A primary group that does not exist and cannot be created.
    mock_call(&m, "bob", "add", &[("primary_group", "Not.Valid$x")])
        .fails(2, "user.group_name_invalid");
    assert!(m.changes().is_empty(), "{:?}", m.changes());
}

#[test]
fn option_shaped_primary_group_is_refused() {
    let m = world();
    for dry in ["false", "true"] {
        let o = mock_call(
            &m,
            "bob",
            "add",
            &[("primary_group", "-probe"), ("dry_run", dry)],
        );
        o.fails(2, "user.group_name_invalid");
        assert!(o.reason().contains("primary_group"), "{}", o.reason());
    }
    assert!(m.changes().is_empty());
}

#[test]
fn add_dry_run_plans_commands_with_operands_after_a_separator() {
    let (o, cmds) = system_call(
        NOBODY_HERE,
        "add",
        &[
            ("uid", "54321"),
            ("primary_group", "resh-ut.team"),
            ("supplementary_groups", "root"),
            ("create_home", "false"),
            ("gecos", "It's me"),
            ("dry_run", "true"),
        ],
    );
    let v = o.ok();
    assert!(cmds.is_empty(), "a dry run records nothing");
    let planned: Vec<&str> = v["planned_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(planned[0].starts_with("groupadd -g "), "{planned:?}");
    assert!(planned[0].ends_with(" -- resh-ut.team"), "{planned:?}");
    assert_eq!(
        planned[1],
        format!(
            "useradd -u 54321 -g resh-ut.team -G root -d /home/{NOBODY_HERE} -M -s /bin/bash \
             -c 'It'\\''s me' -- {NOBODY_HERE}"
        )
    );
    assert_eq!(v["user"]["created"], false);
}

#[test]
fn add_without_dry_run_records_the_commands_in_order() {
    let hash = hash_password("pw", &HashScheme::Sha512Crypt).unwrap();
    let (o, cmds) = system_call(NOBODY_HERE, "add", &[("password_hash", &hash)]);
    o.ok();
    let argv0: Vec<&str> = cmds.iter().map(|c| c.argv[0].as_str()).collect();
    assert_eq!(argv0, ["groupadd", "useradd", "chpasswd"]);
    assert_eq!(cmds[2].argv, ["chpasswd", "-e"]);
    assert_eq!(
        cmds[2].stdin.as_deref(),
        Some(format!("{NOBODY_HERE}:{hash}\n").as_str())
    );
    assert!(cmds[2].display().ends_with("<<< (redacted)"));
    assert!(!cmds[2].display().contains(&hash));
}

#[test]
fn add_group_and_membership() {
    let m = world();
    let v = mock_call(
        &m,
        "group/ops",
        "add",
        &[("mode", "group"), ("gid", "3000")],
    )
    .ok();
    assert_eq!(v["group"]["gid"], 3000);
    assert_eq!(v["group"]["created"], true);
    mock_call(
        &m,
        "group/ops2",
        "add",
        &[("mode", "group"), ("gid", "3000")],
    )
    .fails(1, "user.gid_conflict");
    mock_call(&m, "group/ops2", "add", &[("mode", "group"), ("gid", "99")])
        .fails(2, "user.gid_out_of_range");
    mock_call(&m, "", "add", &[("mode", "group"), ("group_name", "ops3")]).ok();
    let v = mock_call(&m, "group/dev", "add", &[("mode", "group")]).ok();
    assert_eq!(v["group"]["existed"], true);
    mock_call(
        &m,
        "group/dev",
        "add",
        &[("mode", "group"), ("ignore_if_exists", "false")],
    )
    .fails(1, "user.group_conflict");

    let v = mock_call(
        &m,
        "membership/alice",
        "add",
        &[("mode", "membership"), ("groups", "dev,ops,alice")],
    )
    .ok();
    let ms = v["memberships"].as_array().unwrap();
    assert_eq!(ms[0]["already_member"], true);
    assert_eq!(ms[1]["added"], true);
    assert_eq!(ms[2]["already_member"], true, "the primary group");
    assert!(m.membership_exists("alice", "ops").unwrap());
    mock_call(
        &m,
        "membership/alice",
        "add",
        &[
            ("mode", "membership"),
            ("groups", "dev"),
            ("ignore_if_exists", "false"),
        ],
    )
    .fails(1, "user.membership_exists");
    mock_call(
        &m,
        "membership/bob",
        "add",
        &[("mode", "membership"), ("groups", "dev")],
    )
    .fails(1, "user.not_found");
    mock_call(
        &m,
        "membership/alice",
        "add",
        &[("mode", "membership"), ("groups", "empty,nosuch")],
    )
    .fails(1, "user.group_not_found");
    assert!(!m.membership_exists("alice", "empty").unwrap());
    let (o, _) = system_call(
        "membership/root",
        "add",
        &[
            ("mode", "membership"),
            ("groups", "root"),
            ("dry_run", "true"),
        ],
    );
    assert!(
        o.ok()["planned_commands"].is_null(),
        "root is already in its group"
    );
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[test]
fn delete_user_and_its_options() {
    let m = world();
    let v = mock_call(&m, "alice", "delete", &[("remove_home", "true")]).ok();
    assert_eq!(v["user"]["deleted"], true);
    assert_eq!(v["home"]["was_present"], true);
    assert_eq!(v["home"]["removed"], true);
    assert_eq!(v["mail"]["was_present"], false);
    assert!(!m.user_exists("alice").unwrap());
    assert!(!m.membership_exists("alice", "dev").unwrap());
    let v = mock_call(&m, "alice", "delete", &[]).ok();
    assert_eq!(v["user"]["missing"], true);
    mock_call(&m, "alice", "delete", &[("ignore_if_missing", "false")]).fails(1, "user.not_found");
}

#[test]
fn delete_protects_system_users() {
    let m = world();
    let v = mock_call(&m, "daemon", "delete", &[]).fails(1, "user.system_user_protected");
    assert_eq!(v["error"]["details"]["min_uid_for_delete"], 1000);
    mock_call(&m, "daemon", "delete", &[("dry_run", "true")])
        .fails(1, "user.system_user_protected");
    mock_call(&m, "alice", "delete", &[("min_uid_for_delete", "2000")])
        .fails(1, "user.system_user_protected");
    assert!(m.changes().is_empty());
    let v = mock_call(&m, "daemon", "delete", &[("force", "true")]).ok();
    assert!(v["warnings"][0].as_str().unwrap().contains("force=true"));
    let v = mock_call(
        &m,
        "alice",
        "delete",
        &[
            ("protect_system_users", "false"),
            ("min_uid_for_delete", "5000"),
        ],
    )
    .ok();
    assert_eq!(v["user"]["deleted"], true);
    // root everywhere, through the system backend.
    let (o, cmds) = system_call("root", "delete", &[("dry_run", "true")]);
    let v = o.fails(1, "user.system_user_protected");
    assert_eq!(v["error"]["details"]["uid"], 0);
    assert!(cmds.is_empty());
}

#[test]
fn delete_refuses_a_top_level_home() {
    let m = MockBackend::new().with_existing_user("svc", 1200, "svc");
    // with_existing_user puts the home under /home; a top-level one:
    let (o, cmds) = system_call(
        "root",
        "delete",
        &[("force", "true"), ("remove_home", "true")],
    );
    o.fails(2, "user.invalid_argument");
    assert!(o.reason().contains("/root"), "{}", o.reason());
    assert!(cmds.is_empty());
    mock_call(&m, "svc", "delete", &[("remove_home", "true")]).ok();
}

#[test]
fn delete_user_dry_run_and_recorded_commands() {
    let m = world();
    let v = mock_call(
        &m,
        "alice",
        "delete",
        &[("remove_home", "true"), ("dry_run", "1")],
    )
    .ok();
    assert_eq!(v["user"]["deleted"], false);
    assert_eq!(v["home"]["removed"], false);
    assert!(m.changes().is_empty());
    assert!(m.user_exists("alice").unwrap());
    // The system backend's commands (recorded, never run): root with force.
    let (o, cmds) = system_call(
        "root",
        "delete",
        &[("force", "true"), ("remove_mail", "true")],
    );
    o.ok();
    assert_eq!(cmds[0].argv, ["userdel", "--", "root"]);
    assert_eq!(cmds[1].argv, ["rm", "-f", "--", "/var/mail/root"]);
}

#[test]
fn delete_group_rules() {
    let m = world();
    mock_call(&m, "group/dev", "delete", &[("mode", "group")]).fails(1, "user.group_not_empty");
    mock_call(&m, "group/sys", "delete", &[("mode", "group")])
        .fails(1, "user.group_system_protected");
    let v = mock_call(
        &m,
        "group/dev",
        "delete",
        &[("mode", "group"), ("force", "true")],
    )
    .ok();
    assert_eq!(v["group"]["member_count_before"], 1);
    mock_call(
        &m,
        "group/empty",
        "delete",
        &[("mode", "group"), ("dry_run", "true")],
    )
    .ok();
    assert!(m.group_exists("empty").unwrap());
    mock_call(&m, "group/empty", "delete", &[("mode", "group")]).ok();
    assert!(!m.group_exists("empty").unwrap());
    let v = mock_call(&m, "group/empty", "delete", &[("mode", "group")]).ok();
    assert_eq!(v["group"]["missing"], true);
    mock_call(
        &m,
        "group/empty",
        "delete",
        &[("mode", "group"), ("ignore_if_missing", "false")],
    )
    .fails(1, "user.group_not_found");
    mock_call(
        &m,
        "group/sys",
        "delete",
        &[
            ("mode", "group"),
            ("only_if_empty", "false"),
            ("protect_system_groups", "false"),
        ],
    )
    .ok();
    // A user's primary group: the backend refuses (groupdel does too).
    mock_call(&m, "group/alice", "delete", &[("mode", "group")])
        .fails(1, "user.backend_operation_failed");
    let (o, _) = system_call(
        "group/root",
        "delete",
        &[("mode", "group"), ("dry_run", "true")],
    );
    o.fails(1, "user.group_system_protected");
}

#[test]
fn delete_membership_rules() {
    let m = world().with_existing_membership("alice", "empty");
    mock_call(
        &m,
        "membership/alice",
        "delete",
        &[("mode", "membership"), ("groups", "alice")],
    )
    .fails(1, "user.primary_group_membership");
    mock_call(
        &m,
        "membership/alice",
        "delete",
        &[
            ("mode", "membership"),
            ("groups", "dev,nosuch"),
            ("ignore_if_missing", "false"),
        ],
    )
    .fails(1, "user.group_not_found");
    mock_call(
        &m,
        "membership/alice",
        "delete",
        &[
            ("mode", "membership"),
            ("groups", "sys"),
            ("ignore_if_missing", "false"),
        ],
    )
    .fails(1, "user.membership_not_found");
    assert!(m.changes().is_empty(), "checked before changing");
    let v = mock_call(
        &m,
        "membership/alice",
        "delete",
        &[("mode", "membership"), ("groups", "dev,nosuch,sys")],
    )
    .ok();
    assert_eq!(v["memberships"].as_array().unwrap().len(), 3);
    assert!(!m.membership_exists("alice", "dev").unwrap());
    let v = mock_call(
        &m,
        "membership/alice",
        "delete",
        &[("mode", "membership"), ("all_groups", "true")],
    )
    .ok();
    assert_eq!(v["memberships"][0]["group"], "empty");
    assert!(m.user_exists("alice").unwrap());
    let v = mock_call(
        &m,
        "membership/bob",
        "delete",
        &[("mode", "membership"), ("groups", "dev")],
    )
    .ok();
    assert!(v["warnings"][0].as_str().unwrap().contains("bob"));
    mock_call(
        &m,
        "membership/bob",
        "delete",
        &[
            ("mode", "membership"),
            ("groups", "dev"),
            ("ignore_if_missing", "false"),
        ],
    )
    .fails(1, "user.not_found");
}

// ---------------------------------------------------------------------------
// passwd
// ---------------------------------------------------------------------------

#[test]
fn passwd_sources_and_schemes() {
    let m = world();
    for (scheme, prefix) in [
        ("backend_default", "$6$"),
        ("sha512_crypt", "$6$"),
        ("bcrypt", "$2b$"),
        ("argon2id", "$argon2id$"),
    ] {
        let v = mock_call(
            &m,
            "alice",
            "passwd",
            &[("new_password_plain", "S3cr3t!"), ("hash_scheme", scheme)],
        )
        .ok();
        assert_eq!(v["password"]["changed"], true);
        assert_eq!(v["password"]["source"], "plain");
        let stored = m.password_field("alice").unwrap().unwrap();
        assert!(stored.starts_with(prefix), "{scheme}: {stored}");
        assert!(
            verify_password_hash("S3cr3t!", &stored).unwrap(),
            "{scheme}"
        );
        assert!(!verify_password_hash("wrong", &stored).unwrap(), "{scheme}");
    }
    // From stdin (one trailing newline dropped) and from the environment.
    let v = mock_call_stdin(
        &m,
        "alice",
        "passwd",
        &[("new_password_stdin", "true")],
        "from stdin\n",
    )
    .ok();
    assert_eq!(v["password"]["source"], "stdin");
    assert!(
        verify_password_hash("from stdin", &m.password_field("alice").unwrap().unwrap()).unwrap()
    );
    // SAFETY: a variable only this test reads.
    unsafe { std::env::set_var("RESH_UT_USER_PW", "from env") };
    let v = mock_call(
        &m,
        "alice",
        "passwd",
        &[("new_password_env", "RESH_UT_USER_PW")],
    )
    .ok();
    assert_eq!(v["password"]["source"], "env");
    assert!(
        verify_password_hash("from env", &m.password_field("alice").unwrap().unwrap()).unwrap()
    );
    // A precomputed hash.
    let hash = hash_password("pre", &HashScheme::Bcrypt).unwrap();
    let v = mock_call(&m, "alice", "passwd", &[("new_password_hash", &hash)]).ok();
    assert_eq!(v["password"]["scheme"], "bcrypt");
    assert_eq!(v["password"]["source"], "hash");
    assert_eq!(m.password_field("alice").unwrap().unwrap(), hash);
    // The output never holds the password.
    let o = mock_call(
        &m,
        "alice",
        "passwd",
        &[("new_password_plain", "VisibleNot")],
    );
    assert!(!o.stdout.contains("VisibleNot"));
}

#[test]
fn passwd_errors() {
    let m = world();
    let cases: &[(&[(&str, &str)], i32, &str)] = &[
        (&[], 2, "user.passwd_missing_new_password"),
        (
            &[("new_password_plain", "a"), ("new_password_hash", "$6$x")],
            2,
            "user.passwd_conflicting_sources",
        ),
        (
            &[("new_password_plain", "a"), ("new_password_env", "X")],
            2,
            "user.passwd_conflicting_sources",
        ),
        (&[("new_password_plain", "")], 2, "user.invalid_argument"),
        (
            &[("new_password_plain", "a\nb")],
            2,
            "user.invalid_argument",
        ),
        (
            &[("new_password_stdin", "false")],
            2,
            "user.invalid_argument",
        ),
        (
            &[("new_password_env", "RESH_UT_SURELY_UNSET_VAR")],
            2,
            "user.invalid_argument",
        ),
        (
            &[("new_password_hash", "not-a-hash")],
            2,
            "user.hash_params_invalid",
        ),
        (
            &[("new_password_hash", "$6$salt$short")],
            2,
            "user.hash_params_invalid",
        ),
        (
            &[("new_password_plain", "a"), ("hash_scheme", "md5")],
            2,
            "user.invalid_argument",
        ),
        (
            &[
                ("new_password_plain", &"x".repeat(73)),
                ("hash_scheme", "bcrypt"),
            ],
            2,
            "user.hash_params_invalid",
        ),
        (
            &[
                ("new_password_plain", "a"),
                ("require_old_password", "true"),
            ],
            2,
            "user.old_password_required",
        ),
        (
            &[("new_password_plain", "a"), ("old_password_plain", "b")],
            2,
            "user.invalid_argument",
        ),
        (
            &[
                ("new_password_plain", "a"),
                ("require_old_password", "true"),
                ("old_password_plain", "b"),
                ("old_password_env", "X"),
            ],
            2,
            "user.invalid_argument",
        ),
    ];
    for (pairs, code, err) in cases {
        mock_call(&m, "alice", "passwd", pairs).fails(*code, err);
    }
    let h = hash_password("x", &HashScheme::Bcrypt).unwrap();
    mock_call(
        &m,
        "alice",
        "passwd",
        &[("new_password_hash", &h), ("hash_scheme", "sha512_crypt")],
    )
    .fails(2, "user.invalid_argument");
    mock_call_stdin(
        &m,
        "alice",
        "passwd",
        &[("new_password_stdin", "true")],
        "\n",
    )
    .fails(2, "user.invalid_argument");
    // Missing user.
    let v = mock_call(&m, "bob", "passwd", &[("new_password_plain", "a")]).ok();
    assert_eq!(v["user"]["missing"], true);
    mock_call(
        &m,
        "bob",
        "passwd",
        &[("new_password_plain", "a"), ("ignore_if_missing", "false")],
    )
    .fails(1, "user.not_found");
    assert!(m.changes().is_empty(), "{:?}", m.changes());
    // argon2id is refused by the system backend, before any lookup.
    let (o, cmds) = system_call(
        NOBODY_HERE,
        "passwd",
        &[("new_password_plain", "a"), ("hash_scheme", "argon2id")],
    );
    o.fails(2, "user.hash_scheme_unsupported");
    assert!(cmds.is_empty());
}

#[test]
fn passwd_checks_the_old_password() {
    let old = hash_password("old pw", &HashScheme::Sha512Crypt).unwrap();
    let m = world().with_password("alice", &old);
    let v = mock_call(
        &m,
        "alice",
        "passwd",
        &[
            ("new_password_plain", "new pw"),
            ("require_old_password", "true"),
            ("old_password_plain", "old pw"),
        ],
    )
    .ok();
    assert_eq!(v["password"]["old_password_verified"], true);
    mock_call(
        &m,
        "alice",
        "passwd",
        &[
            ("new_password_plain", "newer"),
            ("require_old_password", "true"),
            ("old_password_plain", "old pw"),
        ],
    )
    .fails(1, "user.old_password_mismatch");
    // yescrypt (made by Debian 13's chpasswd) is checked by the system
    // crypt library when it can be loaded.
    let yes = "$y$j9T$Cm8IvKsdOzfFgiL1k1zm1.$o2GHHTASPFxp1KnD1/T7uGKDwxhpLA.O4VEsoDrvSs7";
    let old = |m: &MockBackend, pw: &str| {
        mock_call(
            m,
            "alice",
            "passwd",
            &[
                ("new_password_plain", "n"),
                ("require_old_password", "true"),
                ("old_password_plain", pw),
            ],
        )
    };
    if libcrypt::available() {
        old(&world().with_password("alice", yes), "Hello yescrypt").ok();
        old(&world().with_password("alice", yes), "wrong").fails(1, "user.old_password_mismatch");
    } else {
        old(&world().with_password("alice", yes), "Hello yescrypt")
            .fails(1, "user.old_password_verification_unsupported");
    }
    // A scheme neither the library nor resh knows.
    old(&world().with_password("alice", "$zz$abc$def"), "o")
        .fails(1, "user.old_password_verification_unsupported");
    // The system backend reads /etc/shadow, which unit tests cannot (or
    // must not rely on reading).
    let (o, _) = system_call(
        "root",
        "passwd",
        &[
            ("new_password_plain", "n"),
            ("require_old_password", "true"),
            ("old_password_plain", "o"),
            ("dry_run", "true"),
            ("force", "true"),
        ],
    );
    assert!(!o.status.ok);
}

#[test]
fn passwd_dry_run_plans_a_redacted_chpasswd() {
    let (o, cmds) = system_call(
        "root",
        "passwd",
        &[
            ("new_password_plain", "S3cr3t"),
            ("dry_run", "true"),
            ("force", "true"),
        ],
    );
    let v = o.ok();
    assert!(o.stderr.contains("new_password_plain"), "{}", o.stderr);
    assert!(!o.stderr.contains("S3cr3t"));
    assert_eq!(v["planned_commands"][0], "chpasswd -e <<< (redacted)");
    assert_eq!(v["password"]["scheme"], "sha512_crypt");
    assert_eq!(v["password"]["changed"], false);
    assert!(!o.stdout.contains("S3cr3t"));
    assert!(cmds.is_empty());
    let (o, cmds) = system_call(
        "root",
        "passwd",
        &[("new_password_plain", "S3cr3t"), ("force", "true")],
    );
    o.ok();
    assert_eq!(cmds[0].argv, ["chpasswd", "-e"]);
    let line = cmds[0].stdin.clone().unwrap();
    let hash = line.trim_end().strip_prefix("root:").unwrap();
    assert!(verify_password_hash("S3cr3t", hash).unwrap());
}

// ---------------------------------------------------------------------------
// lock / unlock
// ---------------------------------------------------------------------------

#[test]
fn lock_and_unlock_change_and_check_the_state() {
    let pw = hash_password("pw", &HashScheme::Sha512Crypt).unwrap();
    let m = world().with_password("alice", &pw);
    let v = mock_call(&m, "alice", "lock", &[]).ok();
    assert_eq!(v["lock"]["was_locked"], false);
    assert_eq!(v["lock"]["is_locked"], true);
    assert_eq!(v["lock"]["changed"], true);
    let v = mock_call(&m, "alice", "lock", &[]).ok();
    assert_eq!(v["lock"]["changed"], false);
    assert!(
        v["warnings"][0]
            .as_str()
            .unwrap()
            .contains("already locked")
    );
    let v = mock_call(&m, "alice", "unlock", &[("dry_run", "true")]).ok();
    assert_eq!(v["unlock"]["is_locked"], true);
    assert!(m.is_locked("alice").unwrap());
    let v = mock_call(&m, "alice", "unlock", &[]).ok();
    assert_eq!(v["unlock"]["changed"], true);
    assert_eq!(v["unlock"]["is_locked"], false);
    assert_eq!(m.password_field("alice").unwrap().unwrap(), pw);
    let v = mock_call(&m, "alice", "unlock", &[]).ok();
    assert_eq!(v["unlock"]["changed"], false);
}

#[test]
fn lock_and_unlock_errors() {
    let m = world();
    for verb in ["lock", "unlock"] {
        let v = mock_call(&m, "daemon", verb, &[]).fails(1, "user.system_user_protected");
        assert_eq!(v["error"]["details"][format!("min_uid_for_{verb}")], 1000);
        mock_call(&m, "bob", verb, &[("ignore_if_missing", "false")]).fails(1, "user.not_found");
        let v = mock_call(&m, "bob", verb, &[]).ok();
        assert_eq!(v["user"]["missing"], true);
        let key = format!("min_uid_for_{verb}");
        mock_call(&m, "alice", verb, &[(key.as_str(), "5000")])
            .fails(1, "user.system_user_protected");
    }
    // A new account has no password: unlocking it would leave it without one.
    mock_call(&m, "alice", "unlock", &[]).fails(1, "user.unlock_backend_failure");
    let v = mock_call(&m, "daemon", "lock", &[("force", "true")]).ok();
    assert!(v["warnings"][0].as_str().unwrap().contains("force=true"));
    // The system backend: root is protected, even in a dry run.
    let (o, cmds) = system_call("root", "lock", &[("dry_run", "true")]);
    o.fails(1, "user.system_user_protected");
    assert!(cmds.is_empty());
    // Without a readable shadow file a dry run reports an unknown state.
    let (o, _) = system_call("root", "lock", &[("dry_run", "true"), ("force", "true")]);
    let v = o.ok();
    if v["lock"]["was_locked"].is_null() {
        assert!(v["warnings"].to_string().contains("Could not determine"));
    }
}

#[test]
fn text_format_renders_every_verb() {
    let pw = hash_password("pw", &HashScheme::Sha512Crypt).unwrap();
    let m = world().with_password("alice", &pw);
    for (target, verb, extra) in [
        ("alice", "exists", vec![]),
        ("alice", "groups", vec![]),
        ("bob", "add", vec![("dry_run", "true")]),
        ("alice", "delete", vec![("dry_run", "true")]),
        (
            "alice",
            "passwd",
            vec![("new_password_plain", "x"), ("dry_run", "true")],
        ),
        ("alice", "lock", vec![("dry_run", "true")]),
        ("alice", "unlock", vec![("dry_run", "true")]),
    ] {
        let mut pairs = extra.clone();
        pairs.push(("format", "text"));
        let o = mock_call(&m, target, verb, &pairs);
        assert!(o.status.ok, "{verb}: {:?}", o.status);
        assert!(serde_json::from_str::<Value>(&o.stdout).is_err(), "{verb}");
        assert!(!o.stdout.is_empty());
    }
    // A failure in text format prints nothing on stdout.
    let o = mock_call(&m, "daemon", "delete", &[("format", "text")]);
    o.fails(1, "user.system_user_protected");
    assert!(o.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[test]
fn shadow_utils_commands_put_operands_after_a_separator() {
    let info = UserInfo {
        username: "alice".into(),
        uid: 1001,
        primary_group: "alice".into(),
        supplementary_groups: vec!["dev".into(), "ops".into()],
        home: Some("/home/alice".into()),
        shell: Some("/bin/bash".into()),
        gecos: None,
        created: false,
        existed: false,
    };
    let argv = |op: BackendOp| system_commands(&op).unwrap()[0].argv.clone();
    assert_eq!(
        argv(BackendOp::CreateUser {
            info: &info,
            create_home: true
        }),
        [
            "useradd",
            "-u",
            "1001",
            "-g",
            "alice",
            "-G",
            "dev,ops",
            "-d",
            "/home/alice",
            "-m",
            "-s",
            "/bin/bash",
            "--",
            "alice"
        ]
    );
    let groups = vec!["dev".to_string()];
    assert_eq!(
        argv(BackendOp::AddMemberships {
            username: "alice",
            groups: &groups
        }),
        ["usermod", "-a", "-G", "dev", "--", "alice"]
    );
    assert_eq!(
        argv(BackendOp::DeleteUser {
            username: "alice",
            remove_home: true,
            remove_mail: false
        }),
        ["userdel", "-r", "--", "alice"]
    );
    assert_eq!(
        argv(BackendOp::DeleteGroup("dev")),
        ["groupdel", "--", "dev"]
    );
    assert_eq!(
        argv(BackendOp::RemoveMembership {
            username: "alice",
            group: "dev"
        }),
        ["gpasswd", "-d", "alice", "--", "dev"]
    );
    assert_eq!(
        argv(BackendOp::Lock("alice")),
        ["usermod", "-L", "--", "alice"]
    );
    assert_eq!(
        argv(BackendOp::Unlock("alice")),
        ["usermod", "-U", "--", "alice"]
    );
    assert!(
        system_commands(&BackendOp::SetPasswordHash {
            username: "alice",
            hash: "plain"
        })
        .is_err()
    );
}

#[test]
fn shadow_and_passwd_status_parsing() {
    let shadow = "root:*:19000:0:99999:7:::\nalice:!$6$x$y:19000::::::\nbob:$6$a$b:1::::::\n";
    assert_eq!(shadow_password_field(shadow, "alice").unwrap(), "!$6$x$y");
    assert!(shadow_field_is_locked("!$6$x$y"));
    assert!(shadow_field_is_locked("*"));
    assert!(!shadow_field_is_locked("$6$a$b"));
    assert_eq!(shadow_password_field(shadow, "carol"), None);
    assert_eq!(
        parse_passwd_status("alice L 11/07/2026 0 99999 7 -1\n", "alice"),
        Some(true)
    );
    assert_eq!(
        parse_passwd_status(
            "alice LK 2026-11-07 0 99999 7 -1 (Password locked.)",
            "alice"
        ),
        Some(true)
    );
    assert_eq!(
        parse_passwd_status("alice P 11/07/2026", "alice"),
        Some(false)
    );
    assert_eq!(
        parse_passwd_status("alice NP 11/07/2026", "alice"),
        Some(false)
    );
    assert_eq!(parse_passwd_status("alice ?? x", "alice"), None);
    assert_eq!(parse_passwd_status("bob P x", "alice"), None);
}

#[test]
fn system_is_locked_reads_a_shadow_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shadow");
    std::fs::write(&path, "root:!$6$x$y:1::::::\n").unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let b = SystemBackend::recording(log).with_shadow_path(&path);
    assert!(b.is_locked("root").unwrap());
    assert_eq!(b.password_field("root").unwrap().unwrap(), "!$6$x$y");
    let b = SystemBackend::recording(Arc::new(Mutex::new(Vec::new())))
        .with_shadow_path(dir.path().join("missing"));
    assert!(b.is_locked("root").is_err());
}

#[test]
fn hash_formats_are_recognized() {
    let sha = hash_password("pw", &HashScheme::Sha512Crypt).unwrap();
    let bc = hash_password("pw", &HashScheme::Bcrypt).unwrap();
    let ar = hash_password("pw", &HashScheme::Argon2id).unwrap();
    assert_eq!(hash_scheme_of(&sha), Some("sha512_crypt"));
    assert_eq!(hash_scheme_of(&bc), Some("bcrypt"));
    assert_eq!(hash_scheme_of(&ar), Some("argon2id"));
    assert_eq!(
        hash_scheme_of("$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        Some("sha256_crypt")
    );
    assert_eq!(
        hash_scheme_of("$y$j9T$abcdefgh$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
        Some("yescrypt")
    );
    for bad in ["", "x", "$1$a$b", "$6$x:y$z", "$2b$12$short", "$y$a$b"] {
        assert_eq!(hash_scheme_of(bad), None, "{bad}");
    }
    // A lock prefix is ignored when checking; no password never matches.
    assert!(verify_password_hash("pw", &format!("!{sha}")).unwrap());
    assert!(!verify_password_hash("pw", "!").unwrap());
    assert!(!verify_password_hash("pw", "*").unwrap());
    assert!(verify_password_hash("pw", "$zz$abc$def").is_err());
    if libcrypt::available() {
        let yes = "$y$j9T$Cm8IvKsdOzfFgiL1k1zm1.$o2GHHTASPFxp1KnD1/T7uGKDwxhpLA.O4VEsoDrvSs7";
        assert!(verify_password_hash("Hello yescrypt", yes).unwrap());
        assert!(!verify_password_hash("Hello yescrypX", yes).unwrap());
        assert!(verify_password_hash("Hello yescrypt", &format!("!{yes}")).unwrap());
        assert_eq!(libcrypt::crypt("pw", "$zz$x"), None);
    }
}

#[test]
fn tools_run_under_a_deadline_with_stdin() {
    use std::time::{Duration, Instant};
    let soon = || Instant::now() + Duration::from_secs(20);
    let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let r = exec::run(&argv(&["cat"]), Some("secret line\n"), soon()).unwrap();
    assert_eq!(r.stdout, "secret line\n");
    match exec::run(&argv(&["false"]), None, soon()) {
        Err(exec::RunError::Failed { code, .. }) => assert_eq!(code, Some(1)),
        _ => panic!("false must fail"),
    }
    assert!(matches!(
        exec::run(&argv(&["resh-ut-no-such-tool"]), None, soon()),
        Err(exec::RunError::NotFound(_))
    ));
    let start = Instant::now();
    let r = exec::run(
        &argv(&["sleep", "30"]),
        None,
        Instant::now() + Duration::from_millis(200),
    );
    assert!(matches!(r, Err(exec::RunError::Timeout(_))));
    assert!(start.elapsed() < Duration::from_secs(10));
    crate::core::process::take_lost();
    assert!(matches!(
        exec::run(&argv(&["true"]), None, Instant::now()),
        Err(exec::RunError::Timeout(_))
    ));
}

#[test]
fn passwd_protects_system_accounts_and_warns_about_plain_passwords() {
    let m = world();
    let o = mock_call(&m, "daemon", "passwd", &[("new_password_env", "PATH")]);
    let v = o.fails(2, "user.protected_account");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("force=true")
    );
    assert!(o.stderr.is_empty(), "no warning without new_password_plain");
    mock_call(
        &m,
        "daemon",
        "passwd",
        &[("new_password_env", "PATH"), ("dry_run", "true")],
    )
    .fails(2, "user.protected_account");
    assert!(m.changes().is_empty());
    let v = mock_call(
        &m,
        "daemon",
        "passwd",
        &[("new_password_env", "PATH"), ("force", "true")],
    )
    .ok();
    assert!(v["warnings"][0].as_str().unwrap().contains("force=true"));
    mock_call(
        &m,
        "alice",
        "passwd",
        &[("new_password_env", "PATH"), ("force", "maybe")],
    )
    .fails(2, "user.invalid_argument");
    // Every use of new_password_plain warns, also when the call fails, and
    // the error line follows the warning.
    let o = mock_call(&m, "alice", "passwd", &[("new_password_plain", "Secret9")]);
    o.ok();
    assert!(
        o.stderr.starts_with("Warning: new_password_plain="),
        "{}",
        o.stderr
    );
    assert!(!o.stderr.contains("Secret9"));
    let o = mock_call(&m, "daemon", "passwd", &[("new_password_plain", "Secret9")]);
    o.fails(2, "user.protected_account");
    assert!(
        o.stderr.contains("Warning: new_password_plain="),
        "{}",
        o.stderr
    );
    assert!(
        o.stderr.contains("Error: [user.protected_account] "),
        "{}",
        o.stderr
    );
    let (o, _) = system_call(
        "root",
        "passwd",
        &[("new_password_plain", "x"), ("dry_run", "true")],
    );
    o.fails(2, "user.protected_account");
}
