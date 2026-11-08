use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};

#[path = "mail_secrets.rs"]
mod mail_secrets;

use lettre::{
    Message, SmtpTransport, Transport,
    message::Mailbox,
    transport::smtp::{authentication::Credentials, client::Tls},
};

/// Metadata for `resh mail --help` and `resh mail <verb> --help`.
static MAIL_HELP: HandleHelp = HandleHelp {
    description: "The mail handle sends email over SMTP with the lettre library, renders \
        built-in message templates, checks SMTP settings with a real session, and keeps \
        named SMTP profiles in ~/.config/resh/mail/smtp_profiles.json. The verb is the \
        first path segment of the URL, such as mail://send, and its arguments follow as \
        key=value words. SMTP settings come from arguments, then from the MAIL_SMTP_HOST, \
        MAIL_SMTP_PORT, MAIL_SMTP_USERNAME, MAIL_SMTP_PASSWORD, and MAIL_FROM environment \
        variables when MAIL_SMTP_HOST is set, and otherwise from the active stored profile.",
    usage: "resh mail://<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "test",
            definition: "Checks SMTP settings by opening a real session (TLS and AUTH as \
                configured) and closing it, and also sends a test message when \
                send_test_email=true.",
            detail: Some(VerbDetail {
                usage: "resh mail://test [smtp_host=<host>] [smtp_port=<n>]\n  \
                    [use_tls=none|starttls|tls] [smtp_username=<user>] [smtp_password=<pass>]\n  \
                    [tls_accept_invalid_certs=true|false] [ca_file=<pem>]\n  \
                    [connection_only=true|false] [send_test_email=true|false]\n  \
                    [to=<addr,...>] [from=<addr>]\n  \
                    [subject=<text>] [text_body=<text>] [html_body=<html>]\n  \
                    [timeout_ms=<ms>] [max_retry=<n>] [retry_backoff_ms=<ms>]\n  \
                    [format_output=json|text]",
                example: "resh mail://test connection_only=true",
                example_output: Some(
                    r#"{
  "connection": {
    "attempts": 1,
    "auth_attempted": true,
    "auth_succeeded": true,
    "last_response": "Connection test completed",
    "resolved_ip": "192.0.2.25",
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "tls_established": true,
    "use_tls": "starttls"
  },
  "error": null,
  "ok": true,
  "query": {
    "connection_only": true,
    "from": null,
    "max_retry": 0,
    "send_test_email": false,
    "smtp_host": null,
    "smtp_port": null,
    "subject": "SMTP test",
    "timeout_ms": 10000,
    "to": [],
    "use_tls": "starttls"
  },
  "send_test_email": null,
  "timestamp_unix_ms": 1792141964512,
  "warnings": [
    "Using stored SMTP profile 'work'."
  ]
}

Shown with an active stored profile 'work'. The session connects, upgrades
with STARTTLS and logs in, then closes. mail prints sorted, indented JSON
without --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "config",
            definition: "Manages named SMTP profiles in a local JSON file, with action choosing \
                list, get, set, delete, activate, or get_active.",
            detail: Some(VerbDetail {
                usage: "resh mail://config action=list|get|set|delete|activate|get_active\n  \
                    [profile=<name>] [smtp_host=<host>] [smtp_port=<n>]\n  \
                    [use_tls=none|starttls|tls] [smtp_username=<user>] [smtp_password=<pass>]\n  \
                    [from=<addr>] [reply_to=<addr>] [description=<text>]\n  \
                    [is_default=true|false] [tls_accept_invalid_certs=true|false]\n  \
                    [format_output=json|text]",
                example: "resh mail://config action=list",
                example_output: Some(
                    r#"{
  "active_profile": "work",
  "error": null,
  "ok": true,
  "profiles": [
    {
      "description": "Office relay",
      "from": "alice@example.com",
      "has_password": true,
      "is_active": true,
      "name": "work",
      "reply_to": null,
      "smtp_host": "smtp.example.com",
      "smtp_port": 587,
      "tls_accept_invalid_certs": false,
      "use_tls": "starttls"
    }
  ],
  "query": {
    "action": "list"
  },
  "timestamp_unix_ms": 1792141964512,
  "warnings": []
}

profile is required for get, set, delete, and activate. mail prints sorted,
indented JSON without --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "send",
            definition: "Sends an email over SMTP and reports the server, attempt count, and \
                message ID as JSON.",
            detail: Some(VerbDetail {
                usage: "resh mail://send to=<addr,...> subject=<text> text_body=<text>\n  \
                    [html_body=<html>] [cc=<addr,...>] [bcc=<addr,...>] [from=<addr>]\n  \
                    [reply_to=<addr>] [attachments=<json-array>]\n  \
                    [header_<Name>=<value> ...] [smtp_host=<host>] [smtp_port=<n>]\n  \
                    [use_tls=none|starttls|tls] [smtp_username=<user>] [smtp_password=<pass>]\n  \
                    [tls_accept_invalid_certs=true|false] [ca_file=<pem>] [timeout_ms=<ms>]\n  \
                    [max_retry=<n>] [retry_backoff_ms=<ms>] [format_output=json|text]",
                example: "resh mail://send to=alice@example.com subject=Backup \
                    'text_body=Backup done'",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "bcc": [],
    "cc": [],
    "from": null,
    "max_retry": 0,
    "subject": "Backup",
    "timeout_ms": 10000,
    "to": [
      "alice@example.com"
    ],
    "use_tls": "starttls"
  },
  "result": {
    "attempts": 1,
    "last_response": "Response { code: Code { .. }, message: [\"Ok\"] }",
    "message_id": "<0f9c2c1e-6a1d-4f55-9a43-2b1e7a5f3c11@buildhost>",
    "smtp_host": "smtp.example.com",
    "smtp_port": 587
  },
  "timestamp_unix_ms": 1792141964512,
  "warnings": []
}

Shown with MAIL_SMTP_HOST and MAIL_FROM set in the environment, which
query.from does not reflect. last_response is the SMTP reply in Rust debug
form, shortened here. mail prints sorted, indented JSON itself."#,
                ),
            }),
        },
        VerbHelp {
            name: "send_template",
            definition: "Renders a built-in template (welcome or password_reset) with vars and \
                sends it the same way as send, or only previews it when dry_run=true.",
            detail: Some(VerbDetail {
                usage: "resh mail://send_template template=welcome|password_reset\n  \
                    to=<addr,...> [vars=<json-object>] [locale=<code>]\n  \
                    [strict_vars=true|false] [dry_run=true|false] [cc=<addr,...>]\n  \
                    [bcc=<addr,...>] [from=<addr>] [reply_to=<addr>]\n  \
                    [attachments=<json-array>] [headers=<json-object>]\n  \
                    [smtp_host=<host>] [smtp_port=<n>] [use_tls=none|starttls|tls]\n  \
                    [smtp_username=<user>] [smtp_password=<pass>]\n  \
                    [tls_accept_invalid_certs=true|false] [ca_file=<pem>] [timeout_ms=<ms>]\n  \
                    [max_retry=<n>] [retry_backoff_ms=<ms>] [format_output=json|text]",
                example: "resh mail://send_template template=welcome to=bob@example.com \
                    dry_run=true",
                example_output: Some(
                    r#"{
  "error": null,
  "ok": true,
  "query": {
    "dry_run": true,
    "locale": null,
    "strict_vars": false,
    "template": "welcome",
    "to": [
      "bob@example.com"
    ]
  },
  "rendered": {
    "html_body": "<p>Hi <strong></strong>,</p><p>Welcome to .</p>",
    "subject": "Welcome to , !",
    "text_body": "Hi ,\n\nWelcome to .\n"
  },
  "send_result": null,
  "timestamp_unix_ms": 1792141964512,
  "warnings": [
    "Dry run: email was not sent."
  ]
}

Variables missing from vars render as empty strings unless strict_vars=true;
fill them with 'vars={"user_name":"Bob","app_name":"Acme"}'. mail prints
sorted, indented JSON without --json-pretty."#,
                ),
            }),
        },
    ],
};

// Error code constants
pub const MAIL_SEND_MISSING_RECIPIENTS: &str = "mail.send_missing_recipients";
pub const MAIL_SEND_MISSING_SUBJECT: &str = "mail.send_missing_subject";
pub const MAIL_SEND_MISSING_BODY: &str = "mail.send_missing_body";
pub const MAIL_SEND_INVALID_ADDRESS: &str = "mail.send_invalid_address";
pub const MAIL_SEND_HEADER_CONFLICT: &str = "mail.send_header_conflict";
pub const MAIL_SEND_INVALID_TIMEOUT: &str = "mail.send_invalid_timeout";
pub const MAIL_SEND_INVALID_RETRY_CONFIG: &str = "mail.send_invalid_retry_config";
pub const MAIL_SEND_ATTACHMENT_MISSING: &str = "mail.send_attachment_missing";
pub const MAIL_SEND_ATTACHMENT_IO_ERROR: &str = "mail.send_attachment_io_error";
pub const MAIL_SEND_ATTACHMENTS_TOO_LARGE: &str = "mail.send_attachments_too_large";
pub const MAIL_SEND_SMTP_NOT_CONFIGURED: &str = "mail.send_smtp_not_configured";
pub const MAIL_SEND_SMTP_CONNECTION_FAILED: &str = "mail.send_smtp_connection_failed";
pub const MAIL_SEND_SMTP_TLS_ERROR: &str = "mail.send_smtp_tls_error";
pub const MAIL_SEND_SMTP_AUTH_FAILED: &str = "mail.send_smtp_auth_failed";
pub const MAIL_SEND_SMTP_REJECTED: &str = "mail.send_smtp_rejected";
pub const MAIL_SEND_SMTP_TRANSIENT_FAILED: &str = "mail.send_smtp_transient_failed";
pub const MAIL_SEND_INTERNAL_ERROR: &str = "mail.send_internal_error";

// Template-related error codes
pub const MAIL_SEND_TEMPLATE_NOT_FOUND: &str = "mail.send_template_not_found";
pub const MAIL_SEND_TEMPLATE_MISSING_VAR: &str = "mail.send_template_missing_var";
pub const MAIL_SEND_TEMPLATE_HEADER_CONFLICT: &str = "mail.send_template_header_conflict";

// Test-related error codes
pub const MAIL_TEST_INVALID_TIMEOUT: &str = "mail.test_invalid_timeout";
pub const MAIL_TEST_INVALID_RETRY_CONFIG: &str = "mail.test_invalid_retry_config";
pub const MAIL_TEST_MISSING_SMTP_HOST: &str = "mail.test_missing_smtp_host";
pub const MAIL_TEST_SEND_EMAIL_MISSING_RECIPIENTS: &str = "mail.test_send_email_missing_recipients";
pub const MAIL_TEST_SEND_EMAIL_MISSING_FROM: &str = "mail.test_send_email_missing_from";
pub const MAIL_TEST_INVALID_ADDRESS: &str = "mail.test_invalid_address";
pub const MAIL_TEST_DNS_ERROR: &str = "mail.test_dns_error";
pub const MAIL_TEST_CONNECTION_FAILED: &str = "mail.test_connection_failed";
pub const MAIL_TEST_TLS_ERROR: &str = "mail.test_tls_error";
pub const MAIL_TEST_AUTH_FAILED: &str = "mail.test_auth_failed";
pub const MAIL_TEST_SEND_REJECTED: &str = "mail.test_send_rejected";
pub const MAIL_TEST_TRANSIENT_FAILED: &str = "mail.test_transient_failed";
pub const MAIL_TEST_SMTP_NOT_CONFIGURED: &str = "mail.test_smtp_not_configured";
pub const MAIL_TEST_INTERNAL_ERROR: &str = "mail.test_internal_error";

// Config-related error codes
pub const MAIL_CONFIG_INVALID_ACTION: &str = "mail.config_invalid_action";
pub const MAIL_CONFIG_PROFILE_REQUIRED: &str = "mail.config_profile_required";
pub const MAIL_CONFIG_INVALID_PROFILE_NAME: &str = "mail.config_invalid_profile_name";
pub const MAIL_CONFIG_INVALID_SMTP_HOST: &str = "mail.config_invalid_smtp_host";
pub const MAIL_CONFIG_INVALID_SMTP_PORT: &str = "mail.config_invalid_smtp_port";
pub const MAIL_CONFIG_INVALID_TLS_MODE: &str = "mail.config_invalid_tls_mode";
pub const MAIL_CONFIG_INVALID_FLAG: &str = "mail.config_invalid_flag";
pub const MAIL_CONFIG_PROFILE_NOT_FOUND: &str = "mail.config_profile_not_found";
pub const MAIL_CONFIG_NO_ACTIVE_PROFILE: &str = "mail.config_no_active_profile";
pub const MAIL_CONFIG_ACTIVE_PROFILE_INCONSISTENT: &str = "mail.config_active_profile_inconsistent";
pub const MAIL_CONFIG_STORE_READ_ERROR: &str = "mail.config_store_read_error";
pub const MAIL_CONFIG_STORE_WRITE_ERROR: &str = "mail.config_store_write_error";
pub const MAIL_CONFIG_STORE_PARSE_ERROR: &str = "mail.config_store_parse_error";
pub const MAIL_CONFIG_INTERNAL_ERROR: &str = "mail.config_internal_error";
pub const MAIL_CONFIG_INVALID_ADDRESS: &str = "mail.config_invalid_address";
pub const MAIL_CONFIG_KEYRING_UNAVAILABLE: &str = "mail.config_keyring_unavailable";
pub const MAIL_SEND_KEYRING_ERROR: &str = "mail.send_keyring_error";
pub const MAIL_TEST_KEYRING_ERROR: &str = "mail.test_keyring_error";

// Codes added with the strict validation and real SMTP sessions.
pub const MAIL_SEND_MISSING_FROM: &str = "mail.send_missing_from";
pub const MAIL_SEND_INVALID_HEADER: &str = "mail.send_invalid_header";
pub const MAIL_SEND_TIMEOUT: &str = "mail.send_timeout";
pub const MAIL_TEST_TIMEOUT: &str = "mail.test_timeout";
/// A verb the handle does not have (exit 2).
pub const MAIL_UNKNOWN_VERB: &str = "mail.unknown_verb";
/// Arguments that are unknown, malformed or conflicting (exit 2).
pub const MAIL_INVALID_ARGUMENT: &str = "mail.invalid_argument";

/// Exit code for a timeout or an unknown outcome.
pub const EXIT_TIMEOUT: i32 = crate::core::status::exit::TIMEOUT;

/// SMTP settings accepted by send, send_template and test.
const SMTP_ARGS: [&str; 7] = [
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "use_tls",
    "tls_accept_invalid_certs",
    "ca_file",
];

/// Arguments `send` accepts, besides `header_<Name>` words. Help usage lists
/// exactly these, and anything else is refused (exit 2) before any work.
pub const SEND_ARGS: &[&str] = &[
    "to",
    "cc",
    "bcc",
    "subject",
    "text_body",
    "html_body",
    "from",
    "reply_to",
    "attachments",
    SMTP_ARGS[0],
    SMTP_ARGS[1],
    SMTP_ARGS[2],
    SMTP_ARGS[3],
    SMTP_ARGS[4],
    SMTP_ARGS[5],
    SMTP_ARGS[6],
    "timeout_ms",
    "max_retry",
    "retry_backoff_ms",
    "format_output",
];

/// Arguments `send_template` accepts.
pub const SEND_TEMPLATE_ARGS: &[&str] = &[
    "template",
    "to",
    "cc",
    "bcc",
    "from",
    "reply_to",
    "attachments",
    "vars",
    "locale",
    "strict_vars",
    "headers",
    "dry_run",
    SMTP_ARGS[0],
    SMTP_ARGS[1],
    SMTP_ARGS[2],
    SMTP_ARGS[3],
    SMTP_ARGS[4],
    SMTP_ARGS[5],
    SMTP_ARGS[6],
    "timeout_ms",
    "max_retry",
    "retry_backoff_ms",
    "format_output",
];

/// Arguments `test` accepts.
pub const TEST_ARGS: &[&str] = &[
    SMTP_ARGS[0],
    SMTP_ARGS[1],
    SMTP_ARGS[2],
    SMTP_ARGS[3],
    SMTP_ARGS[4],
    SMTP_ARGS[5],
    SMTP_ARGS[6],
    "connection_only",
    "send_test_email",
    "to",
    "from",
    "subject",
    "text_body",
    "html_body",
    "timeout_ms",
    "max_retry",
    "retry_backoff_ms",
    "format_output",
];

/// Arguments `config` accepts (which ones apply depends on `action`).
pub const CONFIG_ARGS: &[&str] = &[
    "action",
    "profile",
    "smtp_host",
    "smtp_port",
    "use_tls",
    "smtp_username",
    "smtp_password",
    "from",
    "reply_to",
    "description",
    "is_default",
    "tls_accept_invalid_certs",
    "format_output",
];

/// `config` arguments that only `action=set` uses.
const CONFIG_SET_ONLY_ARGS: &[&str] = &[
    "smtp_host",
    "smtp_port",
    "use_tls",
    "smtp_username",
    "smtp_password",
    "from",
    "reply_to",
    "description",
    "is_default",
    "tls_accept_invalid_certs",
];

/// Most retries `max_retry` may ask for (send, send_template and test).
const MAX_RETRY_LIMIT: u32 = 10;

/// Arguments accepted by `verb`, or `None` for an unknown verb.
pub fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    match verb {
        "send" => Some(SEND_ARGS),
        "send_template" => Some(SEND_TEMPLATE_ARGS),
        "test" => Some(TEST_ARGS),
        "config" => Some(CONFIG_ARGS),
        _ => None,
    }
}

/// Refuses an argument `verb` does not take. Returns the message for exit 2.
/// `dry_run=false` is accepted everywhere (the dispatcher refuses a true
/// value for verbs without a dry-run mode, and `send` refuses it itself).
fn unknown_arg(verb: &str, args: &Args) -> Option<String> {
    let allowed = verb_args(verb)?;
    // Verbs without a dry-run mode never treat dry_run=true as a request
    // they can ignore (the dispatcher refuses it too).
    if verb != "send_template" && args.contains_key("dry_run") {
        match crate::core::lenient::dry_run(args) {
            Ok(false) => {}
            Ok(true) => {
                return Some(format!(
                    "mail {verb} does not support dry_run; nothing was done"
                ));
            }
            Err(e) => return Some(e.to_string()),
        }
    }
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let bad = keys.into_iter().find(|k| {
        let k = k.as_str();
        k != "dry_run" && !allowed.contains(&k) && !(verb == "send" && k.starts_with("header_"))
    })?;
    if bad == "timeout_ms" {
        return Some(format!(
            "timeout_ms is not accepted: mail {verb} only reads and writes a local file"
        ));
    }
    Some(format!(
        "unknown argument: {bad}{}",
        did_you_mean(bad, allowed)
    ))
}

/// The accepted argument closest to `bad` (edit distance at most 2, or a
/// case-only difference), for a "did you mean" hint.
fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// " (did you mean `x`?)" when `bad` looks like a typo of an accepted name.
fn did_you_mean(bad: &str, allowed: &[&str]) -> String {
    suggest(bad, allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default()
}

/// The exit code for an error code: 2 when the arguments were invalid and
/// nothing was done, 124 for a timeout (the outcome may be unknown), and 1
/// for every other failure.
pub fn exit_code_for(code: &str) -> i32 {
    const USAGE: &[&str] = &[
        MAIL_UNKNOWN_VERB,
        MAIL_INVALID_ARGUMENT,
        MAIL_SEND_MISSING_RECIPIENTS,
        MAIL_SEND_MISSING_SUBJECT,
        MAIL_SEND_MISSING_BODY,
        MAIL_SEND_MISSING_FROM,
        MAIL_SEND_INVALID_ADDRESS,
        MAIL_SEND_HEADER_CONFLICT,
        MAIL_SEND_INVALID_HEADER,
        MAIL_SEND_INVALID_TIMEOUT,
        MAIL_SEND_INVALID_RETRY_CONFIG,
        MAIL_SEND_SMTP_NOT_CONFIGURED,
        MAIL_SEND_TEMPLATE_MISSING_VAR,
        MAIL_SEND_TEMPLATE_HEADER_CONFLICT,
        MAIL_TEST_INVALID_TIMEOUT,
        MAIL_TEST_INVALID_RETRY_CONFIG,
        MAIL_TEST_MISSING_SMTP_HOST,
        MAIL_TEST_SEND_EMAIL_MISSING_RECIPIENTS,
        MAIL_TEST_SEND_EMAIL_MISSING_FROM,
        MAIL_TEST_INVALID_ADDRESS,
        MAIL_TEST_SMTP_NOT_CONFIGURED,
        MAIL_CONFIG_INVALID_ACTION,
        MAIL_CONFIG_PROFILE_REQUIRED,
        MAIL_CONFIG_INVALID_PROFILE_NAME,
        MAIL_CONFIG_INVALID_SMTP_HOST,
        MAIL_CONFIG_INVALID_SMTP_PORT,
        MAIL_CONFIG_INVALID_TLS_MODE,
        MAIL_CONFIG_INVALID_FLAG,
        MAIL_CONFIG_INVALID_ADDRESS,
    ];
    use crate::core::status::exit;
    if USAGE.contains(&code) {
        exit::USAGE
    } else if code == MAIL_SEND_TIMEOUT || code == MAIL_TEST_TIMEOUT {
        exit::TIMEOUT
    } else {
        exit::FAILED
    }
}

/// Checks an SMTP host name or IP address: not empty, no whitespace or
/// control characters, does not start with `-`, and only characters that
/// can appear in a host name or address literal.
fn check_smtp_host(host: &str) -> std::result::Result<(), String> {
    if host.is_empty() {
        return Err("smtp_host is empty".to_string());
    }
    if host.starts_with('-') {
        return Err(format!("smtp_host {host:?} starts with '-'"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
    {
        return Err(format!(
            "smtp_host {host:?} is not a host name or IP address"
        ));
    }
    Ok(())
}

/// Parses an SMTP port: an integer from 1 to 65535.
fn parse_port(name: &str, value: &str) -> std::result::Result<u16, String> {
    match value.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!(
            "invalid {name}: {value:?} (expected a port from 1 to 65535)"
        )),
    }
}

#[derive(Clone, Debug)]
pub enum TlsMode {
    None,
    StartTls,
    Tls,
}

impl TlsMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" => Ok(TlsMode::None),
            "starttls" => Ok(TlsMode::StartTls),
            "tls" => Ok(TlsMode::Tls),
            _ => bail!("Invalid TLS mode '{}'. Supported: none, starttls, tls", s),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TlsMode::None => "none",
            TlsMode::StartTls => "starttls",
            TlsMode::Tls => "tls",
        }
    }
}

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "text" => Ok(OutputFormat::Text),
            _ => bail!("Invalid output format '{}'. Supported: json, text", s),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MailConfigAction {
    List,
    Get,
    Set,
    Delete,
    Activate,
    GetActive,
}

impl MailConfigAction {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "list" => Ok(MailConfigAction::List),
            "get" => Ok(MailConfigAction::Get),
            "set" => Ok(MailConfigAction::Set),
            "delete" => Ok(MailConfigAction::Delete),
            "activate" => Ok(MailConfigAction::Activate),
            "get_active" => Ok(MailConfigAction::GetActive),
            _ => bail!(
                "Invalid config action '{}'. Supported: list, get, set, delete, activate, get_active",
                s
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MailConfigAction::List => "list",
            MailConfigAction::Get => "get",
            MailConfigAction::Set => "set",
            MailConfigAction::Delete => "delete",
            MailConfigAction::Activate => "activate",
            MailConfigAction::GetActive => "get_active",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtpProfile {
    pub name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    /// Where the password is kept: `keyring:<service>/<profile>` in the OS
    /// keyring. The password itself is never written to the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp_password_ref: Option<String>,
    /// Legacy (before the keyring): the password base64-encoded. Still read,
    /// with a warning, and moved to the keyring on the next write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp_password_encrypted: Option<String>,
    pub use_tls: String, // "none" | "starttls" | "tls"
    pub tls_accept_invalid_certs: bool,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub description: Option<String>,
    pub is_active: bool,
}

#[derive(Clone, Debug)]
pub struct SmtpProfileView {
    pub name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub use_tls: String,
    pub tls_accept_invalid_certs: bool,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub description: Option<String>,
    pub is_active: bool,
    pub has_password: bool,
}

impl SmtpProfile {
    pub fn to_view(&self) -> SmtpProfileView {
        SmtpProfileView {
            name: self.name.clone(),
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            use_tls: self.use_tls.clone(),
            tls_accept_invalid_certs: self.tls_accept_invalid_certs,
            from: self.from.clone(),
            reply_to: self.reply_to.clone(),
            description: self.description.clone(),
            is_active: self.is_active,
            has_password: self.smtp_password_ref.is_some()
                || self.smtp_password_encrypted.is_some(),
        }
    }

    /// The legacy base64 password, decoded.
    pub fn decrypt_password(&self) -> Option<String> {
        self.smtp_password_encrypted.as_ref().and_then(|enc| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(enc.as_bytes())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
    }
}

#[derive(Clone, Debug)]
pub struct MailConfigOptions {
    pub action: MailConfigAction,
    pub profile: Option<String>,

    // SMTP configuration fields
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub use_tls: Option<String>,
    pub tls_accept_invalid_certs: Option<bool>,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub description: Option<String>,
    pub is_default: Option<bool>,

    pub format_output: OutputFormat,
}

impl MailConfigOptions {
    /// Reads and checks every argument. Any error here means the arguments
    /// are invalid (exit 2) and nothing was read or written.
    pub fn from_args(args: &Args) -> Result<Self> {
        let action_str = args.get("action").ok_or_else(|| {
            anyhow::anyhow!(
                "[{}] 'action' parameter is required",
                MAIL_CONFIG_INVALID_ACTION
            )
        })?;
        let action = MailConfigAction::from_str(action_str)
            .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_ACTION, e))?;

        let profile = args.get("profile").cloned();
        match action {
            MailConfigAction::Get
            | MailConfigAction::Set
            | MailConfigAction::Delete
            | MailConfigAction::Activate => match profile {
                None => bail!(
                    "[{}] 'profile' parameter is required for action '{}'",
                    MAIL_CONFIG_PROFILE_REQUIRED,
                    action.as_str()
                ),
                Some(ref name) => validate_profile_name(name)?,
            },
            MailConfigAction::List | MailConfigAction::GetActive => {
                if profile.is_some() {
                    bail!(
                        "[{}] action '{}' does not take 'profile'",
                        MAIL_CONFIG_INVALID_FLAG,
                        action.as_str()
                    );
                }
            }
        }

        // Profile fields only mean something to action=set.
        if action != MailConfigAction::Set {
            let mut extra: Vec<&str> = CONFIG_SET_ONLY_ARGS
                .iter()
                .copied()
                .filter(|k| args.contains_key(*k))
                .collect();
            extra.sort();
            if let Some(k) = extra.first() {
                bail!(
                    "[{}] '{}' is only used by action=set, not action={}",
                    MAIL_CONFIG_INVALID_FLAG,
                    k,
                    action.as_str()
                );
            }
        }

        let format_output = match args.get("format_output") {
            Some(f) => OutputFormat::from_str(f)
                .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_FLAG, e))?,
            None => OutputFormat::Json,
        };

        let smtp_host = match args.get("smtp_host") {
            Some(h) => {
                check_smtp_host(h)
                    .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_SMTP_HOST, e))?;
                Some(h.clone())
            }
            None => None,
        };

        let smtp_port = match args.get("smtp_port") {
            Some(p) => Some(
                parse_port("smtp_port", p)
                    .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_SMTP_PORT, e))?,
            ),
            None => None,
        };

        let use_tls = match args.get("use_tls") {
            Some(t) => Some(
                TlsMode::from_str(t)
                    .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_TLS_MODE, e))?
                    .as_str()
                    .to_string(),
            ),
            None => None,
        };

        let flag = |key: &str| -> Result<Option<bool>> {
            crate::core::lenient::bool_arg(args, key)
                .map_err(|e| anyhow::anyhow!("[{}] {}", MAIL_CONFIG_INVALID_FLAG, e))
        };
        let tls_accept_invalid_certs = flag("tls_accept_invalid_certs")?;
        let is_default = flag("is_default")?;

        let address = |key: &str| -> Result<Option<String>> {
            match args.get(key) {
                Some(v) => {
                    validate_email_address(v).map_err(|e| {
                        anyhow::anyhow!("[{}] {}: {}", MAIL_CONFIG_INVALID_ADDRESS, key, e)
                    })?;
                    Ok(Some(v.clone()))
                }
                None => Ok(None),
            }
        };
        let from = address("from")?;
        let reply_to = address("reply_to")?;

        Ok(MailConfigOptions {
            action,
            profile,
            smtp_host,
            smtp_port,
            smtp_username: args.get("smtp_username").cloned(),
            smtp_password: args.get("smtp_password").cloned(),
            use_tls,
            tls_accept_invalid_certs,
            from,
            reply_to,
            description: args.get("description").cloned(),
            is_default,
            format_output,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MailConfigResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub profiles: Option<Vec<SmtpProfileView>>,
    pub active_profile: Option<String>,
    pub profile: Option<SmtpProfileView>,
    pub deleted_profile: Option<String>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl MailConfigResponse {
    pub fn new(opts: &MailConfigOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let mut query_obj = json!({
            "action": opts.action.as_str()
        });

        if let Some(ref profile) = opts.profile {
            query_obj["profile"] = json!(profile);
        }

        // Add set-specific query fields
        if matches!(opts.action, MailConfigAction::Set) {
            if let Some(ref host) = opts.smtp_host {
                query_obj["smtp_host"] = json!(host);
            }
            if let Some(port) = opts.smtp_port {
                query_obj["smtp_port"] = json!(port);
            }
            if let Some(ref tls) = opts.use_tls {
                query_obj["use_tls"] = json!(tls);
            }
            if let Some(default) = opts.is_default {
                query_obj["is_default"] = json!(default);
            }
        }

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: query_obj,
            profiles: None,
            active_profile: None,
            profile: None,
            deleted_profile: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut json_obj = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query
        });

        if let Some(ref profiles) = self.profiles {
            let profile_values: Vec<Value> = profiles
                .iter()
                .map(|p| {
                    json!({
                        "name": p.name,
                        "smtp_host": p.smtp_host,
                        "smtp_port": p.smtp_port,
                        "use_tls": p.use_tls,
                        "tls_accept_invalid_certs": p.tls_accept_invalid_certs,
                        "from": p.from,
                        "reply_to": p.reply_to,
                        "description": p.description,
                        "is_active": p.is_active,
                        "has_password": p.has_password
                    })
                })
                .collect();
            json_obj["profiles"] = json!(profile_values);
        }

        if let Some(ref active) = self.active_profile {
            json_obj["active_profile"] = json!(active);
        }

        if let Some(ref profile) = self.profile {
            json_obj["profile"] = json!({
                "name": profile.name,
                "smtp_host": profile.smtp_host,
                "smtp_port": profile.smtp_port,
                "use_tls": profile.use_tls,
                "tls_accept_invalid_certs": profile.tls_accept_invalid_certs,
                "from": profile.from,
                "reply_to": profile.reply_to,
                "description": profile.description,
                "is_active": profile.is_active,
                "has_password": profile.has_password
            });
        }

        if let Some(ref deleted) = self.deleted_profile {
            json_obj["deleted_profile"] = json!(deleted);
        }

        if let Some((ref code, ref message)) = self.error {
            json_obj["error"] = json!({
                "code": code,
                "message": message
            });
        } else {
            json_obj["error"] = Value::Null;
        }

        json_obj["warnings"] = json!(self.warnings);

        serde_json::to_string_pretty(&json_obj).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        if let Some((ref code, ref message)) = self.error {
            return format!(
                "Mail Config\n===========\n\nError:\n  [{}] {}\n",
                code, message
            );
        }

        match self.query["action"].as_str().unwrap_or("") {
            "list" => self.format_list_text(),
            "get" | "get_active" => self.format_get_text(),
            "set" | "activate" => self.format_set_text(),
            "delete" => self.format_delete_text(),
            _ => "Mail Config\n===========\n\nOperation completed.\n".to_string(),
        }
    }

    fn format_list_text(&self) -> String {
        let mut output = "Mail Config — Profiles\n======================\n\n".to_string();

        if let Some(ref active) = self.active_profile {
            output.push_str(&format!("Active Profile: {}\n\n", active));
        } else {
            output.push_str("Active Profile: (none)\n\n");
        }

        if let Some(ref profiles) = self.profiles {
            if profiles.is_empty() {
                output.push_str("No profiles configured.\n");
            } else {
                output.push_str("Profiles:\n");
                for profile in profiles {
                    output.push_str(&format!("  - {}\n", profile.name));
                    output.push_str(&format!(
                        "      Host   : {}:{}\n",
                        profile.smtp_host, profile.smtp_port
                    ));
                    output.push_str(&format!("      TLS    : {}\n", profile.use_tls));
                    output.push_str(&format!(
                        "      From   : {}\n",
                        profile.from.as_deref().unwrap_or("(none)")
                    ));
                    output.push_str(&format!(
                        "      Active : {}\n",
                        if profile.is_active { "yes" } else { "no" }
                    ));
                    output.push_str(&format!(
                        "      Secret : {}\n",
                        if profile.has_password {
                            "set"
                        } else {
                            "not set"
                        }
                    ));
                    if let Some(ref desc) = profile.description {
                        output.push_str(&format!("      Desc   : {}\n", desc));
                    }
                }
            }
        }

        output
    }

    fn format_get_text(&self) -> String {
        if let Some(ref profile) = self.profile {
            let mut output = format!("Mail Config — Profile '{}'\n", profile.name);
            output.push_str(&"=".repeat(28 + profile.name.len()));
            output.push_str("\n\n");

            output.push_str(&format!(
                "Host    : {}:{}\n",
                profile.smtp_host, profile.smtp_port
            ));
            output.push_str(&format!("TLS     : {}\n", profile.use_tls));
            output.push_str(&format!(
                "From    : {}\n",
                profile.from.as_deref().unwrap_or("(none)")
            ));
            output.push_str(&format!(
                "Reply-To: {}\n",
                profile.reply_to.as_deref().unwrap_or("(none)")
            ));
            output.push_str(&format!(
                "Active  : {}\n",
                if profile.is_active { "yes" } else { "no" }
            ));
            output.push_str(&format!(
                "Secret  : {}\n",
                if profile.has_password {
                    "set"
                } else {
                    "not set"
                }
            ));
            if let Some(ref desc) = profile.description {
                output.push_str(&format!("Desc    : {}\n", desc));
            }

            output
        } else {
            "Mail Config\n===========\n\nNo profile found.\n".to_string()
        }
    }

    fn format_set_text(&self) -> String {
        if let Some(ref profile) = self.profile {
            format!(
                "Mail Config\n===========\n\nProfile '{}' {} successfully.\n",
                profile.name,
                match self.query["action"].as_str().unwrap_or("") {
                    "set" => "configured",
                    "activate" => "activated",
                    _ => "updated",
                }
            )
        } else {
            "Mail Config\n===========\n\nOperation completed.\n".to_string()
        }
    }

    fn format_delete_text(&self) -> String {
        if let Some(ref deleted) = self.deleted_profile {
            format!(
                "Mail Config\n===========\n\nProfile '{}' deleted successfully.\n",
                deleted
            )
        } else {
            "Mail Config\n===========\n\nProfile deleted.\n".to_string()
        }
    }
}

/// Unit tests point the profile store at a temporary directory for the
/// current thread instead of changing the process environment.
#[cfg(test)]
mod test_config_dir {
    use std::cell::RefCell;
    use std::path::PathBuf;

    thread_local! {
        static DIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    pub fn set(dir: Option<PathBuf>) {
        DIR.with(|d| *d.borrow_mut() = dir);
    }

    pub fn get() -> Option<PathBuf> {
        DIR.with(|d| d.borrow().clone())
    }

    thread_local! {
        static ENV: RefCell<Option<Vec<(String, String)>>> = const { RefCell::new(None) };
    }

    /// Replaces the MAIL_* environment for this thread (`None` restores the
    /// real one).
    pub fn set_env(vars: Option<&[(&str, &str)]>) {
        let vars = vars.map(|v| {
            v.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        });
        ENV.with(|e| *e.borrow_mut() = vars);
    }

    /// `Some(value)` when the environment is replaced for this thread.
    pub fn env(name: &str) -> Option<Option<String>> {
        ENV.with(|e| {
            e.borrow()
                .as_ref()
                .map(|vars| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        })
    }
}

// Config store functions
/// `$XDG_CONFIG_HOME/resh/mail` (or `~/.config/resh/mail`). Reading never
/// creates it; `code` is the error code to report when neither variable is
/// set.
fn mail_config_dir(code: &str) -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = test_config_dir::get() {
        return Ok(dir);
    }
    let base = dirs::config_dir().ok_or_else(|| {
        anyhow::anyhow!(
            "[{}] Cannot locate the configuration directory: neither XDG_CONFIG_HOME nor HOME is set",
            code
        )
    })?;
    Ok(base.join("resh").join("mail"))
}

fn get_config_file_path() -> Result<PathBuf> {
    Ok(mail_config_dir(MAIL_CONFIG_STORE_READ_ERROR)?.join("smtp_profiles.json"))
}

/// Creates the mail configuration directory owner-only (0700) if needed.
fn ensure_config_dir() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = mail_config_dir(MAIL_CONFIG_STORE_WRITE_ERROR)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| {
            format!(
                "[{}] Failed to create mail config directory: {:?}",
                MAIL_CONFIG_STORE_WRITE_ERROR, dir
            )
        })?;
    Ok(dir)
}

/// Takes an exclusive lock on the profile store for a read-modify-write, so
/// two concurrent `config` commands cannot lose each other's change. The
/// lock is released when the returned file is dropped.
fn lock_profiles() -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let path = ensure_config_dir()?.join("smtp_profiles.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| {
            format!(
                "[{}] Failed to open lock file: {:?}",
                MAIL_CONFIG_STORE_WRITE_ERROR, path
            )
        })?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!(
            "[{}] Failed to lock {:?}: {}",
            MAIL_CONFIG_STORE_WRITE_ERROR,
            path,
            std::io::Error::last_os_error()
        );
    }
    Ok(file)
}

fn load_profiles() -> Result<Vec<SmtpProfile>> {
    let config_path = get_config_file_path()?;

    if fs::symlink_metadata(&config_path).is_err() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&config_path).with_context(|| {
        format!(
            "[{}] Failed to read config file: {:?}",
            MAIL_CONFIG_STORE_READ_ERROR, config_path
        )
    })?;

    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    let profiles: Vec<SmtpProfile> = serde_json::from_str(&content).with_context(|| {
        format!(
            "[{}] Failed to parse config file: {:?}",
            MAIL_CONFIG_STORE_PARSE_ERROR, config_path
        )
    })?;

    Ok(profiles)
}

fn save_profiles(profiles: &[SmtpProfile]) -> Result<()> {
    let config_path = ensure_config_dir()?.join("smtp_profiles.json");

    // Atomic write: write to temp file then rename
    let temp_path = config_path.with_extension("json.tmp");

    let content = serde_json::to_string_pretty(profiles).with_context(|| {
        format!(
            "[{}] Failed to serialize profiles",
            MAIL_CONFIG_STORE_WRITE_ERROR
        )
    })?;

    // The profiles hold SMTP passwords (base64-encoded, not encrypted), so
    // the file is created owner-only (0600) instead of with the umask, and a
    // planted symlink at the temp name is never followed.
    write_private_file(&temp_path, content.as_bytes()).with_context(|| {
        format!(
            "[{}] Failed to write temp config file: {:?}",
            MAIL_CONFIG_STORE_WRITE_ERROR, temp_path
        )
    })?;

    fs::rename(&temp_path, &config_path).with_context(|| {
        format!(
            "[{}] Failed to rename temp config file: {:?}",
            MAIL_CONFIG_STORE_WRITE_ERROR, config_path
        )
    })?;

    Ok(())
}

/// Writes `data` to a new file at `path` with mode 0600, replacing a stale
/// regular file left by an interrupted write. Refuses to follow a symlink.
fn write_private_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "refusing to write through a symlink",
            ));
        }
        Ok(_) => fs::remove_file(path)?,
        Err(_) => {}
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!(
            "[{}] Profile name cannot be empty",
            MAIL_CONFIG_INVALID_PROFILE_NAME
        );
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        bail!(
            "[{}] Profile name '{}' contains invalid characters. Only alphanumeric, '_', '-', and '.' are allowed",
            MAIL_CONFIG_INVALID_PROFILE_NAME,
            name
        );
    }

    Ok(())
}

fn validate_smtp_config(profile: &SmtpProfile) -> Result<()> {
    if profile.smtp_host.trim().is_empty() {
        bail!(
            "[{}] SMTP host cannot be empty",
            MAIL_CONFIG_INVALID_SMTP_HOST
        );
    }

    if profile.smtp_port == 0 {
        bail!(
            "[{}] SMTP port must be greater than 0",
            MAIL_CONFIG_INVALID_SMTP_PORT
        );
    }

    // Validate TLS mode
    match profile.use_tls.as_str() {
        "none" | "starttls" | "tls" => {}
        _ => bail!(
            "[{}] Invalid TLS mode '{}'. Supported: none, starttls, tls",
            MAIL_CONFIG_INVALID_TLS_MODE,
            profile.use_tls
        ),
    }

    Ok(())
}

fn get_default_port(use_tls: &str) -> u16 {
    match use_tls {
        "tls" => 465,
        "starttls" => 587,
        "none" => 25,
        _ => 587, // fallback to starttls default
    }
}

#[derive(Clone, Debug)]
pub struct MailAddress {
    pub email: String,
    pub name: Option<String>,
}

impl MailAddress {
    pub fn new(email: String) -> Self {
        Self { email, name: None }
    }

    pub fn with_name(email: String, name: String) -> Self {
        Self {
            email,
            name: Some(name),
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        validate_email_address(s)?;
        Ok(Self::new(s.to_string()))
    }

    pub fn to_mailbox(&self) -> Result<Mailbox> {
        let email_addr = self
            .email
            .parse()
            .with_context(|| format!("Invalid email address: {}", self.email))?;

        if let Some(ref name) = self.name {
            Ok(Mailbox::new(Some(name.clone()), email_addr))
        } else {
            Ok(Mailbox::new(None, email_addr))
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttachmentSpec {
    pub path: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
}

impl AttachmentSpec {
    pub fn new(path: String) -> Self {
        Self {
            path,
            filename: None,
            content_type: None,
        }
    }

    pub fn get_filename(&self) -> String {
        if let Some(ref filename) = self.filename {
            filename.clone()
        } else {
            Path::new(&self.path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        }
    }

    pub fn get_content_type(&self) -> String {
        if let Some(ref content_type) = self.content_type {
            content_type.clone()
        } else {
            // Detect from file extension
            let path = Path::new(&self.path);
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("txt") | Some("log") => "text/plain".to_string(),
                Some("html") | Some("htm") => "text/html".to_string(),
                Some("pdf") => "application/pdf".to_string(),
                Some("csv") => "text/csv".to_string(),
                Some("json") => "application/json".to_string(),
                Some("xml") => "application/xml".to_string(),
                Some("zip") => "application/zip".to_string(),
                _ => "application/octet-stream".to_string(),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailSendOptions {
    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    pub bcc: Vec<MailAddress>,

    pub from: Option<MailAddress>,
    pub reply_to: Option<MailAddress>,

    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,

    pub attachments: Vec<AttachmentSpec>,
    pub headers: Vec<(String, String)>,

    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub use_tls: Option<TlsMode>,
    pub tls_accept_invalid_certs: Option<bool>,
    pub ca_file: Option<CaFile>,

    pub timeout_ms: u64,
    pub max_retry: u32,
    pub retry_backoff_ms: u64,

    pub format_output: OutputFormat,
}

impl Default for MailSendOptions {
    fn default() -> Self {
        Self {
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            from: None,
            reply_to: None,
            subject: String::new(),
            text_body: None,
            html_body: None,
            attachments: Vec::new(),
            headers: Vec::new(),
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            use_tls: None,
            tls_accept_invalid_certs: None,
            ca_file: None,
            timeout_ms: 10000,
            max_retry: 0,
            retry_backoff_ms: 1000,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailSendResult {
    pub message_id: Option<String>,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub attempts: u32,
    pub last_response: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MailSendResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub result: Option<MailSendResult>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl MailSendResponse {
    pub fn new(opts: &MailSendOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "to": opts.to.iter().map(|addr| &addr.email).collect::<Vec<_>>(),
                "cc": opts.cc.iter().map(|addr| &addr.email).collect::<Vec<_>>(),
                "bcc": opts.bcc.iter().map(|addr| &addr.email).collect::<Vec<_>>(),
                "from": opts.from.as_ref().map(|addr| &addr.email),
                "subject": opts.subject,
                "use_tls": opts.use_tls.as_ref().map_or("starttls", TlsMode::as_str),
                "max_retry": opts.max_retry,
                "timeout_ms": opts.timeout_ms
            }),
            result: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let json_obj = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "result": self.result.as_ref().map(|r| json!({
                "message_id": r.message_id,
                "smtp_host": r.smtp_host,
                "smtp_port": r.smtp_port,
                "attempts": r.attempts,
                "last_response": r.last_response
            })),
            "error": self.error.as_ref().map(|(code, message)| json!({
                "code": code,
                "message": message
            })),
            "warnings": self.warnings
        });

        serde_json::to_string_pretty(&json_obj).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Mail Send\n");
        output.push_str("=========\n\n");

        // Extract recipients from query
        if let Some(to_array) = self.query.get("to") {
            if let Some(to_list) = to_array.as_array() {
                for addr in to_list {
                    if let Some(email) = addr.as_str() {
                        output.push_str(&format!("To      : {}\n", email));
                    }
                }
            }
        }

        if let Some(from) = self.query.get("from").and_then(|v| v.as_str()) {
            output.push_str(&format!("From    : {}\n", from));
        }

        if let Some(subject) = self.query.get("subject").and_then(|v| v.as_str()) {
            output.push_str(&format!("Subject : {}\n", subject));
        }

        output.push('\n');

        if let Some(result) = &self.result {
            output.push_str(&format!("SMTP Host : {}\n", result.smtp_host));
            output.push_str(&format!("SMTP Port : {}\n", result.smtp_port));
            output.push_str(&format!("Attempts  : {}\n", result.attempts));

            if self.ok {
                output.push_str("Status    : sent\n\n");
                if let Some(ref msg_id) = result.message_id {
                    output.push_str(&format!("Message-ID: {}\n", msg_id));
                }
            } else {
                output.push_str("Status    : failed\n\n");
            }
        }

        if let Some((code, message)) = &self.error {
            output.push_str("Error:\n");
            output.push_str(&format!("  [{}] {}.\n", code, message));
        }

        output
    }
}

// Template structs and functionality
#[derive(Clone, Debug)]
pub struct MailTemplate {
    pub name: String,
    pub locale: Option<String>,
    pub version: Option<String>,
    pub subject_template: String,
    pub text_body_template: Option<String>,
    pub html_body_template: Option<String>,
    pub default_from: Option<String>,
    pub default_reply_to: Option<String>,
    pub default_headers: HashMap<String, String>,
    pub default_attachments: Vec<AttachmentSpec>,
}

#[derive(Clone, Debug)]
pub struct MailSendTemplateOptions {
    pub template: String,
    pub locale: Option<String>,

    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    pub bcc: Vec<MailAddress>,

    pub from: Option<MailAddress>,
    pub reply_to: Option<MailAddress>,

    pub vars: Value, // JSON object for template variables

    pub attachments: Vec<AttachmentSpec>,
    pub headers: Vec<(String, String)>,

    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub use_tls: Option<TlsMode>,
    pub tls_accept_invalid_certs: Option<bool>,
    pub ca_file: Option<CaFile>,

    pub timeout_ms: u64,
    pub max_retry: u32,
    pub retry_backoff_ms: u64,

    pub strict_vars: bool,
    pub dry_run: bool,
    pub format_output: OutputFormat,
}

impl Default for MailSendTemplateOptions {
    fn default() -> Self {
        Self {
            template: String::new(),
            locale: None,
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            from: None,
            reply_to: None,
            vars: Value::Object(serde_json::Map::new()),
            attachments: Vec::new(),
            headers: Vec::new(),
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            use_tls: None,
            tls_accept_invalid_certs: None,
            ca_file: None,
            timeout_ms: 10000,
            max_retry: 0,
            retry_backoff_ms: 1000,
            strict_vars: false,
            dry_run: false,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailSendTemplateRendered {
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MailSendTemplateSendResult {
    pub mail_send_response: Option<MailSendResult>,
}

#[derive(Clone, Debug)]
pub struct MailSendTemplateResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub rendered: Option<MailSendTemplateRendered>,
    pub send_result: Option<MailSendTemplateSendResult>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl MailSendTemplateResponse {
    pub fn new(opts: &MailSendTemplateOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "template": opts.template,
                "to": opts.to.iter().map(|addr| &addr.email).collect::<Vec<_>>(),
                "locale": opts.locale,
                "strict_vars": opts.strict_vars,
                "dry_run": opts.dry_run
            }),
            rendered: None,
            send_result: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let json_obj = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "rendered": self.rendered.as_ref().map(|r| json!({
                "subject": r.subject,
                "text_body": r.text_body,
                "html_body": r.html_body
            })),
            "send_result": self.send_result.as_ref().and_then(|sr| sr.mail_send_response.as_ref()).map(|r| json!({
                "ok": true,
                "message_id": r.message_id,
                "smtp_host": r.smtp_host,
                "smtp_port": r.smtp_port,
                "attempts": r.attempts,
                "last_response": r.last_response
            })),
            "error": self.error.as_ref().map(|(code, message)| json!({
                "code": code,
                "message": message
            })),
            "warnings": self.warnings
        });

        serde_json::to_string_pretty(&json_obj).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        output.push_str("Mail Send Template\n");
        output.push_str("==================\n\n");

        if let Some(template_name) = self.query.get("template").and_then(|v| v.as_str()) {
            output.push_str(&format!("Template : {}\n", template_name));
        }

        if let Some(to_array) = self.query.get("to").and_then(|v| v.as_array()) {
            if let Some(first_to) = to_array.first().and_then(|v| v.as_str()) {
                output.push_str(&format!("To       : {}\n", first_to));
            }
        }

        if let Some(rendered) = &self.rendered {
            output.push_str(&format!("Subject  : {}\n", rendered.subject));
        }

        if let Some(dry_run) = self.query.get("dry_run").and_then(|v| v.as_bool()) {
            output.push_str(&format!(
                "Dry Run  : {}\n",
                if dry_run { "yes" } else { "no" }
            ));
        }

        if let Some(send_result) = &self.send_result {
            if let Some(result) = &send_result.mail_send_response {
                output.push_str("\n");
                output.push_str(&format!("SMTP Host : {}\n", result.smtp_host));
                output.push_str(&format!("SMTP Port : {}\n", result.smtp_port));
                output.push_str(&format!("Attempts  : {}\n", result.attempts));

                if self.ok {
                    output.push_str("Status    : sent\n\n");
                    if let Some(ref msg_id) = result.message_id {
                        output.push_str(&format!("Message-ID: {}\n", msg_id));
                    }
                } else {
                    output.push_str("Status    : failed\n\n");
                }
            }
        } else if self.ok
            && self
                .query
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            output.push_str("\nStatus: preview only (dry run)\n");
        } else {
            output.push_str(&format!(
                "\nStatus: {}\n",
                if self.ok { "success" } else { "failed" }
            ));
        }

        if let Some((code, message)) = &self.error {
            output.push_str("\nError:\n");
            output.push_str(&format!("  [{}] {}.\n", code, message));
        }

        output
    }
}

// Mail Test structures and functionality
#[derive(Clone, Debug)]
pub struct MailTestOptions {
    // SMTP / backend config
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub use_tls: Option<TlsMode>,
    pub tls_accept_invalid_certs: Option<bool>,
    pub ca_file: Option<CaFile>,

    // Test behavior
    pub connection_only: bool,
    pub send_test_email: bool,
    pub max_retry: u32,
    pub retry_backoff_ms: u64,
    pub timeout_ms: u64,

    // Optional test email content
    pub to: Vec<MailAddress>,
    pub from: Option<MailAddress>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,

    // Output
    pub format_output: OutputFormat,
}

impl Default for MailTestOptions {
    fn default() -> Self {
        Self {
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            use_tls: None,
            tls_accept_invalid_certs: None,
            ca_file: None,
            connection_only: false,
            send_test_email: false,
            max_retry: 0,
            retry_backoff_ms: 1000,
            timeout_ms: 10000,
            to: Vec::new(),
            from: None,
            subject: Some("SMTP test".to_string()),
            text_body: Some("SMTP test email".to_string()),
            html_body: None,
            format_output: OutputFormat::Json,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MailTestConnectionResult {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub resolved_ip: Option<String>,
    pub use_tls: String,
    pub tls_established: bool,
    pub auth_attempted: bool,
    pub auth_succeeded: bool,
    pub attempts: u32,
    pub last_response: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MailTestSendEmailResult {
    pub attempted: bool,
    pub envelope_from: Option<String>,
    pub envelope_to: Vec<String>,
    pub accepted_recipients: Vec<String>,
    pub rejected_recipients: Vec<String>,
    pub last_response: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MailTestResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub query: Value,
    pub connection: Option<MailTestConnectionResult>,
    pub send_test_email: Option<MailTestSendEmailResult>,
    pub error: Option<(String, String)>,
    pub warnings: Vec<String>,
}

impl MailTestResponse {
    pub fn new(opts: &MailTestOptions) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ok: false,
            timestamp_unix_ms: timestamp,
            query: json!({
                "smtp_host": opts.smtp_host,
                "smtp_port": opts.smtp_port,
                "use_tls": opts.use_tls.as_ref().map_or("starttls", TlsMode::as_str),
                "connection_only": opts.connection_only,
                "send_test_email": opts.send_test_email,
                "max_retry": opts.max_retry,
                "timeout_ms": opts.timeout_ms,
                "to": opts.to.iter().map(|addr| &addr.email).collect::<Vec<_>>(),
                "from": opts.from.as_ref().map(|addr| &addr.email),
                "subject": opts.subject
            }),
            connection: None,
            send_test_email: None,
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let json_obj = json!({
            "ok": self.ok,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "query": self.query,
            "connection": self.connection.as_ref().map(|c| json!({
                "smtp_host": c.smtp_host,
                "smtp_port": c.smtp_port,
                "resolved_ip": c.resolved_ip,
                "use_tls": c.use_tls,
                "tls_established": c.tls_established,
                "auth_attempted": c.auth_attempted,
                "auth_succeeded": c.auth_succeeded,
                "attempts": c.attempts,
                "last_response": c.last_response
            })),
            "send_test_email": self.send_test_email.as_ref().map(|e| json!({
                "attempted": e.attempted,
                "envelope_from": e.envelope_from,
                "envelope_to": e.envelope_to,
                "accepted_recipients": e.accepted_recipients,
                "rejected_recipients": e.rejected_recipients,
                "last_response": e.last_response
            })),
            "error": self.error.as_ref().map(|(code, message)| json!({
                "code": code,
                "message": message
            })),
            "warnings": self.warnings
        });

        serde_json::to_string_pretty(&json_obj).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let mut output = String::from("Mail Test\n=========\n\n");

        if let Some(connection) = &self.connection {
            output.push_str(&format!("SMTP Host : {}\n", connection.smtp_host));
            output.push_str(&format!("SMTP Port : {}\n", connection.smtp_port));
            output.push_str(&format!("TLS Mode  : {}\n\n", connection.use_tls));

            output.push_str(&format!(
                "Connection : {}\n",
                if connection.tls_established || connection.use_tls == "none" {
                    "ok"
                } else {
                    "failed"
                }
            ));

            match connection.use_tls.as_str() {
                "none" => output.push_str("TLS        : disabled\n"),
                _ => output.push_str(&format!(
                    "TLS        : {}\n",
                    if connection.tls_established {
                        "ok"
                    } else {
                        "failed"
                    }
                )),
            }

            if connection.auth_attempted {
                output.push_str(&format!(
                    "Auth       : {}\n",
                    if connection.auth_succeeded {
                        "ok"
                    } else {
                        "failed"
                    }
                ));
            }

            output.push_str(&format!(
                "Retries    : {}\n",
                if connection.attempts > 1 {
                    connection.attempts - 1
                } else {
                    0
                }
            ));
            output.push_str(&format!("Attempts   : {}\n", connection.attempts));

            if let Some(ref last_resp) = connection.last_response {
                output.push_str(&format!("\nLast Response: {}\n", last_resp));
            }
        }

        if let Some(send_email) = &self.send_test_email {
            output.push_str("\nTest Email : ");
            if send_email.attempted {
                output.push_str("sent\n");
                if let Some(ref from) = send_email.envelope_from {
                    output.push_str(&format!("  From : {}\n", from));
                }
                for to in &send_email.envelope_to {
                    output.push_str(&format!("  To   : {}\n", to));
                }
                if let Some(ref last_resp) = send_email.last_response {
                    output.push_str(&format!("  Last : {}\n", last_resp));
                }
            } else {
                output.push_str("not requested\n");
            }
        } else {
            output.push_str("\nTest Email : not requested\n");
        }

        output.push_str(&format!(
            "\nStatus : {}\n",
            if self.ok { "success" } else { "failed" }
        ));

        if let Some((code, message)) = &self.error {
            output.push_str(&format!("\nError:\n  [{}] {}\n", code, message));
        }

        output
    }
}

// Template store trait for abstraction
trait MailTemplateStore {
    fn get_template(
        &self,
        name: &str,
        locale: Option<&str>,
        version: Option<&str>,
    ) -> Result<MailTemplate>;
}

// In-memory template store for this implementation
struct InMemoryTemplateStore {
    templates: HashMap<String, MailTemplate>,
}

impl InMemoryTemplateStore {
    fn new() -> Self {
        let mut templates = HashMap::new();

        // Add some default templates for testing
        templates.insert(
            "welcome".to_string(),
            MailTemplate {
                name: "welcome".to_string(),
                locale: Some("en".to_string()),
                version: Some("v1".to_string()),
                subject_template: "Welcome to {{app_name}}, {{user_name}}!".to_string(),
                text_body_template: Some(
                    "Hi {{user_name}},\n\nWelcome to {{app_name}}.\n".to_string(),
                ),
                html_body_template: Some(
                    "<p>Hi <strong>{{user_name}}</strong>,</p><p>Welcome to {{app_name}}.</p>"
                        .to_string(),
                ),
                default_from: Some("noreply@myapp.io".to_string()),
                default_reply_to: None,
                default_headers: HashMap::new(),
                default_attachments: Vec::new(),
            },
        );

        templates.insert("password_reset".to_string(), MailTemplate {
            name: "password_reset".to_string(),
            locale: Some("en".to_string()),
            version: Some("v1".to_string()),
            subject_template: "Reset your password".to_string(),
            text_body_template: Some("Hi {{user_name}},\n\nClick here to reset your password: {{reset_link}}\n".to_string()),
            html_body_template: Some("<p>Hi {{user_name}},</p><p><a href=\"{{reset_link}}\">Reset your password</a></p>".to_string()),
            default_from: Some("noreply@myapp.io".to_string()),
            default_reply_to: None,
            default_headers: HashMap::new(),
            default_attachments: Vec::new(),
        });

        templates.insert(
            "welcome:fr".to_string(),
            MailTemplate {
                name: "welcome".to_string(),
                locale: Some("fr".to_string()),
                version: Some("v1".to_string()),
                subject_template: "Bienvenue à {{app_name}}, {{user_name}}!".to_string(),
                text_body_template: Some(
                    "Salut {{user_name}},\n\nBienvenue à {{app_name}}.\n".to_string(),
                ),
                html_body_template: Some(
                    "<p>Salut <strong>{{user_name}}</strong>,</p><p>Bienvenue à {{app_name}}.</p>"
                        .to_string(),
                ),
                default_from: Some("noreply@myapp.io".to_string()),
                default_reply_to: None,
                default_headers: HashMap::new(),
                default_attachments: Vec::new(),
            },
        );

        Self { templates }
    }

    fn template_key(name: &str, locale: Option<&str>) -> String {
        if let Some(locale) = locale {
            format!("{}:{}", name, locale)
        } else {
            name.to_string()
        }
    }
}

impl MailTemplateStore for InMemoryTemplateStore {
    fn get_template(
        &self,
        name: &str,
        locale: Option<&str>,
        _version: Option<&str>,
    ) -> Result<MailTemplate> {
        // Try with locale first, then fallback to default
        if let Some(locale) = locale {
            let key = Self::template_key(name, Some(locale));
            if let Some(template) = self.templates.get(&key) {
                return Ok(template.clone());
            }
        }

        // Fallback to default (no locale)
        let key = Self::template_key(name, None);
        self.templates
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Template '{}' not found", name))
    }
}

/// Replaces each `{{name}}` (or `{{a.b}}` for a nested value) in `template`
/// in a single pass, so a value that itself contains `{{...}}` is inserted
/// literally and never expanded. With `html`, values are HTML-escaped. A
/// missing variable renders as an empty string, or is an error with
/// `strict`.
fn render_template(template: &str, vars: &Value, strict: bool, html: bool) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut missing: Vec<String> = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let Some(len) = rest[start + 2..].find("}}") else {
            break;
        };
        out.push_str(&rest[..start]);
        let name = rest[start + 2..start + 2 + len].trim();
        match get_nested_value(vars, name) {
            Some(value) => {
                let text = value_to_string(&value);
                if html {
                    out.push_str(&html_escape(&text));
                } else {
                    out.push_str(&text);
                }
            }
            None => {
                if !missing.iter().any(|m| m == name) {
                    missing.push(name.to_string());
                }
            }
        }
        rest = &rest[start + 2 + len + 2..];
    }
    out.push_str(rest);

    if strict && !missing.is_empty() {
        bail!("Missing variables: {}", missing.join(", "));
    }
    Ok(out)
}

/// Escapes text for insertion into HTML element content or a quoted
/// attribute value.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn get_nested_value(vars: &Value, path: &str) -> Option<Value> {
    if path.contains('.') {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = vars;

        for part in parts {
            current = current.get(part)?;
        }

        Some(current.clone())
    } else {
        vars.get(path).cloned()
    }
}

// Helper function to convert JSON value to string
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

// Email validation function
fn validate_email_address(email: &str) -> Result<()> {
    use email_address_parser::EmailAddress;

    // Both checks: the address must be valid by RFC 5322 rules and usable as
    // an SMTP envelope address by lettre.
    if EmailAddress::parse(email, None).is_none() || email.parse::<lettre::Address>().is_err() {
        bail!("Invalid email address: {:?}", email);
    }
    Ok(())
}

// Main config function
pub fn config(opts: MailConfigOptions) -> Result<MailConfigResponse> {
    let mut response = MailConfigResponse::new(&opts);

    let mut warnings = Vec::new();
    let outcome = handle_config_action(&opts, &mut warnings);
    response.warnings = warnings;
    match outcome {
        Ok(result) => {
            response.ok = true;

            match result {
                ConfigActionResult::List(profiles, active) => {
                    response.profiles = Some(profiles.iter().map(|p| p.to_view()).collect());
                    response.active_profile = active;
                }
                ConfigActionResult::Get(profile) => {
                    response.profile = Some(profile.to_view());
                }
                ConfigActionResult::Set(profile) => {
                    response.profile = Some(profile.to_view());
                }
                ConfigActionResult::Delete(profile_name) => {
                    response.deleted_profile = Some(profile_name);
                }
                ConfigActionResult::Activate(profile) => {
                    response.profile = Some(profile.to_view());
                }
                ConfigActionResult::GetActive(profile) => {
                    response.profile = Some(profile.to_view());
                    response.active_profile = Some(profile.name.clone());
                }
            }
        }
        Err(e) => {
            let code =
                extract_error_code(&e).unwrap_or_else(|| MAIL_CONFIG_INTERNAL_ERROR.to_string());
            let full = format!("{e:#}");
            let message = full
                .strip_prefix(&format!("[{code}] "))
                .map(str::to_string)
                .unwrap_or(full);
            response.error = Some((code, message));
        }
    }

    Ok(response)
}

#[derive(Debug)]
enum ConfigActionResult {
    List(Vec<SmtpProfile>, Option<String>),
    Get(SmtpProfile),
    Set(SmtpProfile),
    Delete(String),
    Activate(SmtpProfile),
    GetActive(SmtpProfile),
}

fn handle_config_action(
    opts: &MailConfigOptions,
    w: &mut Vec<String>,
) -> Result<ConfigActionResult> {
    match opts.action {
        MailConfigAction::List => handle_list_action(w),
        MailConfigAction::Get => handle_get_action(opts, w),
        MailConfigAction::Set => handle_set_action(opts, w),
        MailConfigAction::Delete => handle_delete_action(opts, w),
        MailConfigAction::Activate => handle_activate_action(opts, w),
        MailConfigAction::GetActive => handle_get_active_action(w),
    }
}

/// The keyring error for `config`: nothing was changed.
fn keyring_error(what: &str, e: String) -> anyhow::Error {
    anyhow::anyhow!(
        "[{}] Cannot {what}: {e}. Nothing was changed. Passwords are kept only in the OS \
         keyring; without one, pass smtp_password= per call or set MAIL_SMTP_PASSWORD.",
        MAIL_CONFIG_KEYRING_UNAVAILABLE
    )
}

/// Warns about profiles that still hold a legacy base64 password.
fn legacy_warnings(profiles: &[SmtpProfile], w: &mut Vec<String>) {
    for p in profiles
        .iter()
        .filter(|p| p.smtp_password_encrypted.is_some())
    {
        w.push(format!(
            "Profile '{}' still stores its password base64-encoded in the profile file; \
             it moves to the OS keyring on the next config change.",
            p.name
        ));
    }
}

/// Moves legacy base64 passwords into the keyring before a write. A
/// profile whose password cannot be moved keeps it, with a warning.
fn migrate_legacy(profiles: &mut [SmtpProfile], w: &mut Vec<String>) {
    let store = mail_secrets::store();
    for p in profiles
        .iter_mut()
        .filter(|p| p.smtp_password_encrypted.is_some())
    {
        let Some(password) = p.decrypt_password() else {
            w.push(format!(
                "Profile '{}' has an unreadable legacy password; set it again with smtp_password=.",
                p.name
            ));
            continue;
        };
        match store.set(&p.name, &password) {
            Ok(()) => {
                p.smtp_password_ref = Some(mail_secrets::reference(&p.name));
                p.smtp_password_encrypted = None;
                w.push(format!(
                    "Moved the password of profile '{}' to the OS keyring.",
                    p.name
                ));
            }
            Err(e) => w.push(format!(
                "Profile '{}' still stores its password base64-encoded: {e}",
                p.name
            )),
        }
    }
}

/// The `profile` argument of an action that requires one.
fn required_profile(opts: &MailConfigOptions) -> Result<&String> {
    opts.profile.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "[{}] 'profile' parameter is required for action '{}'",
            MAIL_CONFIG_PROFILE_REQUIRED,
            opts.action.as_str()
        )
    })
}

fn handle_list_action(w: &mut Vec<String>) -> Result<ConfigActionResult> {
    let profiles = load_profiles()?;
    legacy_warnings(&profiles, w);
    let active_profile = profiles
        .iter()
        .find(|p| p.is_active)
        .map(|p| p.name.clone());

    Ok(ConfigActionResult::List(profiles, active_profile))
}

fn handle_get_action(opts: &MailConfigOptions, w: &mut Vec<String>) -> Result<ConfigActionResult> {
    let profile_name = required_profile(opts)?;
    validate_profile_name(profile_name)?;

    let profiles = load_profiles()?;
    legacy_warnings(
        &profiles
            .iter()
            .filter(|p| p.name == *profile_name)
            .cloned()
            .collect::<Vec<_>>(),
        w,
    );
    let profile = profiles
        .into_iter()
        .find(|p| p.name == *profile_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "[{}] SMTP profile '{}' does not exist",
                MAIL_CONFIG_PROFILE_NOT_FOUND,
                profile_name
            )
        })?;

    Ok(ConfigActionResult::Get(profile))
}

fn handle_set_action(opts: &MailConfigOptions, w: &mut Vec<String>) -> Result<ConfigActionResult> {
    let profile_name = required_profile(opts)?;
    validate_profile_name(profile_name)?;

    let _lock = lock_profiles()?;
    let mut profiles = load_profiles()?;

    // Find existing profile or create new one
    let existing_profile = profiles.iter().find(|p| p.name == *profile_name).cloned();

    let mut profile = if let Some(ref existing) = existing_profile {
        existing.clone()
    } else {
        // Create new profile - require smtp_host
        if opts.smtp_host.is_none() {
            bail!(
                "[{}] smtp_host is required for new profiles",
                MAIL_CONFIG_INVALID_SMTP_HOST
            );
        }

        SmtpProfile {
            name: profile_name.clone(),
            smtp_host: String::new(), // Will be set below
            smtp_port: 0,             // Will be set below
            smtp_username: None,
            smtp_password_ref: None,
            smtp_password_encrypted: None,
            use_tls: "starttls".to_string(),
            tls_accept_invalid_certs: false,
            from: None,
            reply_to: None,
            description: None,
            is_active: false,
        }
    };

    // Update fields from options
    if let Some(ref host) = opts.smtp_host {
        profile.smtp_host = host.clone();
    }

    if let Some(port) = opts.smtp_port {
        profile.smtp_port = port;
    } else if existing_profile.is_none() || opts.use_tls.is_some() {
        // Set default port for new profiles or when TLS mode changes
        let tls_mode = opts.use_tls.as_deref().unwrap_or(&profile.use_tls);
        profile.smtp_port = get_default_port(tls_mode);
    }

    if let Some(ref username) = opts.smtp_username {
        profile.smtp_username = Some(username.clone());
    }

    if let Some(ref tls) = opts.use_tls {
        profile.use_tls = tls.clone();
    }

    if let Some(invalid_certs) = opts.tls_accept_invalid_certs {
        profile.tls_accept_invalid_certs = invalid_certs;
    }

    if let Some(ref from) = opts.from {
        profile.from = Some(from.clone());
    }

    if let Some(ref reply_to) = opts.reply_to {
        profile.reply_to = Some(reply_to.clone());
    }

    if let Some(ref desc) = opts.description {
        profile.description = Some(desc.clone());
    }

    // Validate the profile configuration
    validate_smtp_config(&profile)?;

    // The password goes to the OS keyring only; without one, nothing is
    // changed.
    if let Some(ref password) = opts.smtp_password {
        mail_secrets::store()
            .set(profile_name, password)
            .map_err(|e| keyring_error("store the password in the OS keyring", e))?;
        profile.smtp_password_ref = Some(mail_secrets::reference(profile_name));
        profile.smtp_password_encrypted = None;
    }

    // Handle activation
    if opts.is_default.unwrap_or(false) {
        profile.is_active = true;
        // Deactivate all other profiles
        for p in &mut profiles {
            if p.name != *profile_name {
                p.is_active = false;
            }
        }
    }

    // Update or add the profile
    if let Some(index) = profiles.iter().position(|p| p.name == *profile_name) {
        profiles[index] = profile.clone();
    } else {
        profiles.push(profile.clone());
    }

    migrate_legacy(&mut profiles, w);
    save_profiles(&profiles)?;
    let profile = profiles
        .iter()
        .find(|p| p.name == *profile_name)
        .cloned()
        .unwrap_or(profile);

    Ok(ConfigActionResult::Set(profile))
}

fn handle_delete_action(
    opts: &MailConfigOptions,
    w: &mut Vec<String>,
) -> Result<ConfigActionResult> {
    let profile_name = required_profile(opts)?;
    validate_profile_name(profile_name)?;

    let _lock = lock_profiles()?;
    let mut profiles = load_profiles()?;

    let index = profiles
        .iter()
        .position(|p| p.name == *profile_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "[{}] SMTP profile '{}' does not exist",
                MAIL_CONFIG_PROFILE_NOT_FOUND,
                profile_name
            )
        })?;

    // Remove the keyring entry first: if that fails, nothing is changed.
    if profiles[index].smtp_password_ref.is_some() {
        mail_secrets::store()
            .delete(profile_name)
            .map_err(|e| keyring_error("remove the password from the OS keyring", e))?;
    }
    profiles.remove(index);
    migrate_legacy(&mut profiles, w);
    save_profiles(&profiles)?;

    Ok(ConfigActionResult::Delete(profile_name.clone()))
}

fn handle_activate_action(
    opts: &MailConfigOptions,
    w: &mut Vec<String>,
) -> Result<ConfigActionResult> {
    let profile_name = required_profile(opts)?;
    validate_profile_name(profile_name)?;

    let _lock = lock_profiles()?;
    let mut profiles = load_profiles()?;

    let mut target_profile = None;
    for profile in &mut profiles {
        if profile.name == *profile_name {
            profile.is_active = true;
            target_profile = Some(profile.clone());
        } else {
            profile.is_active = false;
        }
    }

    let profile = target_profile.ok_or_else(|| {
        anyhow::anyhow!(
            "[{}] SMTP profile '{}' does not exist",
            MAIL_CONFIG_PROFILE_NOT_FOUND,
            profile_name
        )
    })?;

    migrate_legacy(&mut profiles, w);
    save_profiles(&profiles)?;

    Ok(ConfigActionResult::Activate(profile))
}

fn handle_get_active_action(w: &mut Vec<String>) -> Result<ConfigActionResult> {
    let profiles = load_profiles()?;
    legacy_warnings(
        &profiles
            .iter()
            .filter(|p| p.is_active)
            .cloned()
            .collect::<Vec<_>>(),
        w,
    );

    let active_profiles: Vec<_> = profiles.into_iter().filter(|p| p.is_active).collect();

    match active_profiles.len() {
        0 => bail!(
            "[{}] No active SMTP profile configured",
            MAIL_CONFIG_NO_ACTIVE_PROFILE
        ),
        1 => Ok(ConfigActionResult::GetActive(
            active_profiles.into_iter().next().unwrap(),
        )),
        _ => bail!(
            "[{}] Multiple active profiles detected (inconsistent config)",
            MAIL_CONFIG_ACTIVE_PROFILE_INCONSISTENT
        ),
    }
}

fn extract_error_code(error: &anyhow::Error) -> Option<String> {
    let error_str = error.to_string();
    if let Some(start) = error_str.find("[") {
        if let Some(end) = error_str[start..].find("]") {
            let code = &error_str[start + 1..start + end];
            if code.starts_with("mail.config_") {
                return Some(code.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Argument parsing shared by send, send_template and test. An error from
// these functions means the arguments are invalid: the verb exits 2 and
// does nothing.

/// SMTP settings given as arguments (before environment or profile
/// fallbacks).
#[derive(Clone, Debug, Default)]
struct SmtpArgs {
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    use_tls: Option<TlsMode>,
    accept_invalid_certs: Option<bool>,
    ca_file: Option<CaFile>,
}

/// A private CA bundle given with `ca_file=`: its path and PEM contents.
#[derive(Clone, Debug)]
pub struct CaFile {
    pub path: String,
    pub pem: Vec<u8>,
}

/// Reads and checks `ca_file`: a readable file with at least one PEM
/// certificate that parses.
fn read_ca_file(path: &str) -> Result<CaFile> {
    if path.trim().is_empty() || path.starts_with('-') {
        bail!("invalid ca_file: {path:?}");
    }
    let pem = fs::read(path).map_err(|e| anyhow::anyhow!("cannot read ca_file {path:?}: {e}"))?;
    let text = String::from_utf8_lossy(&pem);
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        bail!("ca_file {path:?} contains no PEM certificate");
    }
    lettre::transport::smtp::client::Certificate::from_pem(&pem).map_err(|e| {
        anyhow::anyhow!("ca_file {path:?} is not a valid PEM certificate bundle: {e}")
    })?;
    Ok(CaFile {
        path: path.to_string(),
        pem,
    })
}

fn parse_smtp_args(args: &Args) -> Result<SmtpArgs> {
    let host = match args.get("smtp_host") {
        Some(h) => {
            check_smtp_host(h).map_err(|e| anyhow::anyhow!(e))?;
            Some(h.clone())
        }
        None => None,
    };
    let port = match args.get("smtp_port") {
        Some(p) => Some(parse_port("smtp_port", p).map_err(|e| anyhow::anyhow!(e))?),
        None => None,
    };
    let use_tls = match args.get("use_tls") {
        Some(t) => Some(TlsMode::from_str(t)?),
        None => None,
    };
    let accept_invalid_certs = crate::core::lenient::bool_arg(args, "tls_accept_invalid_certs")?;
    if accept_invalid_certs == Some(true) && matches!(use_tls, Some(TlsMode::None)) {
        bail!("tls_accept_invalid_certs=true conflicts with use_tls=none, which uses no TLS");
    }
    let ca_file = match args.get("ca_file") {
        Some(path) => {
            if matches!(use_tls, Some(TlsMode::None)) {
                bail!("ca_file conflicts with use_tls=none, which uses no TLS");
            }
            if accept_invalid_certs == Some(true) {
                bail!(
                    "ca_file conflicts with tls_accept_invalid_certs=true: a CA file is for \
                     verifying the certificate, which that option turns off"
                );
            }
            Some(read_ca_file(path)?)
        }
        None => None,
    };
    Ok(SmtpArgs {
        host,
        port,
        username: args.get("smtp_username").cloned(),
        password: args.get("smtp_password").cloned(),
        use_tls,
        accept_invalid_certs,
        ca_file,
    })
}

/// A non-negative integer argument.
fn parse_number<T: std::str::FromStr>(args: &Args, key: &str) -> Result<Option<T>> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => {
            v.trim().parse::<T>().map(Some).map_err(|_| {
                anyhow::anyhow!("invalid {key}: {v:?} (expected a non-negative integer)")
            })
        }
    }
}

fn parse_format(args: &Args) -> Result<OutputFormat> {
    match args.get("format_output") {
        Some(f) => OutputFormat::from_str(f),
        None => Ok(OutputFormat::Json),
    }
}

fn parse_address(args: &Args, key: &str) -> Result<Option<MailAddress>> {
    match args.get(key) {
        Some(v) => Ok(Some(
            MailAddress::from_str(v.trim()).with_context(|| format!("invalid {key}"))?,
        )),
        None => Ok(None),
    }
}

fn parse_address_list(args: &Args, key: &str) -> Result<Vec<MailAddress>> {
    match args.get(key) {
        Some(v) => parse_email_list(v).with_context(|| format!("invalid {key}")),
        None => Ok(Vec::new()),
    }
}

/// Address list: a JSON array of strings or a comma-separated list.
fn parse_email_list(input: &str) -> Result<Vec<MailAddress>> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.starts_with('[') {
        let items: Vec<Value> = serde_json::from_str(input)
            .map_err(|e| anyhow::anyhow!("not a JSON array of addresses: {e}"))?;
        return items
            .into_iter()
            .map(|item| match item {
                Value::String(s) => MailAddress::from_str(s.trim()),
                other => bail!("address list items must be strings, got {other}"),
            })
            .collect();
    }
    input
        .split(',')
        .map(|addr| MailAddress::from_str(addr.trim()))
        .collect()
}

/// `attachments`: a JSON array of `{"path", "filename", "content_type"}`.
fn parse_attachments_list(input: &str) -> Result<Vec<AttachmentSpec>> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<Value> = serde_json::from_str(input)
        .map_err(|e| anyhow::anyhow!("attachments must be a JSON array of objects: {e}"))?;
    let mut attachments = Vec::new();
    for item in items {
        let obj = item
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("each attachment must be a JSON object"))?;
        if let Some(k) = obj
            .keys()
            .find(|k| !["path", "filename", "content_type"].contains(&k.as_str()))
        {
            bail!("unknown attachment field {k:?} (expected path, filename, content_type)");
        }
        let text = |key: &str| -> Result<Option<String>> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => bail!("attachment {key} must be a string"),
            }
        };
        let path = text("path")?
            .filter(|p| !p.is_empty())
            .ok_or_else(|| anyhow::anyhow!("each attachment needs a non-empty \"path\""))?;
        let filename = text("filename")?;
        if filename.as_deref().is_some_and(|f| f.trim().is_empty()) {
            bail!("attachment filename for {path:?} is empty");
        }
        let content_type = text("content_type")?;
        if let Some(ref ct) = content_type {
            lettre::message::header::ContentType::parse(ct)
                .map_err(|_| anyhow::anyhow!("invalid attachment content_type {ct:?}"))?;
        }
        attachments.push(AttachmentSpec {
            path,
            filename,
            content_type,
        });
    }
    Ok(attachments)
}

/// `headers` for send_template: a JSON object of string values.
fn parse_headers_map(arg: &str) -> Result<Vec<(String, String)>> {
    let map: serde_json::Map<String, Value> = serde_json::from_str(arg)
        .map_err(|e| anyhow::anyhow!("headers must be a JSON object: {e}"))?;
    map.into_iter()
        .map(|(k, v)| match v {
            Value::String(s) => Ok((k, s)),
            _ => bail!("header {k:?} must have a string value"),
        })
        .collect()
}

impl MailSendOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let smtp = parse_smtp_args(args)?;
        let defaults = Self::default();
        let mut headers: Vec<(String, String)> = args
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix("header_")
                    .map(|n| (n.to_string(), v.clone()))
            })
            .collect();
        headers.sort();
        Ok(Self {
            to: parse_address_list(args, "to")?,
            cc: parse_address_list(args, "cc")?,
            bcc: parse_address_list(args, "bcc")?,
            from: parse_address(args, "from")?,
            reply_to: parse_address(args, "reply_to")?,
            subject: args.get("subject").cloned().unwrap_or_default(),
            text_body: args.get("text_body").cloned(),
            html_body: args.get("html_body").cloned(),
            attachments: match args.get("attachments") {
                Some(a) => parse_attachments_list(a)?,
                None => Vec::new(),
            },
            headers,
            smtp_host: smtp.host,
            smtp_port: smtp.port,
            smtp_username: smtp.username,
            smtp_password: smtp.password,
            use_tls: smtp.use_tls,
            tls_accept_invalid_certs: smtp.accept_invalid_certs,
            ca_file: smtp.ca_file,
            timeout_ms: parse_number(args, "timeout_ms")?.unwrap_or(defaults.timeout_ms),
            max_retry: parse_number(args, "max_retry")?.unwrap_or(defaults.max_retry),
            retry_backoff_ms: parse_number(args, "retry_backoff_ms")?
                .unwrap_or(defaults.retry_backoff_ms),
            format_output: parse_format(args)?,
        })
    }

    fn smtp_args(&self) -> SmtpArgs {
        SmtpArgs {
            host: self.smtp_host.clone(),
            port: self.smtp_port,
            username: self.smtp_username.clone(),
            password: self.smtp_password.clone(),
            use_tls: self.use_tls.clone(),
            accept_invalid_certs: self.tls_accept_invalid_certs,
            ca_file: self.ca_file.clone(),
        }
    }
}

impl MailSendTemplateOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let smtp = parse_smtp_args(args)?;
        let defaults = Self::default();
        let template = args
            .get("template")
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| anyhow::anyhow!("template is required (welcome or password_reset)"))?;
        let vars = match args.get("vars") {
            Some(v) => {
                let value: Value = serde_json::from_str(v)
                    .map_err(|e| anyhow::anyhow!("vars must be a JSON object: {e}"))?;
                if !value.is_object() {
                    bail!("vars must be a JSON object, got {value}");
                }
                value
            }
            None => defaults.vars.clone(),
        };
        Ok(Self {
            template,
            locale: args
                .get("locale")
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty()),
            to: parse_address_list(args, "to")?,
            cc: parse_address_list(args, "cc")?,
            bcc: parse_address_list(args, "bcc")?,
            from: parse_address(args, "from")?,
            reply_to: parse_address(args, "reply_to")?,
            vars,
            attachments: match args.get("attachments") {
                Some(a) => parse_attachments_list(a)?,
                None => Vec::new(),
            },
            headers: match args.get("headers") {
                Some(h) => parse_headers_map(h)?,
                None => Vec::new(),
            },
            smtp_host: smtp.host,
            smtp_port: smtp.port,
            smtp_username: smtp.username,
            smtp_password: smtp.password,
            use_tls: smtp.use_tls,
            tls_accept_invalid_certs: smtp.accept_invalid_certs,
            ca_file: smtp.ca_file,
            timeout_ms: parse_number(args, "timeout_ms")?.unwrap_or(defaults.timeout_ms),
            max_retry: parse_number(args, "max_retry")?.unwrap_or(defaults.max_retry),
            retry_backoff_ms: parse_number(args, "retry_backoff_ms")?
                .unwrap_or(defaults.retry_backoff_ms),
            strict_vars: crate::core::lenient::bool_arg(args, "strict_vars")?.unwrap_or(false),
            dry_run: crate::core::lenient::dry_run(args)?,
            format_output: parse_format(args)?,
        })
    }
}

impl MailTestOptions {
    pub fn from_args(args: &Args) -> Result<Self> {
        let smtp = parse_smtp_args(args)?;
        let defaults = Self::default();
        let connection_only =
            crate::core::lenient::bool_arg(args, "connection_only")?.unwrap_or(false);
        let send_test_email =
            crate::core::lenient::bool_arg(args, "send_test_email")?.unwrap_or(false);
        if connection_only && send_test_email {
            bail!("connection_only=true and send_test_email=true conflict; choose one");
        }
        if !send_test_email {
            let mut message_args: Vec<&str> = ["to", "from", "subject", "text_body", "html_body"]
                .into_iter()
                .filter(|k| args.contains_key(*k))
                .collect();
            message_args.sort();
            if let Some(k) = message_args.first() {
                bail!("{k} is only used with send_test_email=true");
            }
        } else {
            let blank = |k: &str| args.get(k).is_some_and(|v| v.trim().is_empty());
            if blank("text_body") && (blank("html_body") || !args.contains_key("html_body")) {
                bail!("text_body is empty; the test message needs a body");
            }
            if blank("subject") {
                bail!("subject is empty");
            }
        }
        Ok(Self {
            smtp_host: smtp.host,
            smtp_port: smtp.port,
            smtp_username: smtp.username,
            smtp_password: smtp.password,
            use_tls: smtp.use_tls,
            tls_accept_invalid_certs: smtp.accept_invalid_certs,
            ca_file: smtp.ca_file,
            connection_only,
            send_test_email,
            max_retry: parse_number(args, "max_retry")?.unwrap_or(defaults.max_retry),
            retry_backoff_ms: parse_number(args, "retry_backoff_ms")?
                .unwrap_or(defaults.retry_backoff_ms),
            timeout_ms: parse_number(args, "timeout_ms")?.unwrap_or(defaults.timeout_ms),
            to: parse_address_list(args, "to")?,
            from: parse_address(args, "from")?,
            subject: args.get("subject").cloned().or(defaults.subject),
            text_body: args.get("text_body").cloned().or(defaults.text_body),
            html_body: args.get("html_body").cloned(),
            format_output: parse_format(args)?,
        })
    }

    fn smtp_args(&self) -> SmtpArgs {
        SmtpArgs {
            host: self.smtp_host.clone(),
            port: self.smtp_port,
            username: self.smtp_username.clone(),
            password: self.smtp_password.clone(),
            use_tls: self.use_tls.clone(),
            accept_invalid_certs: self.tls_accept_invalid_certs,
            ca_file: self.ca_file.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// SMTP settings: arguments, then environment variables, then the active
// stored profile.

/// The settings a session uses, after fallbacks.
#[derive(Clone, Debug)]
struct SmtpSettings {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    use_tls: TlsMode,
    accept_invalid_certs: bool,
    /// Extra trusted CA certificates (PEM) from `ca_file`.
    ca_pem: Option<Vec<u8>>,
    /// Sender fallback: `MAIL_FROM`, or the profile's `from`.
    from: Option<MailAddress>,
    /// Reply-To fallback from the profile.
    reply_to: Option<MailAddress>,
    warnings: Vec<String>,
}

impl SmtpSettings {
    fn has_credentials(&self) -> bool {
        self.username.is_some() && self.password.is_some()
    }
}

/// Why SMTP settings could not be resolved.
#[derive(Debug)]
enum SettingsError {
    /// No host anywhere (argument, environment or active profile).
    MissingHost(String),
    /// A fallback value is unusable (bad environment variable, unreadable
    /// profile store).
    Invalid(String),
    /// `MAIL_FROM` or the profile's sender is not a valid address.
    InvalidFrom(String),
    /// The profile's password cannot be read from the OS keyring.
    Keyring(String),
}

fn env_var(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(v) = test_config_dir::env(name) {
        return v.filter(|v| !v.is_empty());
    }
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn default_port(mode: &TlsMode) -> u16 {
    match mode {
        TlsMode::None => 25,
        TlsMode::StartTls => 587,
        TlsMode::Tls => 465,
    }
}

/// Resolves the SMTP settings. Arguments win. Without `smtp_host`, the
/// `MAIL_SMTP_*` and `MAIL_FROM` environment variables are used when
/// `MAIL_SMTP_HOST` is set; otherwise the active stored profile supplies
/// every setting the arguments leave out (and the environment is not read).
fn resolve_smtp(a: &SmtpArgs) -> std::result::Result<SmtpSettings, SettingsError> {
    let env_host = env_var("MAIL_SMTP_HOST");
    let mut s = if a.host.is_some() || env_host.is_some() {
        let host = match a.host.clone() {
            Some(h) => h,
            None => {
                let h = env_host.unwrap_or_default();
                check_smtp_host(&h)
                    .map_err(|e| SettingsError::Invalid(format!("MAIL_SMTP_HOST: {e}")))?;
                h
            }
        };
        let use_tls = a.use_tls.clone().unwrap_or(TlsMode::StartTls);
        let port = match (a.port, env_var("MAIL_SMTP_PORT")) {
            (Some(p), _) => p,
            (None, Some(p)) => parse_port("MAIL_SMTP_PORT", &p).map_err(SettingsError::Invalid)?,
            (None, None) => default_port(&use_tls),
        };
        let from = match env_var("MAIL_FROM") {
            Some(f) => Some(
                MailAddress::from_str(f.trim())
                    .map_err(|e| SettingsError::InvalidFrom(format!("MAIL_FROM: {e}")))?,
            ),
            None => None,
        };
        SmtpSettings {
            host,
            port,
            username: a.username.clone().or_else(|| env_var("MAIL_SMTP_USERNAME")),
            password: a.password.clone().or_else(|| env_var("MAIL_SMTP_PASSWORD")),
            use_tls,
            accept_invalid_certs: a.accept_invalid_certs.unwrap_or(false),
            ca_pem: a.ca_file.as_ref().map(|c| c.pem.clone()),
            from,
            reply_to: None,
            warnings: Vec::new(),
        }
    } else {
        let profiles = load_profiles().map_err(|e| {
            SettingsError::Invalid(format!("cannot read stored SMTP profiles: {e}"))
        })?;
        let active: Vec<&SmtpProfile> = profiles.iter().filter(|p| p.is_active).collect();
        let p = match active.as_slice() {
            [] => {
                return Err(SettingsError::MissingHost(
                    "SMTP host not configured: pass smtp_host=, set MAIL_SMTP_HOST, or \
                     activate a stored profile (mail://config action=activate)"
                        .to_string(),
                ));
            }
            [p] => *p,
            _ => {
                return Err(SettingsError::Invalid(
                    "more than one stored SMTP profile is active; activate one with \
                     mail://config action=activate"
                        .to_string(),
                ));
            }
        };
        let bad = |what: &str| {
            SettingsError::Invalid(format!("stored profile '{}' has an invalid {what}", p.name))
        };
        check_smtp_host(&p.smtp_host).map_err(|_| bad("smtp_host"))?;
        let profile_tls = TlsMode::from_str(&p.use_tls).map_err(|_| bad("use_tls"))?;
        if p.smtp_port == 0 {
            return Err(bad("smtp_port"));
        }
        let mut warnings = vec![format!("Using stored SMTP profile '{}'.", p.name)];
        let password = if a.password.is_some() {
            a.password.clone()
        } else if let Some(reference) = &p.smtp_password_ref {
            let account =
                mail_secrets::account_of(reference).ok_or_else(|| bad("smtp_password_ref"))?;
            match mail_secrets::store().get(account) {
                Ok(Some(pw)) => Some(pw),
                Ok(None) => {
                    return Err(SettingsError::Keyring(format!(
                        "the password of stored profile '{}' is missing from the OS keyring; \
                         set it again with mail://config action=set smtp_password=",
                        p.name
                    )));
                }
                Err(e) => {
                    return Err(SettingsError::Keyring(format!(
                        "cannot read the password of stored profile '{}': {e}; pass \
                         smtp_password= instead",
                        p.name
                    )));
                }
            }
        } else if p.smtp_password_encrypted.is_some() {
            warnings.push(format!(
                "Profile '{}' stores its password base64-encoded (legacy); run mail://config \
                 action=set profile={} to move it to the OS keyring.",
                p.name, p.name
            ));
            Some(p.decrypt_password().ok_or_else(|| bad("smtp_password"))?)
        } else {
            None
        };
        let address = |v: &Option<String>, what: &str| match v {
            Some(addr) => MailAddress::from_str(addr).map(Some).map_err(|_| {
                SettingsError::InvalidFrom(format!(
                    "stored profile '{}' has an invalid {what}: {addr:?}",
                    p.name
                ))
            }),
            None => Ok(None),
        };
        SmtpSettings {
            host: p.smtp_host.clone(),
            port: a.port.unwrap_or(p.smtp_port),
            username: a.username.clone().or_else(|| p.smtp_username.clone()),
            password,
            use_tls: a.use_tls.clone().unwrap_or(profile_tls),
            // A ca_file asks for verification, whatever the profile says.
            accept_invalid_certs: a
                .accept_invalid_certs
                .unwrap_or(p.tls_accept_invalid_certs && a.ca_file.is_none()),
            ca_pem: a.ca_file.as_ref().map(|c| c.pem.clone()),
            from: address(&p.from, "from")?,
            reply_to: address(&p.reply_to, "reply_to")?,
            warnings,
        }
    };

    if s.ca_pem.is_some() && matches!(s.use_tls, TlsMode::None) {
        return Err(SettingsError::Invalid(
            "ca_file conflicts with use_tls=none, which uses no TLS".to_string(),
        ));
    }
    if s.username.is_some() != s.password.is_some() {
        s.warnings.push(
            "Only one of smtp_username and smtp_password is set; the session is not \
             authenticated."
                .to_string(),
        );
    }
    if s.has_credentials() && matches!(s.use_tls, TlsMode::None) {
        s.warnings
            .push("use_tls=none: the password is sent unencrypted.".to_string());
    }
    if s.accept_invalid_certs && !matches!(s.use_tls, TlsMode::None) {
        s.warnings.push(
            "tls_accept_invalid_certs=true: the server certificate is not verified.".to_string(),
        );
    }
    Ok(s)
}

/// The host to connect to: an IPv6 literal loses its brackets.
fn connect_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn build_transport(
    s: &SmtpSettings,
    timeout: std::time::Duration,
) -> std::result::Result<SmtpTransport, lettre::transport::smtp::Error> {
    use lettre::transport::smtp::client::TlsParameters;
    let host = connect_host(&s.host);
    let mut builder = SmtpTransport::builder_dangerous(host)
        .port(s.port)
        .timeout(Some(timeout));
    builder = match s.use_tls {
        TlsMode::None => builder.tls(Tls::None),
        ref mode => {
            let mut params = TlsParameters::builder(host.to_string())
                .dangerous_accept_invalid_certs(s.accept_invalid_certs);
            if let Some(pem) = &s.ca_pem {
                params = params.add_root_certificate(
                    lettre::transport::smtp::client::Certificate::from_pem(pem)?,
                );
            }
            let params = params.build()?;
            builder.tls(match mode {
                TlsMode::StartTls => Tls::Required(params),
                _ => Tls::Wrapper(params),
            })
        }
    };
    if let (Some(user), Some(pass)) = (&s.username, &s.password) {
        builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    Ok(builder.build())
}

// ---------------------------------------------------------------------------
// Deadlines, retries and error classification.

/// `now + ms`, saturating far in the future instead of overflowing.
fn deadline_after(ms: u64) -> std::time::Instant {
    let now = std::time::Instant::now();
    now.checked_add(std::time::Duration::from_millis(ms))
        .unwrap_or_else(|| now + std::time::Duration::from_secs(365 * 24 * 3600))
}

/// Runs `f` on a worker thread and waits for it until `deadline`. `None`
/// means the deadline passed (the worker is abandoned; its socket timeout
/// ends it soon after).
fn run_until<T: Send + 'static>(
    deadline: std::time::Instant,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<std::result::Result<T, String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver is gone only when the deadline already passed.
        let _ = tx.send(f());
    });
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(v) => Some(Ok(v)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Some(Err("the SMTP worker stopped unexpectedly".to_string()))
        }
    }
}

/// What kind of failure an SMTP attempt had.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Failure {
    Timeout,
    Tls,
    Auth,
    Rejected,
    Transient,
    Connection,
    Dns,
    Internal,
}

impl Failure {
    /// Worth another attempt (when max_retry allows).
    fn retryable(self) -> bool {
        matches!(self, Failure::Transient | Failure::Connection)
    }

    fn send_code(self) -> &'static str {
        match self {
            Failure::Timeout => MAIL_SEND_TIMEOUT,
            Failure::Tls => MAIL_SEND_SMTP_TLS_ERROR,
            Failure::Auth => MAIL_SEND_SMTP_AUTH_FAILED,
            Failure::Rejected => MAIL_SEND_SMTP_REJECTED,
            Failure::Transient => MAIL_SEND_SMTP_TRANSIENT_FAILED,
            Failure::Connection | Failure::Dns => MAIL_SEND_SMTP_CONNECTION_FAILED,
            Failure::Internal => MAIL_SEND_INTERNAL_ERROR,
        }
    }

    fn test_code(self) -> &'static str {
        match self {
            Failure::Timeout => MAIL_TEST_TIMEOUT,
            Failure::Tls => MAIL_TEST_TLS_ERROR,
            Failure::Auth => MAIL_TEST_AUTH_FAILED,
            Failure::Rejected => MAIL_TEST_SEND_REJECTED,
            Failure::Transient => MAIL_TEST_TRANSIENT_FAILED,
            Failure::Connection => MAIL_TEST_CONNECTION_FAILED,
            Failure::Dns => MAIL_TEST_DNS_ERROR,
            Failure::Internal => MAIL_TEST_INTERNAL_ERROR,
        }
    }
}

/// Classifies an SMTP error. With rustls the TLS handshake runs on the
/// first read or write, so a failed handshake (bad certificate, a server
/// that does not speak TLS) arrives as an I/O error of kind InvalidData or
/// UnexpectedEof; `tls` says whether the session uses TLS.
fn classify(e: &lettre::transport::smtp::Error, tls: bool) -> Failure {
    if e.is_timeout() {
        return Failure::Timeout;
    }
    if e.is_tls() {
        return Failure::Tls;
    }
    if tls && e.status().is_none() && !e.is_client() {
        let mut source = std::error::Error::source(e);
        while let Some(err) = source {
            if let Some(io) = err.downcast_ref::<std::io::Error>() {
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
                ) {
                    return Failure::Tls;
                }
            }
            source = err.source();
        }
    }
    if let Some(code) = e.status() {
        return match code.to_string().as_str() {
            // 530 authentication required, 534/538 mechanism or encryption
            // required, 535 credentials invalid.
            "530" | "534" | "535" | "538" => Failure::Auth,
            _ if e.is_permanent() => Failure::Rejected,
            _ => Failure::Transient,
        };
    }
    if e.is_client() {
        let msg = e.to_string();
        return if msg.contains("STARTTLS") {
            Failure::Tls
        } else if msg.to_ascii_lowercase().contains("authentication") {
            Failure::Auth
        } else {
            Failure::Internal
        };
    }
    Failure::Connection
}

fn smtp_failure(e: &lettre::transport::smtp::Error, tls: bool) -> (Failure, String) {
    let kind = classify(e, tls);
    let mut msg = e.to_string();
    // Name the underlying cause (for example the certificate problem).
    let mut source = std::error::Error::source(e);
    while let Some(err) = source {
        let text = err.to_string();
        if !msg.contains(&text) {
            msg = format!("{msg}: {text}");
        }
        source = err.source();
    }
    if kind == Failure::Tls && !msg.to_ascii_lowercase().contains("tls") {
        msg = format!("TLS failed: {msg}");
    }
    (kind, msg)
}

/// The message for an attempt that ran out of time.
fn timeout_message(s: &SmtpSettings, timeout_ms: u64, sending: bool) -> String {
    let outcome = if sending {
        "; the message may or may not have been delivered"
    } else {
        ""
    };
    format!(
        "no complete answer from {}:{} within timeout_ms={}{}",
        s.host, s.port, timeout_ms, outcome
    )
}

/// Sleeps `backoff_ms * attempt`, never past the deadline. Returns false
/// when no time is left for another attempt.
fn backoff(deadline: std::time::Instant, backoff_ms: u64, attempt: u32) -> bool {
    let wait = std::time::Duration::from_millis(backoff_ms.saturating_mul(u64::from(attempt)));
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if wait >= remaining {
        return false;
    }
    std::thread::sleep(wait);
    true
}

/// Result of an attempt loop: the attempts made and the server's last reply
/// or the failure.
struct Attempts<T> {
    attempts: u32,
    outcome: std::result::Result<T, (Failure, String)>,
}

/// Runs `attempt` (one SMTP session) until it succeeds, fails for good, the
/// retries are used up, or the deadline passes.
fn with_retries<T: Send + 'static>(
    s: &SmtpSettings,
    timeout_ms: u64,
    max_retry: u32,
    backoff_ms: u64,
    sending: bool,
    attempt: impl Fn(SmtpTransport) -> std::result::Result<T, (Failure, String)>
    + Send
    + Sync
    + Clone
    + 'static,
) -> Attempts<T> {
    let deadline = deadline_after(timeout_ms);
    let mut attempts = 0;
    loop {
        attempts += 1;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Attempts {
                attempts,
                outcome: Err((Failure::Timeout, timeout_message(s, timeout_ms, false))),
            };
        }
        let transport = match build_transport(s, remaining) {
            Ok(t) => t,
            Err(e) => {
                return Attempts {
                    attempts,
                    outcome: Err((
                        classify(&e, false),
                        format!("cannot set up the SMTP client: {e}"),
                    )),
                };
            }
        };
        let f = attempt.clone();
        let failure = match run_until(deadline, move || f(transport)) {
            None => (Failure::Timeout, timeout_message(s, timeout_ms, sending)),
            Some(Err(msg)) => (Failure::Internal, msg),
            Some(Ok(Ok(v))) => {
                return Attempts {
                    attempts,
                    outcome: Ok(v),
                };
            }
            Some(Ok(Err((Failure::Timeout, _)))) => {
                (Failure::Timeout, timeout_message(s, timeout_ms, sending))
            }
            Some(Ok(Err(failure))) => failure,
        };
        if !failure.0.retryable()
            || attempts > max_retry
            || !backoff(deadline, backoff_ms, attempts)
        {
            return Attempts {
                attempts,
                outcome: Err(failure),
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Validation and message building.

#[derive(Debug, thiserror::Error)]
enum MailValidationError {
    #[error("At least one recipient (to, cc or bcc) is required")]
    MissingRecipients,
    #[error("subject is required and must not be empty")]
    MissingSubject,
    #[error("A non-empty text_body or html_body is required")]
    MissingBody,
    #[error("Invalid email address: {0}")]
    InvalidAddress(String),
    #[error("Header {0} cannot be set with a header argument")]
    HeaderConflict(String),
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    #[error("Invalid timeout: {0}")]
    InvalidTimeout(String),
    #[error("Invalid retry configuration: {0}")]
    InvalidRetryConfig(String),
    #[error("Attachment not found: {0}")]
    AttachmentMissing(String),
    #[error("Attachment I/O error: {0}")]
    AttachmentIoError(String),
    #[error("Attachments total more than 100 MB")]
    AttachmentsTooLarge,
}

impl MailValidationError {
    pub fn code(&self) -> String {
        match self {
            MailValidationError::MissingRecipients => MAIL_SEND_MISSING_RECIPIENTS,
            MailValidationError::MissingSubject => MAIL_SEND_MISSING_SUBJECT,
            MailValidationError::MissingBody => MAIL_SEND_MISSING_BODY,
            MailValidationError::InvalidAddress(_) => MAIL_SEND_INVALID_ADDRESS,
            MailValidationError::HeaderConflict(_) => MAIL_SEND_HEADER_CONFLICT,
            MailValidationError::InvalidHeader(_) => MAIL_SEND_INVALID_HEADER,
            MailValidationError::InvalidTimeout(_) => MAIL_SEND_INVALID_TIMEOUT,
            MailValidationError::InvalidRetryConfig(_) => MAIL_SEND_INVALID_RETRY_CONFIG,
            MailValidationError::AttachmentMissing(_) => MAIL_SEND_ATTACHMENT_MISSING,
            MailValidationError::AttachmentIoError(_) => MAIL_SEND_ATTACHMENT_IO_ERROR,
            MailValidationError::AttachmentsTooLarge => MAIL_SEND_ATTACHMENTS_TOO_LARGE,
        }
        .to_string()
    }
}

/// Headers the message itself sets; a header argument cannot replace them.
const RESERVED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "reply-to",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
];

/// Checks extra headers: a reserved name is a conflict; a name that is not
/// printable ASCII without `:`, or a value with a line break, is invalid.
fn check_headers(headers: &[(String, String)]) -> std::result::Result<(), MailValidationError> {
    for (name, value) in headers {
        if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(MailValidationError::HeaderConflict(name.clone()));
        }
        if name.is_empty()
            || name.len() > 76
            || !name.bytes().all(|b| (33..=126).contains(&b) && b != b':')
        {
            return Err(MailValidationError::InvalidHeader(format!(
                "{name:?} is not a valid header name"
            )));
        }
        if value.contains(['\r', '\n']) {
            return Err(MailValidationError::InvalidHeader(format!(
                "the value of {name} contains a line break"
            )));
        }
    }
    Ok(())
}

fn validate_send_options(opts: &MailSendOptions) -> std::result::Result<(), MailValidationError> {
    if opts.to.is_empty() && opts.cc.is_empty() && opts.bcc.is_empty() {
        return Err(MailValidationError::MissingRecipients);
    }
    if opts.subject.trim().is_empty() {
        return Err(MailValidationError::MissingSubject);
    }
    let non_empty = |b: &Option<String>| b.as_ref().is_some_and(|b| !b.trim().is_empty());
    if !non_empty(&opts.text_body) && !non_empty(&opts.html_body) {
        return Err(MailValidationError::MissingBody);
    }
    for addr in opts
        .to
        .iter()
        .chain(&opts.cc)
        .chain(&opts.bcc)
        .chain(&opts.from)
        .chain(&opts.reply_to)
    {
        validate_email_address(&addr.email)
            .map_err(|_| MailValidationError::InvalidAddress(addr.email.clone()))?;
    }
    check_headers(&opts.headers)?;
    if opts.timeout_ms == 0 {
        return Err(MailValidationError::InvalidTimeout(
            "timeout_ms must be greater than 0".to_string(),
        ));
    }
    if opts.max_retry > MAX_RETRY_LIMIT {
        return Err(MailValidationError::InvalidRetryConfig(format!(
            "max_retry cannot exceed {MAX_RETRY_LIMIT}"
        )));
    }
    Ok(())
}

/// Checks that every attachment is a readable regular file and that they
/// total at most 100 MB.
fn validate_attachments(
    attachments: &[AttachmentSpec],
) -> std::result::Result<(), MailValidationError> {
    const MAX_ATTACHMENT_SIZE: u64 = 100 * 1024 * 1024;
    let mut total_size = 0u64;
    for attachment in attachments {
        let path = Path::new(&attachment.path);
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(MailValidationError::AttachmentMissing(
                    attachment.path.clone(),
                ));
            }
            Err(e) => {
                return Err(MailValidationError::AttachmentIoError(format!(
                    "cannot access {}: {e}",
                    attachment.path
                )));
            }
        };
        if !metadata.is_file() {
            return Err(MailValidationError::AttachmentIoError(format!(
                "{} is not a regular file",
                attachment.path
            )));
        }
        if let Err(e) = fs::File::open(path) {
            return Err(MailValidationError::AttachmentIoError(format!(
                "cannot read {}: {e}",
                attachment.path
            )));
        }
        total_size = total_size.saturating_add(metadata.len());
        if total_size > MAX_ATTACHMENT_SIZE {
            return Err(MailValidationError::AttachmentsTooLarge);
        }
    }
    Ok(())
}

/// Builds the message. Bcc recipients are in the envelope only: lettre
/// removes the Bcc header.
fn build_message(
    opts: &MailSendOptions,
    from: &MailAddress,
    reply_to: Option<&MailAddress>,
) -> std::result::Result<Message, (String, String)> {
    use lettre::message::header::{ContentDisposition, ContentType, HeaderName, HeaderValue};
    use lettre::message::{MultiPart, SinglePart};

    let internal =
        |e: &dyn std::fmt::Display| (MAIL_SEND_INTERNAL_ERROR.to_string(), e.to_string());
    let mailbox = |a: &MailAddress| {
        a.to_mailbox()
            .map_err(|e| (MAIL_SEND_INVALID_ADDRESS.to_string(), format!("{e:#}")))
    };

    // lettre adds Date itself but not Message-ID; generate one so the
    // reported message_id is the one the message carries.
    let mut builder = Message::builder()
        .message_id(None)
        .from(mailbox(from)?)
        .subject(opts.subject.clone());
    for addr in &opts.to {
        builder = builder.to(mailbox(addr)?);
    }
    for addr in &opts.cc {
        builder = builder.cc(mailbox(addr)?);
    }
    for addr in &opts.bcc {
        builder = builder.bcc(mailbox(addr)?);
    }
    if let Some(r) = reply_to {
        builder = builder.reply_to(mailbox(r)?);
    }
    for (name, value) in &opts.headers {
        let header = HeaderName::new_from_ascii(name.clone()).map_err(|_| {
            (
                MAIL_SEND_INVALID_HEADER.to_string(),
                format!("{name:?} is not a valid header name"),
            )
        })?;
        builder = builder.raw_header(HeaderValue::new(header, value.clone()));
    }

    // Text, HTML, or both as multipart/alternative.
    enum Body {
        One(SinglePart),
        Both(MultiPart),
    }
    let text = opts.text_body.clone().filter(|b| !b.trim().is_empty());
    let html = opts.html_body.clone().filter(|b| !b.trim().is_empty());
    let body = match (text, html) {
        (Some(t), Some(h)) => Body::Both(MultiPart::alternative_plain_html(t, h)),
        (Some(t), None) => Body::One(SinglePart::plain(t)),
        (None, Some(h)) => Body::One(SinglePart::html(h)),
        (None, None) => {
            return Err((
                MAIL_SEND_MISSING_BODY.to_string(),
                MailValidationError::MissingBody.to_string(),
            ));
        }
    };
    let message = if opts.attachments.is_empty() {
        match body {
            Body::One(part) => builder.singlepart(part),
            Body::Both(parts) => builder.multipart(parts),
        }
    } else {
        let mut mixed = match body {
            Body::One(part) => MultiPart::mixed().singlepart(part),
            Body::Both(parts) => MultiPart::mixed().multipart(parts),
        };
        for attachment in &opts.attachments {
            let content = fs::read(&attachment.path).map_err(|e| {
                (
                    MAIL_SEND_ATTACHMENT_IO_ERROR.to_string(),
                    format!("cannot read attachment {}: {e}", attachment.path),
                )
            })?;
            let content_type =
                ContentType::parse(&attachment.get_content_type()).map_err(|e| internal(&e))?;
            mixed = mixed.singlepart(
                SinglePart::builder()
                    .header(content_type)
                    .header(ContentDisposition::attachment(&attachment.get_filename()))
                    .body(content),
            );
        }
        builder.multipart(mixed)
    };
    message.map_err(|e| internal(&e))
}

// ---------------------------------------------------------------------------
// Verbs.

/// Sends `opts`. `default_from` is the last sender fallback (a template's
/// built-in sender).
fn deliver(opts: MailSendOptions, default_from: Option<&str>) -> MailSendResponse {
    let mut response = MailSendResponse::new(&opts);
    let fail = |mut r: MailSendResponse, code: &str, msg: String| {
        r.error = Some((code.to_string(), msg));
        r
    };

    if let Err(e) = validate_send_options(&opts) {
        return fail(response, &e.code(), e.to_string());
    }
    if let Err(e) = validate_attachments(&opts.attachments) {
        return fail(response, &e.code(), e.to_string());
    }

    let settings = match resolve_smtp(&opts.smtp_args()) {
        Ok(s) => s,
        Err(SettingsError::MissingHost(m)) | Err(SettingsError::Invalid(m)) => {
            return fail(response, MAIL_SEND_SMTP_NOT_CONFIGURED, m);
        }
        Err(SettingsError::InvalidFrom(m)) => {
            return fail(response, MAIL_SEND_INVALID_ADDRESS, m);
        }
        Err(SettingsError::Keyring(m)) => return fail(response, MAIL_SEND_KEYRING_ERROR, m),
    };
    response.query["use_tls"] = json!(settings.use_tls.as_str());
    response.warnings.extend(settings.warnings.iter().cloned());

    let from = match opts.from.clone().or_else(|| settings.from.clone()) {
        Some(f) => f,
        None => match default_from.map(MailAddress::from_str) {
            Some(Ok(f)) => f,
            Some(Err(e)) => return fail(response, MAIL_SEND_INVALID_ADDRESS, e.to_string()),
            None => {
                return fail(
                    response,
                    MAIL_SEND_MISSING_FROM,
                    "No sender: pass from=, set MAIL_FROM, or store from= in the active profile"
                        .to_string(),
                );
            }
        },
    };
    let reply_to = opts.reply_to.clone().or_else(|| settings.reply_to.clone());

    let message = match build_message(&opts, &from, reply_to.as_ref()) {
        Ok(m) => m,
        Err((code, msg)) => return fail(response, &code, msg),
    };
    let message_id = message
        .headers()
        .get_raw("Message-ID")
        .map(|id| id.trim().to_string());

    let tls = !matches!(settings.use_tls, TlsMode::None);
    let run = with_retries(
        &settings,
        opts.timeout_ms,
        opts.max_retry,
        opts.retry_backoff_ms,
        true,
        move |transport: SmtpTransport| transport.send(&message).map_err(|e| smtp_failure(&e, tls)),
    );
    let (ok, last_response, error) = match run.outcome {
        Ok(reply) => (true, Some(format!("{reply:?}")), None),
        Err((kind, msg)) => (false, None, Some((kind.send_code().to_string(), msg))),
    };
    response.ok = ok;
    response.error = error;
    response.result = Some(MailSendResult {
        message_id: if ok { message_id } else { None },
        smtp_host: settings.host,
        smtp_port: settings.port,
        attempts: run.attempts,
        last_response,
    });
    response
}

/// `mail send`: validates the message, resolves the SMTP settings and sends
/// it, retrying transient failures, all within `timeout_ms`.
pub fn send(opts: MailSendOptions) -> Result<MailSendResponse> {
    Ok(deliver(opts, None))
}

/// The error for a template that failed to render: rendering fails only
/// when `strict_vars=true` and variables are missing.
fn render_failure(template: &str, e: &anyhow::Error) -> (String, String) {
    let msg = e.to_string();
    let vars = msg.strip_prefix("Missing variables: ").unwrap_or(&msg);
    (
        MAIL_SEND_TEMPLATE_MISSING_VAR.to_string(),
        format!("Template '{template}' requires missing variables: {vars}"),
    )
}

/// `mail send_template`: renders a built-in template and sends it like
/// `send`, or only renders and checks it with `dry_run=true`.
pub fn send_template(opts: MailSendTemplateOptions) -> Result<MailSendTemplateResponse> {
    let mut response = MailSendTemplateResponse::new(&opts);

    let template = match InMemoryTemplateStore::new().get_template(
        &opts.template,
        opts.locale.as_deref(),
        None,
    ) {
        Ok(t) => t,
        Err(_) => {
            response.error = Some((
                MAIL_SEND_TEMPLATE_NOT_FOUND.to_string(),
                format!(
                    "Mail template '{}' was not found (available: welcome, password_reset).",
                    opts.template
                ),
            ));
            return Ok(response);
        }
    };
    if opts.locale.is_some() && template.locale != opts.locale {
        response.warnings.push(format!(
            "Locale '{}' is not available for template '{}'; the default was used.",
            opts.locale.as_deref().unwrap_or_default(),
            opts.template
        ));
    }

    if opts.to.is_empty() {
        response.error = Some((
            MAIL_SEND_MISSING_RECIPIENTS.to_string(),
            "At least one recipient in 'to' is required".to_string(),
        ));
        return Ok(response);
    }

    let render = |text: &Option<String>, html: bool| match text {
        Some(t) => render_template(t, &opts.vars, opts.strict_vars, html)
            .map(Some)
            .map_err(|e| render_failure(&opts.template, &e)),
        None => Ok(None),
    };
    let rendered = render(&Some(template.subject_template.clone()), false).and_then(|subject| {
        Ok((
            subject.unwrap_or_default(),
            render(&template.text_body_template, false)?,
            render(&template.html_body_template, true)?,
        ))
    });
    let (subject, text_body, html_body) = match rendered {
        Ok(r) => r,
        Err(e) => {
            response.error = Some(e);
            return Ok(response);
        }
    };

    response.rendered = Some(MailSendTemplateRendered {
        subject: subject.clone(),
        text_body: text_body.clone(),
        html_body: html_body.clone(),
    });

    // Template default headers first, then the call's headers.
    let mut headers: Vec<(String, String)> = template
        .default_headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    headers.sort();
    headers.extend(opts.headers.iter().cloned());
    if let Err(e) = check_headers(&opts.headers) {
        let code = match e {
            MailValidationError::HeaderConflict(_) => {
                MAIL_SEND_TEMPLATE_HEADER_CONFLICT.to_string()
            }
            ref other => other.code(),
        };
        response.error = Some((code, e.to_string()));
        return Ok(response);
    }

    let mut attachments = template.default_attachments.clone();
    attachments.extend(opts.attachments.iter().cloned());

    let mail_opts = MailSendOptions {
        to: opts.to,
        cc: opts.cc,
        bcc: opts.bcc,
        from: opts.from,
        reply_to: opts.reply_to.or_else(|| {
            template
                .default_reply_to
                .as_ref()
                .map(|addr| MailAddress::new(addr.clone()))
        }),
        subject,
        text_body,
        html_body,
        attachments,
        headers,
        smtp_host: opts.smtp_host,
        smtp_port: opts.smtp_port,
        smtp_username: opts.smtp_username,
        smtp_password: opts.smtp_password,
        use_tls: opts.use_tls,
        tls_accept_invalid_certs: opts.tls_accept_invalid_certs,
        ca_file: opts.ca_file,
        timeout_ms: opts.timeout_ms,
        max_retry: opts.max_retry,
        retry_backoff_ms: opts.retry_backoff_ms,
        format_output: opts.format_output,
    };

    // A dry run checks everything a real send would check before
    // connecting, then stops.
    if opts.dry_run {
        let checked = validate_send_options(&mail_opts)
            .and_then(|_| validate_attachments(&mail_opts.attachments));
        if let Err(e) = checked {
            response.error = Some((e.code(), e.to_string()));
            return Ok(response);
        }
        response.ok = true;
        response
            .warnings
            .push("Dry run: email was not sent.".to_string());
        return Ok(response);
    }

    let sent = deliver(mail_opts, template.default_from.as_deref());
    response.ok = sent.ok;
    response.error = sent.error;
    response.warnings.extend(sent.warnings);
    response.send_result = sent.result.map(|r| MailSendTemplateSendResult {
        mail_send_response: Some(r),
    });
    Ok(response)
}

/// Resolves `host` to its first address, within `deadline`.
fn resolve_host(
    host: &str,
    port: u16,
    deadline: std::time::Instant,
) -> std::result::Result<String, (Failure, String)> {
    use std::net::ToSocketAddrs;
    let target = (connect_host(host).to_string(), port);
    match run_until(deadline, move || {
        target.to_socket_addrs().map(|mut a| a.next())
    }) {
        None => Err((
            Failure::Timeout,
            format!("resolving {host} took longer than timeout_ms"),
        )),
        Some(Err(msg)) => Err((Failure::Internal, msg)),
        Some(Ok(Ok(Some(addr)))) => Ok(addr.ip().to_string()),
        Some(Ok(Ok(None))) => Err((Failure::Dns, format!("{host} has no address"))),
        Some(Ok(Err(e))) => Err((Failure::Dns, format!("cannot resolve {host}: {e}"))),
    }
}

/// `mail test`: resolves the server, opens a real SMTP session (TLS and
/// AUTH as configured) and closes it, or sends a test message with
/// `send_test_email=true`, retrying transient failures within `timeout_ms`.
pub fn test(opts: MailTestOptions) -> Result<MailTestResponse> {
    let mut response = MailTestResponse::new(&opts);
    let fail = |mut r: MailTestResponse, code: &str, msg: String| {
        r.error = Some((code.to_string(), msg));
        Ok(r)
    };

    if opts.timeout_ms == 0 {
        return fail(
            response,
            MAIL_TEST_INVALID_TIMEOUT,
            "timeout_ms must be greater than 0".to_string(),
        );
    }
    if opts.max_retry > MAX_RETRY_LIMIT {
        return fail(
            response,
            MAIL_TEST_INVALID_RETRY_CONFIG,
            format!("max_retry cannot exceed {MAX_RETRY_LIMIT}"),
        );
    }

    let settings = match resolve_smtp(&opts.smtp_args()) {
        Ok(s) => s,
        Err(SettingsError::MissingHost(m)) => {
            return fail(response, MAIL_TEST_MISSING_SMTP_HOST, m);
        }
        Err(SettingsError::Invalid(m)) => return fail(response, MAIL_TEST_SMTP_NOT_CONFIGURED, m),
        Err(SettingsError::InvalidFrom(m)) => return fail(response, MAIL_TEST_INVALID_ADDRESS, m),
        Err(SettingsError::Keyring(m)) => return fail(response, MAIL_TEST_KEYRING_ERROR, m),
    };
    response.query["use_tls"] = json!(settings.use_tls.as_str());
    response.warnings.extend(settings.warnings.iter().cloned());

    // The test message, when one is requested.
    let message = if opts.send_test_email {
        if opts.to.is_empty() {
            return fail(
                response,
                MAIL_TEST_SEND_EMAIL_MISSING_RECIPIENTS,
                "send_test_email=true requires a non-empty 'to'".to_string(),
            );
        }
        let Some(from) = opts.from.clone().or_else(|| settings.from.clone()) else {
            return fail(
                response,
                MAIL_TEST_SEND_EMAIL_MISSING_FROM,
                "send_test_email=true requires 'from', MAIL_FROM, or a from= in the active \
                 profile"
                    .to_string(),
            );
        };
        let mail = MailSendOptions {
            to: opts.to.clone(),
            subject: opts
                .subject
                .clone()
                .unwrap_or_else(|| "SMTP test".to_string()),
            text_body: opts.text_body.clone(),
            html_body: opts.html_body.clone(),
            ..MailSendOptions::default()
        };
        match build_message(&mail, &from, settings.reply_to.as_ref()) {
            Ok(m) => Some((m, from)),
            Err((code, msg)) => {
                let code = if code == MAIL_SEND_INVALID_ADDRESS {
                    MAIL_TEST_INVALID_ADDRESS
                } else {
                    MAIL_TEST_INTERNAL_ERROR
                };
                return fail(response, code, msg);
            }
        }
    } else {
        None
    };

    let connection =
        |attempts: u32, ok: bool, resolved_ip: Option<String>, last: Option<String>| {
            MailTestConnectionResult {
                smtp_host: settings.host.clone(),
                smtp_port: settings.port,
                resolved_ip,
                use_tls: settings.use_tls.as_str().to_string(),
                tls_established: ok && !matches!(settings.use_tls, TlsMode::None),
                auth_attempted: settings.has_credentials(),
                auth_succeeded: ok && settings.has_credentials(),
                attempts,
                last_response: last,
            }
        };

    let started = std::time::Instant::now();
    let resolved_ip = match resolve_host(
        &settings.host,
        settings.port,
        deadline_after(opts.timeout_ms),
    ) {
        Ok(ip) => ip,
        Err((kind, msg)) => {
            response.connection = Some(connection(0, false, None, None));
            return fail(response, kind.test_code(), msg);
        }
    };
    // DNS time counts against timeout_ms.
    let spent = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let left_ms = opts.timeout_ms.saturating_sub(spent).max(1);

    let tls = !matches!(settings.use_tls, TlsMode::None);
    let (run, sent_from) = match message {
        Some((message, from)) => {
            let run = with_retries(
                &settings,
                left_ms,
                opts.max_retry,
                opts.retry_backoff_ms,
                true,
                move |t: SmtpTransport| {
                    t.send(&message)
                        .map(|r| format!("{r:?}"))
                        .map_err(|e| smtp_failure(&e, tls))
                },
            );
            (run, Some(from))
        }
        None => {
            let run = with_retries(
                &settings,
                left_ms,
                opts.max_retry,
                opts.retry_backoff_ms,
                false,
                move |t: SmtpTransport| match t.test_connection() {
                    Ok(true) => Ok("Connection test completed".to_string()),
                    Ok(false) => Err((
                        Failure::Connection,
                        "the server did not answer NOOP".to_string(),
                    )),
                    Err(e) => Err(smtp_failure(&e, tls)),
                },
            );
            (run, None)
        }
    };

    match run.outcome {
        Ok(last) => {
            response.ok = true;
            response.connection = Some(connection(
                run.attempts,
                true,
                Some(resolved_ip),
                Some(if sent_from.is_some() {
                    "Test message accepted".to_string()
                } else {
                    last.clone()
                }),
            ));
            if let Some(from) = sent_from {
                let to: Vec<String> = opts.to.iter().map(|t| t.email.clone()).collect();
                response.send_test_email = Some(MailTestSendEmailResult {
                    attempted: true,
                    envelope_from: Some(from.email),
                    envelope_to: to.clone(),
                    accepted_recipients: to,
                    rejected_recipients: Vec::new(),
                    last_response: Some(last),
                });
            }
        }
        Err((kind, msg)) => {
            response.connection = Some(connection(run.attempts, false, Some(resolved_ip), None));
            if let Some(from) = sent_from {
                response.send_test_email = Some(MailTestSendEmailResult {
                    attempted: true,
                    envelope_from: Some(from.email),
                    envelope_to: opts.to.iter().map(|t| t.email.clone()).collect(),
                    accepted_recipients: Vec::new(),
                    rejected_recipients: Vec::new(),
                    last_response: None,
                });
            }
            response.error = Some((kind.test_code().to_string(), msg));
        }
    }
    Ok(response)
}

// Mail Handle Implementation
#[derive(Debug)]
pub struct MailHandle {
    _url: Url,
}

impl MailHandle {
    pub fn new(url: Url) -> Self {
        Self { _url: url }
    }

    /// Handle the in-URL help forms (`mail://--help`, `mail://-h`, the `help`
    /// verb, and `mail://--help=VERB`) by printing the handle help metadata.
    /// The parser turns `mail://--help=VERB` into the `help` verb with verb=VERB.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let requested = if verb == "help" || crate::core::help::is_help_flag(verb) {
            args.get("verb").map(|v| v.as_str())
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        let text = crate::core::help::render_legacy("mail", &MAIL_HELP, self.verbs(), requested);
        write!(io.stdout, "{}", text)?;
        Ok(Some(Status::ok()))
    }

    /// Invalid arguments: prints the reason to stderr and exits 2. Nothing
    /// was done.
    /// The error code is the one the message starts with (`[mail.x] ...`),
    /// or `mail.invalid_argument`. resh prints `Error: [code] message`.
    fn usage_error(verb: &str, msg: impl std::fmt::Display, _io: &mut IoStreams) -> Result<Status> {
        let msg = format!("{msg:#}");
        let (code, msg) = match msg
            .strip_prefix('[')
            .and_then(|rest| rest.split_once("] "))
            .filter(|(code, _)| code.starts_with("mail."))
        {
            Some((code, rest)) => (code.to_string(), rest.to_string()),
            None => (MAIL_INVALID_ARGUMENT.to_string(), msg),
        };
        Ok(Status::coded(
            crate::core::status::exit::USAGE,
            &code,
            format!("Invalid mail {verb} options: {msg}"),
        ))
    }

    /// Checks the argument names, then parses them.
    fn parse<T>(
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
        parse: impl FnOnce(&Args) -> Result<T>,
    ) -> Result<std::result::Result<T, Status>> {
        if let Some(msg) = unknown_arg(verb, args) {
            return Self::usage_error(verb, msg, io).map(Err);
        }
        match parse(args) {
            Ok(opts) => Ok(Ok(opts)),
            Err(e) => Self::usage_error(verb, e, io).map(Err),
        }
    }

    /// Prints the response and turns its error into the exit status.
    fn finish(
        verb: &str,
        output: String,
        ok: bool,
        error: Option<&(String, String)>,
        io: &mut IoStreams,
    ) -> Result<Status> {
        writeln!(io.stdout, "{}", output)?;
        io.stdout.flush()?;
        if ok {
            return Ok(Status::ok());
        }
        Ok(match error {
            Some((code, message)) => Status::coded(exit_code_for(code), code, message),
            None => Status::coded(
                crate::core::status::exit::FAILED,
                MAIL_SEND_INTERNAL_ERROR,
                format!("mail {verb} failed"),
            ),
        })
    }

    fn verb_send(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // send has no dry-run mode. A dry-run request (including the bare
        // `dry_run` word main.rs rewrites to dry_run="true") must never send
        // a real message, so it is refused before any SMTP connection.
        match crate::core::lenient::dry_run(args) {
            Ok(false) => {}
            Ok(true) => {
                return Ok(Status::coded(
                    crate::core::status::exit::USAGE,
                    MAIL_INVALID_ARGUMENT,
                    "mail send does not support dry_run; nothing was sent. Use send_template \
                     with dry_run=true to preview a message.",
                ));
            }
            Err(e) => return Self::usage_error("send", e, io),
        }
        let opts = match Self::parse("send", args, io, MailSendOptions::from_args)? {
            Ok(o) => o,
            Err(st) => return Ok(st),
        };
        let format = opts.format_output.clone();
        let response = send(opts)?;
        let output = match format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        Self::finish("send", output, response.ok, response.error.as_ref(), io)
    }

    fn verb_send_template(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse(
            "send_template",
            args,
            io,
            MailSendTemplateOptions::from_args,
        )? {
            Ok(o) => o,
            Err(st) => return Ok(st),
        };
        let format = opts.format_output.clone();
        let response = send_template(opts)?;
        let output = match format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        Self::finish(
            "send_template",
            output,
            response.ok,
            response.error.as_ref(),
            io,
        )
    }

    fn verb_test(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse("test", args, io, MailTestOptions::from_args)? {
            Ok(o) => o,
            Err(st) => return Ok(st),
        };
        let format = opts.format_output.clone();
        let response = test(opts)?;
        let output = match format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        Self::finish("test", output, response.ok, response.error.as_ref(), io)
    }

    fn verb_config(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let opts = match Self::parse("config", args, io, MailConfigOptions::from_args)? {
            Ok(o) => o,
            Err(st) => return Ok(st),
        };
        let format = opts.format_output.clone();
        let response = config(opts)?;
        let output = match format {
            OutputFormat::Json => response.to_json(),
            OutputFormat::Text => response.to_text(),
        };
        Self::finish("config", output, response.ok, response.error.as_ref(), io)
    }
}

impl Handle for MailHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["send", "send_template", "test", "config"]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&MAIL_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }

        match verb {
            "send" => self.verb_send(args, io),
            "send_template" => self.verb_send_template(args, io),
            "test" => self.verb_test(args, io),
            "config" => self.verb_config(args, io),
            _ => Ok(Status::coded(
                crate::core::status::exit::USAGE,
                MAIL_UNKNOWN_VERB,
                format!(
                    "unknown verb for mail://: {verb} (verbs: {}); nothing was done",
                    self.verbs().join(", ")
                ),
            )),
        }
    }
}

// Registry function
pub fn register(registry: &mut crate::core::Registry) {
    registry.register_scheme("mail", |url| Ok(Box::new(MailHandle::new(url.clone()))));
}

// H14: the profile store is written owner-only and never through a symlink.
#[cfg(test)]
mod private_file_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_0600_replaces_stale_files_and_refuses_symlinks() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("smtp_profiles.json.tmp");
        write_private_file(&p, b"one").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = dir.path().join("victim");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link.tmp");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_private_file(&link, b"x").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
}

// Stage 4: `mail send` has no dry run, so a dry-run request is refused
// instead of sending a real message.
#[cfg(test)]
mod send_dry_run_tests {
    use super::*;

    #[test]
    fn send_refuses_dry_run_without_connecting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let h = MailHandle::new(Url::parse("mail://send").unwrap());
        for v in ["true", "1", "yes", "ON", "maybe"] {
            let args: Args = [
                ("to", "[\"a@example.com\"]"),
                ("subject", "s"),
                ("text_body", "b"),
                ("from", "f@example.com"),
                ("smtp_host", "127.0.0.1"),
                ("smtp_port", port.as_str()),
                ("use_tls", "none"),
                ("dry_run", v),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
            let mut io = IoStreams {
                stdin: &mut i,
                stdout: &mut o,
                stderr: &mut e,
            };
            let st = h.call("send", &args, &mut io).unwrap();
            assert!(!st.ok, "dry_run={v} must fail");
            assert_eq!(st.exit_code(), 2);
            let reason = st.reason.clone().unwrap_or_default();
            if v != "maybe" {
                assert!(reason.contains("does not support dry_run"), "{reason}");
            }
            match listener.accept() {
                Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("dry_run={v} opened an SMTP connection: {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod mail_help_tests {
    use super::*;
    use std::io::Cursor;

    fn call_help(verb: &str) -> (String, Status) {
        call_help_with(verb, Args::new())
    }

    fn call_help_with(verb: &str, args: Args) -> (String, Status) {
        let handle = MailHandle::new(Url::parse("mail://send").unwrap());
        let mut stdin = Cursor::new(Vec::new());
        let mut stdout = Cursor::new(Vec::new());
        let mut stderr = Cursor::new(Vec::new());
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };
        let status = handle.call(verb, &args, &mut io).unwrap();
        (String::from_utf8(stdout.into_inner()).unwrap(), status)
    }

    #[test]
    fn in_url_help_renders_metadata() {
        for verb in ["--help", "-h", "help"] {
            let (out, status) = call_help(verb);
            assert!(status.ok);
            assert!(out.starts_with("Handle: mail"), "{}", out);
        }
    }

    #[test]
    fn in_url_verb_help_renders_verb_metadata() {
        let (out, status) = call_help("--help=send");
        assert!(status.ok);
        assert!(out.contains("Verb: send"), "{}", out);
        assert!(!out.contains("RESOURCE SHELL"));

        // mail://--help=test reaches the handle as the help verb with verb=test
        let mut args = Args::new();
        args.insert("verb".to_string(), "test".to_string());
        let (out, _status) = call_help_with("help", args);
        assert!(out.contains("Verb: test"), "{}", out);
    }
}

#[cfg(test)]
#[path = "mail_fake_smtp.rs"]
mod fake_smtp;

/// Every verb called through the handle against an in-process SMTP server on
/// 127.0.0.1. The profile store and the MAIL_* environment are replaced per
/// thread, so nothing outside a temporary directory is read or written.
#[cfg(test)]
mod mail_verb_tests {
    use super::fake_smtp::{Behavior, FakeSmtp, header};
    use super::*;
    use std::time::{Duration, Instant};

    /// A private profile directory and an empty MAIL_* environment for the
    /// current thread, restored on drop.
    struct Ctx {
        dir: tempfile::TempDir,
        secrets: std::sync::Arc<mail_secrets::MemStore>,
    }

    impl Ctx {
        fn new() -> Self {
            Self::with_env(&[])
        }

        fn with_env(env: &[(&str, &str)]) -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            test_config_dir::set(Some(dir.path().join("cfg/resh/mail")));
            test_config_dir::set_env(Some(env));
            let secrets = std::sync::Arc::new(mail_secrets::MemStore::default());
            mail_secrets::set_test_store(Some(secrets.clone()));
            Self { dir, secrets }
        }

        /// Makes the keyring unavailable for this thread.
        fn no_keyring(&self) {
            mail_secrets::set_test_store(Some(std::sync::Arc::new(mail_secrets::Unavailable)));
        }

        fn secret(&self, account: &str) -> Option<String> {
            self.secrets.0.lock().unwrap().get(account).cloned()
        }

        fn store(&self) -> PathBuf {
            self.dir.path().join("cfg/resh/mail/smtp_profiles.json")
        }

        fn file(&self, name: &str, data: &[u8]) -> String {
            let p = self.dir.path().join(name);
            fs::write(&p, data).unwrap();
            p.display().to_string()
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            test_config_dir::set(None);
            test_config_dir::set_env(None);
            mail_secrets::set_test_store(None);
        }
    }

    struct Out {
        status: Status,
        out: String,
        err: String,
    }

    impl Out {
        fn json(&self) -> Value {
            serde_json::from_str(self.out.trim())
                .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.out))
        }

        fn ok(self) -> Self {
            assert!(
                self.status.ok,
                "{:?}\n{}\n{}",
                self.status, self.out, self.err
            );
            assert_eq!(self.json()["ok"], true);
            self
        }

        /// A failure with a JSON response carrying `code`.
        fn fails(self, exit: i32, code: &str) -> Self {
            assert!(!self.status.ok, "{}", self.out);
            assert_eq!(
                self.status.exit_code(),
                exit,
                "{:?}\n{}",
                self.status,
                self.out
            );
            let v = self.json();
            assert_eq!(v["ok"], false);
            assert_eq!(v["error"]["code"], code, "{}", self.out);
            let reason = self.status.reason.clone().unwrap_or_default();
            assert!(reason.starts_with(&format!("[{code}] ")), "{reason}");
            self
        }

        /// Invalid arguments: exit 2, no JSON, `[mail.invalid_argument]` (or
        /// the given code) naming the problem.
        fn usage(self, needle: &str) -> Self {
            self.usage_code(MAIL_INVALID_ARGUMENT, needle)
        }

        fn usage_code(self, code: &str, needle: &str) -> Self {
            assert_eq!(self.status.exit_code(), 2, "{:?} {}", self.status, self.out);
            assert!(self.out.is_empty(), "no JSON expected: {}", self.out);
            let reason = self.status.reason.clone().unwrap_or_default();
            assert!(reason.starts_with(&format!("[{code}] ")), "{reason}");
            assert!(reason.contains(needle), "{reason:?} lacks {needle:?}");
            self
        }
    }

    fn call(verb: &str, args: &[(&str, &str)]) -> Out {
        let h = MailHandle::new(Url::parse("mail://").unwrap());
        let args: Args = args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        let status = h.call(verb, &args, &mut io).unwrap();
        Out {
            status,
            out: String::from_utf8(o).unwrap(),
            err: String::from_utf8(e).unwrap(),
        }
    }

    /// Arguments for a plain-text session with `server`.
    fn smtp(server: &FakeSmtp) -> Vec<(&'static str, String)> {
        vec![
            ("smtp_host", "127.0.0.1".to_string()),
            ("smtp_port", server.port.to_string()),
            ("use_tls", "none".to_string()),
        ]
    }

    fn with<'a>(
        base: &'a [(&'static str, String)],
        extra: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        base.iter()
            .map(|(k, v)| (*k, v.as_str()))
            .chain(extra.iter().copied())
            .collect()
    }

    /// A port nothing listens on.
    fn closed_port() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port().to_string()
    }

    const MSG: &[(&str, &str)] = &[
        ("to", "alice@example.com"),
        ("from", "resh@example.com"),
        ("subject", "Backup"),
        ("text_body", "Backup done"),
    ];

    fn send_to(server: &FakeSmtp, extra: &[(&str, &str)]) -> Out {
        let base = smtp(server);
        let mut args = with(&base, MSG);
        for (k, v) in extra {
            args.retain(|(a, _)| a != k);
            args.push((k, v));
        }
        call("send", &args)
    }

    /// Bodies of the MIME parts of `data`, keyed by the part headers.
    fn parts(data: &str) -> Vec<(String, String)> {
        let boundary = data
            .split("boundary=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .map(str::to_string);
        let Some(_) = boundary else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for b in data.split("boundary=\"").skip(1) {
            let boundary = b.split('"').next().unwrap();
            for chunk in data.split(&format!("--{boundary}")).skip(1) {
                if let Some((head, body)) = chunk.split_once("\r\n\r\n") {
                    out.push((head.trim().to_string(), body.trim_end().to_string()));
                }
            }
        }
        out
    }

    /// Decodes a quoted-printable body.
    fn unqp(s: &str) -> String {
        let s = s.replace("=\r\n", "");
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'=' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).to_string()
    }

    fn unbase64(s: &str) -> Vec<u8> {
        use base64::Engine;
        let joined: String = s.split_whitespace().collect();
        base64::engine::general_purpose::STANDARD
            .decode(joined)
            .unwrap()
    }

    // --- send: delivery -----------------------------------------------------

    #[test]
    fn send_delivers_plain_text_with_envelope_and_headers() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let r = send_to(
            &server,
            &[
                ("to", "alice@example.com,bob@example.com"),
                ("cc", "carol@example.com"),
                ("bcc", "[\"dave@example.com\"]"),
                ("reply_to", "ops@example.com"),
                ("header_X-Ticket", "1234"),
            ],
        )
        .ok();
        let v = r.json();
        assert_eq!(v["result"]["attempts"], 1);
        assert_eq!(v["result"]["smtp_port"], server.port);
        assert_eq!(v["query"]["use_tls"], "none");
        assert_eq!(v["query"]["bcc"], json!(["dave@example.com"]));
        assert!(
            v["result"]["last_response"]
                .as_str()
                .unwrap()
                .contains("Response")
        );

        let msgs = server.messages();
        assert_eq!(msgs.len(), 1);
        let s = &msgs[0];
        assert_eq!(s.mail_from.as_deref(), Some("<resh@example.com>"));
        assert_eq!(
            s.rcpt_to,
            [
                "alice@example.com",
                "bob@example.com",
                "carol@example.com",
                "dave@example.com"
            ]
        );
        let data = s.data.as_deref().unwrap();
        assert_eq!(header(data, "From").unwrap(), "resh@example.com");
        assert_eq!(
            header(data, "To").unwrap(),
            "alice@example.com, bob@example.com"
        );
        assert_eq!(header(data, "Cc").unwrap(), "carol@example.com");
        assert_eq!(header(data, "Reply-To").unwrap(), "ops@example.com");
        assert_eq!(header(data, "Subject").unwrap(), "Backup");
        assert_eq!(header(data, "X-Ticket").unwrap(), "1234");
        assert!(
            header(data, "Bcc").is_none(),
            "Bcc leaked into headers: {data}"
        );
        assert!(!data.contains("dave@example.com"), "{data}");
        assert!(
            header(data, "Content-Type")
                .unwrap()
                .starts_with("text/plain"),
            "{data}"
        );
        assert!(data.contains("\r\n\r\nBackup done"), "{data}");
        let id = header(data, "Message-ID").expect("the message has a Message-ID");
        assert!(id.starts_with('<') && id.ends_with('>'), "{id}");
        assert_eq!(v["result"]["message_id"], id.as_str());
    }

    #[test]
    fn send_html_only_is_text_html_and_both_are_alternative() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        send_to(&server, &[("text_body", ""), ("html_body", "<p>Hi</p>")]).ok();
        send_to(&server, &[("html_body", "<p>Hi</p>")]).ok();
        let msgs = server.messages();
        let html = msgs[0].data.as_deref().unwrap();
        assert!(
            header(html, "Content-Type")
                .unwrap()
                .starts_with("text/html"),
            "{html}"
        );
        assert!(html.contains("<p>Hi</p>"));
        let both = msgs[1].data.as_deref().unwrap();
        assert!(
            header(both, "Content-Type")
                .unwrap()
                .starts_with("multipart/alternative"),
            "{both}"
        );
        let p = parts(both);
        assert!(
            p.iter()
                .any(|(h, b)| h.contains("text/plain") && b == "Backup done")
        );
        assert!(
            p.iter()
                .any(|(h, b)| h.contains("text/html") && b == "<p>Hi</p>")
        );
    }

    #[test]
    fn send_attaches_files_byte_for_byte() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let csv = c.file("daily.csv", b"a,b\r\n1,2\r\n");
        let blob: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        let bin = c.file("blob.bin", &blob);
        let latin1 = c.file("notes.txt", b"caf\xe9\n");
        let spec = json!([
            {"path": csv, "content_type": "text/csv"},
            {"path": bin, "filename": "renamed.dat"},
            {"path": latin1},
        ])
        .to_string();
        send_to(&server, &[("attachments", &spec)]).ok();
        let data = server.messages()[0].data.clone().unwrap();
        assert!(
            header(&data, "Content-Type")
                .unwrap()
                .starts_with("multipart/mixed"),
            "{data}"
        );
        let p = parts(&data);
        assert!(
            p.iter()
                .any(|(h, b)| h.contains("text/plain") && b == "Backup done")
        );
        let part = |name: &str| {
            p.iter()
                .find(|(h, _)| h.contains(&format!("filename=\"{name}\"")))
                .unwrap_or_else(|| panic!("no part {name}: {data}"))
                .clone()
        };
        let (h, b) = part("renamed.dat");
        assert!(h.contains("application/octet-stream"), "{h}");
        assert!(h.contains("Content-Disposition: attachment"), "{h}");
        assert_eq!(unbase64(&b), blob);
        let (h, _) = part("daily.csv");
        assert!(h.contains("text/csv"), "{h}");
        // A non-UTF-8 text file is sent unchanged (base64), not lossily.
        let (h, b) = part("notes.txt");
        assert!(h.contains("text/plain"), "{h}");
        assert!(h.contains("base64"), "{h}");
        assert_eq!(unbase64(&b), b"caf\xe9\n");
    }

    #[test]
    fn send_authenticates_with_plain_and_login() {
        let _c = Ctx::new();
        for mechs in ["PLAIN LOGIN", "LOGIN"] {
            let server = FakeSmtp::start(Behavior {
                auth_mechs: Some(mechs),
                credentials: Some(("alice".into(), "s3cret".into())),
                ..Behavior::default()
            });
            let r = send_to(
                &server,
                &[("smtp_username", "alice"), ("smtp_password", "s3cret")],
            )
            .ok();
            let warnings = r.json()["warnings"].to_string();
            assert!(warnings.contains("unencrypted"), "{warnings}");
            let s = &server.messages()[0];
            let expected = mechs.split(' ').next().unwrap();
            assert_eq!(
                s.auth,
                Some((expected.to_string(), "alice".into(), "s3cret".into()))
            );
        }
    }

    #[test]
    fn send_reports_auth_failure_without_retrying() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            auth_mechs: Some("PLAIN"),
            credentials: Some(("alice".into(), "right".into())),
            ..Behavior::default()
        });
        let r = send_to(
            &server,
            &[
                ("smtp_username", "alice"),
                ("smtp_password", "wrong"),
                ("max_retry", "3"),
                ("retry_backoff_ms", "1"),
            ],
        )
        .fails(1, MAIL_SEND_SMTP_AUTH_FAILED);
        assert_eq!(r.json()["result"]["attempts"], 1);
        assert!(server.messages().is_empty());
    }

    #[test]
    fn send_without_password_does_not_authenticate_and_warns() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let r = send_to(&server, &[("smtp_username", "alice")]).ok();
        assert!(
            r.json()["warnings"]
                .to_string()
                .contains("not authenticated")
        );
        assert!(server.messages()[0].auth.is_none());
    }

    #[test]
    fn send_rejected_recipient_is_permanent() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            reject_rcpt: vec!["alice@example.com".into()],
            ..Behavior::default()
        });
        let r = send_to(&server, &[("max_retry", "2"), ("retry_backoff_ms", "1")])
            .fails(1, MAIL_SEND_SMTP_REJECTED);
        let v = r.json();
        assert_eq!(v["result"]["attempts"], 1);
        assert_eq!(v["result"]["message_id"], Value::Null);
        assert!(v["error"]["message"].as_str().unwrap().contains("550"));
        assert!(server.messages().is_empty());
    }

    #[test]
    fn send_retries_transient_failures() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            mail_reply: Some((2, "451 4.3.0 try again later")),
            ..Behavior::default()
        });
        let r = send_to(&server, &[("max_retry", "2"), ("retry_backoff_ms", "10")]).ok();
        assert_eq!(r.json()["result"]["attempts"], 3);
        assert_eq!(server.messages().len(), 1);

        let server = FakeSmtp::start(Behavior {
            mail_reply: Some((9, "451 4.3.0 try again later")),
            ..Behavior::default()
        });
        let r = send_to(&server, &[("max_retry", "1"), ("retry_backoff_ms", "1")])
            .fails(1, MAIL_SEND_SMTP_TRANSIENT_FAILED);
        assert_eq!(r.json()["result"]["attempts"], 2);
    }

    #[test]
    fn send_data_rejection_is_reported() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            data_reply: Some("554 5.7.1 message refused"),
            ..Behavior::default()
        });
        send_to(&server, &[]).fails(1, MAIL_SEND_SMTP_REJECTED);
    }

    #[test]
    fn send_connection_refused() {
        let _c = Ctx::new();
        let port = closed_port();
        let mut args: Vec<(&str, &str)> = MSG.to_vec();
        args.extend([
            ("smtp_host", "127.0.0.1"),
            ("smtp_port", port.as_str()),
            ("use_tls", "none"),
        ]);
        call("send", &args).fails(1, MAIL_SEND_SMTP_CONNECTION_FAILED);
    }

    #[test]
    fn send_times_out_with_exit_124() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            greeting_delay: Duration::from_secs(5),
            ..Behavior::default()
        });
        let t = Instant::now();
        let r = send_to(&server, &[("timeout_ms", "300"), ("max_retry", "3")])
            .fails(EXIT_TIMEOUT, MAIL_SEND_TIMEOUT);
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("timeout_ms=300")
        );

        // A server that stalls after the data: the outcome is unknown.
        let server = FakeSmtp::start(Behavior {
            data_delay: Duration::from_secs(5),
            ..Behavior::default()
        });
        let t = Instant::now();
        let r = send_to(&server, &[("timeout_ms", "500")]).fails(EXIT_TIMEOUT, MAIL_SEND_TIMEOUT);
        assert!(t.elapsed() < Duration::from_secs(3));
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("may or may not have been delivered")
        );
    }

    #[test]
    fn send_tls_failures() {
        let _c = Ctx::new();
        // STARTTLS offered, but the handshake fails.
        let server = FakeSmtp::start(Behavior {
            starttls: true,
            ..Behavior::default()
        });
        send_to(&server, &[("use_tls", "starttls")]).fails(1, MAIL_SEND_SMTP_TLS_ERROR);
        // STARTTLS required but not offered: never continues in plain text,
        // also with tls_accept_invalid_certs=true.
        let server = FakeSmtp::start(Behavior::default());
        send_to(&server, &[("use_tls", "starttls")]).fails(1, MAIL_SEND_SMTP_TLS_ERROR);
        send_to(
            &server,
            &[
                ("use_tls", "starttls"),
                ("tls_accept_invalid_certs", "true"),
            ],
        )
        .fails(1, MAIL_SEND_SMTP_TLS_ERROR);
        // Implicit TLS against a plain-text server.
        send_to(&server, &[("use_tls", "tls")]).fails(1, MAIL_SEND_SMTP_TLS_ERROR);
        assert!(server.messages().is_empty());
    }

    #[test]
    fn send_text_output() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let r = send_to(&server, &[("format_output", "text")]);
        assert!(r.status.ok);
        assert!(r.out.starts_with("Mail Send\n"), "{}", r.out);
        assert!(r.out.contains("Status    : sent"), "{}", r.out);
        assert!(r.out.contains("Message-ID: <"), "{}", r.out);
    }

    // --- send: settings from the environment and stored profiles -------------

    #[test]
    fn send_uses_mail_environment_when_no_smtp_host_is_given() {
        let server = FakeSmtp::start(Behavior::default());
        let port = server.port.to_string();
        let _c = Ctx::with_env(&[
            ("MAIL_SMTP_HOST", "127.0.0.1"),
            ("MAIL_SMTP_PORT", &port),
            ("MAIL_FROM", "env@example.com"),
        ]);
        let r = call(
            "send",
            &[
                ("to", "a@example.com"),
                ("subject", "s"),
                ("text_body", "b"),
                ("use_tls", "none"),
            ],
        )
        .ok();
        assert_eq!(r.json()["query"]["from"], Value::Null);
        let s = &server.messages()[0];
        assert_eq!(s.mail_from.as_deref(), Some("<env@example.com>"));
    }

    #[test]
    fn send_rejects_unusable_environment() {
        let msg = [
            ("to", "a@example.com"),
            ("subject", "s"),
            ("text_body", "b"),
            ("use_tls", "none"),
        ];
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "127.0.0.1"), ("MAIL_SMTP_PORT", "x")]);
            let r = call("send", &msg).fails(2, MAIL_SEND_SMTP_NOT_CONFIGURED);
            assert!(
                r.json()["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("MAIL_SMTP_PORT")
            );
        }
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "-oops")]);
            call("send", &msg).fails(2, MAIL_SEND_SMTP_NOT_CONFIGURED);
        }
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "127.0.0.1"), ("MAIL_FROM", "nope")]);
            call("send", &msg).fails(2, MAIL_SEND_INVALID_ADDRESS);
        }
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "127.0.0.1")]);
            call("send", &msg).fails(2, MAIL_SEND_MISSING_FROM);
        }
        {
            let _c = Ctx::new();
            call("send", &msg).fails(2, MAIL_SEND_SMTP_NOT_CONFIGURED);
        }
    }

    #[test]
    fn send_uses_the_active_profile() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            auth_mechs: Some("PLAIN"),
            credentials: Some(("bob".into(), "pw".into())),
            ..Behavior::default()
        });
        let port = server.port.to_string();
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "work"),
                ("smtp_host", "127.0.0.1"),
                ("smtp_port", &port),
                ("use_tls", "none"),
                ("smtp_username", "bob"),
                ("smtp_password", "pw"),
                ("from", "work@example.com"),
                ("reply_to", "desk@example.com"),
                ("is_default", "true"),
            ],
        )
        .ok();
        let r = call(
            "send",
            &[
                ("to", "a@example.com"),
                ("subject", "s"),
                ("text_body", "b"),
            ],
        )
        .ok();
        let v = r.json();
        assert_eq!(v["query"]["use_tls"], "none");
        assert!(v["warnings"].to_string().contains("profile 'work'"));
        let s = &server.messages()[0];
        assert_eq!(s.auth, Some(("PLAIN".into(), "bob".into(), "pw".into())));
        assert_eq!(s.mail_from.as_deref(), Some("<work@example.com>"));
        let data = s.data.as_deref().unwrap();
        assert_eq!(header(data, "Reply-To").unwrap(), "desk@example.com");

        // Two active profiles (a hand-edited store) are refused.
        let text = fs::read_to_string(c.store()).unwrap();
        let mut profiles: Vec<Value> = serde_json::from_str(&text).unwrap();
        let mut second = profiles[0].clone();
        second["name"] = json!("other");
        profiles.push(second);
        fs::write(c.store(), serde_json::to_string(&profiles).unwrap()).unwrap();
        let r = call(
            "send",
            &[
                ("to", "a@example.com"),
                ("subject", "s"),
                ("text_body", "b"),
            ],
        )
        .fails(2, MAIL_SEND_SMTP_NOT_CONFIGURED);
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("more than one")
        );
    }

    // --- send: invalid input (nothing is sent) --------------------------------

    #[test]
    fn send_validation_errors_open_no_connection() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let dir = c.dir.path().display().to_string();
        let missing = c.dir.path().join("nope.txt").display().to_string();
        let att = |p: &str| json!([{ "path": p }]).to_string();
        let (att_dir, att_missing) = (att(&dir), att(&missing));
        let cases: Vec<(Vec<(&str, &str)>, i32, &str)> = vec![
            (vec![("to", "")], 2, MAIL_SEND_MISSING_RECIPIENTS),
            (vec![("subject", "  ")], 2, MAIL_SEND_MISSING_SUBJECT),
            (vec![("text_body", "")], 2, MAIL_SEND_MISSING_BODY),
            (vec![("header_Subject", "x")], 2, MAIL_SEND_HEADER_CONFLICT),
            (vec![("header_Bcc", "x")], 2, MAIL_SEND_HEADER_CONFLICT),
            (
                vec![("header_X-A", "1\r\nBcc: e@example.com")],
                2,
                MAIL_SEND_INVALID_HEADER,
            ),
            (vec![("header_", "1")], 2, MAIL_SEND_INVALID_HEADER),
            (vec![("timeout_ms", "0")], 2, MAIL_SEND_INVALID_TIMEOUT),
            (vec![("max_retry", "11")], 2, MAIL_SEND_INVALID_RETRY_CONFIG),
            (
                vec![("attachments", &att_missing)],
                1,
                MAIL_SEND_ATTACHMENT_MISSING,
            ),
            (
                vec![("attachments", &att_dir)],
                1,
                MAIL_SEND_ATTACHMENT_IO_ERROR,
            ),
        ];
        for (extra, exit, code) in cases {
            send_to(&server, &extra).fails(exit, code);
        }
        assert!(server.sessions().is_empty(), "a connection was opened");
    }

    #[test]
    fn send_refuses_attachments_over_100_mb() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let big = c.dir.path().join("big.bin");
        fs::File::create(&big)
            .unwrap()
            .set_len(100 * 1024 * 1024 + 1)
            .unwrap();
        let spec = json!([{ "path": big.display().to_string() }]).to_string();
        send_to(&server, &[("attachments", &spec)]).fails(1, MAIL_SEND_ATTACHMENTS_TOO_LARGE);
        assert!(server.sessions().is_empty());
    }

    #[test]
    fn send_refuses_bad_arguments_with_exit_2() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        send_to(&server, &[("subjct", "x")])
            .usage("unknown argument: subjct (did you mean `subject`?)");
        send_to(&server, &[("verbose", "1")]).usage("unknown argument: verbose");
        send_to(&server, &[("to", "not-an-address")]).usage("invalid to");
        send_to(&server, &[("to", "[1]")]).usage("must be strings");
        send_to(&server, &[("from", "x@")]).usage("invalid from");
        send_to(&server, &[("smtp_port", "0")]).usage("invalid smtp_port");
        send_to(&server, &[("smtp_port", "70000")]).usage("invalid smtp_port");
        send_to(&server, &[("smtp_host", "-x")]).usage("starts with '-'");
        send_to(&server, &[("smtp_host", "a b")]).usage("not a host name");
        send_to(&server, &[("use_tls", "ssl")]).usage("Invalid TLS mode");
        send_to(&server, &[("tls_accept_invalid_certs", "maybe")])
            .usage("tls_accept_invalid_certs");
        send_to(&server, &[("tls_accept_invalid_certs", "true")])
            .usage("conflicts with use_tls=none");
        send_to(&server, &[("timeout_ms", "-1")]).usage("invalid timeout_ms");
        send_to(&server, &[("max_retry", "x")]).usage("invalid max_retry");
        send_to(&server, &[("retry_backoff_ms", "1.5")]).usage("invalid retry_backoff_ms");
        send_to(&server, &[("format_output", "xml")]).usage("Invalid output format");
        send_to(&server, &[("attachments", "{}")]).usage("JSON array");
        send_to(&server, &[("attachments", "[{\"file\":\"x\"}]")])
            .usage("unknown attachment field");
        send_to(
            &server,
            &[(
                "attachments",
                "[{\"path\":\"/x\",\"content_type\":\"bad\"}]",
            )],
        )
        .usage("content_type");
        send_to(&server, &[("dry_run", "true")]).usage("does not support dry_run");
        send_to(&server, &[("dry_run", "maybe")]).usage("dry_run");
        assert!(server.sessions().is_empty());
        // dry_run=false is not a dry run.
        send_to(&server, &[("dry_run", "false")]).ok();
    }

    // --- send_template --------------------------------------------------------

    #[test]
    fn send_template_dry_run_renders_without_connecting() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let base = smtp(&server);
        let r = call(
            "send_template",
            &with(
                &base,
                &[
                    ("template", "welcome"),
                    ("to", "bob@example.com"),
                    ("dry_run", "true"),
                    (
                        "vars",
                        r#"{"user_name":"<Bob & {{app_name}}>","app_name":"Acme"}"#,
                    ),
                ],
            ),
        )
        .ok();
        let v = r.json();
        assert_eq!(
            v["rendered"]["subject"],
            "Welcome to Acme, <Bob & {{app_name}}>!"
        );
        assert_eq!(
            v["rendered"]["html_body"],
            "<p>Hi <strong>&lt;Bob &amp; {{app_name}}&gt;</strong>,</p><p>Welcome to Acme.</p>"
        );
        assert_eq!(v["send_result"], Value::Null);
        assert_eq!(v["warnings"], json!(["Dry run: email was not sent."]));
        assert!(server.sessions().is_empty());
    }

    #[test]
    fn send_template_help_example_works() {
        let _c = Ctx::new();
        let r = call(
            "send_template",
            &[
                ("template", "welcome"),
                ("to", "bob@example.com"),
                ("dry_run", "true"),
            ],
        )
        .ok();
        assert_eq!(r.json()["rendered"]["subject"], "Welcome to , !");
    }

    #[test]
    fn send_template_sends_rendered_message() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let base = smtp(&server);
        let r = call(
            "send_template",
            &with(
                &base,
                &[
                    ("template", "password_reset"),
                    ("to", "bob@example.com"),
                    ("bcc", "audit@example.com"),
                    ("headers", r#"{"X-Campaign":"reset"}"#),
                    (
                        "vars",
                        r#"{"user_name":"Bob","reset_link":"https://example.com/r?a=1&b=2"}"#,
                    ),
                ],
            ),
        )
        .ok();
        let v = r.json();
        assert_eq!(v["send_result"]["attempts"], 1);
        let s = &server.messages()[0];
        // The template's built-in sender when nothing else is given.
        assert_eq!(s.mail_from.as_deref(), Some("<noreply@myapp.io>"));
        assert_eq!(s.rcpt_to, ["bob@example.com", "audit@example.com"]);
        let data = s.data.as_deref().unwrap();
        assert!(header(data, "Bcc").is_none());
        assert_eq!(header(data, "Subject").unwrap(), "Reset your password");
        assert_eq!(header(data, "X-Campaign").unwrap(), "reset");
        let p = parts(data);
        assert!(
            p.iter()
                .any(|(h, b)| h.contains("text/plain")
                    && b.contains("https://example.com/r?a=1&b=2"))
        );
        assert!(
            p.iter().any(|(h, b)| h.contains("text/html")
                && unqp(b).contains("href=\"https://example.com/r?a=1&amp;b=2\"")),
            "{data}"
        );
    }

    #[test]
    fn send_template_sender_falls_back_to_mail_from_then_template() {
        let server = FakeSmtp::start(Behavior::default());
        let port = server.port.to_string();
        let _c = Ctx::with_env(&[
            ("MAIL_SMTP_HOST", "127.0.0.1"),
            ("MAIL_SMTP_PORT", &port),
            ("MAIL_FROM", "env@example.com"),
        ]);
        call(
            "send_template",
            &[
                ("template", "welcome"),
                ("locale", "fr"),
                ("to", "b@example.com"),
                ("use_tls", "none"),
                ("vars", r#"{"user_name":"Zoé","app_name":"Acme"}"#),
            ],
        )
        .ok();
        let s = &server.messages()[0];
        assert_eq!(s.mail_from.as_deref(), Some("<env@example.com>"));
        let subject = header(s.data.as_deref().unwrap(), "Subject").unwrap();
        // Non-ASCII subjects are encoded (RFC 2047).
        assert!(subject.starts_with("Bienvenue =?utf-8?"), "{subject}");
    }

    #[test]
    fn send_template_locale_and_errors() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let base = smtp(&server);
        let dry = |extra: &[(&'static str, &'static str)]| {
            let mut a = with(
                &base,
                &[
                    ("template", "welcome"),
                    ("to", "b@example.com"),
                    ("dry_run", "true"),
                ],
            );
            for (k, v) in extra {
                a.retain(|(x, _)| x != k);
                a.push((k, v));
            }
            call("send_template", &a)
        };
        let r = dry(&[("locale", "fr")]).ok();
        assert!(
            r.json()["rendered"]["subject"]
                .as_str()
                .unwrap()
                .starts_with("Bienvenue")
        );
        let r = dry(&[("locale", "de")]).ok();
        assert!(
            r.json()["warnings"]
                .to_string()
                .contains("Locale 'de' is not available")
        );

        dry(&[("template", "nope")]).fails(1, MAIL_SEND_TEMPLATE_NOT_FOUND);
        dry(&[("to", "")]).fails(2, MAIL_SEND_MISSING_RECIPIENTS);
        let r = dry(&[("strict_vars", "true")]).fails(2, MAIL_SEND_TEMPLATE_MISSING_VAR);
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("app_name, user_name")
        );
        dry(&[
            ("strict_vars", "yes"),
            ("vars", r#"{"user_name":"B","app_name":"A"}"#),
        ])
        .ok();
        dry(&[("headers", r#"{"From":"x@example.com"}"#)])
            .fails(2, MAIL_SEND_TEMPLATE_HEADER_CONFLICT);
        dry(&[("headers", r#"{"X-A":"1\nB"}"#)]).fails(2, MAIL_SEND_INVALID_HEADER);
        dry(&[("timeout_ms", "0")]).fails(2, MAIL_SEND_INVALID_TIMEOUT);
        let missing = c.dir.path().join("gone").display().to_string();
        let spec: &'static str =
            Box::leak(json!([{ "path": missing }]).to_string().into_boxed_str());
        dry(&[("attachments", spec)]).fails(1, MAIL_SEND_ATTACHMENT_MISSING);

        dry(&[("template", "")]).usage("template is required");
        dry(&[("vars", "[1]")]).usage("vars must be a JSON object");
        dry(&[("vars", "{bad")]).usage("vars must be a JSON object");
        dry(&[("headers", "[]")]).usage("headers must be a JSON object");
        dry(&[("headers", r#"{"X":1}"#)]).usage("string value");
        dry(&[("strict_vars", "perhaps")]).usage("strict_vars");
        dry(&[("dry_run", "perhaps")]).usage("dry_run");
        dry(&[("version", "v1")]).usage("unknown argument: version");
        dry(&[("tempate", "welcome")]).usage("did you mean `template`?");
        dry(&[("header_X-A", "1")]).usage("unknown argument: header_X-A");
        assert!(server.sessions().is_empty());

        // A real send reports SMTP failures like send.
        let mut a = with(&base, &[("template", "welcome"), ("to", "b@example.com")]);
        let port = closed_port();
        a.retain(|(k, _)| *k != "smtp_port");
        a.push(("smtp_port", &port));
        let r = call("send_template", &a).fails(1, MAIL_SEND_SMTP_CONNECTION_FAILED);
        assert_eq!(r.json()["send_result"]["attempts"], 1);
    }

    #[test]
    fn send_template_text_output() {
        let _c = Ctx::new();
        let r = call(
            "send_template",
            &[
                ("template", "welcome"),
                ("to", "b@example.com"),
                ("dry_run", "true"),
                ("format_output", "text"),
            ],
        );
        assert!(r.status.ok);
        assert!(
            r.out.contains("Status: preview only (dry run)"),
            "{}",
            r.out
        );
    }

    // --- test -----------------------------------------------------------------

    fn test_with(server: &FakeSmtp, extra: &[(&str, &str)]) -> Out {
        let base = smtp(server);
        let mut args = with(&base, &[]);
        for (k, v) in extra {
            args.retain(|(a, _)| a != k);
            args.push((k, v));
        }
        call("test", &args)
    }

    #[test]
    fn test_opens_a_real_session() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let r = test_with(&server, &[("connection_only", "true")]).ok();
        let v = r.json();
        let conn = &v["connection"];
        assert_eq!(conn["resolved_ip"], "127.0.0.1");
        assert_eq!(conn["tls_established"], false);
        assert_eq!(conn["auth_attempted"], false);
        assert_eq!(conn["last_response"], "Connection test completed");
        assert_eq!(v["send_test_email"], Value::Null);
        let s = &server.wait_sessions(1)[0];
        assert!(s.commands[0].starts_with("EHLO "), "{:?}", s.commands);
        assert!(s.commands.contains(&"NOOP".to_string()), "{:?}", s.commands);
        assert!(s.data.is_none());
    }

    #[test]
    fn test_checks_authentication() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            auth_mechs: Some("PLAIN LOGIN"),
            credentials: Some(("u".into(), "p".into())),
            ..Behavior::default()
        });
        let r = test_with(&server, &[("smtp_username", "u"), ("smtp_password", "p")]).ok();
        assert_eq!(r.json()["connection"]["auth_succeeded"], true);
        assert_eq!(
            server.wait_sessions(1)[0].auth,
            Some(("PLAIN".into(), "u".into(), "p".into()))
        );
        let r = test_with(&server, &[("smtp_username", "u"), ("smtp_password", "bad")])
            .fails(1, MAIL_TEST_AUTH_FAILED);
        let conn = &r.json()["connection"];
        assert_eq!(conn["auth_attempted"], true);
        assert_eq!(conn["auth_succeeded"], false);
    }

    #[test]
    fn test_sends_a_test_message() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let r = test_with(
            &server,
            &[
                ("send_test_email", "true"),
                ("to", "me@example.com"),
                ("from", "resh@example.com"),
            ],
        )
        .ok();
        let v = r.json();
        assert_eq!(
            v["send_test_email"]["accepted_recipients"],
            json!(["me@example.com"])
        );
        assert_eq!(v["send_test_email"]["envelope_from"], "resh@example.com");
        let data = server.messages()[0].data.clone().unwrap();
        assert_eq!(header(&data, "Subject").unwrap(), "SMTP test");
        assert!(data.contains("SMTP test email"));

        let server = FakeSmtp::start(Behavior {
            reject_rcpt: vec!["me@example.com".into()],
            ..Behavior::default()
        });
        test_with(
            &server,
            &[
                ("send_test_email", "true"),
                ("to", "me@example.com"),
                ("from", "resh@example.com"),
            ],
        )
        .fails(1, MAIL_TEST_SEND_REJECTED);
    }

    #[test]
    fn test_failure_codes() {
        let _c = Ctx::new();
        let port = closed_port();
        call(
            "test",
            &[
                ("smtp_host", "127.0.0.1"),
                ("smtp_port", &port),
                ("use_tls", "none"),
            ],
        )
        .fails(1, MAIL_TEST_CONNECTION_FAILED);

        // A name the resolver rejects locally (a label over 63 bytes).
        let host = format!("{}.test", "a".repeat(64));
        call("test", &[("smtp_host", &host), ("use_tls", "none")]).fails(1, MAIL_TEST_DNS_ERROR);

        let server = FakeSmtp::start(Behavior {
            starttls: true,
            ..Behavior::default()
        });
        test_with(&server, &[("use_tls", "starttls")]).fails(1, MAIL_TEST_TLS_ERROR);

        let busy = FakeSmtp::start(Behavior {
            greeting: Some("421 4.3.2 busy"),
            ..Behavior::default()
        });
        let r = test_with(&busy, &[("max_retry", "2"), ("retry_backoff_ms", "1")])
            .fails(1, MAIL_TEST_TRANSIENT_FAILED);
        assert_eq!(r.json()["connection"]["attempts"], 3);

        let slow = FakeSmtp::start(Behavior {
            greeting_delay: Duration::from_secs(5),
            ..Behavior::default()
        });
        let t = Instant::now();
        test_with(&slow, &[("timeout_ms", "300")]).fails(EXIT_TIMEOUT, MAIL_TEST_TIMEOUT);
        assert!(t.elapsed() < Duration::from_secs(3));

        let noop = FakeSmtp::start(Behavior {
            noop_reply: Some("500 no"),
            ..Behavior::default()
        });
        test_with(&noop, &[]).fails(1, MAIL_TEST_CONNECTION_FAILED);
    }

    #[test]
    fn test_validation_errors() {
        let server = FakeSmtp::start(Behavior::default());
        {
            let _c = Ctx::new();
            test_with(&server, &[("timeout_ms", "0")]).fails(2, MAIL_TEST_INVALID_TIMEOUT);
            test_with(&server, &[("max_retry", "11")]).fails(2, MAIL_TEST_INVALID_RETRY_CONFIG);
            call("test", &[]).fails(2, MAIL_TEST_MISSING_SMTP_HOST);
            test_with(&server, &[("send_test_email", "true")])
                .fails(2, MAIL_TEST_SEND_EMAIL_MISSING_RECIPIENTS);
            test_with(
                &server,
                &[("send_test_email", "true"), ("to", "a@example.com")],
            )
            .fails(2, MAIL_TEST_SEND_EMAIL_MISSING_FROM);
            test_with(
                &server,
                &[("connection_only", "true"), ("send_test_email", "true")],
            )
            .usage("conflict");
            test_with(&server, &[("to", "a@example.com")])
                .usage("to is only used with send_test_email=true");
            test_with(&server, &[("send_test_email", "1"), ("text_body", " ")]).usage("empty");
            test_with(&server, &[("connection_only", "sure")]).usage("connection_only");
            test_with(&server, &[("smtp_hots", "x")]).usage("did you mean `smtp_host`?");
            test_with(&server, &[("cc", "a@example.com")]).usage("unknown argument: cc");
            test_with(&server, &[("dry_run", "true")]).usage("does not support dry_run");
            call("config", &[("action", "list"), ("dry_run", "yes")])
                .usage("does not support dry_run");
        }
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "127.0.0.1"), ("MAIL_SMTP_PORT", "0")]);
            call("test", &[]).fails(2, MAIL_TEST_SMTP_NOT_CONFIGURED);
        }
        {
            let _c = Ctx::with_env(&[("MAIL_SMTP_HOST", "127.0.0.1"), ("MAIL_FROM", "bad")]);
            call("test", &[]).fails(2, MAIL_TEST_INVALID_ADDRESS);
        }
        assert!(server.sessions().is_empty());
    }

    #[test]
    fn test_help_example_uses_the_active_profile() {
        let _c = Ctx::new();
        let server = FakeSmtp::start(Behavior::default());
        let port = server.port.to_string();
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "work"),
                ("smtp_host", "127.0.0.1"),
                ("smtp_port", &port),
                ("use_tls", "none"),
                ("is_default", "true"),
            ],
        )
        .ok();
        let r = call("test", &[("connection_only", "true")]).ok();
        assert_eq!(r.json()["connection"]["smtp_port"], server.port);
        let r = call("test", &[("format_output", "text")]);
        assert!(r.status.ok);
        assert!(r.out.starts_with("Mail Test\n"), "{}", r.out);
        assert!(r.out.contains("Status : success"), "{}", r.out);
    }

    // --- config ---------------------------------------------------------------

    #[test]
    fn config_set_get_list_activate_delete() {
        use std::os::unix::fs::PermissionsExt;
        let c = Ctx::new();
        let r = call("config", &[("action", "list")]).ok();
        assert_eq!(r.json()["profiles"], json!([]));
        assert!(
            !c.dir.path().join("cfg").exists(),
            "list created the store directory"
        );

        let r = call(
            "config",
            &[
                ("action", "set"),
                ("profile", "work"),
                ("smtp_host", "smtp.example.com"),
                ("use_tls", "TLS"),
                ("smtp_username", "alice"),
                ("smtp_password", "pa:ss"),
                ("from", "alice@example.com"),
                ("description", "Office relay"),
            ],
        )
        .ok();
        let v = r.json();
        assert_eq!(v["profile"]["smtp_port"], 465);
        assert_eq!(v["profile"]["use_tls"], "tls");
        assert_eq!(v["profile"]["has_password"], true);
        assert!(!r.out.contains("pa:ss"));
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&c.store()), 0o600);
        assert_eq!(mode(c.store().parent().unwrap()), 0o700);
        let stored = fs::read_to_string(c.store()).unwrap();
        // The file keeps only a keyring reference; the keyring has the
        // password.
        assert!(
            !stored.contains("pa:ss") && !stored.contains("cGE6c3M="),
            "{stored}"
        );
        assert!(
            stored.contains("\"smtp_password_ref\": \"keyring:resh-mail-smtp/work\""),
            "{stored}"
        );
        assert!(!stored.contains("smtp_password_encrypted"), "{stored}");
        assert_eq!(c.secret("work").as_deref(), Some("pa:ss"));

        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "home"),
                ("smtp_host", "h.example.com"),
            ],
        )
        .ok();
        // Updating keeps fields not given; a new use_tls resets the port.
        let r = call(
            "config",
            &[
                ("action", "set"),
                ("profile", "work"),
                ("use_tls", "starttls"),
            ],
        )
        .ok();
        assert_eq!(r.json()["profile"]["smtp_port"], 587);
        assert_eq!(r.json()["profile"]["from"], "alice@example.com");

        let r = call("config", &[("action", "get"), ("profile", "work")]).ok();
        assert_eq!(r.json()["profile"]["description"], "Office relay");
        call("config", &[("action", "get_active")]).fails(1, MAIL_CONFIG_NO_ACTIVE_PROFILE);
        let r = call("config", &[("action", "activate"), ("profile", "home")]).ok();
        assert_eq!(r.json()["profile"]["is_active"], true);
        let r = call("config", &[("action", "get_active")]).ok();
        assert_eq!(r.json()["active_profile"], "home");
        let r = call(
            "config",
            &[("action", "set"), ("profile", "work"), ("is_default", "1")],
        )
        .ok();
        assert_eq!(r.json()["profile"]["is_active"], true);
        let r = call("config", &[("action", "list")]).ok();
        let v = r.json();
        assert_eq!(v["active_profile"], "work");
        assert_eq!(v["profiles"].as_array().unwrap().len(), 2);
        let r = call("config", &[("action", "delete"), ("profile", "home")]).ok();
        assert_eq!(r.json()["deleted_profile"], "home");
        call("config", &[("action", "get"), ("profile", "home")])
            .fails(1, MAIL_CONFIG_PROFILE_NOT_FOUND);
        call("config", &[("action", "delete"), ("profile", "home")])
            .fails(1, MAIL_CONFIG_PROFILE_NOT_FOUND);
        call("config", &[("action", "activate"), ("profile", "home")])
            .fails(1, MAIL_CONFIG_PROFILE_NOT_FOUND);
        let r = call("config", &[("action", "list"), ("format_output", "text")]);
        assert!(r.out.contains("Active Profile: work"), "{}", r.out);
        assert!(r.out.contains("Secret : set"), "{}", r.out);
    }

    #[test]
    fn config_store_errors() {
        let c = Ctx::new();
        call("config", &[("action", "set"), ("profile", "w")])
            .fails(2, MAIL_CONFIG_INVALID_SMTP_HOST);
        assert!(!c.store().exists());

        fs::create_dir_all(c.store().parent().unwrap()).unwrap();
        fs::write(c.store(), "{not json").unwrap();
        call("config", &[("action", "list")]).fails(1, MAIL_CONFIG_STORE_PARSE_ERROR);
        fs::remove_file(c.store()).unwrap();
        fs::create_dir(c.store()).unwrap();
        call("config", &[("action", "list")]).fails(1, MAIL_CONFIG_STORE_READ_ERROR);
        fs::remove_dir(c.store()).unwrap();

        // Two active profiles.
        let p = json!({"name":"a","smtp_host":"h","smtp_port":25,"smtp_username":null,
            "smtp_password_encrypted":null,"use_tls":"none","tls_accept_invalid_certs":false,
            "from":null,"reply_to":null,"description":null,"is_active":true});
        let mut q = p.clone();
        q["name"] = json!("b");
        fs::write(c.store(), json!([p, q]).to_string()).unwrap();
        call("config", &[("action", "get_active")])
            .fails(1, MAIL_CONFIG_ACTIVE_PROFILE_INCONSISTENT);

        // A symlink planted at the store is replaced, never written through.
        let victim = c.dir.path().join("victim");
        fs::write(&victim, "[]").unwrap();
        fs::remove_file(c.store()).unwrap();
        std::os::unix::fs::symlink(&victim, c.store()).unwrap();
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "x"),
                ("smtp_host", "h.example.com"),
            ],
        )
        .ok();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "[]");
        assert!(
            !fs::symlink_metadata(c.store())
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn config_unwritable_store_is_a_write_error() {
        use std::os::unix::fs::PermissionsExt;
        let c = Ctx::new();
        let dir = c.store().parent().unwrap().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores directory permissions; nothing to check then.
        if fs::write(dir.join("probe"), "x").is_ok() {
            return;
        }
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "x"),
                ("smtp_host", "h.example.com"),
            ],
        )
        .fails(1, MAIL_CONFIG_STORE_WRITE_ERROR);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn config_invalid_arguments_are_exit_2_and_touch_nothing() {
        let c = Ctx::new();
        let cases: &[(&[(&str, &str)], &str, &str)] = &[
            (
                &[],
                MAIL_CONFIG_INVALID_ACTION,
                "'action' parameter is required",
            ),
            (
                &[("action", "rename")],
                MAIL_CONFIG_INVALID_ACTION,
                "Invalid config action",
            ),
            (
                &[("action", "get")],
                MAIL_CONFIG_PROFILE_REQUIRED,
                "'profile'",
            ),
            (
                &[("action", "set"), ("profile", "a b")],
                MAIL_CONFIG_INVALID_PROFILE_NAME,
                "invalid characters",
            ),
            (
                &[("action", "delete"), ("profile", "")],
                MAIL_CONFIG_INVALID_PROFILE_NAME,
                "empty",
            ),
            (
                &[("action", "list"), ("profile", "w")],
                MAIL_CONFIG_INVALID_FLAG,
                "does not take 'profile'",
            ),
            (
                &[("action", "get"), ("profile", "w"), ("smtp_host", "h")],
                MAIL_CONFIG_INVALID_FLAG,
                "only used by action=set",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("smtp_host", "-h")],
                MAIL_CONFIG_INVALID_SMTP_HOST,
                "starts with '-'",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("smtp_port", "0")],
                MAIL_CONFIG_INVALID_SMTP_PORT,
                "smtp_port",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("use_tls", "ssl")],
                MAIL_CONFIG_INVALID_TLS_MODE,
                "ssl",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("is_default", "sure")],
                MAIL_CONFIG_INVALID_FLAG,
                "is_default",
            ),
            (
                &[
                    ("action", "set"),
                    ("profile", "w"),
                    ("tls_accept_invalid_certs", "2"),
                ],
                MAIL_CONFIG_INVALID_FLAG,
                "tls_accept_invalid_certs",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("from", "nope")],
                MAIL_CONFIG_INVALID_ADDRESS,
                "from",
            ),
            (
                &[("action", "set"), ("profile", "w"), ("reply_to", "x@")],
                MAIL_CONFIG_INVALID_ADDRESS,
                "reply_to",
            ),
            (
                &[("action", "list"), ("format_output", "yaml")],
                MAIL_CONFIG_INVALID_FLAG,
                "yaml",
            ),
        ];
        for (args, code, needle) in cases {
            call("config", args).usage_code(code, needle);
        }
        call("config", &[("action", "list"), ("timeout_ms", "5")])
            .usage("timeout_ms is not accepted");
        call("config", &[("action", "list"), ("profiel", "x")]).usage("did you mean `profile`?");
        assert!(!c.dir.path().join("cfg").exists());
    }

    // --- keyring ----------------------------------------------------------------

    /// A profile store with one active profile holding a legacy base64
    /// password ("legacy-pw").
    fn legacy_store(c: &Ctx, port: u16) {
        let p = json!({"name":"old","smtp_host":"127.0.0.1","smtp_port":port,
            "smtp_username":"bob","smtp_password_encrypted":"bGVnYWN5LXB3",
            "use_tls":"none","tls_accept_invalid_certs":false,
            "from":"old@example.com","reply_to":null,"description":null,"is_active":true});
        fs::create_dir_all(c.store().parent().unwrap()).unwrap();
        fs::write(c.store(), json!([p]).to_string()).unwrap();
    }

    #[test]
    fn config_refuses_to_store_a_password_without_a_keyring() {
        let c = Ctx::new();
        c.no_keyring();
        let r = call(
            "config",
            &[
                ("action", "set"),
                ("profile", "w"),
                ("smtp_host", "h.example.com"),
                ("smtp_password", "secret"),
            ],
        )
        .fails(1, MAIL_CONFIG_KEYRING_UNAVAILABLE);
        let msg = r.json()["error"]["message"].as_str().unwrap().to_string();
        assert!(
            msg.contains("MAIL_SMTP_PASSWORD") && msg.contains("Nothing was changed"),
            "{msg}"
        );
        assert!(!c.store().exists());
        // Without a password the profile is stored.
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "w"),
                ("smtp_host", "h.example.com"),
            ],
        )
        .ok();
        assert!(!fs::read_to_string(c.store()).unwrap().contains("secret"));
    }

    #[test]
    fn config_delete_removes_the_keyring_entry() {
        let c = Ctx::new();
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "w"),
                ("smtp_host", "h.example.com"),
                ("smtp_password", "secret"),
            ],
        )
        .ok();
        assert_eq!(c.secret("w").as_deref(), Some("secret"));
        // A keyring that cannot be reached: nothing is deleted.
        c.no_keyring();
        call("config", &[("action", "delete"), ("profile", "w")])
            .fails(1, MAIL_CONFIG_KEYRING_UNAVAILABLE);
        assert!(fs::read_to_string(c.store()).unwrap().contains("\"w\""));
        mail_secrets::set_test_store(Some(c.secrets.clone()));
        call("config", &[("action", "delete"), ("profile", "w")]).ok();
        assert_eq!(c.secret("w"), None);
    }

    #[test]
    fn legacy_passwords_are_read_with_a_warning_and_migrated_on_write() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            auth_mechs: Some("PLAIN"),
            credentials: Some(("bob".into(), "legacy-pw".into())),
            ..Behavior::default()
        });
        legacy_store(&c, server.port);
        let msg = [
            ("to", "a@example.com"),
            ("subject", "s"),
            ("text_body", "b"),
        ];

        let r = call("config", &[("action", "list")]).ok();
        assert!(
            r.json()["warnings"].to_string().contains("base64"),
            "{}",
            r.out
        );
        assert_eq!(r.json()["profiles"][0]["has_password"], true);

        // Sending still works, with a warning.
        let r = call("send", &msg).ok();
        assert!(
            r.json()["warnings"].to_string().contains("legacy"),
            "{}",
            r.out
        );
        assert_eq!(
            server.messages()[0].auth,
            Some(("PLAIN".into(), "bob".into(), "legacy-pw".into()))
        );

        // A write without a keyring keeps it, with a warning.
        c.no_keyring();
        let r = call("config", &[("action", "activate"), ("profile", "old")]).ok();
        assert!(
            r.json()["warnings"].to_string().contains("still stores"),
            "{}",
            r.out
        );
        assert!(
            fs::read_to_string(c.store())
                .unwrap()
                .contains("bGVnYWN5LXB3")
        );

        // A write with a keyring moves it.
        mail_secrets::set_test_store(Some(c.secrets.clone()));
        let r = call("config", &[("action", "activate"), ("profile", "old")]).ok();
        assert!(
            r.json()["warnings"].to_string().contains("Moved"),
            "{}",
            r.out
        );
        let stored = fs::read_to_string(c.store()).unwrap();
        assert!(
            !stored.contains("bGVnYWN5LXB3") && stored.contains("keyring:"),
            "{stored}"
        );
        assert_eq!(c.secret("old").as_deref(), Some("legacy-pw"));
        // And is read from the keyring afterwards.
        let r = call("send", &msg).ok();
        assert!(!r.json()["warnings"].to_string().contains("legacy"));
        assert_eq!(server.messages()[1].auth.as_ref().unwrap().2, "legacy-pw");
    }

    #[test]
    fn keyring_read_failures_are_reported() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            auth_mechs: Some("PLAIN"),
            ..Behavior::default()
        });
        let port = server.port.to_string();
        call(
            "config",
            &[
                ("action", "set"),
                ("profile", "w"),
                ("smtp_host", "127.0.0.1"),
                ("smtp_port", &port),
                ("use_tls", "none"),
                ("smtp_username", "u"),
                ("smtp_password", "p"),
                ("from", "w@example.com"),
                ("is_default", "true"),
            ],
        )
        .ok();
        let msg = [
            ("to", "a@example.com"),
            ("subject", "s"),
            ("text_body", "b"),
        ];
        c.secrets.0.lock().unwrap().clear();
        call("send", &msg).fails(1, MAIL_SEND_KEYRING_ERROR);
        c.no_keyring();
        call("send", &msg).fails(1, MAIL_SEND_KEYRING_ERROR);
        call("test", &[]).fails(1, MAIL_TEST_KEYRING_ERROR);
        // A password given with the call does not need the keyring.
        let mut with_pw = msg.to_vec();
        with_pw.push(("smtp_password", "p"));
        call("send", &with_pw).ok();
        assert_eq!(server.messages().len(), 1);
    }

    // --- ca_file ----------------------------------------------------------------

    fn ca_pem(c: &Ctx) -> String {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new());
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = rcgen::Certificate::from_params(params).unwrap();
        c.file("ca.pem", ca.serialize_pem().unwrap().as_bytes())
    }

    #[test]
    fn ca_file_is_checked_and_used() {
        let c = Ctx::new();
        let server = FakeSmtp::start(Behavior {
            starttls: true,
            ..Behavior::default()
        });
        let ca = ca_pem(&c);
        let not_pem = c.file("x.txt", b"hello");
        let missing = c.dir.path().join("none.pem").display().to_string();
        send_to(&server, &[("use_tls", "starttls"), ("ca_file", &missing)])
            .usage("cannot read ca_file");
        send_to(&server, &[("use_tls", "starttls"), ("ca_file", &not_pem)])
            .usage("no PEM certificate");
        send_to(&server, &[("ca_file", &ca)]).usage("conflicts with use_tls=none");
        send_to(
            &server,
            &[
                ("use_tls", "tls"),
                ("ca_file", &ca),
                ("tls_accept_invalid_certs", "1"),
            ],
        )
        .usage("conflicts with tls_accept_invalid_certs=true");
        test_with(&server, &[("ca_file", &ca)]).usage("conflicts with use_tls=none");
        let base = smtp(&server);
        call(
            "send_template",
            &with(
                &base,
                &[
                    ("template", "welcome"),
                    ("to", "b@example.com"),
                    ("dry_run", "true"),
                    ("ca_file", &ca),
                ],
            ),
        )
        .usage("conflicts with use_tls=none");
        assert!(server.sessions().is_empty());
        // A valid CA file is accepted; this server's TLS still fails.
        send_to(&server, &[("use_tls", "starttls"), ("ca_file", &ca)])
            .fails(1, MAIL_SEND_SMTP_TLS_ERROR);
    }

    // --- shared ---------------------------------------------------------------

    #[test]
    fn verb_args_match_help_usage() {
        for verb in MAIL_HELP.verbs {
            let usage = verb.detail.as_ref().unwrap().usage;
            let mut in_usage: Vec<&str> = usage
                .split(|c: char| c == '[' || c.is_whitespace())
                .filter_map(|w| w.split_once('=').map(|(k, _)| k))
                .filter(|k| *k != "header_<Name>")
                .collect();
            in_usage.sort();
            in_usage.dedup();
            let mut parsed = verb_args(verb.name).unwrap().to_vec();
            parsed.sort();
            assert_eq!(
                in_usage, parsed,
                "usage of {} disagrees with its arguments",
                verb.name
            );
        }
        let send = MAIL_HELP.verbs.iter().find(|v| v.name == "send").unwrap();
        assert!(
            send.detail
                .as_ref()
                .unwrap()
                .usage
                .contains("[header_<Name>=<value> ...]")
        );
    }

    #[test]
    fn every_error_code_is_documented_and_mapped() {
        let doc = include_str!("../../../docs/Network_RemoteOperations/mail.md");
        let src = include_str!("mailh.rs");
        let codes: Vec<&str> = src
            .lines()
            .filter_map(|l| l.strip_prefix("pub const MAIL_"))
            .filter_map(|l| l.split('"').nth(1))
            .collect();
        assert!(codes.len() > 40, "{codes:?}");
        for code in codes {
            assert!(
                code.starts_with("mail.") && crate::core::status::is_valid_error_code(code),
                "{code}"
            );
            assert!(
                doc.contains(&format!("`{code}`")),
                "{code} is not documented in mail.md"
            );
            let exit = exit_code_for(code);
            assert!([1, 2, EXIT_TIMEOUT].contains(&exit));
        }
    }

    #[test]
    fn render_template_is_single_pass() {
        let vars = json!({"a": "{{b}}", "b": "x", "n": {"m": 3}});
        assert_eq!(
            render_template("{{a}}-{{b}}-{{ n.m }}", &vars, true, false).unwrap(),
            "{{b}}-x-3"
        );
        assert_eq!(
            render_template("{{a}}", &vars, false, true).unwrap(),
            "{{b}}"
        );
        assert_eq!(
            render_template("{{zz}}!", &vars, false, false).unwrap(),
            "!"
        );
        let e = render_template("{{zz}}{{yy}}{{zz}}", &vars, true, false).unwrap_err();
        assert_eq!(e.to_string(), "Missing variables: zz, yy");
        assert_eq!(
            render_template("{{open", &vars, true, false).unwrap(),
            "{{open"
        );
        assert_eq!(
            html_escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn exit_codes_follow_the_convention() {
        assert_eq!(exit_code_for(MAIL_SEND_MISSING_RECIPIENTS), 2);
        assert_eq!(exit_code_for(MAIL_SEND_SMTP_REJECTED), 1);
        assert_eq!(exit_code_for(MAIL_SEND_TIMEOUT), 124);
        assert_eq!(exit_code_for(MAIL_TEST_TIMEOUT), 124);
        assert_eq!(exit_code_for(MAIL_CONFIG_PROFILE_NOT_FOUND), 1);
        assert_eq!(exit_code_for(MAIL_CONFIG_INVALID_FLAG), 2);
    }

    #[test]
    fn unknown_verb_is_an_error() {
        let h = MailHandle::new(Url::parse("mail://").unwrap());
        let (mut i, mut o, mut e) = (std::io::empty(), Vec::new(), Vec::new());
        let mut io = IoStreams {
            stdin: &mut i,
            stdout: &mut o,
            stderr: &mut e,
        };
        assert!(h.call("bogus", &Args::new(), &mut io).is_err());
    }
}
