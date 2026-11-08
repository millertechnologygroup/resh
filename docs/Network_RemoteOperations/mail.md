# Resource Shell (resh): Mail Handle

## 1. Overview

The `mail` handle sends email over SMTP with the lettre library, renders two
built-in message templates, checks SMTP settings with a real SMTP session,
and keeps named SMTP profiles in a local JSON file.

Passwords of stored profiles are kept in the OS keyring, never in the
profile file (section 7).

Linux is the only supported and verified platform. Each `resh` invocation is a
separate process; there is no SMTP connection reuse or queue between
commands.

```bash
resh mail --help
resh mail send --help
```

## 2. Command syntax

Unlike most handles, the verb is the first path segment of the URL. There is
no host part:

```text
resh mail://<verb> key=value ...
resh 'mail://<verb>(key=value,...)'
resh 'mail://<verb>?key=value&key2=value2'
```

```bash
resh mail://send to=alice@example.com subject=Backup 'text_body=Backup done'
resh mail://test smtp_host=smtp.example.com connection_only=true
resh mail://config action=list
```

A dotted form such as `mail://smtp.send` also reaches the `send` verb (the
part before the dot is ignored); it has no advantage over `mail://send`.

### Words the shell split

Trailing `key=value` words are passed to the verb exactly as typed (quotes,
commas and JSON included). Two conveniences remain
(`reconstruct_mail_command` in `src/main.rs`):

* For `send` and `send_template`, a word without `=` that follows one of the
  message arguments `to`, `subject`, `text_body`, `html_body`, `from`, `cc`
  or `bcc` is appended, with a space, to that value. So an unquoted
  `text_body=Backup done` is sent as `Backup done`. Quoting the whole word
  for the shell (`'text_body=Backup done'`) is clearer. Any other bare word
  (except `dry_run`) is refused.
* An unquoted function-call stage that the shell split at spaces
  (`mail://send(to=a@example.com, subject=Hi)`) is joined back together.

`mail://test` and `mail://config` words are never changed.

### Strict arguments

Every verb accepts only the arguments listed for it in section 5 (and in
`resh mail <verb> --help`). An unknown argument, a malformed value (port,
number, boolean, address, JSON) or a conflicting combination is refused with
exit 2 and `[mail.invalid_argument]` (or a more specific `mail.config_*`
code), naming the argument and suggesting the closest valid name for a
likely typo. Nothing is sent, connected or written. Booleans accept
`true/false`, `1/0`, `yes/no` and `on/off`.

## 3. Verbs

| Verb            | What it does | Network traffic |
| --------------- | ------------ | --------------- |
| `send`          | Sends one message over SMTP. **No dry run** (`dry_run=true` is refused). | Yes |
| `send_template` | Renders a built-in template and sends it, or only renders and checks it with `dry_run=true`. | Unless `dry_run=true` |
| `test`          | Opens a real SMTP session (TLS and AUTH as configured) and closes it; also sends a test message with `send_test_email=true`. | Yes |
| `config`        | Lists, reads, writes, deletes and activates stored SMTP profiles. | No |

## 4. SMTP settings (send, send_template, test)

Settings are resolved in this order:

1. Arguments always win.
2. If `smtp_host` is given or `MAIL_SMTP_HOST` is set, the other settings
   fall back to the environment, then to the defaults below.
3. Otherwise the **active stored profile** (section 7) supplies the host and
   every setting the arguments leave out: port, `use_tls`, user name,
   password (read from the OS keyring), `tls_accept_invalid_certs`, `from`
   and `reply_to`. If the keyring cannot be read or has no entry for the
   profile, the verb fails with `mail.send_keyring_error` /
   `mail.test_keyring_error` (exit 1); `smtp_password=` on the call avoids
   the keyring. The
   environment is not read in this case, and the response carries the
   warning `Using stored SMTP profile '<name>'.`
4. With neither, the verb fails with `mail.send_smtp_not_configured` or
   `mail.test_missing_smtp_host` (exit 2).

| Argument        | Environment fallback | Default |
| --------------- | -------------------- | ------- |
| `smtp_host`     | `MAIL_SMTP_HOST`     | (required, or an active profile) |
| `smtp_port`     | `MAIL_SMTP_PORT`     | 587 for `starttls`, 465 for `tls`, 25 for `none` |
| `smtp_username` | `MAIL_SMTP_USERNAME` | (none) |
| `smtp_password` | `MAIL_SMTP_PASSWORD` | (none) |
| `from`          | `MAIL_FROM`          | (required for `send` and `test`; see `send_template`) |
| `use_tls`       | (none)               | `starttls` |
| `tls_accept_invalid_certs` | (none)    | `false` |
| `ca_file`       | (none)               | (none) |

An invalid `MAIL_SMTP_HOST` or `MAIL_SMTP_PORT`, an unreadable profile store,
or more than one active profile is an error (`mail.send_smtp_not_configured`,
`mail.test_smtp_not_configured`, exit 2); an invalid `MAIL_FROM` is
`mail.send_invalid_address` / `mail.test_invalid_address`. Ports are 1-65535.

`use_tls` values:

* `starttls`: connect in plain text and require STARTTLS. A server that does
  not offer STARTTLS is an error; the session never continues in plain text.
* `tls`: implicit TLS from the first byte.
* `none`: no encryption at all. Credentials and message travel in clear text
  (a warning says so when credentials are used).

The server certificate is verified against the built-in public CA roots
(webpki roots). `ca_file=<pem>` adds the CA certificates in that PEM file
for this call, for a server whose certificate comes from a private CA;
verification stays on. The file must be readable and contain at least one
PEM certificate (otherwise exit 2, nothing done). `ca_file` is refused with
`use_tls=none` (also when that mode comes from the active profile) and
together with `tls_accept_invalid_certs=true` (exit 2); with a profile that
has `tls_accept_invalid_certs=true`, a `ca_file` turns verification back
on.
`tls_accept_invalid_certs=true` turns that verification off (self-signed,
expired or wrong-host certificates are accepted) for both `starttls` and
`tls`, and adds a warning. **This is insecure**: anyone on the network path
can read the mail and the password. Prefer `ca_file`.
`tls_accept_invalid_certs=true` with `use_tls=none` is refused (exit 2).

Credentials are used only when both a user name and a password are set; if
only one is set the session is not authenticated and a warning says so.
AUTH PLAIN and LOGIN are supported.

Passing `smtp_password=` on the command line exposes it in the process list
and shell history. `MAIL_SMTP_PASSWORD` in the environment is safer.

## 5. Verb reference

### send

```bash
resh mail://send to=alice@example.com subject=Backup 'text_body=Backup done'
resh mail://send to=ops@example.com,oncall@example.com cc=lead@example.com subject='Disk alert' 'text_body=Disk /srv at 91%' smtp_host=smtp.example.com from=resh@example.com
resh mail://send to=alice@example.com subject=Report 'text_body=See attachment' 'attachments=[{"path":"/var/reports/daily.csv","content_type":"text/csv"}]'
```

| Argument            | Notes |
| ------------------- | ----- |
| `to`, `cc`, `bcc`   | Address lists (comma-separated or JSON array of strings). At least one recipient is required. Bcc recipients get the message but never appear in its headers. |
| `subject`           | Required, not blank. |
| `text_body`, `html_body` | At least one non-empty body is required. Text only is `text/plain`, HTML only is `text/html`, both give `multipart/alternative`. |
| `from`, `reply_to`  | Addresses. `from` falls back as in section 4; with no sender at all: `mail.send_missing_from`. |
| `attachments`       | JSON array of `{"path", "filename", "content_type"}` (only these fields). Each path must be a readable regular file; total size limit 100 MB. Files are attached byte for byte; `content_type` must be a valid MIME type and otherwise is guessed from the extension. |
| `header_<Name>`     | Adds a header, for example `header_X-Ticket=1234`. From, To, Cc, Bcc, Subject, Date, Message-ID, Reply-To, MIME-Version, Content-Type and Content-Transfer-Encoding cannot be set this way (`mail.send_header_conflict`); a name that is not printable ASCII without `:` or a value with a line break is `mail.send_invalid_header`. |
| `timeout_ms`        | Deadline for the whole command (all attempts and back-off), default 10000. `0` is rejected. |
| `max_retry`         | Extra attempts after a transient failure (4xx reply, connection failure), default 0, at most 10. Permanent rejections, authentication and TLS failures are not retried. |
| `retry_backoff_ms`  | Default 1000, multiplied by the attempt number; never waits past the deadline. |
| `format_output`     | `json` (default) or `text`. |
| SMTP settings       | See section 4. |

**`send` has no dry-run mode.** A `dry_run` request (`dry_run=true`, any
true spelling, or a bare `dry_run` word) is refused with exit 2 before any
SMTP connection; a malformed `dry_run` value is also an error. To preview a
message, use `send_template ... dry_run=true` or send to a test mailbox.

Output (sorted, indented JSON): `ok`, `timestamp_unix_ms`, `query`
(`to`, `cc`, `bcc`, `from`, `subject`, `use_tls`, `timeout_ms`, `max_retry`),
`result` (`message_id`, `smtp_host`, `smtp_port`, `attempts`,
`last_response`), `error` and `warnings`. `query.from` shows only the `from`
argument; `query.use_tls` is the mode actually used. `message_id` is the
Message-ID header of the sent message (null when nothing was sent).
`last_response` is the SMTP reply in Rust debug form.

```json
{
  "error": null,
  "ok": true,
  "query": { "bcc": [], "cc": [], "from": null, "max_retry": 0, "subject": "Backup", "timeout_ms": 10000, "to": ["alice@example.com"], "use_tls": "starttls" },
  "result": { "attempts": 1, "last_response": "Response { ... }", "message_id": "<0f9c2c1e-6a1d-4f55-9a43-2b1e7a5f3c11@buildhost>", "smtp_host": "smtp.example.com", "smtp_port": 587 },
  "timestamp_unix_ms": 1792141964512,
  "warnings": []
}
```

### send_template

```bash
resh mail://send_template template=welcome to=bob@example.com dry_run=true 'vars={"user_name":"Bob","app_name":"Acme"}'
resh mail://send_template template=password_reset to=bob@example.com from=noreply@example.com 'vars={"user_name":"Bob","reset_link":"https://example.com/r/abc"}'
```

Templates are built in and cannot be added or changed:

| Template         | Variables                 | Locales |
| ---------------- | ------------------------- | ------- |
| `welcome`        | `user_name`, `app_name`   | default, `fr` |
| `password_reset` | `user_name`, `reset_link` | default |

| Argument      | Notes |
| ------------- | ----- |
| `template`    | Required. An unknown name is `mail.send_template_not_found` (exit 1). |
| `to`          | Required (at least one address). |
| `cc`, `bcc`, `from`, `reply_to`, `attachments` | As for `send`. |
| `vars`        | JSON object. `{{name}}` or `{{a.b}}` placeholders are replaced in one pass (a value containing `{{...}}` is inserted literally); values are HTML-escaped in the HTML body. Missing variables render as empty strings unless `strict_vars=true`, which makes them `mail.send_template_missing_var`. |
| `locale`      | Falls back to the default template, with a warning, if the locale is unknown. |
| `headers`     | JSON object of extra headers with string values (not the `header_<Name>` form). A reserved header is `mail.send_template_header_conflict`. |
| `dry_run`     | Render and check everything a send would check before connecting (addresses, headers, attachments, timeout, retries); nothing is sent and no SMTP settings are needed. |
| `timeout_ms`, `max_retry`, `retry_backoff_ms`, `format_output`, SMTP settings | As for `send`. |

**Sender:** `from`, else `MAIL_FROM` or the active profile's `from`
(section 4), else the template's built-in sender `noreply@myapp.io`. Pass
`from=` for real sends.

Output: `ok`, `timestamp_unix_ms`, `query`, `rendered` (`subject`,
`text_body`, `html_body`), `send_result` (null in a dry run), `error`,
`warnings` (a dry run adds `"Dry run: email was not sent."`).

### test

```bash
resh mail://test smtp_host=smtp.example.com connection_only=true
resh mail://test connection_only=true
resh mail://test smtp_host=smtp.example.com send_test_email=true to=me@example.com from=resh@example.com
```

`test` resolves the host, connects, says EHLO, upgrades to TLS
(`starttls`/`tls`), authenticates when credentials are set, sends NOOP and
closes. `tls_established` and `auth_succeeded` are therefore the result of a
live session. With `send_test_email=true` it also sends a real message to
`to` (required) from `from` (section 4 fallbacks; required) with `subject`
(default `SMTP test`) and `text_body` (default `SMTP test email`) /
`html_body`.

`connection_only=true` and `send_test_email=true` together are refused
(exit 2), as are `to`, `from`, `subject`, `text_body` and `html_body`
without `send_test_email=true`.

| Argument          | Default | Notes |
| ----------------- | ------- | ----- |
| `connection_only` | `false` | Session check only (the default behaviour). |
| `send_test_email` | `false` | |
| `timeout_ms`      | `10000` | Deadline for the whole command, DNS included. `0` is rejected. |
| `max_retry`       | `0`     | At most 10. |
| `retry_backoff_ms`| `1000`  | |
| `format_output`   | `json`  | |

Output: `ok`, `timestamp_unix_ms`, `query`, `connection` (`smtp_host`,
`smtp_port`, `resolved_ip`, `use_tls`, `tls_established`, `auth_attempted`,
`auth_succeeded`, `attempts`, `last_response`), `send_test_email` (details of
the test message, or null), `error`, `warnings`.

### config

```bash
resh mail://config action=list
resh mail://config action=set profile=work smtp_host=smtp.example.com smtp_username=alice from=alice@example.com is_default=true
resh mail://config action=get profile=work
resh mail://config action=activate profile=work
resh mail://config action=get_active
resh mail://config action=delete profile=work
```

| Action       | Needs `profile` | Effect |
| ------------ | --------------- | ------ |
| `list`       | no (refused)  | All profiles and the active one. |
| `get`        | yes | One profile. |
| `set`        | yes | Creates (requires `smtp_host`) or updates a profile. |
| `delete`     | yes | Removes a profile. |
| `activate`   | yes | Marks one profile active and the others inactive. |
| `get_active` | no (refused) | The active profile; an error if none or more than one. |

`set` stores `smtp_password` in the OS keyring (section 7); if no keyring is
available it fails with `mail.config_keyring_unavailable` (exit 1) and
changes nothing. `delete` also removes the keyring entry (if the keyring
cannot be reached: the same error, nothing deleted).

`set` fields: `smtp_host`, `smtp_port` (1-65535; defaults from `use_tls` as
in section 4, and is reset to that default when `use_tls` changes without a
port), `use_tls` (`none`, `starttls`, `tls`, any case), `smtp_username`,
`smtp_password`, `from`, `reply_to` (valid addresses), `description`,
`is_default` (`true` activates the profile; `false` leaves activation
unchanged), `tls_accept_invalid_certs`. These fields are refused for other
actions (exit 2). Profile names may contain letters, digits, `_`, `-` and
`.`. `config` does not take `timeout_ms` (it only touches a local file).

Output never contains the password; it shows `has_password` instead.

The active profile is what `send`, `send_template` and `test` use when no
host is given by argument or `MAIL_SMTP_HOST` (section 4).

## 6. Timeouts

| Verb            | `timeout_ms` |
| --------------- | ------------ |
| `send`          | Deadline for the whole command, default 10000. On expiry: exit 124, `mail.send_timeout`; if the server stalled after the message data, the message may or may not have been delivered. `0` rejected. |
| `send_template` | Same as `send` when sending; checked but unused for `dry_run=true`. |
| `test`          | Deadline for DNS, session and test message, default 10000; exit 124, `mail.test_timeout`. `0` rejected. |
| `config`        | Not accepted (exit 2). |

## 7. Profile storage and password handling

Profiles are written to `$XDG_CONFIG_HOME/resh/mail/smtp_profiles.json`
(`~/.config/resh/mail/smtp_profiles.json` when `XDG_CONFIG_HOME` is unset).
Reading (`list`, `get`, `get_active`, sending) never creates anything.

* **Passwords are kept in the OS keyring** (the Secret Service on Linux,
  for example GNOME Keyring or KWallet over D-Bus; the Keychain on macOS),
  under the service `resh-mail-smtp` with the profile name as the account.
  The profile file keeps only a reference,
  `"smtp_password_ref": "keyring:resh-mail-smtp/<profile>"`.
* Without a reachable keyring (no D-Bus session, no Secret Service, a
  locked keyring that does not answer within 10 seconds), `config set` with
  `smtp_password=` is refused with `mail.config_keyring_unavailable`
  (exit 1) and nothing is written. The password is never stored in the file
  instead. Pass `smtp_password=` per call or set `MAIL_SMTP_PASSWORD`.
* **Legacy files.** Earlier versions stored the password base64-encoded in
  `smtp_password_encrypted`. Such a password is still used, with a warning,
  and every `config set`, `delete` or `activate` moves it to the keyring
  (warning `Moved the password of profile ...`). If the keyring is not
  available it stays, with a warning, until a later write.
* The file is written owner-only (`0600`) through a temporary file that is
  renamed into place; a symlink at the temporary name is refused and a
  symlink at the store itself is replaced, never written through. Created
  directories are owner-only (`0700`). Changes take an exclusive lock
  (`smtp_profiles.lock`, `0600`) so concurrent `config` commands cannot lose
  each other's update.

Testing note: debug builds of resh honour `RESH_TEST_KEYRING=unavailable`
(simulate no keyring) and `RESH_TEST_KEYRING=file:<path>` (a test-only
file store) for the test suite. Release builds ignore the variable.

## 8. Errors and exit codes

| Exit | Meaning |
| ---- | ------- |
| 0    | Success. |
| 1    | The operation failed (SMTP refused, connection/TLS/auth failure, not found, file errors). |
| 2    | Invalid arguments; nothing was sent, connected or written. |
| 124  | Timeout; for `send` the outcome may be unknown. |

When a verb has started (its arguments parsed), the JSON response is printed
to stdout even on failure, with `ok: false` and
`error: {"code": "...", "message": "..."}`. resh prints
`Error: [code] message` to stderr. Argument errors print only the stderr
line (no JSON).

| Code | Exit | When |
| ---- | ---- | ---- |
| `mail.unknown_verb` | 2 | A verb the handle does not have. |
| `mail.invalid_argument` | 2 | Unknown argument, malformed value (including an unreadable `ca_file`), conflicting options, `dry_run` on a verb without one. |
| `mail.send_missing_recipients` | 2 | No `to`/`cc`/`bcc` (send), no `to` (send_template). |
| `mail.send_missing_subject` | 2 | Blank subject. |
| `mail.send_missing_body` | 2 | No non-empty body. |
| `mail.send_missing_from` | 2 | No sender anywhere. |
| `mail.send_invalid_address` | 2 | Invalid `MAIL_FROM` or profile address. |
| `mail.send_header_conflict` | 2 | `header_<Name>` for a reserved header. |
| `mail.send_invalid_header` | 2 | Bad header name or a line break in a value. |
| `mail.send_invalid_timeout` | 2 | `timeout_ms=0`. |
| `mail.send_invalid_retry_config` | 2 | `max_retry` above 10. |
| `mail.send_smtp_not_configured` | 2 | No host, invalid `MAIL_SMTP_*`, unreadable profile store, several active profiles, `ca_file` with a profile using `use_tls=none`. |
| `mail.send_attachment_missing` | 1 | Attachment path does not exist. |
| `mail.send_attachment_io_error` | 1 | Attachment is not a regular file or cannot be read. |
| `mail.send_attachments_too_large` | 1 | Attachments total more than 100 MB. |
| `mail.send_smtp_connection_failed` | 1 | Connection refused, reset or unreadable reply. |
| `mail.send_smtp_tls_error` | 1 | STARTTLS not offered, handshake or certificate failure. |
| `mail.send_smtp_auth_failed` | 1 | Credentials refused (530/534/535/538) or no common mechanism. |
| `mail.send_smtp_rejected` | 1 | Permanent (5xx) reply, for example an unknown recipient. |
| `mail.send_smtp_transient_failed` | 1 | Temporary (4xx) reply after all retries. |
| `mail.send_timeout` | 124 | Deadline passed. |
| `mail.send_keyring_error` | 1 | The active profile's password cannot be read from the OS keyring. |
| `mail.send_internal_error` | 1 | The message could not be built (should not happen). |
| `mail.send_template_not_found` | 1 | Unknown template. |
| `mail.send_template_missing_var` | 2 | `strict_vars=true` and variables missing. |
| `mail.send_template_header_conflict` | 2 | `headers` sets a reserved header. |
| `mail.test_invalid_timeout` | 2 | `timeout_ms=0`. |
| `mail.test_invalid_retry_config` | 2 | `max_retry` above 10. |
| `mail.test_missing_smtp_host` | 2 | No host and no active profile. |
| `mail.test_smtp_not_configured` | 2 | Invalid `MAIL_SMTP_*`, unreadable profile store, several active profiles. |
| `mail.test_send_email_missing_recipients` | 2 | `send_test_email=true` without `to`. |
| `mail.test_send_email_missing_from` | 2 | `send_test_email=true` without a sender. |
| `mail.test_invalid_address` | 2 | Invalid `MAIL_FROM` or profile address. |
| `mail.test_dns_error` | 1 | The host does not resolve. |
| `mail.test_connection_failed` | 1 | Connection refused or the server does not answer NOOP. |
| `mail.test_tls_error` | 1 | As `mail.send_smtp_tls_error`. |
| `mail.test_auth_failed` | 1 | As `mail.send_smtp_auth_failed`. |
| `mail.test_send_rejected` | 1 | Permanent (5xx) reply, including a 5xx greeting. |
| `mail.test_transient_failed` | 1 | Temporary (4xx) reply after all retries. |
| `mail.test_timeout` | 124 | Deadline passed. |
| `mail.test_keyring_error` | 1 | As `mail.send_keyring_error`. |
| `mail.test_internal_error` | 1 | Internal client error (should not happen). |
| `mail.config_invalid_action` | 2 | Missing or unknown `action`. |
| `mail.config_profile_required` | 2 | `get`/`set`/`delete`/`activate` without `profile`. |
| `mail.config_invalid_profile_name` | 2 | Empty name or invalid characters. |
| `mail.config_invalid_smtp_host` | 2 | Invalid `smtp_host`, or a new profile without one. |
| `mail.config_invalid_smtp_port` | 2 | Port not 1-65535. |
| `mail.config_invalid_tls_mode` | 2 | `use_tls` not none/starttls/tls. |
| `mail.config_invalid_flag` | 2 | Bad boolean or `format_output`, an argument the action does not use. |
| `mail.config_invalid_address` | 2 | Invalid `from` or `reply_to`. |
| `mail.config_profile_not_found` | 1 | No such profile. |
| `mail.config_no_active_profile` | 1 | `get_active` with none active. |
| `mail.config_active_profile_inconsistent` | 1 | More than one profile active (hand-edited file). |
| `mail.config_keyring_unavailable` | 1 | The OS keyring cannot store or remove a password; nothing was changed. |
| `mail.config_store_read_error` | 1 | The store cannot be read (or no HOME/XDG_CONFIG_HOME). |
| `mail.config_store_write_error` | 1 | The store or its directory cannot be written or locked. |
| `mail.config_store_parse_error` | 1 | The store is not valid JSON. |
| `mail.config_internal_error` | 1 | Unexpected internal error (should not happen). |

## 9. Limitations

* `send` has no dry run; `dry_run=true` is refused and nothing is sent.
* Storing a profile password needs an OS keyring (section 7).
* `ca_file` is per call; profiles do not store one.
* Templates are fixed; there is no template store.
* Linux only.
