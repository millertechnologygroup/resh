# Resource Shell (resh): Mail Handle

## 1. Overview

The `mail` handle sends email over SMTP with the lettre library, renders two
built-in message templates, checks SMTP settings, and keeps named SMTP
profiles in a local JSON file.

Read section 7 before storing a password: profiles are **not encrypted**.

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

### How `send` and `send_template` arguments are rewritten

Before dispatch, `resh` rewrites a `mail://send` or `mail://send_template`
stage when at least one trailing word starts with one of the keys `to=`,
`subject=`, `text_body=`, `html_body=`, `from=`, `cc=` or `bcc=`
(`reconstruct_mail_command` in `src/main.rs`). The trailing words are turned
into the function-call form `mail://send(key="value",...)`:

* `to`, `cc` and `bcc` values are split on commas into an address list:
  `to=a@example.com,b@example.com`.
* Other values are wrapped in double quotes. Leading and trailing `"` are
  removed from the value first; a value that itself contains `"` characters
  may be altered or split, so avoid double quotes inside values.
* A word without `=` is appended, with a space, to the previous value. So an
  unquoted `text_body=Backup done` is sent as `Backup done`. Quoting the whole
  word for the shell (`'text_body=Backup done'`) is clearer.
* A bare `dry_run` becomes `dry_run="true"`.

`mail://test` and `mail://config` arguments are never rewritten; they are
passed through unchanged.

## 3. Verbs

| Verb            | What it does | Network traffic |
| --------------- | ------------ | --------------- |
| `send`          | Sends one message over SMTP. **No dry run** (`dry_run=true` is refused). | Yes |
| `send_template` | Renders a built-in template and sends it, or only renders it with `dry_run=true`. | Unless `dry_run=true` |
| `test`          | Checks SMTP settings; sends a real test message only with `send_test_email=true`. | DNS lookup of the host; SMTP only with `send_test_email=true` |
| `config`        | Lists, reads, writes, deletes and activates stored SMTP profiles. | No |

## 4. SMTP settings (send, send_template, test)

`send`, `send_template` and `test` take their SMTP settings from arguments,
falling back to environment variables. **Stored profiles (section 7) are never
read by these verbs.**

| Argument        | Environment fallback | Default |
| --------------- | -------------------- | ------- |
| `smtp_host`     | `MAIL_SMTP_HOST`     | (required) |
| `smtp_port`     | `MAIL_SMTP_PORT`     | 587 for `starttls`, 465 for `tls`, 25 for `none` |
| `smtp_username` | `MAIL_SMTP_USERNAME` | (none) |
| `smtp_password` | `MAIL_SMTP_PASSWORD` | (none) |
| `from`          | `MAIL_FROM`          | (required for `send`; see `send_template`) |
| `use_tls`       | (none)               | `starttls` |

`use_tls` values:

* `starttls`: connect in plain text and require STARTTLS (certificate
  verified).
* `tls`: implicit TLS from the first byte (certificate verified).
* `none`: no encryption at all. Credentials and message travel in clear text.

Credentials are used only when both a user name and a password are set.

Passing `smtp_password=` on the command line exposes it in the process list
and shell history. `MAIL_SMTP_PASSWORD` in the environment is safer.

### `tls_accept_invalid_certs` does not do what its name says

No verb ever disables certificate verification. The option instead changes
the TLS mode, and can make the connection *less* safe:

* `send` and `send_template`: `tls_accept_invalid_certs=true` forces implicit
  TLS (wrapper mode) whatever `use_tls` says. With the default `starttls` on
  port 587 this normally fails to connect. It accepts only exactly `true` or
  `false`.
* `test` with `use_tls=starttls`: `tls_accept_invalid_certs=true` switches to
  *opportunistic* STARTTLS, which silently **continues in plain text** if the
  server does not offer STARTTLS. With `use_tls=tls` it has no effect.
  Accepts true/false/yes/no/1/0.

Do not set it. A server with an invalid certificate cannot be used.

## 5. Verb reference

### send

```bash
resh mail://send to=alice@example.com subject=Backup 'text_body=Backup done'
resh mail://send to=ops@example.com,oncall@example.com cc=lead@example.com subject='Disk alert' 'text_body=Disk /srv at 91%' smtp_host=smtp.example.com from=resh@example.com
resh mail://send to=alice@example.com subject=Report 'text_body=See attachment' 'attachments=[{"path":"/var/reports/daily.csv","content_type":"text/csv"}]'
```

| Argument            | Notes |
| ------------------- | ----- |
| `to`, `cc`, `bcc`   | Address lists (comma-separated or JSON array). At least one recipient is required. |
| `subject`           | Required, non-empty. |
| `text_body`, `html_body` | At least one non-empty body is required. Both together give a multipart/alternative message. |
| `from`, `reply_to`  | Addresses. |
| `attachments`       | JSON array of `{"path", "filename", "content_type"}`. Files must exist; total size limit 100 MB. |
| `header_<Name>`     | Adds a header, for example `header_X-Ticket=1234`. From, To, Cc, Bcc, Subject, Date and Message-ID cannot be overridden. |
| `timeout_ms`        | SMTP transport timeout, default 10000. `0` is rejected. |
| `max_retry`         | Extra attempts after a failure, default 0. Errors containing `550`, `authentication` or `invalid` are not retried. |
| `retry_backoff_ms`  | Default 1000, multiplied by the attempt number. |
| `format_output`     | `json` (default) or `text`. |
| SMTP settings       | See section 4. |

**`send` has no dry-run mode.** A `dry_run` request (`dry_run=true`, any
true spelling, or a bare `dry_run` word) is refused with exit 2 and
`mail send does not support dry_run; nothing was sent`, before any SMTP
connection; a malformed `dry_run` value is also an error. To preview a
message, use `send_template ... dry_run=true` or send to a test mailbox.

Output (sorted, indented JSON): `ok`, `timestamp_unix_ms`, `query`
(`to`, `cc`, `bcc`, `from`, `subject`, `use_tls`, `timeout_ms`, `max_retry`),
`result` (`message_id`, `smtp_host`, `smtp_port`, `attempts`,
`last_response`), `error` and `warnings`. `query.from` shows only the `from`
argument, not `MAIL_FROM`. `last_response` is the SMTP reply in Rust debug
form.

```json
{
  "error": null,
  "ok": true,
  "query": { "bcc": [], "cc": [], "from": null, "max_retry": 0, "subject": "Backup", "timeout_ms": 10000, "to": ["alice@example.com"], "use_tls": "starttls" },
  "result": { "attempts": 1, "last_response": "Response { ... }", "message_id": "<1792141964.resh@localhost>", "smtp_host": "smtp.example.com", "smtp_port": 587 },
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
| `template`    | Required. |
| `to`, `cc`, `bcc`, `from`, `reply_to`, `attachments` | As for `send`. |
| `vars`        | JSON object. Missing variables render as empty strings unless `strict_vars=true`, which makes them an error. |
| `locale`      | Falls back to the default template if the locale is unknown. |
| `headers`     | JSON object of extra headers (not the `header_<Name>` form). |
| `dry_run`     | Render only; nothing is sent and no SMTP settings are needed. |
| `timeout_ms`, `max_retry`, `retry_backoff_ms`, SMTP settings | As for `send`. |

**Sender default:** when `from` is not given, the template's built-in sender
`noreply@myapp.io` is used (not `MAIL_FROM`). Always pass `from=` for real
sends.

Output: `ok`, `timestamp_unix_ms`, `query`, `rendered` (`subject`,
`text_body`, `html_body`), `send_result` (null in a dry run), `error`,
`warnings` (a dry run adds `"Dry run: email was not sent."`).

### test

```bash
resh mail://test smtp_host=smtp.example.com connection_only=true
resh mail://test smtp_host=smtp.example.com send_test_email=true to=me@example.com from=resh@example.com
```

Without `send_test_email=true`, `test` **does not open an SMTP session**. It
resolves the host name to an address and builds the transport. The fields
`tls_established` and `auth_succeeded` then only reflect the settings (true
when TLS or credentials are configured), not a live check. `ok: true` means
the settings are well formed, not that the server accepts them.

With `send_test_email=true` (and `connection_only` not true) it sends a real
message to `to` (required) from `from` or `MAIL_FROM` (required), with
`subject` (default `SMTP test`) and `text_body`/`html_body`. If both
`connection_only=true` and `send_test_email=true` are given, nothing is sent.

| Argument          | Default | Notes |
| ----------------- | ------- | ----- |
| `connection_only` | `false` | |
| `send_test_email` | `false` | |
| `timeout_ms`      | `10000` | Used only when a message is actually sent. `0` is rejected. |
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
| `list`       | no  | All profiles and the active one. |
| `get`        | yes | One profile. |
| `set`        | yes | Creates (requires `smtp_host`) or updates a profile. |
| `delete`     | yes | Removes a profile. |
| `activate`   | yes | Marks one profile active and the others inactive. |
| `get_active` | no  | The active profile; an error if none or more than one. |

`set` fields: `smtp_host`, `smtp_port` (defaults from `use_tls` as in section
4), `use_tls` (`none`, `starttls`, `tls`), `smtp_username`, `smtp_password`,
`from`, `reply_to`, `description`, `is_default` (activates the profile),
`tls_accept_invalid_certs`. Booleans in `config` accept only `true` or
`false`. Profile names may contain letters, digits, `_`, `-` and `.`.

Output never contains the password; it shows `has_password` instead.

Profiles are bookkeeping only: `send`, `send_template` and `test` do not read
them, and activating a profile changes nothing about how mail is sent.

## 6. Timeouts

| Verb            | `timeout_ms` |
| --------------- | ------------ |
| `send`          | Enforced as the SMTP transport timeout, default 10000. `0` rejected. |
| `send_template` | Same as `send` when sending; unused for `dry_run=true`. |
| `test`          | Enforced only when a test message is sent; otherwise no SMTP connection is made. `0` rejected. |
| `config`        | Ignored (local file only). |

## 7. Profile storage and password handling

Profiles are written to `$XDG_CONFIG_HOME/resh/mail/smtp_profiles.json`
(`~/.config/resh/mail/smtp_profiles.json` when `XDG_CONFIG_HOME` is unset),
through a temporary file that is renamed into place.

* The password is stored in the field `smtp_password_encrypted`, but it is
  only **base64-encoded, not encrypted**. Anyone who can read the file can
  decode it (`base64 -d`).
* The file is written owner-only (`0600`) through a temporary file that is
  renamed into place; a symlink at the temporary name is refused. The
  directory itself is created with your umask (typically `0755`). Files
  written by earlier versions keep their old mode until the next save.

A profile file written by an earlier version may still be readable by other
users; resave a profile, or run `chmod 600 ~/.config/resh/mail/smtp_profiles.json`.
Since no verb reads the stored password, the simplest safe choice is not to
store one.

## 8. Errors and exit codes

* Success exits 0; any failure exits 1.
* The JSON response is printed to stdout even on failure, with `ok: false`
  and `error: {"code": "...", "message": "..."}`. resh also prints
  `Error: [code] message` to stderr.
* Invalid arguments print `Invalid mail <verb> options: ...` to stderr and no
  JSON.
* Codes include `mail.send_missing_recipients`, `mail.send_missing_subject`,
  `mail.send_smtp_not_configured`, `mail.send_smtp_auth_failed`,
  `mail.send_smtp_connection_failed`, `mail.test_send_email_missing_from`.

## 9. Limitations

* `send` has no dry run; `dry_run=true` is refused and nothing is sent.
* Stored profiles are not used for sending.
* `tls_accept_invalid_certs` never accepts invalid certificates (see section 4).
* `test` does not verify connectivity, TLS or authentication unless it sends a
  real message.
* Templates are fixed; there is no template store.
* Linux only.
