# Mail Handle Documentation

The mail handle in Resource Shell allows you to send emails, test SMTP connections, manage email profiles, and send template-based emails. This handle supports four main verbs: `send`, `send_template`, `test`, and `config`.

## Verbs

### send

Send an email message with custom content.

**Basic Usage:**
```bash
mail://send(to=["user@example.com"], subject="Test Email", text_body="Hello from test")
```

**Parameters:**
- `to` (required): Array of recipient email addresses
- `subject` (required): Email subject line
- `text_body` or `html_body` (required): Email body content
- `from`: Sender email address
- `cc`: Array of CC recipient email addresses
- `bcc`: Array of BCC recipient email addresses
- `reply_to`: Reply-to email address
- `attachments`: Array of file paths to attach
- `headers`: Custom email headers as JSON object
- `smtp_host`: SMTP server hostname
- `smtp_port`: SMTP server port (default: 587)
- `smtp_username`: SMTP authentication username
- `smtp_password`: SMTP authentication password
- `use_tls`: TLS mode ("none", "starttls", "tls")
- `tls_accept_invalid_certs`: Accept invalid TLS certificates (true/false)
- `timeout_ms`: Connection timeout in milliseconds (default: 10000)
- `max_retry`: Maximum retry attempts (default: 0)
- `retry_backoff_ms`: Retry delay in milliseconds (default: 1000)
- `format_output`: Output format ("json" or "text")

**Examples:**

*Simple email:*
```bash
mail://send(to=["user@example.com"], subject="Test", text_body="Hello", from="test@example.com")
```

*Email with SMTP configuration:*
```bash
mail://send(to=["user@example.com"], subject="Test Email", text_body="Hello from test", smtp_host="127.0.0.1", smtp_port=2525, use_tls="none")
```

*Email with multiple recipients and CC:*
```bash
mail://send(to=["user1@example.com", "user2@example.com"], cc=["manager@example.com"], subject="Team Update", text_body="Weekly update")
```

**Expected Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "to": ["user@example.com"],
    "subject": "Test Email"
  },
  "result": {
    "message_id": "12345",
    "smtp_host": "127.0.0.1",
    "smtp_port": 2525,
    "attempts": 1,
    "last_response": "250 OK: queued as 12345"
  },
  "error": null,
  "warnings": []
}
```

### send_template

Send an email using a predefined template with variable substitution.

**Basic Usage:**
```bash
mail://.send_template(template="welcome", to=["user@example.com"], vars={"user_name":"Alice"})
```

**Parameters:**
- `template` (required): Name of the email template to use
- `to` (required): Array of recipient email addresses
- `vars`: JSON object containing template variables
- `locale`: Template locale/language
- `version`: Template version
- `from`: Sender email address
- `cc`: Array of CC recipient email addresses
- `bcc`: Array of BCC recipient email addresses
- `reply_to`: Reply-to email address
- `attachments`: Array of file paths to attach
- `headers`: Custom email headers as JSON object
- `smtp_host`: SMTP server hostname
- `smtp_port`: SMTP server port (default: 587)
- `smtp_username`: SMTP authentication username
- `smtp_password`: SMTP authentication password
- `use_tls`: TLS mode ("none", "starttls", "tls")
- `tls_accept_invalid_certs`: Accept invalid TLS certificates (true/false)
- `timeout_ms`: Connection timeout in milliseconds (default: 10000)
- `max_retry`: Maximum retry attempts (default: 0)
- `retry_backoff_ms`: Retry delay in milliseconds (default: 1000)
- `strict_vars`: Require all template variables to be provided (true/false)
- `dry_run`: Test template rendering without sending (true/false)
- `format_output`: Output format ("json" or "text")

**Examples:**

*Simple template without variables:*
```bash
mail://.send_template(template="welcome", to=["user@example.com"], dry_run=true, format_output="json")
```

*Template with variables:*
```bash
mail://.send_template(template="welcome", to=["user@example.com"], vars={"user_name":"Alice","app_name":"MyApp"}, dry_run=true, format_output="json")
```

*Template with locale:*
```bash
mail://.send_template(template="newsletter", to=["user@example.com"], vars={"name":"Alice"}, locale="en_US", dry_run=true)
```

**Expected Output:**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "template": "welcome",
    "to": ["user@example.com"],
    "vars": {"user_name": "Alice"}
  },
  "result": {
    "template": "welcome",
    "rendered": {
      "subject": "Welcome Alice!",
      "text_body": "Hello Alice, welcome to our service!"
    },
    "message_id": "12345"
  },
  "error": null,
  "warnings": []
}
```

### test

Test SMTP connection and optionally send a test email.

**Basic Usage:**
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none")
```

**Parameters:**
- `smtp_host`: SMTP server hostname
- `smtp_port`: SMTP server port
- `smtp_username`: SMTP authentication username
- `smtp_password`: SMTP authentication password
- `use_tls`: TLS mode ("none", "starttls", "tls")
- `tls_accept_invalid_certs`: Accept invalid TLS certificates (true/false)
- `connection_only`: Only test connection without sending email (true/false)
- `send_test_email`: Send a test email (true/false)
- `to`: Array of recipient email addresses (required if send_test_email=true)
- `from`: Sender email address (required if send_test_email=true)
- `subject`: Test email subject
- `text_body`: Test email body
- `html_body`: Test email HTML body
- `timeout_ms`: Connection timeout in milliseconds (default: 10000)
- `max_retry`: Maximum retry attempts (default: 0)
- `retry_backoff_ms`: Retry delay in milliseconds (default: 1000)
- `format_output`: Output format ("json" or "text")

**Examples:**

*Basic connection test:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none", connection_only=true)
```

*Connection test with authentication:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none", smtp_username="user", smtp_password="pass")
```

*Send test email:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none", send_test_email=true, to=["test@example.com"], from="sender@example.com", subject="Test Email", text_body="Hello from test")
```

*Test with STARTTLS:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=587, use_tls="starttls", tls_accept_invalid_certs=false)
```

*Test with retry logic:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none", max_retry=2, retry_backoff_ms=100)
```

*Test with text output format:*
```bash
mail://.test(smtp_host="127.0.0.1", smtp_port=2525, use_tls="none", connection_only=true, format_output="text")
```

**Expected Output (Connection Only):**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "smtp_host": "127.0.0.1",
    "smtp_port": 2525,
    "use_tls": "none",
    "connection_only": true
  },
  "connection": {
    "smtp_host": "127.0.0.1",
    "smtp_port": 2525,
    "use_tls": "none",
    "tls_established": false,
    "auth_attempted": false,
    "auth_succeeded": false,
    "attempts": 1,
    "last_response": "220 localhost SMTP ready"
  },
  "send_test_email": {
    "attempted": false
  },
  "error": null,
  "warnings": []
}
```

**Expected Output (Send Test Email):**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "smtp_host": "127.0.0.1",
    "smtp_port": 2525,
    "send_test_email": true,
    "to": ["test@example.com"]
  },
  "connection": {
    "smtp_host": "127.0.0.1",
    "smtp_port": 2525,
    "use_tls": "none",
    "auth_attempted": false,
    "auth_succeeded": false
  },
  "send_test_email": {
    "attempted": true,
    "envelope_from": "sender@example.com",
    "envelope_to": ["test@example.com"],
    "accepted_recipients": ["test@example.com"],
    "rejected_recipients": [],
    "last_response": "250 OK: queued as 12345"
  },
  "error": null,
  "warnings": []
}
```

### config

Manage SMTP profile configurations.

**Basic Usage:**
```bash
mail://.config(action="list")
```

**Parameters:**
- `action` (required): Configuration action ("list", "get", "set", "delete", "activate", "get_active")
- `profile`: Profile name (required for get, set, delete, activate actions)
- `smtp_host`: SMTP server hostname (for set action)
- `smtp_port`: SMTP server port (for set action)
- `smtp_username`: SMTP authentication username (for set action)
- `smtp_password`: SMTP authentication password (for set action)
- `use_tls`: TLS mode ("none", "starttls", "tls") (for set action)
- `tls_accept_invalid_certs`: Accept invalid TLS certificates (for set action)
- `from`: Default sender email address (for set action)
- `reply_to`: Default reply-to email address (for set action)
- `description`: Profile description (for set action)
- `is_default`: Set as default profile (for set action)
- `format_output`: Output format ("json" or "text")

**Examples:**

*List all profiles:*
```bash
mail://.config(action="list")
```

*Get specific profile:*
```bash
mail://.config(action="get", profile="production")
```

*Create/update profile:*
```bash
mail://.config(action="set", profile="production", smtp_host="smtp.example.com", smtp_port=587, use_tls="starttls", smtp_username="user@example.com", smtp_password="password", from="noreply@example.com")
```

*Activate profile:*
```bash
mail://.config(action="activate", profile="production")
```

*Get active profile:*
```bash
mail://.config(action="get_active")
```

*Delete profile:*
```bash
mail://.config(action="delete", profile="old_profile")
```

**Expected Output (List):**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "action": "list"
  },
  "profiles": [
    {
      "name": "production",
      "smtp_host": "smtp.example.com",
      "smtp_port": 587,
      "use_tls": "starttls",
      "tls_accept_invalid_certs": false,
      "from": "noreply@example.com",
      "reply_to": null,
      "description": null,
      "is_active": true,
      "has_password": true
    }
  ],
  "active_profile": "production",
  "error": null,
  "warnings": []
}
```

**Expected Output (Get Profile):**
```json
{
  "ok": true,
  "timestamp_unix_ms": 1672531200000,
  "query": {
    "action": "get",
    "profile": "production"
  },
  "profile": {
    "name": "production",
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "use_tls": "starttls",
    "tls_accept_invalid_certs": false,
    "from": "noreply@example.com",
    "reply_to": null,
    "description": null,
    "is_active": true,
    "has_password": true
  },
  "error": null,
  "warnings": []
}
```

## Common Error Codes

### Send Verb Errors
- `mail.send_missing_recipients`: No recipients specified
- `mail.send_missing_subject`: Subject line not provided
- `mail.send_missing_body`: Neither text_body nor html_body provided
- `mail.send_invalid_address`: Invalid email address format
- `mail.send_smtp_not_configured`: SMTP configuration missing
- `mail.send_smtp_connection_failed`: Failed to connect to SMTP server
- `mail.send_smtp_auth_failed`: SMTP authentication failed
- `mail.send_smtp_rejected`: Email rejected by SMTP server

### Test Verb Errors
- `mail.test_missing_smtp_host`: SMTP host not specified
- `mail.test_connection_failed`: Unable to connect to SMTP server
- `mail.test_auth_failed`: SMTP authentication failed
- `mail.test_send_rejected`: Test email rejected by server
- `mail.test_invalid_timeout`: Invalid timeout value
- `mail.test_send_email_missing_recipients`: Recipients required for send_test_email
- `mail.test_invalid_address`: Invalid email address format

### Config Verb Errors
- `mail.config_invalid_action`: Invalid action specified
- `mail.config_profile_required`: Profile name required for action
- `mail.config_profile_not_found`: Specified profile does not exist
- `mail.config_no_active_profile`: No active profile configured
- `mail.config_invalid_smtp_host`: Invalid SMTP host
- `mail.config_invalid_smtp_port`: Invalid SMTP port

### Template Verb Errors
- `mail.send_template_not_found`: Template file not found
- `mail.send_template_missing_var`: Required template variable missing
- `mail.send_template_empty_subject`: Template rendered empty subject
- `mail.send_template_empty_body`: Template rendered empty body
- `mail.send_template_render_error`: Template rendering failed

## Tips

1. **SMTP Configuration**: You can either provide SMTP settings in each command or use the `config` verb to manage reusable profiles.

2. **TLS Modes**: 
   - `"none"`: No encryption
   - `"starttls"`: Use STARTTLS for encryption
   - `"tls"`: Use TLS from the start

3. **Testing**: Always use the `test` verb to verify your SMTP configuration before sending actual emails.

4. **Templates**: Use `dry_run=true` with `send_template` to test template rendering without sending emails.

5. **Attachments**: Specify file paths as an array of strings for the `attachments` parameter.

6. **Output Formats**: Use `format_output="text"` for human-readable output or `format_output="json"` for programmatic use.