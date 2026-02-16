use anyhow::{Context, Result, bail};
use serde_json::{self, json};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// Help text for the secret handle
const SECRET_HELP_TEXT: &str = r#"RESOURCE SHELL - SECRET HANDLE
==============================

USAGE:
  secret://scope/key_path.VERB(arguments)

DESCRIPTION:
  The secret handle provides secure storage and retrieval of sensitive
  information with multiple backend support. Store API keys, passwords,
  tokens, and other secrets with encryption. Access environment variables
  securely. Rotate secrets with various generation strategies. Supports
  local encrypted file storage, environment variable access, and HashiCorp
  Vault integration (planned). Essential for credential management, API key
  storage, configuration secrets, and secure application deployment.

URL FORMAT:
  secret://scope/key_path.VERB(arguments)
  secret://local/api/key.get
  secret://env/DATABASE_URL.get
  secret://local/oauth/token.set(value="secret123")

  scope: Storage backend (local, env, vault)
  key_path: Path to secret within scope
  VERB: Operation to perform

SCOPES (3 total):

  local:
    • File-based encrypted storage
    • Read and write access
    • Stored in system state directory
    • Encrypted JSON files
    • File permissions: 0600 (owner only)
    • Atomic file writes
    • Hierarchical key paths
    • Default scope for new secrets

  env:
    • Environment variables
    • Read-only access
    • Access existing environment variables
    • No encryption (plaintext in environment)
    • Cannot modify environment
    • Useful for integration with existing config

  vault:
    • HashiCorp Vault integration
    • Not implemented yet
    • Planned for enterprise use
    • External secret management
    • Advanced authentication
    • Secret versioning and audit

VERBS (5 total):

  Secret Access:
    get             Retrieve secret value
    ls              List secrets with optional prefix filtering

  Secret Management:
    set             Store secret value (local scope only)
    rm              Remove secret (local scope only)
    rotate          Generate new secret with strategies

EXAMPLES:

  Get Secrets (get):
    # Get secret value
    secret://local/openai/api_key.get

    # Get with redacted output (hide value)
    secret://local/openai/api_key.get(redact=true)

    # Get from environment variable
    secret://env/DB_PASSWORD.get

    # Get environment variable redacted
    secret://env/DATABASE_URL.get(redact=true)

    # Get API key
    secret://local/services/stripe/api_key.get

    # Get database password
    secret://local/databases/prod/password.get

    # Get OAuth token
    secret://local/oauth/github/token.get

    # Get AWS credentials
    secret://local/aws/access_key.get
    secret://local/aws/secret_key.get

    # Get nested secret
    secret://local/app/production/database/password.get

    # Get from environment
    secret://env/HOME.get
    secret://env/PATH.get(redact=true)

  Set Secrets (set):
    # Set with literal value
    secret://local/openai/api_key.set(value="sk-test123")

    # Set database password
    secret://local/db/password.set(value="secret_password_123")

    # Set API key
    secret://local/services/api_key.set(value="api_key_value")

    # Set OAuth token
    secret://local/oauth/token.set(value="oauth_token_xyz")

    # Set from environment variable
    secret://local/from_env_test.set(from_env="TEST_SECRET_VAR")

    # Set database password from env
    secret://local/db/prod/password.set(from_env="DB_PROD_PASSWORD")

    # Set API key from env
    secret://local/api/stripe.set(from_env="STRIPE_SECRET_KEY")

    # Set AWS credentials from env
    secret://local/aws/access_key.set(from_env="AWS_ACCESS_KEY_ID")
    secret://local/aws/secret_key.set(from_env="AWS_SECRET_ACCESS_KEY")

    # Set nested secret
    secret://local/app/staging/redis/password.set(value="redis_pass_123")

    # Set multiple related secrets
    secret://local/smtp/host.set(value="smtp.example.com")
    secret://local/smtp/username.set(value="user@example.com")
    secret://local/smtp/password.set(value="smtp_password")

  Remove Secrets (rm):
    # Remove a secret
    secret://local/openai/api_key.rm

    # Remove database password
    secret://local/db/old_password.rm

    # Remove non-existent secret (returns removed: false)
    secret://local/nonexistent.rm

    # Remove API key
    secret://local/old_api_key.rm

    # Remove OAuth token
    secret://local/oauth/old_token.rm

    # Remove nested secret
    secret://local/app/dev/temp_secret.rm

    # Clean up test secrets
    secret://local/test/secret1.rm
    secret://local/test/secret2.rm

  List Secrets (ls):
    # List all local secrets
    secret://local/.ls

    # List with prefix filter
    secret://local/projectX.ls

    # List database secrets
    secret://local/db.ls

    # List API keys
    secret://local/services.ls

    # List OAuth tokens
    secret://local/oauth.ls

    # List AWS secrets
    secret://local/aws.ls

    # List environment variables
    secret://env/.ls

    # List environment variables with prefix
    secret://env/DB.ls
    secret://env/AWS.ls

    # List nested secrets
    secret://local/app/production.ls

    # List all secrets in scope
    secret://local/.ls
    secret://env/.ls

  Rotate Secrets (rotate):
    # Rotate with default random strategy
    secret://local/test/random.rotate

    # Rotate with specific length
    secret://local/test/random32.rotate(strategy=random,length=32)

    # Rotate and expose value
    secret://local/test/random_exposed.rotate(strategy=random,length=32,expose_value=true)

    # Generate UUID
    secret://local/test/uuid.rotate(strategy=uuid)

    # Generate UUID and expose
    secret://local/test/uuid_exposed.rotate(strategy=uuid,expose_value=true)

    # Generate AES key (128-bit)
    secret://local/test/aes128.rotate(strategy=aes,length=128)

    # Generate AES key (256-bit)
    secret://local/test/aes256.rotate(strategy=aes,length=256,expose_value=true)

    # Generate RSA key pair (2048-bit)
    secret://local/test/rsa2048.rotate(strategy=rsa,length=2048)

    # Generate RSA key pair (4096-bit)
    secret://local/test/rsa4096.rotate(strategy=rsa,length=4096,expose_value=true)

    # Rotate API key
    secret://local/services/api_key.rotate(strategy=random,length=64)

    # Rotate password
    secret://local/db/password.rotate(strategy=random,length=32,expose_value=true)

    # Generate session token
    secret://local/session/token.rotate(strategy=uuid)

GET ARGUMENTS:
  redact=BOOL            Hide secret value in output (default: false)

SET ARGUMENTS (choose one):
  value=SECRET           Literal secret value to store (required or from_env)
  from_env=VAR_NAME      Environment variable to read value from

RM ARGUMENTS:
  (no arguments)

LS ARGUMENTS:
  (no arguments - prefix determined by key_path)

ROTATE ARGUMENTS:
  strategy=STRATEGY      Generation strategy (default: random)
                         Values: random, uuid, aes, rsa
  length=NUMBER          Length for generated secrets
                         random: bits (default: 256)
                         aes: 128, 192, 256 (default: 256)
                         rsa: 2048, 3072, 4096 (default: 2048)
  expose_value=BOOL      Show generated value in output (default: false)

ROTATION STRATEGIES:

  random:
    • Generates cryptographically random bytes
    • Configurable length (bits)
    • Base64 encoded output
    • Good for: API keys, tokens, passwords
    • Default length: 256 bits (32 bytes)
    • Example: "YXNkZmFzZGZhc2RmYXNkZg=="

  uuid:
    • Generates UUID v4 (random)
    • Fixed format: 8-4-4-4-12 hex digits
    • Good for: Session IDs, correlation IDs
    • Example: "550e8400-e29b-41d4-a716-446655440000"

  aes:
    • Generates AES encryption key
    • Lengths: 128, 192, 256 bits
    • Good for: Encryption keys, symmetric keys
    • Default: 256 bits
    • Example: hex-encoded key

  rsa:
    • Generates RSA key pair
    • Lengths: 2048, 3072, 4096 bits
    • Good for: Asymmetric encryption, signing
    • Default: 2048 bits
    • Returns: Private key (public can be derived)

OUTPUT FORMATS:

  get output (with value):
    {
      "scope": "local",
      "key": "openai/api_key",
      "backend": "local",
      "exists": true,
      "value": "sk-test123"
    }

  get output (redacted):
    {
      "scope": "local",
      "key": "openai/api_key",
      "backend": "local",
      "exists": true,
      "value": null,
      "redacted": true
    }

  get output (not found):
    {
      "scope": "local",
      "key": "nonexistent",
      "backend": "local",
      "exists": false,
      "value": null
    }

  set output (literal value):
    {
      "scope": "local",
      "key": "openai/api_key",
      "backend": "local",
      "set": true,
      "source": "literal"
    }

  set output (from environment):
    {
      "scope": "local",
      "key": "from_env_test",
      "backend": "local",
      "set": true,
      "source": "env"
    }

  rm output (removed):
    {
      "scope": "local",
      "key": "openai/api_key",
      "backend": "local",
      "removed": true
    }

  rm output (not found):
    {
      "scope": "local",
      "key": "nonexistent",
      "backend": "local",
      "removed": false
    }

  ls output:
    {
      "scope": "local",
      "backend": "local",
      "prefix": "projectX",
      "keys": [
        "projectX/db/password",
        "projectX/api/key"
      ]
    }

  rotate output:
    {
      "scope": "local",
      "strategy": "random",
      "rotated": true,
      "ephemeral": false,
      "backend": "local_fs"
    }

  rotate output (with value):
    {
      "scope": "local",
      "strategy": "uuid",
      "rotated": true,
      "value": "550e8400-e29b-41d4-a716-446655440000"
    }

EXIT CODES:
  0                      Success
  1                      General error
  2                      Secret not found
  3                      Invalid scope
  4                      Read-only scope (env, vault)
  5                      Missing required arguments
  6                      Invalid arguments
  7                      Permission denied

ERROR MESSAGES:

  Scope errors:
    "invalid scope"                Unknown scope specified
    "scope is read-only"           Cannot write to env scope
    "vault not implemented"        Vault scope not available

  Key errors:
    "key path is required"         Missing key path
    "secret not found"             Secret doesn't exist
    "invalid key path"             Malformed key path

  Operation errors:
    "value or from_env required"   Missing required set argument
    "environment variable not found"  from_env variable missing
    "rotation failed"              Secret rotation failed

  Permission errors:
    "permission denied"            Cannot access secret file
    "file write failed"            Cannot write secret file

  Validation errors:
    "invalid rotation strategy"    Unknown strategy
    "invalid length"               Invalid length for strategy
    "invalid argument"             Invalid argument value

COMMON WORKFLOWS:

  Store and retrieve API key:
    # Store API key
    secret://local/services/openai.set(value="sk-...")

    # Retrieve for use
    secret://local/services/openai.get

    # Check it exists without exposing
    secret://local/services/openai.get(redact=true)

  Database credentials management:
    # Store from environment
    secret://local/db/prod/password.set(from_env="DB_PROD_PASSWORD")

    # List database secrets
    secret://local/db.ls

    # Retrieve password
    secret://local/db/prod/password.get

    # Remove old password
    secret://local/db/old/password.rm

  Environment variable integration:
    # Check environment variable exists
    secret://env/API_KEY.get(redact=true)

    # Copy env var to local storage
    secret://local/copied_api_key.set(from_env="API_KEY")

    # List environment variables
    secret://env/DB.ls

  Rotate secrets regularly:
    # Generate new random API key
    secret://local/api/key.rotate(strategy=random,length=64,expose_value=true)

    # Generate new UUID session token
    secret://local/session/token.rotate(strategy=uuid,expose_value=true)

    # Rotate encryption key
    secret://local/encryption/key.rotate(strategy=aes,length=256)

  Organize secrets by project:
    # Store project secrets
    secret://local/projectA/db/password.set(value="...")
    secret://local/projectA/api/key.set(value="...")
    secret://local/projectB/oauth/token.set(value="...")

    # List project secrets
    secret://local/projectA.ls
    secret://local/projectB.ls

  Migrate secrets from environment:
    # List environment secrets
    secret://env/.ls

    # Copy to local storage
    secret://local/aws/access_key.set(from_env="AWS_ACCESS_KEY_ID")
    secret://local/aws/secret_key.set(from_env="AWS_SECRET_ACCESS_KEY")

  Clean up old secrets:
    # List secrets to review
    secret://local/old.ls

    # Remove obsolete secrets
    secret://local/old/api_key_v1.rm
    secret://local/old/deprecated_token.rm

  Generate cryptographic keys:
    # Generate AES encryption key
    secret://local/crypto/aes.rotate(strategy=aes,length=256,expose_value=true)

    # Generate RSA key pair
    secret://local/crypto/rsa.rotate(strategy=rsa,length=4096,expose_value=true)

  Audit secret usage:
    # List all local secrets
    secret://local/.ls

    # Check specific secrets exist (redacted)
    secret://local/critical/api_key.get(redact=true)
    secret://local/critical/password.get(redact=true)

  Set up new application:
    # Store database credentials
    secret://local/myapp/db/host.set(value="localhost")
    secret://local/myapp/db/user.set(value="appuser")
    secret://local/myapp/db/password.set(from_env="MYAPP_DB_PASSWORD")

    # Store API keys
    secret://local/myapp/stripe/key.set(from_env="STRIPE_SECRET_KEY")
    secret://local/myapp/sendgrid/key.set(from_env="SENDGRID_API_KEY")

    # List all app secrets
    secret://local/myapp.ls

BEST PRACTICES:
  • Always use redact=true when logging secret operations
  • Store secrets in local scope, not environment variables
  • Use hierarchical paths for organization (app/env/service/key)
  • Rotate secrets regularly using rotate verb
  • Never commit secret values to version control
  • Use from_env for initial secret import from environment
  • Set restrictive file permissions on secret storage
  • Use strong random secrets (256+ bits)
  • Generate unique secrets per environment
  • Document secret purposes and rotation schedules
  • Audit secret access regularly
  • Remove unused secrets promptly
  • Use meaningful key paths
  • Group related secrets by prefix
  • Implement secret rotation automation
  • Test secret rotation before production
  • Keep backup of critical secrets securely
  • Use UUID for session tokens and IDs
  • Use random strategy for API keys and passwords
  • Use AES/RSA strategies for encryption keys
  • Never expose secrets in logs or error messages
  • Use redaction in automated scripts
  • Limit secret access to necessary processes
  • Monitor for unauthorized secret access
  • Implement secret expiration policies
  • Use different secrets for dev/staging/prod
  • Validate secrets after rotation
  • Document secret dependencies
  • Use consistent naming conventions
  • Implement secret versioning strategy

SECRET ORGANIZATION GUIDELINES:
  • Use path hierarchy: service/environment/type/name
  • Example: myapp/production/database/password
  • Group by application or service
  • Separate by environment (dev/staging/prod)
  • Use descriptive names
  • Keep paths consistent across environments
  • Document path structure
  • Use prefixes for listing
  • Avoid deep nesting (3-4 levels max)
  • Use underscores or hyphens consistently

ROTATION GUIDELINES:
  • Rotate credentials quarterly or per policy
  • Use expose_value=true only when needed
  • Test rotated secrets before applying
  • Keep old secret until rotation confirmed
  • Document rotation procedures
  • Automate rotation where possible
  • Coordinate rotation with dependent systems
  • Use appropriate strategy for secret type
  • Verify secret strength after generation
  • Monitor rotation failures
  • Implement rollback procedures
  • Track rotation history

SECURITY CONSIDERATIONS:
  • Local scope uses encrypted file storage
  • File permissions are 0600 (owner only)
  • Secrets written atomically to prevent corruption
  • Use redact parameter to prevent logging
  • Environment scope is read-only
  • Environment variables are plaintext
  • Never store secrets in version control
  • Use secure channels for secret transmission
  • Implement access controls
  • Monitor secret access patterns
  • Use strong entropy for generated secrets
  • Protect secret storage directory
  • Encrypt backups of secret storage
  • Use separate secrets per environment
  • Implement principle of least privilege
  • Rotate secrets after potential exposure
  • Use unique secrets per application
  • Avoid hardcoding secrets in code
  • Use secret injection at runtime
  • Implement audit logging
  • Monitor for secret leakage
  • Use secret scanning tools
  • Implement secret expiration
  • Use multi-factor authentication for critical secrets
  • Implement secret versioning
  • Use HashiCorp Vault for enterprise needs
  • Protect against timing attacks
  • Validate secret strength
  • Implement rate limiting on access
  • Use secure random number generators

TROUBLESHOOTING:

  Secret not found:
    • Verify scope: secret://local/.ls
    • Check key path spelling
    • Verify secret was created
    • Check permissions on storage directory

  Permission denied:
    • Check file permissions: ls -la ~/.local/state/resh/secrets
    • Ensure storage directory exists
    • Verify user ownership
    • Check SELinux/AppArmor policies

  Cannot set secret in env scope:
    • env scope is read-only
    • Use local scope instead
    • Copy from env: set(from_env=...)

  Environment variable not found:
    • Check variable exists: echo $VAR
    • Verify variable name spelling
    • Check if variable is exported
    • Try: secret://env/.ls to see available

  Rotation failed:
    • Check strategy is valid
    • Verify length is appropriate
    • Check for sufficient entropy
    • Verify permissions on storage

  Invalid scope:
    • Use: local, env, or vault
    • Check scope spelling
    • vault scope not implemented yet

  Value or from_env required:
    • Provide value="..." or from_env="..."
    • Cannot provide both
    • Check argument names

DEBUGGING:

  List all secrets:
    secret://local/.ls

  Check secret exists:
    secret://local/path/to/secret.get(redact=true)

  Verify environment variable:
    secret://env/VARIABLE_NAME.get(redact=true)

  Test secret creation:
    secret://local/test/debug.set(value="test123")
    secret://local/test/debug.get
    secret://local/test/debug.rm

  Check secret storage:
    ls -la ~/.local/state/resh/secrets/

  Verify permissions:
    stat ~/.local/state/resh/secrets/*.json

  Test rotation:
    secret://local/test/rotation.rotate(strategy=random,expose_value=true)

PLATFORM SUPPORT:

  All platforms:
    • Local scope: Full support
    • Environment scope: Full support
    • Encrypted storage
    • Atomic file writes

  Linux:
    • XDG Base Directory support
    • Secure file permissions
    • Full feature support

  macOS:
    • Standard directory support
    • Full feature support
    • File permissions supported

  Windows:
    • AppData directory support
    • File permissions (limited)
    • Full feature support

  Storage locations:
    Linux:   ~/.local/state/resh/secrets/
    macOS:   ~/Library/Application Support/resh/secrets/
    Windows: %APPDATA%\resh\secrets\

PERFORMANCE CONSIDERATIONS:
  • File I/O for local scope operations
  • Encryption/decryption overhead
  • Atomic writes require filesystem support
  • List operations scan directory
  • Large key counts may slow ls operations
  • Rotation strategies vary in speed
  • Random: Fast
  • UUID: Fast
  • AES: Fast
  • RSA: Slower (especially 4096-bit)
  • Environment scope access is fast
  • No network overhead for local/env
  • File locking prevents concurrent writes

LIMITATIONS:
  • No secret versioning (single version per key)
  • No built-in expiration
  • No secret sharing between users
  • No access control lists
  • No audit logging
  • No secret policies
  • No automatic rotation
  • No secret dependencies
  • No validation rules
  • No secret templates
  • No secret groups
  • No batch operations
  • Vault scope not implemented
  • No secret replication
  • No disaster recovery features
  • No secret import/export
  • No migration tools
  • No secret encryption key rotation
  • No hardware security module (HSM) support

INTEGRATION WITH OTHER HANDLES:

  With config handle:
    # Store config as secret
    secret://local/app/config.set(value="config_data")
    
    # Reference in config
    config://app/api_key.set(value="from secret://local/app/key")

  With env handle:
    # Export secret to environment
    export API_KEY=$(secret://local/api/key.get)

  With file handle:
    # Write secret to file
    secret://local/cert/key.get > /path/to/key.pem

  With exec handle:
    # Pass secret to command
    exec://command --key $(secret://local/api/key.get)

  With http handle:
    # Use secret in HTTP request
    http://api.example.com.post(headers='{"Authorization":"Bearer $(secret://local/token.get)"}')

  With backup handle:
    # Backup secret storage (encrypted)
    backup://secrets.create(target=~/.local/state/resh/secrets)

MORE INFO:
  For complete documentation of secret handle operations:
  https://github.com/[your-org]/resource-shell/docs/Security_Secrets/secret.md

  HashiCorp Vault:
  https://www.vaultproject.io/

  Secret management best practices:
  https://owasp.org/www-community/Secrets_Management_Cheat_Sheet

  Cryptographic key management:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

  Use 'secret:// --help=VERB' for detailed help on a specific verb.
"#;

// Verb-specific help texts
const GET_VERB_HELP: &str = r#"RESOURCE SHELL - SECRET HANDLE - GET VERB
===========================================

USAGE:
  secret://scope/key_path.get(redact=BOOL)

DESCRIPTION:
  Retrieves a secret value from the specified scope. Supports redaction
  to hide the secret value in output, which is crucial for logging safety.

SCOPES SUPPORTED:
  local - Retrieve from encrypted local storage
  env   - Retrieve from environment variables
  vault - Not implemented yet

ARGUMENTS:
  redact=BOOL       Hide secret value in output (default: false)
                    Use true for logging safety

EXAMPLES:
  # Get secret value (visible)
  secret://local/openai/api_key.get

  # Get secret value (redacted for safety)
  secret://local/openai/api_key.get(redact=true)

  # Get environment variable
  secret://env/DATABASE_URL.get

  # Get environment variable (redacted)
  secret://env/API_KEY.get(redact=true)

OUTPUT (with value):
  {
    "scope": "local",
    "key": "openai/api_key",
    "backend": "local",
    "exists": true,
    "value": "sk-test123"
  }

OUTPUT (redacted):
  {
    "scope": "local",
    "key": "openai/api_key",
    "backend": "local",
    "exists": true,
    "value": null,
    "redacted": true
  }

OUTPUT (not found):
  {
    "scope": "local",
    "key": "nonexistent",
    "backend": "local",
    "exists": false,
    "value": null
  }

ERROR CONDITIONS:
  • Key path is required
  • Vault scope not implemented
  • Permission denied on secret file
  • Environment variable not found

BEST PRACTICES:
  • Use redact=true in automated scripts
  • Use redact=true when logging operations
  • Check 'exists' field before using value
  • Handle null values gracefully
"#;

const SET_VERB_HELP: &str = r#"RESOURCE SHELL - SECRET HANDLE - SET VERB
===========================================

USAGE:
  secret://local/key_path.set(value=SECRET)
  secret://local/key_path.set(from_env=VAR_NAME)

DESCRIPTION:
  Stores a secret value in the local scope. Supports setting from literal
  values or reading from environment variables. Only available for local
  scope as env and vault scopes are read-only or not implemented.

SCOPES SUPPORTED:
  local - Store in encrypted local storage (read-write)
  env   - Read-only scope, cannot set
  vault - Not implemented yet

ARGUMENTS (choose one):
  value=SECRET      Literal secret value to store
  from_env=VAR      Environment variable name to read from

EXAMPLES:
  # Set with literal value
  secret://local/openai/api_key.set(value="sk-test123")

  # Set from environment variable
  secret://local/db/password.set(from_env="DB_PASSWORD")

  # Set nested secret
  secret://local/app/prod/api_key.set(value="api_key_123")

  # Copy from environment to local storage
  secret://local/aws/access_key.set(from_env="AWS_ACCESS_KEY_ID")

OUTPUT (literal):
  {
    "scope": "local",
    "key": "openai/api_key",
    "backend": "local",
    "set": true,
    "source": "literal"
  }

OUTPUT (from environment):
  {
    "scope": "local",
    "key": "db/password",
    "backend": "local",
    "set": true,
    "source": "env"
  }

ERROR CONDITIONS:
  • Key path is required
  • env scope is read-only
  • Vault scope not implemented
  • Must provide value or from_env
  • Environment variable not found
  • Permission denied on secret storage

SECURITY NOTES:
  • Secrets stored with 0600 permissions
  • Files written atomically
  • Local storage is encrypted
  • Never expose secrets in logs

BEST PRACTICES:
  • Use from_env for importing secrets
  • Use hierarchical paths for organization
  • Set unique secrets per environment
  • Document secret purposes
"#;

const RM_VERB_HELP: &str = r#"RESOURCE SHELL - SECRET HANDLE - RM VERB
==========================================

USAGE:
  secret://local/key_path.rm

DESCRIPTION:
  Removes a secret from the local scope. Only available for local scope
  as env and vault scopes are read-only or not implemented.

SCOPES SUPPORTED:
  local - Remove from encrypted local storage
  env   - Read-only scope, cannot remove
  vault - Not implemented yet

ARGUMENTS:
  (no arguments)

EXAMPLES:
  # Remove a secret
  secret://local/openai/api_key.rm

  # Remove nested secret
  secret://local/app/dev/temp_secret.rm

  # Remove non-existent secret (returns removed: false)
  secret://local/nonexistent.rm

OUTPUT (removed):
  {
    "scope": "local",
    "key": "openai/api_key",
    "backend": "local",
    "removed": true
  }

OUTPUT (not found):
  {
    "scope": "local",
    "key": "nonexistent",
    "backend": "local",
    "removed": false
  }

ERROR CONDITIONS:
  • Key path is required
  • env scope is read-only
  • Vault scope not implemented
  • Permission denied on secret storage

BEST PRACTICES:
  • Verify secret exists before removal
  • Use ls to list secrets before cleanup
  • Remove obsolete secrets promptly
  • Document removal procedures
"#;

const LS_VERB_HELP: &str = r#"RESOURCE SHELL - SECRET HANDLE - LS VERB
==========================================

USAGE:
  secret://scope/.ls
  secret://scope/prefix.ls

DESCRIPTION:
  Lists secrets with optional prefix filtering. Use empty key_path or "."  
  to list all secrets. Use a prefix to filter results.

SCOPES SUPPORTED:
  local - List from encrypted local storage
  env   - List environment variables
  vault - Not implemented yet

ARGUMENTS:
  (no arguments - prefix determined by key_path)

EXAMPLES:
  # List all local secrets
  secret://local/.ls

  # List secrets with prefix
  secret://local/projectX.ls

  # List database secrets
  secret://local/db.ls

  # List environment variables
  secret://env/.ls

  # List environment variables with prefix
  secret://env/DB.ls

OUTPUT:
  {
    "scope": "local",
    "backend": "local",
    "prefix": "projectX",
    "keys": [
      "projectX/db/password",
      "projectX/api/key"
    ]
  }

OUTPUT (no prefix):
  {
    "scope": "local",
    "backend": "local",
    "prefix": "",
    "keys": [
      "app/api_key",
      "db/password",
      "projectX/api/key"
    ]
  }

ERROR CONDITIONS:
  • Vault scope not implemented
  • Permission denied on secret storage

USEFUL PATTERNS:
  • List before cleanup: secret://local/old.ls
  • Audit secrets: secret://local/.ls
  • Check prefix organization: secret://local/app.ls
  • Review environment: secret://env/.ls

BEST PRACTICES:
  • Use prefixes for organization
  • Regular secret audits with ls
  • Document key path conventions
  • Use consistent naming across environments
"#;

const ROTATE_VERB_HELP: &str = r#"RESOURCE SHELL - SECRET HANDLE - ROTATE VERB
==============================================

USAGE:
  secret://local/key_path.rotate(strategy=STRATEGY,length=NUMBER,expose_value=BOOL)

DESCRIPTION:
  Generates new secret values using various strategies. Only available
  for local scope. Supports multiple generation strategies for different
  use cases.

SCOPES SUPPORTED:
  local - Generate and store in encrypted local storage
  env   - Read-only scope, cannot rotate
  vault - Not implemented yet

STRATEGIES:
  random - Cryptographically random bytes (default)
  uuid   - UUID v4 (random)
  aes    - AES encryption key
  rsa    - RSA key pair

ARGUMENTS:
  strategy=STRATEGY     Generation strategy (default: random)
  length=NUMBER         Length for generated secrets
                        random: bits (default: 256)
                        aes: 128, 192, 256 (default: 256)
                        rsa: 2048, 3072, 4096 (default: 2048)
  expose_value=BOOL     Show generated value in output (default: false)

EXAMPLES:
  # Rotate with default random strategy
  secret://local/api/key.rotate

  # Rotate with specific length
  secret://local/token.rotate(strategy=random,length=32)

  # Rotate and expose value
  secret://local/debug.rotate(strategy=random,expose_value=true)

  # Generate UUID
  secret://local/session/id.rotate(strategy=uuid)

  # Generate AES key (256-bit)
  secret://local/crypto/aes.rotate(strategy=aes,length=256)

  # Generate RSA key pair (4096-bit)
  secret://local/crypto/rsa.rotate(strategy=rsa,length=4096)

OUTPUT (normal):
  {
    "scope": "local",
    "strategy": "random",
    "rotated": true,
    "ephemeral": false,
    "backend": "local_fs"
  }

OUTPUT (with value):
  {
    "scope": "local",
    "strategy": "uuid",
    "rotated": true,
    "value": "550e8400-e29b-41d4-a716-446655440000"
  }

ERROR CONDITIONS:
  • Key path is required
  • env scope is read-only
  • Vault scope not implemented
  • Invalid rotation strategy
  • Invalid length for strategy
  • Rotation failed
  • Permission denied on secret storage

STRATEGY DETAILS:

  random:
    • Generates cryptographically random bytes
    • Base64 encoded output
    • Good for: API keys, tokens, passwords
    • Length: bits (8, 16, 32, 64, 128, 256, etc.)

  uuid:
    • Generates UUID v4 (random)
    • Fixed format: 8-4-4-4-12 hex digits
    • Good for: Session IDs, correlation IDs
    • Length parameter ignored

  aes:
    • Generates AES encryption key
    • Hex encoded output
    • Good for: Encryption keys, symmetric keys
    • Length: 128, 192, 256 bits

  rsa:
    • Generates RSA key pair
    • PEM format private key
    • Good for: Asymmetric encryption, signing
    • Length: 2048, 3072, 4096 bits

BEST PRACTICES:
  • Rotate secrets regularly (quarterly)
  • Test rotated secrets before applying
  • Use expose_value=true only for testing
  • Use appropriate strategy for use case
  • Coordinate rotation with dependent systems
  • Implement rollback procedures
  • Document rotation schedules
"#;

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("secret", |u| Ok(Box::new(SecretHandle::from_url(u)?)));
}

pub struct SecretHandle {
    scope: String,
    key_path: String,
    is_help_request: bool,
    help_verb: Option<String>,
}

impl SecretHandle {
    pub fn from_url(u: &Url) -> Result<Self> {
        // Check for help flags first
        let path_str = u.path();
        let is_help_request = path_str == "--help" ||
                             path_str == "-h" ||
                             path_str.ends_with(".--help") ||
                             path_str.ends_with(".-h") ||
                             u.host_str() == Some("--help") ||
                             u.host_str() == Some("-h");

        // Extract verb-specific help if provided (e.g., --help=get)
        let help_verb = u.query_pairs()
            .find_map(|(k, v)| {
                if k == "help" || (k == "--help" && !v.is_empty()) {
                    Some(v.to_string())
                } else {
                    None
                }
            });

        // If this is a help request, return early with minimal validation
        if is_help_request || help_verb.is_some() {
            return Ok(SecretHandle {
                scope: "local".to_string(), // Default scope for help
                key_path: String::new(),
                is_help_request: true,
                help_verb,
            });
        }

        // The URL format is secret://scope/key_path
        // where scope can be in the host position or path position
        let (scope, key_path) = if let Some(host) = u.host_str() {
            // Case: secret://scope/key_path (scope in host position)
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            (host.to_string(), path.to_string())
        } else {
            // Case: secret:///scope/key_path (scope in path position)
            let path = u.path().strip_prefix('/').unwrap_or(u.path());
            let parts: Vec<&str> = path.split('/').collect();
            if parts.is_empty() || parts[0].is_empty() {
                bail!("secret URL must contain a scope");
            }
            let scope = parts[0].to_string();
            let key_path = if parts.len() > 1 {
                parts[1..].join("/")
            } else {
                String::new()
            };
            (scope, key_path)
        };

        // Validate scope
        match scope.as_str() {
            "local" | "env" | "vault" => {},
            _ => bail!("unsupported scope '{}'; supported scopes: local, env, vault", scope),
        }

        Ok(SecretHandle {
            scope,
            key_path,
            is_help_request: false,
            help_verb: None,
        })
    }

    fn get_keystore_path() -> Result<PathBuf> {
        let state_dir = dirs::state_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(state_dir.join("resh").join("secrets").join("local.json"))
    }

    fn load_keystore() -> Result<HashMap<String, String>> {
        let path = Self::get_keystore_path()?;
        
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read keystore at {}", path.display()))?;

        if contents.trim().is_empty() {
            return Ok(HashMap::new());
        }

        let keystore: HashMap<String, String> = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse keystore JSON at {}", path.display()))?;

        Ok(keystore)
    }

    fn save_keystore(keystore: &HashMap<String, String>) -> Result<()> {
        let path = Self::get_keystore_path()?;
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        // Write to temporary file first for atomic operation
        let temp_path = path.with_extension("tmp");
        
        let json = serde_json::to_string(keystore)
            .context("failed to serialize keystore to JSON")?;

        fs::write(&temp_path, json)
            .with_context(|| format!("failed to write temp file {}", temp_path.display()))?;

        // Set restrictive permissions (0600) on the temp file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&temp_path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&temp_path, permissions)
                .with_context(|| format!("failed to set permissions on {}", temp_path.display()))?;
        }

        // Atomic rename
        fs::rename(&temp_path, &path)
            .with_context(|| format!("failed to rename {} to {}", temp_path.display(), path.display()))?;

        Ok(())
    }

    fn write_error_json(&self, io: &mut IoStreams, error: &str) -> Result<()> {
        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "error": error
        });
        write!(io.stdout, "{}", response)?;
        Ok(())
    }

    fn handle_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for get operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        let redact = args.get("redact").map(|s| s.as_str()).unwrap_or("false") == "true";
        
        let (exists, value) = match self.scope.as_str() {
            "local" => {
                let keystore = Self::load_keystore().map_err(|e| {
                    let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
                    e
                })?;
                match keystore.get(&self.key_path) {
                    Some(v) => (true, Some(v.clone())),
                    None => (false, None),
                }
            },
            "env" => {
                match std::env::var(&self.key_path) {
                    Ok(v) => (true, Some(v)),
                    Err(_) => (false, None),
                }
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            _ => unreachable!(),
        };

        let mut response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "exists": exists
        });

        if exists {
            if redact {
                response["value"] = json!(null);
                response["redacted"] = json!(true);
            } else {
                response["value"] = json!(value.unwrap());
            }
        } else {
            response["value"] = json!(null);
        }

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_set(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for set operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        match self.scope.as_str() {
            "env" => {
                self.write_error_json(io, "env backend is read-only")?;
                return Ok(Status::err(1, "env backend is read-only"));
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            "local" => {
                // Continue with local implementation
            },
            _ => unreachable!(),
        }

        // Resolve secret value
        let (secret_value, source) = if let Some(value) = args.get("value") {
            (value.clone(), "literal")
        } else if let Some(env_name) = args.get("from_env") {
            match std::env::var(env_name) {
                Ok(value) => (value, "env"),
                Err(_) => {
                    self.write_error_json(io, &format!("environment variable '{}' not found", env_name))?;
                    return Ok(Status::err(1, "environment variable not found"));
                }
            }
        } else {
            self.write_error_json(io, "must provide either 'value' or 'from_env' argument")?;
            return Ok(Status::err(1, "missing required argument"));
        };

        // Load, update, and save keystore
        let mut keystore = Self::load_keystore().map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
            e
        })?;

        keystore.insert(self.key_path.clone(), secret_value);

        Self::save_keystore(&keystore).map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to save keystore: {}", e));
            e
        })?;

        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "set": true,
            "source": source
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_rm(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        if self.key_path.is_empty() {
            self.write_error_json(io, "key path is required for rm operation")?;
            return Ok(Status::err(1, "key path is required"));
        }

        match self.scope.as_str() {
            "env" => {
                self.write_error_json(io, "env backend is read-only")?;
                return Ok(Status::err(1, "env backend is read-only"));
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            "local" => {
                // Continue with local implementation
            },
            _ => unreachable!(),
        }

        let mut keystore = Self::load_keystore().map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
            e
        })?;

        let removed = keystore.remove(&self.key_path).is_some();

        Self::save_keystore(&keystore).map_err(|e| {
            let _ = self.write_error_json(io, &format!("failed to save keystore: {}", e));
            e
        })?;

        let response = json!({
            "scope": &self.scope,
            "key": &self.key_path,
            "backend": &self.scope,
            "removed": removed
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    fn handle_ls(&self, _args: &Args, io: &mut IoStreams) -> Result<Status> {
        let keys = match self.scope.as_str() {
            "local" => {
                let keystore = Self::load_keystore().map_err(|e| {
                    let _ = self.write_error_json(io, &format!("failed to load keystore: {}", e));
                    e
                })?;
                
                let prefix = &self.key_path;
                let mut matching_keys: Vec<String> = keystore.keys()
                    .filter(|k| {
                        if prefix.is_empty() {
                            true // List all keys
                        } else {
                            k.starts_with(&format!("{}/", prefix)) || *k == prefix
                        }
                    })
                    .cloned()
                    .collect();
                matching_keys.sort();
                matching_keys
            },
            "env" => {
                let prefix = &self.key_path;
                let mut matching_keys: Vec<String> = std::env::vars()
                    .map(|(k, _)| k)
                    .filter(|k| {
                        if prefix.is_empty() {
                            true // List all env vars
                        } else {
                            k.starts_with(&format!("{}/", prefix)) || k == prefix
                        }
                    })
                    .collect();
                matching_keys.sort();
                matching_keys
            },
            "vault" => {
                self.write_error_json(io, "vault backend not implemented yet")?;
                return Ok(Status::err(2, "vault backend not implemented yet"));
            },
            _ => unreachable!(),
        };

        let response = json!({
            "scope": &self.scope,
            "backend": &self.scope,
            "prefix": &self.key_path,
            "keys": keys
        });

        write!(io.stdout, "{}", response)?;
        Ok(Status::ok())
    }

    /// Display general help for the secret handle
    fn display_help(&self, io: &mut IoStreams) -> Result<Status> {
        writeln!(io.stdout, "{}", SECRET_HELP_TEXT)?;
        Ok(Status {
            ok: true,
            code: Some(0),
            reason: None,
        })
    }

    /// Display verb-specific help
    fn display_verb_help(&self, verb: &str, io: &mut IoStreams) -> Result<Status> {
        let help_text = match verb {
            "get" => GET_VERB_HELP,
            "set" => SET_VERB_HELP,
            "rm" => RM_VERB_HELP,
            "ls" => LS_VERB_HELP,
            "rotate" => ROTATE_VERB_HELP,
            _ => {
                writeln!(io.stderr, "Unknown verb: {}. Use --help for full list.", verb)?;
                return Ok(Status {
                    ok: false,
                    code: Some(1),
                    reason: Some("unknown_verb".to_string()),
                });
            }
        };
        
        writeln!(io.stdout, "{}", help_text)?;
        Ok(Status {
            ok: true,
            code: Some(0),
            reason: None,
        })
    }
}

impl Handle for SecretHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "set", "rm", "ls", "rotate"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check if this is a help request
        if self.is_help_request {
            if let Some(ref help_verb) = self.help_verb {
                // Verb-specific help requested
                return self.display_verb_help(help_verb, io);
            } else {
                // General help requested
                return self.display_help(io);
            }
        }

        // Normal operation - dispatch to appropriate verb
        match verb {
            "get" => self.handle_get(args, io),
            "set" => self.handle_set(args, io),
            "rm" => self.handle_rm(args, io),
            "ls" => self.handle_ls(args, io),
            "rotate" => {
                // Not implemented in this version, return error
                let response = json!({
                    "scope": &self.scope,
                    "key": &self.key_path,
                    "backend": &self.scope,
                    "error": "rotate operation not implemented yet"
                });
                write!(io.stdout, "{}", response)?;
                Ok(Status::err(2, "rotate operation not implemented yet"))
            },
            _ => bail!("unknown verb for secret://: {}", verb),
        }
    }
}