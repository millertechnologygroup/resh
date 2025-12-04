# Secret Handle

The secret handle provides secure storage and retrieval of sensitive information in Resource Shell. It supports multiple backends for different security requirements and use cases.

## URL Format

```
secret://scope/key_path
```

Where:
- `scope` - The storage backend (local, env, or vault)
- `key_path` - The path to the secret within the scope

## Supported Scopes

### local
File-based secret storage on the local system. Secrets are stored in encrypted JSON files in your system's state directory.

### env
Environment variables (read-only access). Use this to access existing environment variables as secrets.

### vault
HashiCorp Vault integration (not implemented yet).

## Verbs

### get

Retrieves a secret value from the specified scope.

**Arguments:**
- `redact` (optional) - Set to "true" to hide the secret value in the output

**Examples:**

```bash
# Get a secret value
resh secret://local/openai/api_key.get

# Get with redacted output
resh secret://local/openai/api_key.get(redact="true")

# Get from environment variables
resh secret://env/DB_PASSWORD.get

# Get environment variable with redaction
resh secret://env/DB_PASSWORD.get(redact="true")
```

**Output Format:**
```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "exists": true,
  "value": "sk-test123"
}
```

When `redact="true"`:
```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "exists": true,
  "value": null,
  "redacted": true
}
```

When secret doesn't exist:
```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "exists": false,
  "value": null
}
```

### set

Stores a secret value (only available for local scope).

**Arguments:**
- `value` - The literal secret value to store
- `from_env` - Environment variable name to read the value from (alternative to `value`)

**Examples:**

```bash
# Set a secret with literal value
resh secret://local/openai/api_key.set(value="sk-test123")

# Set a secret from environment variable
resh secret://local/from_env_test.set(from_env="TEST_SECRET_VAR")
```

**Output Format:**
```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "set": true,
  "source": "literal"
}
```

When setting from environment variable:
```json
{
  "scope": "local",
  "key": "from_env_test",
  "backend": "local",
  "set": true,
  "source": "env"
}
```

**Error Cases:**
- Environment scope is read-only
- Vault scope is not implemented yet
- Missing required arguments

### rm

Removes a secret (only available for local scope).

**Examples:**

```bash
# Remove a secret
resh secret://local/openai/api_key.rm

# Remove non-existent secret (returns removed: false)
resh secret://local/nonexistent.rm
```

**Output Format:**
```json
{
  "scope": "local",
  "key": "openai/api_key",
  "backend": "local",
  "removed": true
}
```

When secret doesn't exist:
```json
{
  "scope": "local",
  "key": "nonexistent",
  "backend": "local",
  "removed": false
}
```

### ls

Lists secrets with optional prefix filtering.

**Examples:**

```bash
# List all secrets in local scope
resh secret://local/.ls

# List secrets with specific prefix
resh secret://local/projectX.ls

# List environment variables
resh secret://env/.ls
```

**Output Format:**
```json
{
  "scope": "local",
  "backend": "local",
  "prefix": "",
  "keys": [
    "projectX/db/password",
    "projectX/openai/api_key",
    "projectY/api_key",
    "standalone"
  ]
}
```

With prefix filtering:
```json
{
  "scope": "local",
  "backend": "local",
  "prefix": "projectX",
  "keys": [
    "projectX/db/password",
    "projectX/openai/api_key"
  ]
}
```

### rotate

Generates new secret values using various strategies (not fully implemented yet).

**Arguments:**
- `strategy` - Generation strategy (random, uuid, aes, rsa)
- `length` - Length for generated secrets
- `expose_value` - Set to "true" to show the generated value in output

**Examples:**

```bash
# Rotate with default random strategy
resh secret://local/test/random.rotate

# Rotate with specific length
resh secret://local/test/random32.rotate(strategy=random,length=32,expose_value=true)

# Generate UUID
resh secret://local/test/uuid.rotate(strategy=uuid,expose_value=true)

# Generate AES key
resh secret://local/test/aes.rotate(strategy=aes,length=256,expose_value=true)

# Generate RSA key pair
resh secret://local/test/rsa.rotate(strategy=rsa,length=2048,expose_value=true)
```

**Output Format:**
```json
{
  "scope": "local",
  "strategy": "random",
  "rotated": true,
  "ephemeral": false,
  "backend": "local_fs"
}
```

With exposed value:
```json
{
  "scope": "local",
  "strategy": "uuid",
  "rotated": true,
  "value": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Error Handling

All operations return JSON error responses when they fail:

```json
{
  "scope": "local",
  "key": "test_key",
  "backend": "local",
  "error": "key path is required for get operation"
}
```

Common error scenarios:
- Missing key path for operations that require it
- Attempting write operations on read-only scopes (env)
- Environment variable not found when using `from_env`
- Invalid scope names
- Vault operations (not implemented yet)

## Security Notes

- Local secrets are stored with restricted file permissions (0600)
- Secret files are written atomically to prevent corruption
- Environment variables can be accessed but not modified
- Use the `redact` parameter to prevent secrets from appearing in logs
- Vault integration is planned for enterprise secret management

## Common Usage Patterns

### API Key Management
```bash
# Store API key
resh secret://local/services/openai.set(value="sk-...")

# Retrieve for use in applications
resh secret://local/services/openai.get
```

### Database Credentials
```bash
# Store database password
resh secret://local/db/prod/password.set(from_env="DB_PROD_PASSWORD")

# List all database secrets
resh secret://local/db.ls
```

### Environment Integration
```bash
# Check if environment variable exists
resh secret://env/API_KEY.get

# List environment variables with prefix
resh secret://env/DB.ls
```