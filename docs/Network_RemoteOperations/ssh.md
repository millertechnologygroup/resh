# SSH Handle Documentation

The SSH handle allows you to connect to remote systems using the SSH protocol. You can execute commands, transfer files, and create secure tunnels through SSH connections.

## URL Format

```
ssh://[username@]hostname[:port]/
```

**Examples:**
- `ssh://user@server.example.com/`
- `ssh://admin@192.168.1.10:2222/`
- `ssh://server.local/` (uses current user and default port 22)

## Available Verbs

The SSH handle supports these operations:

- [`exec`](#exec) - Execute commands on remote hosts
- [`upload`](#upload) - Upload files to remote hosts  
- [`download`](#download) - Download files from remote hosts
- [`tunnel`](#tunnel) - Create SSH tunnels (local, remote, dynamic)
- [`keys.list`](#keyslist) - List SSH keys
- [`key.add`](#keyadd) - Add SSH keys
- [`config.get`](#configget) - Get SSH configuration
- [`test`](#test) - Test SSH connections

---

## exec

Execute commands on remote SSH hosts.

### Basic Usage

Execute a simple command:

```bash
# Execute 'echo hello' on the remote host
resh ssh://user@host.com/ exec command="echo hello"
```

### Dry Run

Test what would be executed without running the command:

```bash
resh ssh://host.com/ exec command="echo hello" dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "result": {
    "executed": false,
    "exit_code": null,
    "stdout": null,
    "stderr": null
  },
  "warnings": ["Dry run: command was not executed."]
}
```

### Successful Execution

Execute a command that succeeds:

```bash
resh ssh://host.com/ exec command="echo hello"
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "result": {
    "executed": true,
    "exit_code": 0,
    "stdout": "hello\n",
    "stderr": ""
  }
}
```

### Authentication Methods

#### Password Authentication

```bash
resh ssh://host.com/ exec command="echo hello" auth_method=password password=secret
```

#### Key Authentication

```bash
resh ssh://host.com/ exec command="echo hello" auth_method=key identity_path=/path/to/key
```

### Shell Execution

Execute commands through different shells:

```bash
# Using bash shell
resh ssh://host.com/ exec command="echo hello" shell_mode=bash
```

**Result:** Command becomes `bash -c 'echo hello'`

```bash
# Using bash with working directory
resh ssh://host.com/ exec command="pwd" shell_mode=bash cwd="/tmp"
```

**Result:** Command becomes `bash -c 'cd '/tmp' && pwd'`

### Output Formats

#### Text Format

```bash
resh ssh://host.com/ exec command="echo hello" format=text
```

**Expected Output (Text):**
```
SSH Exec
========

Host     : host.com
Port     : 22  
User     : user
Command  : echo hello
Exit Code: 0
Stdout   : hello
```

#### Base64 Output Encoding

```bash
resh ssh://host.com/ exec command="echo hello" output_encoding=base64
```

### Advanced Options

#### Timeouts and Limits

```bash
resh ssh://host.com/ exec \
  command="long-running-task" \
  connect_timeout_ms=5000 \
  command_timeout_ms=30000 \
  max_output_bytes=2048
```

#### Disable Output Capture

```bash
resh ssh://host.com/ exec command="echo hello" capture_output=false
```

**Result:** Output fields will be `null` in the response

### Error Handling

#### Missing Password

```bash
resh ssh://host.com/ exec command="echo hello" auth_method=password
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.auth_missing_password",
    "message": "Password is required for password authentication"
  }
}
```

#### Missing Key

```bash
resh ssh://host.com/ exec command="echo hello" auth_method=key
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.auth_missing_key", 
    "message": "Identity path or data is required for key authentication"
  }
}
```

#### Missing Host

```bash
resh ssh:/// exec command="echo hello"
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.host_required",
    "message": "Host is required for SSH connection"
  }
}
```

#### Missing Command

```bash
resh ssh://host.com/ exec
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.command_required",
    "message": "Command is required for SSH exec"
  }
}
```

---

## upload

Upload files to remote SSH hosts.

### Basic Upload with Inline Content

Upload text content directly:

```bash
resh ssh://user@host.com/ upload \
  source="Hello, World!" \
  source_mode=inline \
  dest="/tmp/test.txt" \
  overwrite=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "source": {
    "mode": "inline",
    "size_bytes": 13
  },
  "dest": {
    "path": "/tmp/test.txt",
    "atomic": false,
    "overwrite": true
  },
  "result": {
    "uploaded": true,
    "planned": false,
    "verify_checksum": false
  }
}
```

### Dry Run Upload

Test what would be uploaded without actually transferring:

```bash
resh ssh://host.com/ upload \
  source="Test content" \
  source_mode=inline \
  dest="/tmp/test.txt" \
  dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"  
  },
  "source": {
    "mode": "inline",
    "size_bytes": 12
  },
  "dest": {
    "path": "/tmp/test.txt",
    "atomic": false,
    "overwrite": false
  },
  "result": {
    "uploaded": false,
    "planned": true,
    "verify_checksum": false
  },
  "warnings": ["Dry run: file was not uploaded."]
}
```

### File Upload

Upload from a local file:

```bash
resh ssh://host.com/ upload \
  source="/home/smiller/Development/rust/resh/test_upload.txt" \
  source_mode=file \
  dest="/tmp/test.txt" \
  overwrite=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "source": {
    "mode": "file",
    "size_bytes": 1024
  },
  "dest": {
    "path": "/tmp/test.txt",
    "atomic": false,
    "overwrite": true
  },
  "result": {
    "uploaded": true,
    "planned": false,
    "verify_checksum": false
  }
}
```

### Base64 Content Upload

Upload base64-encoded content:

```bash
# "Hello, Base64!" encoded in base64
resh ssh://host.com/ upload \
  source="SGVsbG8sIEJhc2U2NCE=" \
  source_mode=inline \
  source_encoding=base64 \
  dest="/tmp/test.txt" \
  overwrite=true
```

**Expected Output:** Source size shows the decoded size (14 bytes)

### Atomic Upload

Upload with atomic operations (temporary file then rename):

```bash
resh ssh://host.com/ upload \
  source="atomic test data" \
  source_mode=inline \
  dest="/tmp/atomic_test.txt" \
  atomic=true \
  overwrite=true
```

**Expected Output:** `dest.atomic` will be `true`

### Checksum Verification

Upload with checksum verification:

```bash
resh ssh://host.com/ upload \
  source="test data for checksum" \
  source_mode=inline \
  dest="/tmp/checksum_test.txt" \
  verify_checksum=true \
  checksum_algorithm=sha256
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "result": {
    "uploaded": true,
    "verify_checksum": true,
    "checksum_algorithm": "sha256",
    "checksum_verified": true
  }
}
```

### Text Format Output

```bash
resh ssh://host.com/ upload \
  source="text format test" \
  source_mode=inline \
  dest="/tmp/text_test.txt" \
  format=text
```

**Expected Output (Text):**
```
SSH Upload
==========

Host    : host.com
Port    : 22
User    : user

Source  :
  Mode     : inline
  Size     : 16 bytes

Dest    :
  Path     : /tmp/text_test.txt
  Atomic   : no
  Overwrite: no

Result  :
  Uploaded   : yes
  Planned    : no
  Checksum   : no
```

### Error Conditions

#### Missing Source

```bash
resh ssh://host.com/ upload dest="/tmp/test.txt"
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_source_missing",
    "message": "Source is required for upload"
  }
}
```

#### Missing Destination

```bash
resh ssh://host.com/ upload source="test data" source_mode=inline
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_dest_missing", 
    "message": "Destination path is required for upload"
  }
}
```

#### Destination Exists (No Overwrite)

```bash
resh ssh://host.com/ upload \
  source="test data" \
  source_mode=inline \
  dest="/tmp/existing_file.txt" \
  overwrite=false
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_dest_exists",
    "message": "Destination file exists and overwrite is disabled"
  }
}
```

#### Checksum Mismatch

```bash
resh ssh://host.com/ upload \
  source="test data" \
  source_mode=inline \
  dest="/tmp/checksum_mismatch.txt" \
  verify_checksum=true
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_checksum_mismatch",
    "message": "Uploaded file checksum does not match expected"
  }
}
```

#### Permission Denied

```bash
resh ssh://host.com/ upload \
  source="permission test" \
  source_mode=inline \
  dest="/tmp/permission_denied.txt"
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_remote_write_failed",
    "message": "Failed to write file on remote host"
  }
}
```

#### Upload Timeout

```bash
resh ssh://host.com/ upload \
  source="timeout test" \
  source_mode=inline \
  dest="/tmp/timeout_test.txt"
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.upload_timeout",
    "message": "Upload operation timed out"
  }
}
```

---

## download

Download files from remote SSH hosts.

### Basic Download to File

Download a file to local filesystem:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/myapp/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/config.yaml" \
  return_content=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "example.com",
    "port": 22,
    "username": "deploy",
    "auth_method": "password"
  },
  "source": {
    "path": "/etc/myapp/config.yaml",
    "size_bytes": 2048
  },
  "dest": {
    "mode": "file",
    "path": "/tmp/config.yaml"
  },
  "result": {
    "downloaded": true,
    "planned": false,
    "return_content": true,
    "return_encoding": "utf8",
    "content": "# Config file content here\nkey: value\n"
  }
}
```

### Download Content Only (No File)

Download content without saving to file:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest_mode=none \
  return_content=true \
  return_encoding=utf8
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "example.com",
    "port": 22,
    "username": "deploy",
    "auth_method": "password"
  },
  "source": {
    "path": "/etc/config.yaml",
    "size_bytes": 1024
  },
  "dest": {
    "mode": "none",
    "path": null
  },
  "result": {
    "downloaded": true,
    "planned": false,
    "return_content": true,
    "return_encoding": "utf8",
    "content": "config content..."
  }
}
```

### Download with Base64 Encoding

Download binary content as base64:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/bin/data" \
  auth_method=password \
  password=testpass \
  dest_mode=none \
  return_content=true \
  return_encoding=base64
```

**Expected Output:** Content will be base64-encoded, and `return_encoding` will be "base64"

### Dry Run Download

Test what would be downloaded:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/config.yaml" \
  dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "example.com",
    "port": 22,
    "username": "deploy",
    "auth_method": "password"
  },
  "source": {
    "path": "/etc/config.yaml",
    "size_bytes": 1024
  },
  "dest": {
    "mode": "file",
    "path": "/tmp/config.yaml"
  },
  "result": {
    "downloaded": false,
    "planned": true,
    "return_content": false,
    "content": null
  },
  "warnings": ["Dry run: file was not downloaded."]
}
```

### Download with Overwrite

Download and overwrite existing file:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/existing_config.yaml" \
  overwrite=true
```

### Download with Parent Directory Creation

Download to a nested path, creating directories:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/nested/subdir/file.txt" \
  mkdir_parents=true
```

### Download without Content Return

Download file but don't return content in response:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/config.yaml" \
  return_content=false
```

**Expected Output:** `result.content` will be `null`

### Download with Checksum Verification

Download with checksum verification:

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest_mode=none \
  return_content=true \
  verify_checksum=true \
  checksum_algorithm=sha256
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "result": {
    "downloaded": true,
    "verify_checksum": true,
    "checksum_algorithm": "sha256",
    "checksum_verified": true
  }
}
```

### Text Format Output

```bash
resh ssh://deploy@example.com:22/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/config.yaml" \
  format=text
```

**Expected Output (Text):**
```
SSH Download
============

Host    : example.com
Port    : 22
User    : deploy

Source  :
  Path    : /etc/config.yaml
  Size    : 1024 bytes

Dest    :
  Mode    : file
  Path    : /tmp/config.yaml
```

### Error Conditions

#### Missing Source

```bash
resh ssh://example.com/ download dest="/tmp/output.txt"
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.download_source_missing",
    "message": "Source path is required for download"
  }
}
```

#### Missing Destination (File Mode)

```bash
resh ssh://example.com/ download source="/etc/config.yaml" dest_mode=file
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.download_dest_missing",
    "message": "Destination path is required when dest_mode is file"
  }
}
```

#### Destination Exists (No Overwrite)

```bash
resh ssh://example.com/ download \
  source="/etc/config.yaml" \
  auth_method=password \
  password=testpass \
  dest="/tmp/existing_file.txt" \
  overwrite=false
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.download_dest_exists",
    "message": "Destination file exists and overwrite is disabled"
  }
}
```

#### File Too Large

```bash
resh ssh://example.com/ download \
  source="/large/file.bin" \
  auth_method=password \
  password=testpass \
  dest_mode=none \
  max_size_bytes=100
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.download_too_large", 
    "message": "File size exceeds maximum allowed size"
  }
}
```

#### Missing Password

```bash
resh ssh://example.com/ download \
  source="/etc/config.yaml" \
  dest_mode=none \
  auth_method=password
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.auth_missing_password",
    "message": "Password is required for password authentication"
  }
}
```

#### Missing Key

```bash
resh ssh://example.com/ download \
  source="/etc/config.yaml" \
  dest_mode=none \
  auth_method=key
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.auth_missing_key",
    "message": "Identity path or data is required for key authentication"
  }
}
```

---

## tunnel

Create SSH tunnels for secure port forwarding.

### Local Tunnel (Forward Local Port to Remote)

Forward local port 5433 to remote database server:

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  local_bind_port=5433 \
  dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "tunnel": {
    "mode": "local",
    "local_bind_host": "127.0.0.1",
    "local_bind_port": 5433,
    "remote_dest_host": "db.internal", 
    "remote_dest_port": 5432
  },
  "lifetime": {
    "connect_timeout_ms": 30000,
    "tunnel_timeout_ms": null,
    "idle_timeout_ms": null,
    "max_connections": null,
    "max_bytes_in": null,
    "max_bytes_out": null
  },
  "warnings": ["Dry run: tunnel was not created."]
}
```

### Remote Tunnel (Forward Remote Port to Local)

Forward remote port 9090 to local service on port 8080:

```bash
resh ssh://user@host.com/ tunnel \
  mode=remote \
  local_dest_host=localhost \
  local_dest_port=8080 \
  remote_bind_port=9090 \
  dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user", 
    "auth_method": "agent"
  },
  "tunnel": {
    "mode": "remote",
    "remote_bind_host": "127.0.0.1",
    "remote_bind_port": 9090,
    "local_dest_host": "localhost",
    "local_dest_port": 8080
  },
  "lifetime": {
    "connect_timeout_ms": 30000,
    "tunnel_timeout_ms": null,
    "idle_timeout_ms": null,
    "max_connections": null,
    "max_bytes_in": null,
    "max_bytes_out": null
  },
  "warnings": ["Dry run: tunnel was not created."]
}
```

### Dynamic Tunnel (SOCKS Proxy)

Create a SOCKS proxy on local port 1080:

```bash
resh ssh://user@host.com/ tunnel \
  mode=dynamic \
  local_bind_port=1080 \
  socks_version=socks5 \
  dry_run=true
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": true,
  "connection": {
    "host": "host.com",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "tunnel": {
    "mode": "dynamic",
    "local_bind_host": "127.0.0.1",
    "local_bind_port": 1080,
    "socks_version": "socks5"
  },
  "lifetime": {
    "connect_timeout_ms": 30000,
    "tunnel_timeout_ms": null,
    "idle_timeout_ms": null,
    "max_connections": null,
    "max_bytes_in": null,
    "max_bytes_out": null
  },
  "warnings": ["Dry run: tunnel was not created."]
}
```

### Tunnel with Lifetime Configuration

Configure tunnel limits and timeouts:

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  local_bind_port=5433 \
  tunnel_timeout_ms=60000 \
  idle_timeout_ms=30000 \
  max_connections=10 \
  max_bytes_in=1048576 \
  max_bytes_out=2097152 \
  dry_run=true
```

**Expected Output:** The `lifetime` object will contain the specified limits

### Wildcard Bind with Warning

Allow wildcard binding (security warning):

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  local_bind_host=0.0.0.0 \
  local_bind_port=5433 \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  allow_wildcard_binds=true \
  dry_run=true
```

**Expected Output:** Warnings will include a security warning about wildcard binding

### Insecure Mode Warning

Disable host key verification (security warning):

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  local_bind_port=5433 \
  known_hosts_mode=insecure \
  dry_run=true
```

**Expected Output:** Warnings will include "Host key verification disabled"

### Text Format Output

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  local_bind_port=5433 \
  dry_run=true \
  format=text
```

**Expected Output (Text):**
```
SSH Tunnel
==========

Host     : host.com
Port     : 22  
User     : user

Mode     : local

Local Bind:
  Host   : 127.0.0.1
  Port   : 5433

Remote Dest:
  Host   : db.internal
  Port   : 5432
```

### Error Conditions

#### Missing Mode

```bash
resh ssh://user@host.com/ tunnel \
  remote_dest_host=db.internal \
  remote_dest_port=5432
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.tunnel_mode_required",
    "message": "Tunnel mode is required (local, remote, or dynamic)"
  }
}
```

#### Local Mode Missing Remote Destination

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  local_bind_port=5433
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.tunnel_missing_remote_dest", 
    "message": "Remote destination host and port are required for local tunnels"
  }
}
```

#### Remote Mode Missing Local Destination

```bash
resh ssh://user@host.com/ tunnel \
  mode=remote \
  remote_bind_port=9090
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.tunnel_missing_local_dest",
    "message": "Local destination host and port are required for remote tunnels"
  }
}
```

#### Wildcard Bind Forbidden

```bash
resh ssh://user@host.com/ tunnel \
  mode=local \
  local_bind_host=0.0.0.0 \
  local_bind_port=5433 \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  allow_wildcard_binds=false
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.tunnel_wildcard_bind_forbidden",
    "message": "Wildcard binding is not allowed"
  }
}
```

#### Missing Host

```bash
resh ssh:/// tunnel \
  mode=local \
  remote_dest_host=db.internal \
  remote_dest_port=5432 \
  local_bind_port=5433 \
  dry_run=true
```

**Error Response:**
```json
{
  "ok": false,
  "error": {
    "code": "ssh.host_required",
    "message": "Host is required for SSH connection"
  }
}
```

---

## keys.list

List SSH keys from authorized_keys files, host keys, or custom paths.

### Basic Usage - Authorized Keys (Default)

List authorized keys for the current user:

```bash
resh ssh://testhost/ keys.list
```

**Expected Output (JSON):**
```json
{
  "ok": true,
  "dry_run": false,
  "connection": {
    "host": "testhost",
    "port": 22,
    "username": "user",
    "auth_method": "agent"
  },
  "options": {
    "scope": "authorized",
    "key_types": ["rsa", "ecdsa", "ed25519", "dsa"],
    "fingerprint_algorithm": "sha256",
    "max_keys": 1024,
    "max_bytes": 1048576,
    "include_options": true,
    "include_raw_key": true
  },
  "result": {
    "keys": [],
    "total_count": 0,
    "truncated": false
  }
}
```

### Custom Scope - Specific Paths

List keys from custom file paths:

```bash
resh ssh://testhost/ keys.list \
  scope=custom \
  custom_paths="/path/to/keys1,/path/to/keys2"
```

**Expected Output:** `options.scope` will be "custom" and `custom_paths` will contain the specified paths

### Host Scope

List host keys:

```bash
resh ssh://testhost/ keys.list scope=host
```

**Expected Output:** `options.scope` will be "host"

### Filter by Key Types

List only specific key types:

```bash
resh ssh://testhost/ keys.list key_types="ed25519,rsa"
```

**Expected Output:** `options.key_types` will be `["ed25519", "rsa"]`

---

## key.add

Add SSH keys to authorized_keys files or other locations.

*Note: This verb is implemented but specific test examples were not found in the unit tests reviewed. The verb accepts parameters for adding public keys to remote hosts.*

### Basic Usage

```bash
resh ssh://host.com/ key.add \
  public_key="ssh-rsa AAAAB3NzaC1yc2E... user@host" \
  target_path="~/.ssh/authorized_keys"
```

---

## config.get

Get SSH configuration values.

*Note: This verb is implemented but specific test examples were not found in the unit tests reviewed. The verb returns SSH configuration information.*

### Basic Usage

```bash
resh ssh://host.com/ config.get
```

---

## test

Test SSH connections to verify connectivity and authentication.

*Note: This verb is implemented but specific test examples were not found in the unit tests reviewed. The verb tests connectivity without executing commands.*

### Basic Usage

```bash
resh ssh://host.com/ test auth_method=password password=secret
```

---

## Common Parameters

### Authentication Options

| Parameter | Description | Values |
|-----------|-------------|--------|
| `auth_method` | Authentication method | `agent`, `password`, `key` |
| `password` | Password for password auth | String |
| `identity_path` | Path to private key file | File path |
| `identity_data` | Private key data inline | String |
| `identity_passphrase` | Key passphrase | String |
| `agent_socket` | SSH agent socket path | File path |

### Connection Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `host` | Remote hostname or IP | From URL |
| `port` | Remote SSH port | 22 |
| `username` | SSH username | From URL or current user |
| `connect_timeout_ms` | Connection timeout | 30000 |

### Host Key Verification

| Parameter | Description | Values |
|-----------|-------------|--------|
| `known_hosts_mode` | Host key verification | `strict`, `accept_new`, `insecure` |
| `known_hosts_path` | Path to known_hosts file | File path |

### Output Options

| Parameter | Description | Values |
|-----------|-------------|--------|
| `format` | Output format | `json`, `text` |
| `dry_run` | Test without executing | `true`, `false` |

## Security Considerations

1. **Password Authentication**: Avoid using password authentication in scripts. Use SSH keys or SSH agent instead.

2. **Host Key Verification**: Always verify host keys. Only use `known_hosts_mode=insecure` for testing.

3. **Wildcard Binds**: Be careful with `0.0.0.0` bind addresses as they expose tunnels to the network.

4. **Key Management**: Protect private keys with proper file permissions (600) and use passphrases.

5. **Tunnel Security**: Limit tunnel lifetime and connection counts for production use.