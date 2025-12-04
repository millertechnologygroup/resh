# Firewall Handle

The Firewall handle in Resource Shell provides complete firewall management across multiple Linux firewall backends. This handle supports rule management, status checking, and firewall service control for iptables, nftables, UFW, and firewalld.

## URL Format

```
firewall://
```

## Verbs

The Firewall handle supports eight main verbs:

- `rules.list` - List existing firewall rules
- `rules.add` - Add new firewall rules
- `rules.delete` - Delete existing firewall rules 
- `rules.save` - Save firewall rules to files
- `rules.reload` - Reload firewall rules from files
- `status` - Check firewall status and backend availability
- `enable` - Enable firewall service
- `disable` - Disable firewall service

---

## rules.list

List existing firewall rules from various firewall backends.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Firewall backend (auto, iptables, nftables, ufw, firewalld, all) |
| `family` | string | No | `any` | IP family (any, ipv4, ipv6) |
| `table` | string | No | - | Table to list rules from |
| `chain` | string | No | - | Chain to list rules from |
| `direction` | string | No | - | Rule direction (input, output, forward) |
| `action` | string | No | - | Rule action (accept, drop, reject) |
| `proto` | string | No | - | Protocol (tcp, udp, icmp) |
| `sport` | string | No | - | Source port filter |
| `dport` | string | No | - | Destination port filter |
| `saddr` | string | No | - | Source address filter |
| `daddr` | string | No | - | Destination address filter |
| `in_iface` | string | No | - | Input interface filter |
| `out_iface` | string | No | - | Output interface filter |
| `comment_contains` | string | No | - | Filter by comment content |
| `include_backend_raw` | boolean | No | `false` | Include raw backend output |
| `include_counters` | boolean | No | `false` | Include packet/byte counters |
| `max_rules` | number | No | `10000` | Maximum rules to return |
| `timeout_ms` | number | No | `5000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### List All Rules (Auto-detect Backend)

```bash
# List all rules using auto-detected backend
resh firewall:// rules.list
```

Expected output:
```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "family": "ipv4",
      "rules": [
        {
          "chain": "INPUT",
          "action": "ACCEPT",
          "proto": "tcp",
          "dport": "22"
        }
      ]
    }
  ],
  "query": {
    "backend": "auto",
    "include_metrics": true
  }
}
```

#### List Rules from Specific Backend

```bash
# List rules from iptables specifically
resh firewall:// rules.list backend=iptables format_output=json
```

---

## rules.add

Add new firewall rules to various firewall backends.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | Yes | - | Firewall backend (iptables, nftables, ufw, firewalld) |
| `family` | string | No | `ipv4` | IP family (ipv4, ipv6) |
| `direction` | string | Yes | - | Rule direction (input, output, forward) |
| `action` | string | Yes | - | Rule action (accept, drop, reject) |
| `proto` | string | No | - | Protocol (tcp, udp, icmp, all) |
| `dport` | string | No | - | Destination port |
| `sport` | string | No | - | Source port |
| `saddr` | string | No | - | Source address/network |
| `daddr` | string | No | - | Destination address/network |
| `comment` | string | No | - | Rule comment |
| `zone` | string | No | - | Zone (required for firewalld) |
| `dry_run` | boolean | No | `false` | Generate commands without executing |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Allow SSH Access (iptables)

```bash
# Allow SSH access using iptables
resh firewall:// rules.add \
  backend=iptables \
  family=ipv4 \
  direction=input \
  action=accept \
  proto=tcp \
  dport=22 \
  comment="Allow SSH" \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "rule": {
    "backend": "iptables",
    "action": "accept",
    "proto": "tcp",
    "dport": "22"
  },
  "backend_commands": [
    "iptables -A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment 'Allow SSH'"
  ]
}
```

#### Block HTTP from Subnet (iptables)

```bash
# Block HTTP traffic from specific subnet
resh firewall:// rules.add \
  backend=iptables \
  family=ipv4 \
  direction=input \
  action=drop \
  proto=tcp \
  dport=80 \
  saddr=192.168.1.0/24 \
  comment="Block HTTP from 192.168.1.0/24" \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "rule": {
    "backend": "iptables",
    "action": "drop",
    "proto": "tcp",
    "dport": "80",
    "saddr": "192.168.1.0/24"
  },
  "backend_commands": [
    "iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 80 -j DROP"
  ]
}
```

#### Drop Telnet Traffic (nftables)

```bash
# Drop telnet traffic using nftables
resh firewall:// rules.add \
  backend=nftables \
  family=ipv4 \
  direction=input \
  action=drop \
  proto=tcp \
  dport=23 \
  comment="Block telnet" \
  dry_run=true \
  format_output=json
```

#### Allow App Port from Corporate Network (UFW)

```bash
# Allow port 8080 from corporate subnet using UFW
resh firewall:// rules.add \
  backend=ufw \
  direction=input \
  action=accept \
  proto=tcp \
  dport=8080 \
  saddr=10.0.0.0/8 \
  comment="Allow app port from corp" \
  dry_run=true \
  format_output=json
```

#### Allow HTTP on Public Zone (firewalld)

```bash
# Allow HTTP on firewalld public zone
resh firewall:// rules.add \
  backend=firewalld \
  family=ipv4 \
  direction=input \
  action=accept \
  proto=tcp \
  dport=80 \
  zone=public \
  dry_run=true \
  format_output=json
```

---

## rules.delete

Delete existing firewall rules from various firewall backends.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | Yes | - | Firewall backend (iptables, nftables, ufw, firewalld) |
| `family` | string | No | `ipv4` | IP family (ipv4, ipv6) |
| `direction` | string | No | - | Rule direction (input, output, forward) |
| `action` | string | No | - | Rule action (accept, drop, reject) |
| `proto` | string | No | - | Protocol (tcp, udp, icmp, all) |
| `dport` | string | No | - | Destination port |
| `sport` | string | No | - | Source port |
| `saddr` | string | No | - | Source address/network |
| `daddr` | string | No | - | Destination address/network |
| `require_match` | boolean | No | `true` | Require rules to match for success |
| `dry_run` | boolean | No | `false` | Show what would be deleted without executing |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Delete with No Match (require_match=false)

```bash
# Delete rules with no matches allowed
resh firewall:// rules.delete \
  backend=iptables \
  family=ipv4 \
  direction=input \
  action=accept \
  proto=tcp \
  dport=65535 \
  require_match=false \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "result": {
    "deleted_count": 0
  },
  "warnings": [
    "No matching rules found"
  ]
}
```

#### Delete with Match Required (require_match=true)

```bash
# Delete rules requiring matches
resh firewall:// rules.delete \
  backend=iptables \
  family=ipv4 \
  direction=input \
  action=accept \
  proto=tcp \
  dport=65535 \
  require_match=true \
  dry_run=true \
  format_output=json
```

Expected output when no matches:
```json
{
  "ok": false,
  "error": {
    "code": "firewall.rules_delete_no_match",
    "message": "No matching rules found"
  }
}
```

---

## rules.save

Save current firewall rules to files in various formats.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Firewall backend (auto, iptables, nftables, ufw, firewalld) |
| `family` | string | No | `any` | IP family (any, ipv4, ipv6) |
| `format` | string | No | `normalized_json` | Save format (normalized_json, backend_native, both) |
| `path` | string | No | auto-generated | Output file path |
| `compress` | string | No | `none` | Compression (none, gzip, bzip2) |
| `include_metadata` | boolean | No | `true` | Include metadata in output |
| `include_all_backends` | boolean | No | `false` | Save all available backends |
| `dry_run` | boolean | No | `false` | Show what would be saved without executing |
| `overwrite` | boolean | No | `false` | Overwrite existing files |
| `create_dirs` | boolean | No | `true` | Create directories if needed |
| `timeout_ms` | number | No | `5000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Save Normalized JSON Snapshot (iptables)

```bash
# Save iptables rules as normalized JSON
resh firewall:// rules.save \
  backend=iptables \
  family=ipv4 \
  format=normalized_json \
  path=/tmp/firewall-backup.json \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "timestamp_unix_ms": 1732538560123,
  "summary": {
    "backends": [
      {
        "backend": "iptables",
        "family": "ipv4", 
        "rules_count": 3,
        "has_native": false
      }
    ],
    "bytes_written": 1024,
    "compressed": false,
    "path": "/tmp/firewall-backup.json"
  },
  "query": {
    "backend": "iptables",
    "format": "normalized_json",
    "path": "/tmp/firewall-backup.json"
  }
}
```

---

## rules.reload

Reload firewall rules from saved files.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Target firewall backend |
| `source_format` | string | No | `auto` | Source format (auto, backend_native, normalized_json) |
| `path` | string | Yes | - | Path to rules file |
| `family` | string | No | `any` | IP family (any, ipv4, ipv6) |
| `backup_before_apply` | boolean | No | `true` | Create backup before applying |
| `validate_before_apply` | boolean | No | `true` | Validate rules before applying |
| `dry_run` | boolean | No | `false` | Show what would be reloaded without executing |
| `timeout_ms` | number | No | `30000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Reload from Backend Native Format

```bash
# Reload iptables rules from native format file
resh firewall:// rules.reload \
  backend=iptables \
  source_format=backend_native \
  path=/tmp/iptables.rules \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "iptables",
  "source_format": "backend_native",
  "actions": [
    "iptables-restore < /tmp/iptables.rules"
  ],
  "query": {
    "backend": "iptables",
    "source_format": "backend_native",
    "path": "/tmp/iptables.rules"
  }
}
```

---

## status

Check firewall status and backend availability across different firewall systems.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Backend to check (auto, all, iptables, nftables, ufw, firewalld) |
| `family` | string | No | `any` | IP family (any, ipv4, ipv6) |
| `include_metrics` | boolean | No | `true` | Include performance metrics |
| `include_rules_summary` | boolean | No | `false` | Include rules count summary |
| `timeout_ms` | number | No | `5000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Check Status (Auto-detect Backend)

```bash
# Check status using auto-detected backend
resh firewall:// status format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "available": true,
      "active": true,
      "enabled": true
    }
  ],
  "query": {
    "backend": "auto",
    "include_metrics": true
  }
}
```

#### Check All Backends Status

```bash
# Check status of all backends
resh firewall:// status backend=all format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "available": true,
      "active": true,
      "enabled": true
    },
    {
      "backend": "nftables", 
      "available": false,
      "active": false,
      "enabled": false
    },
    {
      "backend": "ufw",
      "available": true,
      "active": false,
      "enabled": false
    },
    {
      "backend": "firewalld",
      "available": true,
      "active": false,
      "enabled": false
    }
  ]
}
```

#### Check Specific Backend Status

```bash
# Check iptables backend specifically
resh firewall:// status backend=iptables format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backends": [
    {
      "backend": "iptables",
      "available": true,
      "active": true,
      "enabled": true
    }
  ]
}
```

#### Check Status with Metrics

```bash
# Check status with metrics enabled
resh firewall:// status backend=auto include_metrics=true format_output=json
```

#### Check Status without Metrics

```bash
# Check status with metrics disabled
resh firewall:// status backend=auto include_metrics=false format_output=json
```

#### Check Status with Rules Summary

```bash
# Check status with rules summary
resh firewall:// status backend=auto include_rules_summary=true format_output=json
```

#### Check IPv4 Family Status

```bash
# Check status for IPv4 family only
resh firewall:// status backend=auto family=ipv4 format_output=json
```

---

## enable

Enable firewall service on various firewall backends.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Firewall backend to enable (auto, ufw, firewalld, iptables, nftables) |
| `path` | string | No | - | Path to rules file to apply during enable |
| `dry_run` | boolean | No | `false` | Show what would be enabled without executing |
| `validate_only` | boolean | No | `false` | Only validate parameters without enabling |
| `timeout_ms` | number | No | `30000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Enable UFW Firewall

```bash
# Enable UFW firewall
resh firewall:// enable backend=ufw format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "ufw",
  "previous_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "ufw --force enable"
  ]
}
```

#### Enable UFW with Dry Run

```bash
# Enable UFW in dry-run mode
resh firewall:// enable backend=ufw dry_run=true format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "ufw",
  "previous_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "ufw --force enable"
  ]
}
```

---

## disable

Disable firewall service on various firewall backends.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `backend` | string | No | `auto` | Firewall backend to disable (auto, ufw, firewalld, iptables, nftables) |
| `path` | string | No | - | Path to rules file to apply during disable |
| `backup_before_apply` | boolean | No | `true` | Create backup before disabling |
| `dry_run` | boolean | No | `false` | Show what would be disabled without executing |
| `validate_only` | boolean | No | `false` | Only validate parameters without disabling |
| `timeout_ms` | number | No | `30000` | Command timeout in milliseconds |
| `format_output` | string | No | `json` | Output format (json or text) |

### Examples

#### Disable UFW Firewall

```bash
# Disable UFW firewall
resh firewall:// disable backend=ufw format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "ufw",
  "previous_state": {
    "available": true,
    "active": true,
    "enabled": true
  },
  "current_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "ufw --force disable"
  ]
}
```

#### Disable with Backup (iptables)

```bash
# Disable iptables with backup
resh firewall:// disable \
  backend=iptables \
  backup_before_apply=true \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "iptables",
  "previous_state": {
    "available": true,
    "active": true,
    "enabled": true
  },
  "current_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "firewall.rules.save(...) -> /var/backups/firewall/.resh-backup-iptables-v4-1732538612.rules",
    "iptables -P INPUT ACCEPT",
    "iptables -P OUTPUT ACCEPT", 
    "iptables -P FORWARD ACCEPT",
    "iptables -F",
    "iptables -t nat -F",
    "iptables -t mangle -F"
  ]
}
```

#### Disable firewalld

```bash
# Disable firewalld service
resh firewall:// disable backend=firewalld dry_run=true format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "firewalld", 
  "previous_state": {
    "available": true,
    "active": true,
    "enabled": true
  },
  "current_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "systemctl stop firewalld"
  ]
}
```

#### Disable nftables

```bash
# Disable nftables with backup
resh firewall:// disable \
  backend=nftables \
  backup_before_apply=true \
  dry_run=true \
  format_output=json
```

Expected output:
```json
{
  "ok": true,
  "backend": "nftables",
  "previous_state": {
    "available": true,
    "active": true,
    "enabled": true
  },
  "current_state": {
    "available": true,
    "active": false,
    "enabled": false
  },
  "actions": [
    "firewall.rules.save(...) -> /var/backups/firewall/.resh-backup-nft-1732538612.rules",
    "nft flush ruleset"
  ]
}
```

---

## Supported Backends

The firewall handle supports these firewall backends:

- **auto** - Automatically detect the best available backend
- **iptables** - Traditional Linux netfilter iptables
- **nftables** - Modern Linux netfilter nftables 
- **ufw** - Uncomplicated Firewall (Ubuntu/Debian)
- **firewalld** - Dynamic firewall manager (Red Hat/CentOS)

## Error Handling

The firewall handle provides detailed error information including:

- Backend availability checks
- Parameter validation 
- Command execution failures
- Timeout handling
- Permission issues

All error responses include structured error codes like `firewall.status_invalid_backend` for consistent error handling.

## Security Considerations

- Most firewall operations require root privileges
- Dry-run mode allows testing without system changes
- Backup options help prevent configuration loss
- Validation ensures rules are syntactically correct before application