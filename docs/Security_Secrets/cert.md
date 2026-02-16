# Resource Shell (resh) – Cert Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations using structured URI-based commands. The `cert://` handle provides structured management of digital certificates and cryptographic keys.

### Purpose

The certificate domain enables:

* Inspection of certificates, keys, CSRs, and chains
* Generation of private keys and certificates
* Creation and signing of CSRs
* Certificate renewal
* Certificate verification and chain analysis
* Digital signing operations

All operations return structured JSON output suitable for automation and infrastructure workflows.

### Architectural Problem Addressed

Traditional certificate tooling (e.g., OpenSSL CLI):

* Uses complex flag-based syntax
* Produces human-oriented output
* Requires manual parsing for automation
* Has inconsistent workflows for lifecycle operations

resh addresses these limitations by:

* Exposing certificate lifecycle operations as typed verbs
* Using structured parameters instead of positional flags
* Returning deterministic JSON output
* Providing consistent error codes and validation semantics

### Resource-Oriented URI Model

Certificate operations follow:

```
handle://target.verb(options)
```

For certificate management:

* **handle**: `cert://`
* **target**: File path or resource path
* **verb**: Operation (e.g., `info`, `generate`, `verify`)
* **options**: Structured parameters

Examples:

```
cert:///etc/ssl/certs/server.pem.info
cert:///tmp/server.generate(mode=self_signed,subject='{"common_name":"example.com"}')
cert:///tmp/server.pem.verify
```

---

## 2. Design Philosophy and Core Principles

### Structured Interface Model

* Eight explicitly defined verbs.
* JSON-based structured subject and SAN definitions.
* Explicit mode selection for generation and signing.
* Deterministic output schemas.

---

### Safety-First Execution

* `overwrite=false` by default.
* Key generation enforces minimum RSA 2048 bits.
* Password-based key encryption supported.
* CSR signing requires explicit CA certificate and key.
* Certificate verification validates expiration and signatures.

---

### Deterministic Behavior

* Identical inputs produce consistent JSON outputs.
* Validation errors are explicit and structured.
* Encoding detection (`pem`, `der`, `auto`) is deterministic.
* Explicit key strategy (`reuse`, `rekey`) during renewal.

---

### JSON-Based Structured Output

All verbs return structured JSON with:

* `ok` or `success`
* Metadata about certificates or keys
* Validity windows
* Fingerprints
* Error objects (if failure)

Representative example:

```json
{
  "type": "certificate",
  "encoding": "pem",
  "objects": [
    {
      "subject": {
        "common_name": "example.com"
      },
      "validity": {
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:00:00Z",
        "is_currently_valid": true
      },
      "fingerprints": {
        "sha256": "AB:CD:EF:..."
      }
    }
  ]
}
```

---

### AI-Readiness

Structured output enables:

* Automated certificate expiration monitoring
* Trust chain validation
* Algorithm compliance checks
* Policy enforcement on SANs and key sizes
* Automated renewal workflows

---

## 3. Command Syntax and Execution Model

### 3.1 URI Structure

```
cert:///<path>.VERB(options)
```

| Component | Description               |
| --------- | ------------------------- |
| `handle`  | `cert://`                 |
| `target`  | Absolute or relative path |
| `VERB`    | Certificate operation     |
| `options` | Structured parameters     |

---

### Supported Verbs (8)

| Verb         | Purpose                     |
| ------------ | --------------------------- |
| `info`       | Inspect certificate/key/CSR |
| `generate`   | Generate key or certificate |
| `verify`     | Validate certificate        |
| `sign`       | Sign data or CSR            |
| `renew`      | Renew existing certificate  |
| `csr.create` | Create CSR                  |
| `csr.sign`   | Sign CSR                    |
| `chain.info` | Inspect certificate chain   |

---

### Production Examples

#### Inspect Certificate

```
cert:///etc/ssl/certs/server.pem.info
```

#### Generate RSA Key

```
cert:///tmp/key.generate(mode=key,algorithm=rsa,rsa_bits=2048)
```

#### Generate Self-Signed Certificate

```
cert:///tmp/server.generate(
  mode=self_signed,
  subject='{"common_name":"example.com"}',
  algorithm=rsa,
  rsa_bits=2048
)
```

#### Create CSR

```
cert:///tmp/server.csr.create(
  key_strategy=generate,
  algorithm=ecdsa,
  ecdsa_curve=P-256,
  new_key_output_path=/tmp/server-key.pem,
  subject='{"common_name":"example.com"}',
  sans='["DNS:example.com","DNS:www.example.com"]'
)
```

#### Sign CSR

```
cert:///tmp/server.csr.sign(
  signer_ca=/ca/root.pem,
  signer_key=/ca/root-key.pem,
  cert_output_path=/tmp/server.pem
)
```

#### Verify Certificate

```
cert:///tmp/server.pem.verify(ca_bundle=/ca/root.pem)
```

---

## 3.2 Execution Semantics

### Deterministic Behavior

* Required parameters enforced.
* Invalid JSON subject/SAN definitions rejected.
* Key sizes validated.
* Signature algorithm compatibility enforced.
* Chain validation explicitly reported.

---

### Structured Output Contracts

Example: Verification

```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "chain_length": 2,
  "expires_in_days": 89
}
```

Example: Renewal

```json
{
  "ok": true,
  "key_strategy": "reuse",
  "validity": {
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z"
  }
}
```

---

### Error Handling Structure

Representative error:

```json
{
  "ok": false,
  "error": {
    "code": "cert.parse_failed",
    "message": "Invalid certificate format"
  }
}
```

Standardized exit codes:

| Code | Meaning               |
| ---- | --------------------- |
| 0    | Success               |
| 1    | General error         |
| 2    | Certificate not found |
| 3    | Parse error           |
| 4    | Invalid options       |
| 5    | Target exists         |
| 6    | Verification failed   |
| 7    | Permission denied     |

---

## 4. Functional Domains

---

### 4.1 Automation Utilities

**Handle**

* `cert://`

**Use Cases**

* Automated TLS provisioning
* Automated CSR creation in CI pipelines
* Renewal workflows
* Policy compliance validation

---

### 4.2 Data & State Management

**Scope**

* Certificate metadata inspection
* Fingerprint calculation
* Expiration tracking
* Chain relationship analysis

---

### 4.3 Filesystem & Storage

**Scope**

* Secure key storage
* PEM/DER encoding management
* Encrypted private key support
* File overwrite protection

---

### 4.4 Network & Remote Operations

**Scope**

* TLS certificate provisioning
* Server and client authentication
* Trust chain validation
* Secure endpoint configuration

---

### 4.5 Packages & Software

Supports:

* Post-install TLS configuration
* Secure service enablement
* Certificate-based authentication for services

---

### 4.6 Process & Service Management

Integrates with:

* `svc://` for reloading services after certificate renewal
* `cron://` for scheduled renewal checks
* `secret://` for storing key passwords

---

### 4.7 Security & Secrets

Primary domain:

* RSA, ECDSA, Ed25519 key generation
* Password-protected private keys
* CA hierarchy creation
* Chain validation
* Key derivation functions (PBKDF2, Argon2id)

Security considerations:

* Minimum RSA 2048-bit enforcement
* Support for encrypted private keys
* Explicit CA flag (`is_ca`)
* SAN validation
* Explicit overwrite control

---

### 4.8 System Information

Structured reporting includes:

* Certificate subject and issuer
* Validity window
* Public key algorithm and size
* Fingerprints (SHA-1, SHA-256)
* Chain trust validation status

---

## 5. Platform Support

The certificate handle operates on:

* Linux
* Unix/macOS (where filesystem and crypto libraries are available)
* Windows (limited to file-based operations)

Platform compatibility depends on filesystem access and cryptographic support.

Limitations (as documented):

* No ACME protocol support
* No automatic renewal
* No CRL/OCSP integration
* No HSM/PKCS#11 support

---

## 6. Operational Best Practices

### Safe Usage Guidelines

* Use RSA 2048-bit minimum.
* Prefer ECDSA P-256 or Ed25519 for modern deployments.
* Use `overwrite=false` in production.
* Store CA private keys offline.
* Use short validity for leaf certificates.
* Validate certificates before deployment.

---

### Automation Considerations

* Monitor `expires_in_days`.
* Use structured verification output.
* Automate renewal workflows.
* Validate SAN presence for domain certificates.
* Log certificate operations.

---

### CI/CD Integration

Typical workflow:

1. Generate CSR.
2. Sign CSR using CA.
3. Verify certificate.
4. Deploy certificate to service.
5. Reload service via `svc://`.
6. Schedule renewal checks with `cron://`.

---

### Production Environment Recommendations

* Implement certificate inventory tracking.
* Rotate certificates proactively.
* Protect private keys with strict file permissions.
* Use password encryption with Argon2id for sensitive keys.
* Avoid self-signed certificates in production.
* Validate full chain before deployment.

---

## 7. Use Cases by Role

### DevOps Engineers

* Automate TLS provisioning.
* Generate and sign CSRs.
* Integrate certificate renewal in pipelines.
* Enforce algorithm compliance policies.

---

### SRE Engineers

* Monitor certificate expiration.
* Verify trust chains during incident response.
* Rotate compromised certificates.
* Audit SAN and issuer metadata.

---

### Network Administrators

* Provision TLS certificates for web servers.
* Maintain internal CA hierarchies.
* Validate secure communication endpoints.
* Manage certificate chains.

---

### AI / Automation Engineers

* Parse structured certificate metadata.
* Detect policy violations (weak algorithms, missing SANs).
* Automate remediation workflows.
* Evaluate trust path validity programmatically.

---

## 8. Technical Foundation

### Rust Implementation Advantages

resh is implemented in Rust, providing:

* Memory safety
* Strong type guarantees
* Deterministic command parsing
* Secure cryptographic handling

---

### Type Safety

* Enumerated verbs
* Structured subject JSON validation
* Strict algorithm selection
* Defined error codes

---

### Performance Characteristics

* Efficient key generation
* Compact DER support
* Deterministic serialization
* Minimal overhead JSON output

---

### Cross-Platform Architecture

* Filesystem-based operation model
* Unified encoding detection
* Consistent structured output
* Explicit unsupported-feature signaling
