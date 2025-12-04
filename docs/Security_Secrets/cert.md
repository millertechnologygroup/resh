# Certificate Handle Documentation

The Certificate Handle lets you work with digital certificates and cryptographic keys. You can view certificate information, create new certificates, generate keys, sign data, and manage certificate chains. Think of certificates like digital ID cards that prove identity and enable secure communication.

## What Certificate Types Are Supported?

The system works with these common certificate and key formats:

- **X.509 Certificates** (.pem, .crt, .cer, .der) - Standard digital certificates
- **Private Keys** (.pem, .key, .der) - RSA, ECDSA (P-256, P-384), and Ed25519 keys
- **Certificate Signing Requests (CSR)** (.csr, .pem, .der) - Requests for new certificates
- **Certificate Chains** (.pem) - Multiple certificates in sequence
- **Encrypted Private Keys** (.pem) - Password-protected private keys

## Certificate Commands (Verbs)

### Info - View Certificate Information

**What it does:** Shows detailed information about certificates, private keys, or CSRs including subject, validity dates, and fingerprints.

**Optional settings:**
- `format` - Output format (json or text, default: json)
- `encoding` - File encoding (auto, pem, or der, default: auto)
- `include_pem` - Include PEM data in output (true/false, default: false)
- `include_raw` - Include raw DER data as base64 (true/false, default: false)
- `fingerprint_algs` - Fingerprint algorithms to calculate (JSON array: ["sha1", "sha256"], default: ["sha256"])

**Example use:**
```
cert:///tmp/test_cert.pem.info
```

**Example output:**
```json
{
  "type": "certificate",
  "encoding": "pem",
  "objects": [
    {
      "kind": "certificate",
      "version": 2,
      "serial_number": "123456789",
      "subject": {
        "common_name": "example.com",
        "organization": "Test Corp",
        "country": "US"
      },
      "issuer": {
        "common_name": "example.com",
        "organization": "Test Corp",
        "country": "US"
      },
      "validity": {
        "not_before": "2023-01-01T00:00:00Z",
        "not_after": "2024-01-01T00:00:00Z",
        "is_currently_valid": true
      },
      "public_key": {
        "algorithm": "RSA",
        "key_size": 2048
      },
      "fingerprints": {
        "sha256": "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56"
      },
      "extensions": {},
      "is_ca": false
    }
  ]
}
```

**Example with text format:**
```
cert:///tmp/test_cert.pem.info(format="text")
```

**Example text output:**
```
Type: Certificate
Encoding: pem
Valid From: 2023-01-01 00:00:00 UTC
Valid To: 2024-01-01 00:00:00 UTC
Is Currently Valid: true
SHA256 Fingerprint: AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56
```

**Example with fingerprint algorithms:**
```
cert:///tmp/test_cert.pem.info(fingerprint_algs=["sha1","sha256"])
```

### Generate - Create New Certificates and Keys

**What it does:** Generates new private keys, self-signed certificates, CSRs, or leaf certificates.

**Required settings:**
- `mode` - What to generate (key, self_signed, csr, or leaf_cert)

**For key generation:**
- `algorithm` - Key algorithm (rsa, ecdsa, or ed25519, default: rsa)
- `rsa_bits` - RSA key size (2048, 3072, or 4096, default: 2048)
- `ecdsa_curve` - ECDSA curve (P-256 or P-384, default: P-256)
- `key_format` - Key format (pkcs8, pkcs1 for RSA, sec1 for ECDSA, default: pkcs8)
- `key_encoding` - Encoding (pem or der, default: pem)

**For certificate generation:**
- `subject` - Certificate subject as JSON object with common_name, organization, etc.
- `sans` - Subject Alternative Names as JSON array (e.g., ["DNS:example.com", "IP:192.0.2.1"])
- `validity_days` - Certificate validity in days (default: 365)
- `is_ca` - Whether this is a CA certificate (true/false, default: false)

**For leaf certificates:**
- `signer_cert` - Path to CA certificate
- `signer_key` - Path to CA private key

**Optional settings:**
- `overwrite` - Replace existing files (true/false, default: false)
- `key_path` - Custom path for private key output
- `password` - Password to encrypt private key
- `kdf` - Key derivation function for encryption (argon2id or pbkdf2, default: pbkdf2)
- `kdf_iterations` - Iterations for key derivation (default: 100000)

**Example key generation:**
```
cert:///tmp/test.generate mode=key algorithm=rsa rsa_bits=2048 format=json
```

**Example key output:**
```json
{
  "ok": true,
  "mode": "key",
  "algorithm": "rsa",
  "rsa_bits": 2048,
  "key": {
    "algorithm": "rsa",
    "rsa_bits": 2048,
    "key_format": "pkcs8",
    "encoding": "pem",
    "stored_at": "/tmp/test-key.pem"
  }
}
```

**Example self-signed certificate:**
```
cert:///tmp/test.generate mode=self_signed subject='{"common_name":"Test Certificate"}' algorithm=rsa rsa_bits=2048 format=json
```

**Example self-signed output:**
```json
{
  "ok": true,
  "mode": "selfsigned",
  "algorithm": "rsa",
  "rsa_bits": 2048,
  "certificate": {
    "subject": {
      "common_name": "Test Certificate"
    },
    "serial_number": "1234567890abcdef",
    "stored_at": "/tmp/test.pem"
  },
  "key": {
    "stored_at": "/tmp/test-key.pem"
  },
  "validity": {
    "not_before": "2023-01-01T00:00:00Z",
    "not_after": "2024-01-01T00:00:00Z"
  }
}
```

### Verify - Validate Certificates

**What it does:** Checks if certificates are valid, properly signed, and within their validity period.

**Optional settings:**
- `ca_bundle` - Path to CA certificates bundle for verification
- `check_revocation` - Check certificate revocation status (true/false, default: false)
- `allow_self_signed` - Allow self-signed certificates (true/false, default: false)

**Example use:**
```
cert:///tmp/test_cert.pem.verify
```

**Example output:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "chain_length": 1,
  "is_self_signed": true,
  "expires_in_days": 364
}
```

### Sign - Sign Data or CSRs

**What it does:** Creates digital signatures for data or signs Certificate Signing Requests to create certificates.

**Required settings:**
- `mode` - What to sign (data or csr)

**For data signing:**
- `data` - Data to sign (as string or base64)
- `signer_key` - Path to private key for signing
- `algorithm` - Signature algorithm (rsa_pss_sha256, ecdsa_sha256, ed25519, etc.)

**For CSR signing:**
- `signer_cert` - Path to CA certificate
- `signer_key` - Path to CA private key
- `cert_output_path` - Where to save the signed certificate

**Optional settings:**
- `signer_key_password` - Password for encrypted private key
- `validity_days` - Certificate validity in days (default: 365)
- `copy_extensions` - Copy extensions from CSR (true/false, default: false)

**Example data signing:**
```
cert:///tmp/data.sign mode=data data="Hello World" signer_key=cert:///tmp/private.key algorithm=rsa_pss_sha256
```

**Example CSR signing:**
```
cert:///tmp/request.csr.sign mode=csr signer_cert=cert:///tmp/ca.pem signer_key=cert:///tmp/ca-key.pem cert_output_path=cert:///tmp/certificate.pem
```

### Renew - Renew Existing Certificates

**What it does:** Creates a new certificate with updated validity dates, optionally using the same or new private key.

**Required settings:**
- `mode` - Renewal mode (self_signed, ca_signed, etc.)

**Optional settings:**
- `key_strategy` - Key handling (reuse or rekey, default: reuse)
- `validity_days` - New certificate validity in days (default: 365)
- `algorithm` - Algorithm for new key if rekeying (rsa, ecdsa, ed25519)
- `rsa_bits` - RSA key size if generating new RSA key (default: 2048)

**Example renewal:**
```
cert:///tmp/test.pem.renew mode=self_signed key_strategy=reuse format=json
```

**Example output:**
```json
{
  "ok": true,
  "key_strategy": "reuse",
  "certificate": {
    "renewed": true,
    "stored_at": "/tmp/test.pem"
  },
  "validity": {
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z"
  }
}
```

### CSR.Create - Generate Certificate Signing Requests

**What it does:** Creates a Certificate Signing Request (CSR) that can be sent to a Certificate Authority for signing.

**Required settings:**
- `subject` - Certificate subject as JSON with at least common_name
- `key_strategy` - Key handling (generate or reuse)

**For generate strategy:**
- `new_key_output_path` - Where to save the new private key
- `algorithm` - Key algorithm (rsa, ecdsa, ed25519, default: rsa)
- `rsa_bits` - RSA key size (minimum 2048, default: 2048)
- `ecdsa_curve` - ECDSA curve (P-256 or P-384, default: P-256)

**For reuse strategy:**
- `existing_key_path` - Path to existing private key

**Optional settings:**
- `sans` - Subject Alternative Names as JSON array
- `key_usage` - Key usage extensions as JSON array
- `extended_key_usage` - Extended key usage as JSON array
- `key_format` - Private key format (pkcs8, pkcs1, sec1, default: pkcs8)
- `key_encoding` - Encoding (pem or der, default: pem)
- `csr_encoding` - CSR encoding (pem or der, default: pem)
- `overwrite` - Overwrite existing files (true/false, default: false)
- `include_csr_pem` - Include CSR PEM in response (true/false, default: false)
- `include_new_key_pem` - Include new key PEM in response (true/false, default: false)

**Example RSA CSR generation:**
```
cert:///tmp/test.csr.create key_strategy=generate algorithm=rsa rsa_bits=2048 new_key_output_path=cert://keys/test-key.pem subject='{"common_name": "example.com"}'
```

**Example output:**
```json
{
  "ok": true,
  "key_strategy": "generate",
  "csr": {
    "subject": {
      "common_name": "example.com"
    },
    "encoding": "pem",
    "stored_at": "/tmp/test.csr"
  },
  "key": {
    "algorithm": "rsa",
    "rsa_bits": 2048,
    "encoding": "pem",
    "key_format": "pkcs8",
    "reused": false,
    "stored_at": "keys/test-key.pem"
  }
}
```

**Example ECDSA P-256 CSR:**
```
cert:///tmp/test.csr.create key_strategy=generate algorithm=ecdsa ecdsa_curve=P-256 new_key_output_path=cert://keys/test-key.pem subject='{"common_name": "example.com"}'
```

**Example ECDSA output:**
```json
{
  "ok": true,
  "key_strategy": "generate",
  "csr": {
    "subject": {
      "common_name": "example.com"
    },
    "encoding": "pem"
  },
  "key": {
    "algorithm": "ecdsa",
    "ecdsa_curve": "P-256",
    "encoding": "pem",
    "key_format": "pkcs8",
    "reused": false
  }
}
```

**Example Ed25519 CSR:**
```
cert:///tmp/test.csr.create key_strategy=generate algorithm=ed25519 new_key_output_path=cert://keys/test-key.pem subject='{"common_name": "example.com"}'
```

**Example Ed25519 output:**
```json
{
  "ok": true,
  "key_strategy": "generate",
  "csr": {
    "subject": {
      "common_name": "example.com"
    },
    "encoding": "pem"
  },
  "key": {
    "algorithm": "ed25519",
    "encoding": "pem",
    "key_format": "pkcs8",
    "reused": false
  }
}
```

**Example with Subject Alternative Names:**
```
cert:///tmp/test.csr.create key_strategy=generate algorithm=rsa new_key_output_path=cert://keys/test-key.pem subject='{"common_name": "example.com"}' sans='["DNS:example.com", "DNS:www.example.com", "IP:192.0.2.1", "EMAIL:admin@example.com"]'
```

**Example SAN output:**
```json
{
  "ok": true,
  "key_strategy": "generate",
  "csr": {
    "subject": {
      "common_name": "example.com"
    },
    "sans": [
      "DNS:example.com",
      "DNS:www.example.com",
      "IP:192.0.2.1",
      "EMAIL:admin@example.com"
    ],
    "encoding": "pem"
  },
  "key": {
    "algorithm": "rsa",
    "rsa_bits": 2048,
    "encoding": "pem",
    "key_format": "pkcs8",
    "reused": false
  }
}
```

### CSR.Sign - Sign Certificate Signing Requests

**What it does:** Signs a CSR with a Certificate Authority's private key to create a new certificate.

**Required settings:**
- `signer_ca` - Path to CA certificate
- `signer_key` - Path to CA private key
- `cert_output_path` - Where to save the signed certificate

**Optional settings:**
- `signer_key_password` - Password for encrypted CA private key
- `validity_days` - Certificate validity in days (default: 365)
- `copy_subject` - Copy subject from CSR (true/false, default: true)
- `copy_sans` - Copy Subject Alternative Names (true/false, default: true)
- `copy_key_usage` - Copy key usage extensions (true/false, default: true)

**Example use:**
```
cert:///tmp/request.csr.sign signer_ca=cert:///tmp/ca.crt signer_key=cert:///tmp/ca.key cert_output_path=cert:///tmp/output.crt copy_subject=true copy_sans=true copy_key_usage=true
```

**Example output:**
```json
{
  "success": true,
  "response": {
    "cert": {
      "subject": {
        "common_name": "example.com"
      },
      "serial_number": "123456789abcdef",
      "stored_at": "/tmp/output.crt"
    },
    "csr": {
      "subject": {
        "common_name": "example.com"
      }
    },
    "signer": {
      "subject": {
        "common_name": "CA Certificate"
      }
    }
  }
}
```

### Chain.Info - Analyze Certificate Chains

**What it does:** Examines certificate chains to show the trust path, validation status, and relationship between certificates.

**Optional settings:**
- `trust_store` - Path to trust store for validation
- `include_details` - Include detailed certificate information (true/false, default: false)

**Example use:**
```
cert:///tmp/chain.pem.chain.info
```

**Example output:**
```json
{
  "chain_length": 3,
  "certificates": [
    {
      "index": 0,
      "role": "end_entity",
      "subject": "CN=example.com",
      "issuer": "CN=Intermediate CA",
      "is_valid": true
    },
    {
      "index": 1,
      "role": "intermediate",
      "subject": "CN=Intermediate CA",
      "issuer": "CN=Root CA",
      "is_valid": true
    },
    {
      "index": 2,
      "role": "root",
      "subject": "CN=Root CA",
      "issuer": "CN=Root CA",
      "is_valid": true,
      "is_self_signed": true
    }
  ],
  "trust_path_valid": true,
  "errors": [],
  "warnings": []
}
```

## Common Use Cases

### Creating a Self-Signed Certificate

1. Generate a self-signed certificate for testing:
```
cert:///tmp/test-cert.generate mode=self_signed subject='{"common_name":"test.example.com","organization":"Test Corp","country":"US"}' algorithm=rsa rsa_bits=2048
```

### Setting Up a Certificate Authority

1. Create CA certificate:
```
cert:///tmp/ca.generate mode=self_signed subject='{"common_name":"My CA","organization":"My Organization"}' is_ca=true validity_days=3650
```

2. Create a CSR for a server certificate:
```
cert:///tmp/server.csr.create key_strategy=generate algorithm=rsa new_key_output_path=cert:///tmp/server-key.pem subject='{"common_name":"server.example.com"}' sans='["DNS:server.example.com","DNS:www.server.example.com"]'
```

3. Sign the CSR with your CA:
```
cert:///tmp/server.csr.sign signer_ca=cert:///tmp/ca.pem signer_key=cert:///tmp/ca-key.pem cert_output_path=cert:///tmp/server.pem
```

### Checking Certificate Information

1. View basic certificate details:
```
cert:///tmp/certificate.pem.info
```

2. View certificate in human-readable format:
```
cert:///tmp/certificate.pem.info(format="text")
```

3. Check if a certificate is valid:
```
cert:///tmp/certificate.pem.verify
```

## Error Handling

The system provides clear error messages for common problems:

- **cert.not_found** - Certificate file doesn't exist
- **cert.parse_failed** - Invalid certificate format
- **cert.invalid_options** - Invalid command options
- **cert.target_exists** - Output file exists and overwrite=false

## Security Notes

- Private keys are stored securely with appropriate file permissions
- Password-protected keys use strong key derivation functions (PBKDF2/Argon2)
- Generated serial numbers are cryptographically random
- Default RSA key size is 2048 bits minimum for security
- Certificate validation includes expiration and signature checks