# Resource Shell (resh) – Cert Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `cert://` handle inspects and manages X.509 certificates, private keys, and certificate signing requests (CSRs) stored as PEM or DER files.

It uses pure-Rust libraries (x509-parser, rcgen, ring, rsa, p256, p384, ed25519-dalek); OpenSSL is not required. All work is on local files: the handle makes no network connections.

### What the handle does

* Inspect certificates, bundles, CSRs, and private keys (`info`).
* Verify a certificate's structure, signature chain, validity period, hostname, purpose, and matching private key (`verify`).
* Generate private keys, self-signed certificates, CA-signed leaf certificates, and CSRs (`generate`).
* Create a CSR from an existing or new key (`csr.create`).
* Sign data with a private key, or issue a certificate from a CSR with `mode=csr` (`sign`).
* Issue a replacement for an existing certificate (`renew`).
* List the certificates of a bundle as chain candidates (`chain.info`, limited; see below).

### What the handle does not do

* **No encrypted private keys.** `key_passphrase` (on `generate` and `renew`) is rejected with an error. Encrypted signer keys (`signer_key_passphrase`) and encrypted existing keys are rejected too. All keys are written unencrypted.
* **No CMS/PKCS#7 signatures** (see [sign](#sign)).
* **No revocation checking** (CRL/OCSP): `check_revocation=soft` reports `not_checked` and `hard` fails.
* No ACME, no automatic renewal, no HSM/PKCS#11.

---

## 2. Command Syntax

```text
resh cert://<file-path>.<verb> [key=value ...]
```

* Absolute path: `cert:///etc/ssl/certs/server.pem.info` (three slashes).
* Relative path: `cert://./server.pem.info`.
* The verb is the text after the last dot; `csr.create`, `csr.sign`, and `chain.info` are recognized as whole verbs.
* JSON-valued options (`subject`, `sans`, `output`, ...) must be quoted for the shell: `subject='{"common_name":"example.com"}'`.

Built-in help (authoritative for every option):

```bash
resh cert --help
resh cert generate --help
```

---

## 3. Verbs

| Verb         | Purpose                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `info`       | Report type, serial, subject, issuer, validity, public key, extensions, fingerprints for each object in a file |
| `verify`     | Check a certificate against a policy; each check is passed, failed, skipped, not_checked, or unsupported |
| `chain.info` | List leaf candidates of a bundle (no real chain building; see below)     |
| `generate`   | Generate a key, self-signed certificate, CA-signed leaf, or CSR           |
| `csr.create` | Create a CSR at the target path                                           |
| `sign`       | Sign data, or with `mode=csr` issue a certificate for a CSR              |
| `csr.sign`   | Registered, but **cannot be reached from the command line** (see below)  |
| `renew`      | Issue a replacement certificate with the same subject, SANs, and extensions |

### info

```bash
resh --json-pretty cert:///etc/ssl/certs/server.pem.info
resh cert://./bundle.pem.info fingerprint_algs=sha256,sha512
```

Options: `format=json|text`, `encoding=auto|pem|der`, `fingerprint_algs=sha1,sha256,sha384,sha512`, `include_pem`, `include_raw`. A bundle reports `"type": "certificatechain"` with one object per certificate; a CSR or key reports `kind` `csr` or `private_key`. `version` is zero-based (2 means X.509 v3).

### verify

```bash
resh cert://./web.pem.verify trust_paths=ca.pem hostname=web.test format=text
resh cert:///etc/ssl/certs/server.pem.verify purpose=server_auth
```

Options: `hostname=`, `trust=system|mount|inline` (default `system`, the system CA bundle), `trust_paths=<path>,...` and `trust_pem=<pem>` (add trust anchors), `max_chain_depth`, `min_rsa_bits`, `purpose=server_auth|client_auth|code_signing|email_protection|any`, `allow_self_signed`, `allow_expired`, `allow_not_yet_valid`, `check_revocation=none|soft|hard`, `keypair_target=<key-path>`, `disallow_weak_signatures`, `format`.

* The first certificate in the file is verified; any others are used as intermediates.
* Every signature in the chain is checked (RSA PKCS#1 v1.5 SHA-256/384/512, ECDSA P-256/P-384, Ed25519). Other algorithms report `unsupported`.
* If any check fails, the command exits with status 7.

There is no `ca_bundle` option; use `trust_paths=`.

### chain.info (limited)

```bash
resh cert://./bundle.pem.chain.info format=text
```

**Current behaviour:** `chain.info` parses the bundle and lists leaf candidates, but it does not link certificates to their issuers. Each reported chain has length 1 and a `trust_status` of `incomplete` (or `self_signed_untrusted` for a self-signed certificate), even when the issuer is in the same bundle or in `trust_paths`. The `trust`, `trust_paths`, and `trust_pem` options do not change the result. Use `verify` for real chain validation.

### generate

```bash
resh --json-pretty cert://./server.generate mode=key algorithm=ecdsa
resh cert://./ca.generate mode=self_signed algorithm=ecdsa is_ca=true subject='{"common_name":"Example CA"}'
resh cert://./web.generate mode=leaf_cert signer_ca=ca.pem signer_key=ca-key.pem subject='{"common_name":"web.test"}' sans='["DNS:web.test"]'
```

Files are written beside the target path: `<target>-key.pem` (key), `<target>.pem` (certificate), `<target>.csr` (CSR, `mode=csr`).

| Option                  | Values / default                                                        |
| ----------------------- | ----------------------------------------------------------------------- |
| `mode`                  | `key` (default), `self_signed`, `csr`, `leaf_cert`                       |
| `algorithm`             | `rsa` (default), `ecdsa`, `ed25519`                                      |
| `rsa_bits`              | default 2048; values below 2048 are rejected                             |
| `ecdsa_curve`           | `P-256` (default), `P-384`; P-521 and secp256k1 are rejected             |
| `subject`               | JSON object; `common_name` required for every mode except `key`. Also `organization`, `organizational_unit`, `country`, `state_or_province`, `locality` (arrays of strings) |
| `sans`                  | JSON array (or comma list) of `DNS:`, `IP:`, `EMAIL:` entries            |
| `is_ca`, `path_len`     | CA flag and path length constraint                                       |
| `not_before`, `not_after`, `not_after_offset_days` | validity (`not_after_offset_days` default 365)   |
| `signer_ca`, `signer_key` | required for `mode=leaf_cert`                                          |
| `key_format`, `key_encoding`, `cert_encoding`, `csr_encoding` | `pkcs8`/`pkcs1`/`sec1`, `pem`/`der` |
| `output`                | JSON object: `write_key`, `write_cert`, `write_csr`, `return_key`, `return_cert`, `return_csr` |
| `overwrite`             | default `false`: if any output file exists, nothing is written and the command fails with `cert.target_exists` |

`key_passphrase` is rejected: "key_passphrase is not supported: private key encryption is not available in this build".

### csr.create

```bash
resh cert://./web-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=web-key.pem subject='{"common_name":"web.test"}' sans='["DNS:web.test"]'
resh cert://./web-req.pem.csr.create existing_key_path=web-key.pem algorithm=ecdsa subject='{"common_name":"web.test"}'
```

The CSR is written to the target path exactly (here `./web-req.pem`). Options: `subject` (required), `key_strategy=reuse|generate` (default `reuse`, which needs `existing_key_path`), `new_key_output_path`, `algorithm` (default `rsa`), `rsa_bits`, `ecdsa_curve`, `sans`, `key_usage`, `extended_key_usage`, `overwrite`, `format`.

* When reusing a non-RSA key, pass the matching `algorithm=` (for example `algorithm=ecdsa`); it is not inferred from the key, and a mismatch fails with "signature algorithm is incompatible with the given key pair".
* Do not pass `new_key_passphrase`: the new key is still written **unencrypted**, although the output reports `"encrypted": true`.

### sign

Data signing:

```bash
resh --json-pretty cert://./ca.sign signer_key=ca-key.pem data_source=app.tar signature_output_path=app.tar.sig
```

The target (`./ca`) is only a label in the output. Options: `signer_key` (required), `data_source=<path>` or `data_bytes_base64=`, `signature_algorithm`, `signature_encoding=base64|pem|der`, `signature_output_path`, `include_signature_bytes=true`. Without `signature_output_path` or `include_signature_bytes=true` the signature is computed but not kept.

`signature_format=cms_detached` or `cms_attached` is accepted and echoed in the output, but **CMS is not implemented**: a raw signature is produced regardless. Do not rely on CMS output.

Issuing a certificate from a CSR (`mode=csr`):

```bash
resh cert://./ca.sign mode=csr csr_source=web-req.pem signer_cert=ca.pem signer_key=ca-key.pem cert_output_path=web.pem
```

The CSR signature is verified; the certificate keeps the CSR's subject, SANs, and public key. Validity and extensions can be set with `not_before`, `not_after`, `not_after_offset_days` (default 365), `is_ca`, `path_len`, `key_usage`, `extended_key_usage`, `sans_override`. The output `cert` object reports the real serial number, validity, and fingerprints.

### csr.sign (not reachable from the CLI)

`csr.sign` is a registered verb, but the stage parser never produces it: `cert://<target>.csr.sign` is parsed as the `sign` verb with target `<target>.csr`, which then runs data signing (and typically fails with "For data mode, either data_source or data_bytes_base64 must be specified"). **Use `sign mode=csr`** as shown above. See `resh cert csr.sign --help`.

### renew

```bash
resh cert:///etc/ssl/certs/server.pem.renew format=text
resh cert://./web.pem.renew signer_ca=ca.pem signer_key=ca-key.pem existing_key_path=web-key.pem
```

Options: `renewal_mode=auto|self_signed|explicit_signer`, `signer_ca`, `signer_key`, `key_strategy=reuse|rekey` (default `reuse`), `existing_key_path` (default `<name>-key.pem`), `algorithm`, `new_cert_output_path` (default `<name>-renewed.pem`), `new_key_output_path` (default `<name>-renewed-key.pem` with `rekey`), `not_before=now|carry_over_start|<rfc3339>`, `not_after`, `not_after_offset_days`, `overwrite`, `format`. A CA-signed certificate needs `signer_ca` and `signer_key`. `key_passphrase` is rejected.

---

## 4. Output and Errors

Output is pretty-printed JSON on stdout (or text with `format=text`). See each verb's `--help` for a full example. Abbreviated `info` example:

```json
{
  "encoding": "pem",
  "type": "certificate",
  "objects": [
    {
      "kind": "certificate",
      "subject": { "common_name": "example.com", "raw_dn": "CN=example.com" },
      "validity": {
        "is_currently_valid": true,
        "not_after": "2027-10-16T19:10:00+00:00",
        "not_before": "2026-10-16T19:10:00+00:00"
      },
      "fingerprints": { "sha256": "C2:76:3C:C0:...:6C:B1:F2:3C" }
    }
  ]
}
```

Errors are also JSON on **stdout** (resh additionally prints `Error: <reason>` on stderr), for example:

```json
{
  "error": {
    "code": "cert.invalid_options",
    "details": { "path": "./k3" },
    "message": "RSA key size too small: 1024. Minimum is 2048 bits"
  }
}
```

### Exit codes (verified in the source)

| Verb                 | Exit status on failure                                                       |
| -------------------- | ---------------------------------------------------------------------------- |
| `info`               | 1 invalid options, 2 file cannot be read, 3 encoding detection failed, 4 parse failed |
| `verify`             | 1 invalid options, 2 file cannot be read, 3 encoding detection failed, 4 type detection failed, 5 parse failed, 6 unsupported object type, 7 a verification check failed |
| `generate`, `sign`, `renew` | 1 invalid options or a result with `ok: false`, 2 operation error     |
| `csr.create`, `chain.info` | 1                                                                      |

Success is always 0.

---

## 5. Options That Are Not Supported

* `timeout_ms`: ignored by every cert verb (all work is local).
* `key_passphrase`, `signer_key_passphrase`, `existing_key_passphrase`: rejected (no encrypted keys).
* `new_key_passphrase` (csr.create): accepted but has no effect (see above).
* `signature_format=cms_detached|cms_attached`: accepted but produces a raw signature.
* `key_kdf`, `key_kdf_iterations`: parsed, but only meaningful with `key_passphrase`, which is rejected.
* `trust`, `trust_paths`, `trust_pem` on `chain.info`: no effect on the result.

`overwrite` is parsed strictly: `true/false/1/0/yes/no/on/off`; any other value is an error.

---

## 6. File Safety

* Existing files are not replaced unless `overwrite=true`.
* Private keys are written with the normal file mode and then changed to 0600. There is a short window in which a new key file has the default (umask) permissions, so write keys only into directories other users cannot read. On `csr.create`, a failure to set 0600 is ignored.
* Certificates and CSRs are written with default permissions.

---

## 7. Platform Support

Linux is the only supported and tested platform. macOS and Windows are not supported.

---

## 8. Usage Guidance

* Prefer ECDSA P-256 or Ed25519, or RSA 2048+ (smaller RSA keys are rejected).
* Keep CA private keys in a directory only you can read; keys are never encrypted by this handle.
* Validate certificates with `verify` (not `chain.info`) before deploying them.
* Monitor expiry with `info` (`validity.not_after`, `validity.is_currently_valid`).

Typical CA-signed workflow:

```bash
resh cert://./ca.generate mode=self_signed algorithm=ecdsa is_ca=true subject='{"common_name":"Example CA"}'
resh cert://./web-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=web-key.pem subject='{"common_name":"web.test"}' sans='["DNS:web.test"]'
resh cert://./ca.sign mode=csr csr_source=web-req.pem signer_cert=ca.pem signer_key=ca-key.pem cert_output_path=web.pem
resh cert://./web.pem.verify trust_paths=ca.pem hostname=web.test format=text
```
