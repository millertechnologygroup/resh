# Resource Shell (resh) – Cert Handle Documentation

## 1. Overview

### Definition

Resource Shell (resh) is a resource-oriented command-line environment that models infrastructure operations as URI-style commands. The `cert://` handle inspects and manages X.509 certificates, private keys, and certificate signing requests (CSRs) stored as PEM or DER files.

It uses pure-Rust libraries (x509-parser, rcgen, ring, rustls-webpki, rsa, p256, p384, ed25519-dalek, pkcs8); OpenSSL is not required. All work is on local files: the handle makes no network connections.

### What the handle does

* Inspect certificates, bundles, CSRs, public keys, and private keys, encrypted ones included (`info`).
* Verify a certificate's structure, chain to a trust anchor, validity period, hostname, purpose, and matching private key (`verify`). The chain is validated by rustls-webpki.
* Find the chains of a certificate bundle (`chain.info`).
* Generate private keys, self-signed certificates, CA-signed leaf certificates, and CSRs (`generate`).
* Create a CSR from an existing or new key, with SANs, key usage, and extended key usage (`csr.create`).
* Sign data with a private key, as a raw signature or a CMS (PKCS#7) SignedData, or issue a certificate from a CSR with `mode=csr` (`sign`).
* Issue a replacement for an existing certificate (`renew`).
* Read and write encrypted private keys (PKCS#8 `ENCRYPTED PRIVATE KEY`) with a passphrase.

### What the handle does not do

* **No revocation checking** (CRL/OCSP): `check_revocation=soft` reports `not_checked` and `hard` fails.
* No legacy OpenSSL PEM encryption (`Proc-Type: 4,ENCRYPTED`), no PBES1, no scrypt-encrypted keys: convert them with `openssl pkcs8 -topk8 -v2 aes-256-cbc`.
* No P-521, secp256k1, Ed448, or DSA keys; no RSA keys below 2048 bits.
* No ACME, no automatic renewal, no HSM/PKCS#11.

---

## 2. Command Syntax

```text
resh cert://<file-path>.<verb> [key=value ...]
```

* Absolute path: `cert:///etc/ssl/certs/server.pem.info` (three slashes).
* Relative path: `cert://./server.pem.info`.
* The verb is the text after the last dot; `csr.create` and `chain.info` are recognized as whole verbs (`csr.sign` is not reachable, see below).
* JSON-valued options (`subject`, `output`, ...) must be quoted for the shell: `subject='{"common_name":"example.com"}'`. List options (`sans`, `trust_paths`, `key_usage`, ...) take a JSON array or a comma-separated list.
* Path options accept a plain path, `file://<path>` or `cert://<path>`; key and certificate options also accept `string:<PEM text>`.

Built-in help (authoritative for every option):

```bash
resh cert --help
resh cert generate --help
```

### Strict arguments

Every verb refuses (exit 2, `cert.invalid_argument`, nothing is read or written):

* an unknown argument, with a "did you mean" hint and the list of accepted arguments;
* an invalid value (an unknown choice, a number out of range, a boolean that is not `true|false|1|0|yes|no|on|off`, malformed JSON, an unknown field in a JSON object, a malformed SAN);
* an option of another mode (for example `subject` with `generate mode=key`, `csr_source` with `sign` in data mode, `rsa_bits` with `algorithm=ecdsa`, `existing_key_path` with `key_strategy=generate`);
* `timeout_ms` on `info`, `verify`, `chain.info` and `csr.sign` (they read files of at most 16 MiB and finish at once), and `dry_run` on every verb.

This is a breaking change from v1.0.6-beta, which ignored unknown arguments and read unexpected boolean spellings as `false`.

---

## 3. Verbs

| Verb         | Purpose                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `info`       | Report type, serial, subject, issuer, validity, public key, extensions, fingerprints for each object in a file |
| `verify`     | Check a certificate against a policy; each check is passed, failed, skipped, not_checked, or unsupported |
| `chain.info` | Find the leaf candidates of a bundle and every chain from them to a root |
| `generate`   | Generate a key, self-signed certificate, CA-signed leaf, or CSR           |
| `csr.create` | Create a CSR at the target path                                           |
| `sign`       | Sign data, or with `mode=csr` issue a certificate for a CSR              |
| `csr.sign`   | Registered, but **cannot be reached from the command line** (see below)  |
| `renew`      | Issue a replacement certificate with the same subject, SANs, and extensions |

### info

```bash
resh --json-pretty cert://./server.pem.info
resh cert://./bundle.pem.info fingerprint_algs=sha256,sha512 format=text
```

Options: `format=json|text`, `encoding=auto|pem|der` (default `auto`), `fingerprint_algs=sha1,sha256,sha384,sha512` (default `sha256`), `include_pem`, `include_raw` (base64 DER of each certificate).

* A bundle reports `"type": "certificatechain"` with one object per certificate; a CSR, private key, or public key reports `kind` `csr`, `private_key` or `public_key`. `version` is zero-based (2 means X.509 v3).
* Certificates report the public key algorithm, curve and size, the extensions (key usage, extended key usage, SANs, basic constraints, key identifiers) and `is_ca`.
* A CSR reports `public_key.signature_valid`. A private key reports `algorithm`, `key_format` and `is_encrypted` (an encrypted key is not decrypted; its algorithm is `unknown (encrypted)`).
* Fingerprints are digests of the whole DER certificate (the same as `openssl x509 -fingerprint`). Before this release they were computed over the wrong bytes.
* A file that holds no certificate, CSR or key fails with `cert.parse_failed` (exit 1).

### verify

```bash
resh cert://./web.pem.verify trust_paths=ca.pem hostname=web.test format=text
resh cert:///etc/ssl/certs/server.pem.verify purpose=server_auth
resh cert://./web.pem.verify ca_file=private-ca.pem keypair_target=web-key.pem
```

Options: `hostname=`, `purpose=server_auth|client_auth|code_signing|email_protection|any` (default `any`), `trust=system|mount|inline` (default `system`), `trust_paths=<path>,...`, `ca_file=<pem>`, `trust_pem=<pem>`, `max_chain_depth` (1-20, default 10), `min_rsa_bits` (2048-16384, default 2048), `allow_self_signed`, `allow_expired`, `allow_not_yet_valid`, `check_revocation=none|soft|hard`, `keypair_target=<key-path>`, `disallow_weak_signatures` (default `true`), `include_chain_report` (default `true`), `encoding=auto|pem|der`, `format=json|text`.

Trust anchors:

* `trust=system` (the default) uses the system CA bundle (`SSL_CERT_FILE`, then `/etc/ssl/certs/ca-certificates.crt` and the other usual locations).
* `trust_paths` (files or directories of PEM/DER certificates), `ca_file` (one PEM bundle, convention 9) and `trust_pem` (PEM text; `\n` escapes are accepted) **add** anchors in every trust mode.
* `trust=mount` requires `trust_paths` or `ca_file` and does not load the system bundle; `trust=inline` requires `trust_pem`.
* An unreadable `trust_paths`/`ca_file` or one without certificates fails with `cert.trust_load_failed` (exit 1); a missing system bundle is a warning.

Checks:

| Check        | What is checked |
| ------------ | --------------- |
| `structure`  | X.509 version, matching signature algorithm fields, weak signature algorithm (SHA-1, MD5) when `disallow_weak_signatures=true`, RSA key size against `min_rsa_bits` |
| `chain`      | The first certificate is validated by **rustls-webpki** through the other certificates in the file (intermediates) to a trust anchor: every signature, the validity of every certificate, basic constraints, path length, name constraints. Then the path length against `max_chain_depth` and every RSA key against `min_rsa_bits`. A certificate that is itself an anchor passes. A self-signed certificate that is not an anchor fails with `cert.self_signed_not_allowed` unless `allow_self_signed=true` (its self-signature is still checked). |
| `time`       | The certificate's own validity period; `allow_expired` / `allow_not_yet_valid` accept it, and the chain is then validated at the certificate's expiry (or start). |
| `hostname`   | rustls-webpki's TLS name check against the subjectAltName DNS and IP entries (wildcards in the leftmost label). The common name is not used. |
| `usage`      | The leaf's extended key usage and key usage allow `purpose`, and webpki accepts the extended key usage of every certificate in the chain for it. |
| `keypair`    | The private key in `keypair_target` belongs to the certificate (encrypted keys cannot be checked here). |
| `revocation` | Not implemented: `none` skips, `soft` reports `not_checked`, `hard` reports `unsupported` and fails. |

* Supported in chains: RSA 2048-8192 bits (PKCS#1 v1.5 SHA-256/384/512, PSS), ECDSA P-256/P-384, Ed25519. Other algorithms report `cert.unsupported_signature_algorithm` (status `unsupported`). `disallow_weak_signatures=false` only stops the structure check from failing on SHA-1: a SHA-1 chain is never accepted.
* webpki does not accept a CA certificate as the end-entity: verifying a CA certificate that is not itself an anchor fails with `cert.ca_used_as_end_entity`.
* A private key file is checked for structure only (the other checks are skipped). A CSR or public key fails with `cert.unsupported_type`.
* If any check fails, the full report is printed with `"ok": false` and an `error` object (`cert.verification_failed`), and the command exits 1.

Check codes (`checks.<name>.error_code`): `cert.unsupported_version`, `cert.signature_algorithm_mismatch`, `cert.weak_signature`, `cert.weak_key`, `cert.trust_load_failed`, `cert.self_signed_not_allowed`, `cert.bad_signature`, `cert.issuer_not_found`, `cert.issuer_not_ca`, `cert.ca_used_as_end_entity`, `cert.path_len_exceeded`, `cert.name_constraint_violation`, `cert.chain_expired`, `cert.chain_not_yet_valid`, `cert.chain_too_long`, `cert.chain_invalid`, `cert.unsupported_signature_algorithm`, `cert.expired`, `cert.not_yet_valid`, `cert.hostname_mismatch`, `cert.invalid_hostname`, `cert.eku_mismatch`, `cert.key_usage_mismatch`, `cert.eku_parse_failed`, `cert.key_usage_parse_failed`, `cert.keypair_load_failed`, `cert.keypair_mismatch`, `cert.key_parse_failed`, `cert.revocation_not_implemented`.

### chain.info

```bash
resh cert://./bundle.pem.chain.info trust_paths=ca.pem format=text
resh --json-pretty cert://./fullchain.pem.chain.info trust=system
```

Options: `trust=none|system|mount|inline|system+mount|system+inline|mount+inline` (default `none`), `trust_paths`, `ca_file`, `trust_pem` (anchors, as for `verify`: they are added in every mode; `mount` requires `trust_paths` or `ca_file`, `inline` requires `trust_pem`, `system` adds the system bundle), `max_depth` (1-50, default 10), `max_paths` (1-20, default 5), `include_raw_subjects`, `include_raw_issuers` (add `raw_dn` to subject/issuer names), `include_cert_refs` (default `true`: `cert_ref` is `cert://<path>#<index>` for bundle certificates, `null` for anchors), `encoding`, `format`.

* Leaf candidates are the bundle certificates that issue no other certificate in the bundle.
* From each leaf every path is followed through the bundle and the anchors, linking a certificate to an issuer whose subject matches its issuer name **and** whose key verifies its signature, up to `max_depth` certificates.
* `trust_status` of a chain: `trusted` (ends at an anchor and rustls-webpki validates the path), `invalid` (ends at an anchor but webpki rejects it; `reason` says why, for example an expired intermediate), `untrusted_root` (ends at a self-signed certificate that is not an anchor), `self_signed_untrusted` (a single self-signed certificate that is not an anchor), `incomplete` (an issuer is missing, or `max_depth` was reached; see `gaps`).
* The best `max_paths` chains are shown (trusted first); a warning says how many were found.
* Each hop reports its role (`leaf`, `intermediate`, `root`), source (`target_bundle`, `system`, `mount`, `inline`), whether it is a trust anchor, subject, issuer, CA flag and path length, key identifiers, public key (algorithm, RSA bits, curve), validity and SHA-256 fingerprint.
* chain.info describes; it exits 0 whatever the trust status. Use `verify` to enforce a policy.

Before this release chain.info did not link certificates to their issuers and always reported chains of length 1.

### generate

```bash
resh --json-pretty cert://./server.generate mode=key algorithm=ecdsa
resh cert://./ca.generate mode=self_signed algorithm=ecdsa is_ca=true subject='{"common_name":"Example CA"}' key_passphrase='ca secret'
resh cert://./web.generate mode=leaf_cert signer_ca=ca.pem signer_key=ca-key.pem signer_key_passphrase='ca secret' subject='{"common_name":"web.test"}' sans='["DNS:web.test"]'
```

Files are written beside the target path: `<target>-key.pem` (key), `<target>.pem` (certificate), `<target>.csr` (CSR, `mode=csr`), also when the encoding is DER.

| Option                  | Values / default                                                        |
| ----------------------- | ----------------------------------------------------------------------- |
| `mode`                  | `key` (default), `self_signed`, `csr`, `leaf_cert`                       |
| `algorithm`             | `rsa` (default), `ecdsa`, `ed25519`                                      |
| `rsa_bits`              | `2048` (default), `3072`, `4096`; only with `algorithm=rsa`             |
| `ecdsa_curve`           | `P-256` (default), `P-384`; only with `algorithm=ecdsa`. P-521 and secp256k1 are refused (exit 2) |
| `subject`               | JSON object; `common_name` (required for every mode except `key`), `organization`, `organizational_unit`, `country` (two letters), `state_or_province`, `locality` (a string, or an array of one string) |
| `sans`                  | `DNS:`, `IP:`, `EMAIL:`, `URI:` entries                                  |
| `is_ca`, `path_len`     | CA flag (a CA gets key usage keyCertSign, cRLSign, digitalSignature) and path length constraint (`path_len` needs `is_ca=true`); certificate modes only |
| `not_before`, `not_after`, `not_after_offset_days` | validity: `not_before=now|<rfc3339>`; `not_after=<rfc3339>` or `not_after_offset_days` (1-36500, default 365), not both; certificate modes only |
| `signer_ca`, `signer_key`, `signer_key_passphrase` | required for (and only with) `mode=leaf_cert`         |
| `key_format`            | `pkcs8` (default), `pkcs1` (RSA only), `sec1` (ECDSA only, with the named curve) |
| `key_encoding`, `cert_encoding`, `csr_encoding` | `pem` (default), `der`                       |
| `key_passphrase`        | encrypts the key as PKCS#8 `ENCRYPTED PRIVATE KEY` (PBKDF2-HMAC-SHA256, AES-256-CBC, random salt and IV); needs `key_format=pkcs8` |
| `key_kdf`               | `pbkdf2` (default); `argon2id` is refused (PKCS#8 has no standard argon2 scheme). Only with `key_passphrase` |
| `key_kdf_iterations`    | PBKDF2 iterations, 10000-10000000, default 100000. Only with `key_passphrase` |
| `output`                | JSON object: `write_key`, `write_cert`, `write_csr` (default `true`), `return_key`, `return_csr` (default `false`), `return_cert` (default `true`); the cert fields only in certificate modes, the CSR fields only with `mode=csr` |
| `overwrite`             | default `false`: if any output file exists, nothing is written and the command fails with `cert.target_exists` |
| `timeout_ms`            | default 300000 (key generation can be slow); at the deadline nothing is written (exit 124, `cert.timeout`) |

* The key file is mode 0600 from the moment it exists. Passphrases never appear in the output.
* `mode=csr` writes `<target>.csr` by default (`output.write_csr=false` to skip it).

### csr.create

```bash
resh cert://./web-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=web-key.pem subject='{"common_name":"web.test"}' sans='["DNS:web.test"]' key_usage=digitalSignature extended_key_usage=serverAuth
resh cert://./web-req.pem.csr.create existing_key_path=web-key.pem subject='{"common_name":"web.test"}'
```

The CSR is written to the target path exactly (here `./web-req.pem`).

* `subject` (required, with `common_name`), `sans`, `key_usage` (`digitalSignature`, `contentCommitment`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`), `extended_key_usage` (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`): the key usage (critical) and extended key usage are requested in the CSR's extension request. Before this release `key_usage` made csr.create fail.
* `key_strategy=reuse` (default) needs `existing_key_path`; `existing_key_passphrase` decrypts an encrypted key. The algorithm is read from the key; `algorithm=` is only checked against it (a mismatch fails with `cert.keypair_mismatch`).
* `key_strategy=generate` needs `new_key_output_path` (mode 0600, different from the CSR path) and takes `algorithm`, `rsa_bits`, `ecdsa_curve`, `key_format`, `key_encoding`, `new_key_passphrase` (encrypted PKCS#8, as `key_passphrase` on generate), `key_kdf`, `key_kdf_iterations`, `include_new_key_pem`. Before this release `new_key_passphrase` had no effect and `key_format=pkcs1|sec1` wrote a mislabelled key.
* `csr_encoding=pem|der`, `include_csr_pem` (returns the CSR, PEM or base64 DER), `overwrite` (covers both the CSR and the new key), `format`, `timeout_ms` (default 300000).

### sign

Data signing:

```bash
resh --json-pretty cert://./ca.sign signer_key=ca-key.pem data_source=app.tar signature_output_path=app.tar.sig
```

The target (`./ca`) is only a label in the output. Options: `signer_key` (required), `signer_key_passphrase`, `data_source=<path>` or `data_bytes_base64=` (exactly one), `signature_algorithm`, `signature_format=raw|cms_detached|cms_attached` (default `raw`), `signer_cert` (required for CMS, refused for `raw`), `signature_encoding=base64|pem|der` (default `base64`), `signature_output_path`, `include_signature_bytes=true`, `overwrite` (only with `signature_output_path`), `timeout_ms` (default 300000; it bounds reading and signing the data). Without `signature_output_path` or `include_signature_bytes=true` the signature is computed but not kept, and a warning says so. `bytes_base64` in the output is the base64 of the raw signature or of the DER CMS structure, whatever `signature_encoding` is.

`signature_algorithm` defaults to the key's natural algorithm (`rsa_pss_sha256` for RSA; `rsa_pss_sha384`, `rsa_pkcs1_sha256` and `rsa_pkcs1_sha384` are also available for RSA keys; `ecdsa_sha256` for P-256, `ecdsa_sha384` for P-384, `ed25519`). An explicit value is honoured exactly or refused: `ecdsa_sha512` with a P-384 key signs a SHA-512 digest (truncated to 384 bits, as ECDSA specifies), and a key/algorithm pair resh does not implement, such as P-256 with `ecdsa_sha384`, fails with `cert.sign_failed` without writing a signature.

Raw signatures (`signature_format=raw`) are the bare signature bytes: PKCS#1 v1.5 or PSS (salt length equal to the digest length) for RSA, a DER `ECDSA-Sig-Value` for ECDSA, and 64 bytes for Ed25519. With `signature_encoding=pem` the label is `SIGNATURE`.

CMS signatures:

```bash
resh cert://./signer.sign signer_key=signer-key.pem signer_cert=signer.pem data_source=app.tar signature_format=cms_detached signature_encoding=der signature_output_path=app.tar.p7s
openssl cms -verify -binary -inform DER -in app.tar.p7s -content app.tar -CAfile signer.pem -purpose any
```

`signature_format=cms_detached` and `cms_attached` produce a CMS `SignedData` (RFC 5652) in a DER `ContentInfo`, then apply `signature_encoding` (PEM label `CMS`). `cms_detached` leaves the data out; `cms_attached` carries it as the encapsulated content. There is one signer, identified by the issuer and serial number of `signer_cert`, with the signed attributes content-type (`id-data`), message-digest and signing-time (the local clock), and `signer_cert` is included in `certificates`. The digest algorithm follows `signature_algorithm`; Ed25519 uses SHA-512 for the message digest (RFC 8419).

* CMS needs `signer_cert`, the certificate (PEM or DER; the first certificate of a PEM bundle is used) whose public key is that of `signer_key`. Without it the request is refused with `cert.invalid_argument` (exit 2). A `signer_cert` that cannot be read or parsed fails with `cert.signer_load_failed`, and one for a different key with `cert.keypair_mismatch` (exit 1); nothing is written.
* The certificate is not validated (expiry, key usage, chain): verifiers do that.

Issuing a certificate from a CSR (`mode=csr`):

```bash
resh cert://./ca.sign mode=csr csr_source=web-req.pem signer_cert=ca.pem signer_key=ca-key.pem cert_output_path=web.pem
```

The CSR signature is verified (`cert.csr_invalid` if it does not verify); the certificate keeps the CSR's subject, SANs, and public key. Options: `csr_source`, `signer_cert` (the CA certificate), `signer_key`, `cert_output_path` (all required), `csr_encoding=auto|pem|der`, `cert_encoding`, `not_before`, `not_after`, `not_after_offset_days` (default 365), `is_ca`, `path_len`, `key_usage` (default `digitalSignature`), `extended_key_usage` (default `serverAuth`), `sans_override`, `include_cert_pem`, `overwrite`, `timeout_ms`. The key usage and extended key usage requested in the CSR are replaced by these (a warning names what was replaced); other requested extensions are not copied (a warning names them). The signer must be a CA certificate whose key is `signer_key`.

### csr.sign (not reachable from the CLI)

`csr.sign` is a registered verb, but the stage parser never produces it: `cert://<target>.csr.sign` is parsed as the `sign` verb with target `<target>.csr`. **Use `sign mode=csr`.** Programmatic callers (`Handle::call("csr.sign", ...)`) issue a certificate for the CSR at the target path with: `signer_ca`, `signer_key`, `cert_output_path` (required), `signer_key_passphrase`, `csr_encoding`, `cert_encoding`, `copy_subject` (default `true`) with `subject_common_name`, `subject_organization`, `subject_country` (override fields; `copy_subject=false` needs one), `copy_sans` / `sans_override`, `copy_key_usage` / `key_usage_override`, `copy_extended_key_usage` / `extended_key_usage_override` (copy takes what the CSR requests), `is_ca`, `path_len`, validity options, `serial_strategy=random|uuid` (`increment` is refused: there is no serial store) or `serial_override=<hex>` (1-20 bytes, not both), `include_cert_pem`, `overwrite`, `format`. It does not take `timeout_ms`.

### renew

```bash
resh cert:///etc/ssl/certs/server.pem.renew format=text
resh cert://./web.pem.renew signer_ca=ca.pem signer_key=ca-key.pem existing_key_path=web-key.pem
resh cert://./web.pem.renew key_strategy=rekey algorithm=ecdsa key_passphrase='new secret' signer_ca=ca.pem signer_key=ca-key.pem
```

* `renewal_mode=auto` (default: self-signed certificates are self-signed again, CA-signed ones need `signer_ca` and `signer_key` together, else `cert.signer_required`, exit 2), `self_signed` (refuses signer options), `explicit_signer` (requires both). `signer_key_passphrase` decrypts an encrypted CA key.
* `key_strategy=reuse` (default): the key in `existing_key_path` (default `<name>-key.pem`) signs a self-signed renewal and must match the certificate (`cert.keypair_mismatch`); `key_passphrase` is its passphrase. For a CA-signed renewal without the key file, the old public key is reused (a warning says so). The rekey options are refused.
* `key_strategy=rekey`: a new key (`algorithm`, default the old key's algorithm; `rsa_bits`, `ecdsa_curve`, `key_format`, `key_encoding`, `key_passphrase` to encrypt it, `key_kdf`, `key_kdf_iterations`) is written to `new_key_output_path` (default `<name>-renewed-key.pem`, mode 0600). `existing_key_path` is refused.
* `new_cert_output_path` (default `<name>-renewed.pem`; the old certificate itself only with `overwrite=true`), `cert_encoding`, `copy_subject`/`subject_override`, `copy_sans`/`sans_override`, `copy_key_usage`/`key_usage_override`, `copy_extended_key_usage`/`extended_key_usage_override`, `is_ca`, `path_len`, `not_before=now|carry_over_start|<rfc3339>`, `not_after`, `not_after_offset_days`, `include_cert_pem` and `include_new_key_pem` (returned under `returned`), `overwrite`, `format`, `timeout_ms` (default 300000).

---

## 4. Output and Errors

Output is pretty-printed JSON on stdout (or text with `format=text`). See each verb's `--help` for an example.

Every failure prints `Error: [cert.<code>] <message>` on stderr. With `format=json` stdout also carries the failure:

```json
{
  "error": {
    "code": "cert.invalid_argument",
    "message": "invalid value for rsa_bits: \"1024\" (accepted: 2048, 3072, 4096)"
  },
  "ok": false,
  "target": "./k3"
}
```

With `format=text` nothing is printed on stdout for a failure. A failed `verify` prints its full report and an `error` object.

### Exit codes

0 success; 1 the operation failed; 2 invalid usage (nothing was read or written); 124 `timeout_ms` reached (nothing was written).

### Error codes

| Code                        | Exit | Meaning |
| --------------------------- | ---- | ------- |
| `cert.invalid_argument`     | 2    | Unknown argument, invalid value, missing, conflicting, or other-mode option |
| `cert.passphrase_required`  | 2    | A key is encrypted and its passphrase option was not given |
| `cert.signer_required`      | 2    | renew: the certificate is CA-signed and no signer was given |
| `cert.not_found`            | 1    | The target or an input file does not exist |
| `cert.read_failed`          | 1    | An input file cannot be read (permission, directory, larger than 16 MiB) |
| `cert.parse_failed`         | 1    | The file holds no certificate, CSR, or key that can be parsed |
| `cert.unsupported_type`     | 1    | verify: the file is a CSR or public key |
| `cert.verification_failed`  | 1    | verify: at least one check failed |
| `cert.target_exists`        | 1    | An output exists and `overwrite` is not `true` |
| `cert.symlink_refused`      | 1    | An output path is a symbolic link (never written through) |
| `cert.write_failed`         | 1    | An output cannot be written |
| `cert.key_load_failed`      | 1    | A private key cannot be parsed or is not supported |
| `cert.key_decrypt_failed`   | 1    | An encrypted key cannot be decrypted (wrong passphrase) |
| `cert.key_unsupported`      | 1    | Legacy PEM encryption, PBES1, scrypt, or another unsupported key encryption |
| `cert.signer_load_failed`   | 1    | The signer key or CA certificate cannot be read, or the certificate is not a CA |
| `cert.keypair_mismatch`     | 1    | A key does not belong to the certificate it is used with |
| `cert.csr_invalid`          | 1    | A CSR cannot be parsed or its signature does not verify |
| `cert.sign_failed`          | 1    | Signing or issuing failed (for example an unsupported key/algorithm pair) |
| `cert.generation_failed`    | 1    | Key, certificate, or CSR generation failed |
| `cert.trust_load_failed`    | 1    | `trust_paths` or `ca_file` cannot be read or has no certificates |
| `cert.timeout`              | 124  | `timeout_ms` reached; nothing was written |

The per-check codes of `verify` and `chain.info` are listed under verify.

---

## 5. File Safety

* Existing files are not replaced unless `overwrite=true`; all outputs of a command are checked before anything is generated, so a refusal writes nothing.
* No output is ever written through a symbolic link: a symlink at an output path is refused (`cert.symlink_refused`), with or without `overwrite`. Every file is written to a new temporary file in the same directory and then linked or renamed into place.
* Private keys are mode 0600 from the moment they exist; certificates, CSRs, and signatures are mode 0644.
* If a later file of a set cannot be written, the files this command created are removed again.
* Passphrases are never printed or written anywhere except as the key encryption.

---

## 6. Platform Support

Linux is the only supported and tested platform. macOS and Windows are not supported.

---

## 7. Usage Guidance

* Prefer ECDSA P-256 or Ed25519, or RSA 2048+.
* Protect CA keys with `key_passphrase` and keep them in a directory only you can read. Passphrases on the command line are visible in the process list and shell history.
* Validate certificates with `verify` before deploying them; use `chain.info` to see why a chain does not validate.
* Monitor expiry with `info` (`validity.not_after`, `validity.is_currently_valid`).

Typical CA-signed workflow:

```bash
resh cert://./ca.generate mode=self_signed algorithm=ecdsa is_ca=true subject='{"common_name":"Example CA"}' key_passphrase='ca secret'
resh cert://./web-req.pem.csr.create key_strategy=generate algorithm=ecdsa new_key_output_path=web-key.pem subject='{"common_name":"web.test"}' sans='["DNS:web.test"]'
resh cert://./ca.sign mode=csr csr_source=web-req.pem signer_cert=ca.pem signer_key=ca-key.pem signer_key_passphrase='ca secret' cert_output_path=web.pem
resh cert://./web.pem.verify ca_file=ca.pem hostname=web.test purpose=server_auth format=text
```
