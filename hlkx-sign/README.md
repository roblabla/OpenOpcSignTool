# hlkx-sign

A Rust tool to sign HLKX (and VSIX) OPC packages using a PKCS#11 module.

It uses the [`cryptoki`](https://crates.io/crates/cryptoki) crate to talk
directly to the PKCS#11 library — **no OpenSSL dependency**.

## Requirements

* A PKCS#11 shared library for your hardware token or software HSM, e.g.:
  * OpenSC: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`
  * SoftHSM2: `/usr/lib/softhsm/libsofthsm2.so`

## Building

```
cargo build --release
```

The resulting binary is at `target/release/hlkx-sign`.

## Usage

```
hlkx-sign sign \
  --pkcs11-module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --pkcs11-cert  "pkcs11:token=MyToken;type=cert;object=MyCert" \
  --pkcs11-key   "pkcs11:token=MyToken;type=private;object=MyCert;pin-value=1234" \
  [--file-digest sha256] \
  [--timestamp http://timestamp.example.com/] \
  [--timestamp-algorithm sha256] \
  [--force] \
  path/to/package.hlkx
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--pkcs11-module` | Path to the PKCS#11 shared library | *(required)* |
| `--pkcs11-cert` | PKCS#11 URI (`pkcs11:…;object=Label`) or plain CKA_LABEL | *(required)* |
| `--pkcs11-key` | PKCS#11 URI (`pkcs11:…;object=Label;pin-value=PIN`) or plain CKA_LABEL | *(required)* |
| `--file-digest` | Hash algorithm: `sha1`, `sha256`, `sha384`, `sha512` | `sha256` |
| `--timestamp` | URL of a RFC 3161 Time Stamping Authority | none |
| `--timestamp-algorithm` | Hash algorithm for the timestamp request | `sha256` |
| `--force` / `-f` | Overwrite an existing signature | off |

### Object identification

`--pkcs11-cert` and `--pkcs11-key` accept either a PKCS#11 URI (RFC 7512)
with an `object=` component, or a plain object label (`CKA_LABEL`).

When a `token=` component is present in the URI, only slots whose token
label matches are searched — preventing accidental login to the wrong token.

The PIN is supplied via the `pin-value=` field of the `--pkcs11-key` URI
(same convention as OpenSSL's `engine_pkcs11`).  If omitted, no login is
attempted.

Examples:
```
--pkcs11-cert "pkcs11:token=MyHSM;type=cert;object=CodeSigningCert"
--pkcs11-key  "pkcs11:token=MyHSM;type=private;object=CodeSigningCert;pin-value=1234"
--pkcs11-key  CodeSigningCert          # plain label, no PIN
```

## How it works

1. The package (ZIP file) is read into memory.
2. A `package/services/digital-signature/origin.psdsor` origin part is added,
   linked from the package root `_rels/.rels`.
3. All non-signature parts are digested with the chosen hash algorithm.
   The `_rels/.rels` file produces **two** manifest entries:
   * a C14N (Canonical XML 1.0) transform of the raw relationship document;
   * a RelationshipTransform + C14N transform of the filtered relationships.
4. An XML digital signature is built following ECMA-376 Part 2 §13:
   * `<Object>` containing the manifest and a `<SignatureTime>` property is
     C14N-hashed and referenced from `<SignedInfo>`.
   * The canonical `<SignedInfo>` bytes are sent to the PKCS#11 token which
     computes the hash and produces an RSA PKCS#1 v1.5 signature in one
     operation (`CKM_SHA256_RSA_PKCS` etc.).
5. The signature XML is written to
   `package/services/digital-signature/xml-signature/<uuid>.psdsxs`.
6. The DER-encoded certificate is written to
   `package/services/digital-signature/certificate/<serial>.cer`.
7. The updated package is written back to disk atomically.
