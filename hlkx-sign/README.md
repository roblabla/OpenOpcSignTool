# hlkx-sign

A Rust tool to sign HLKX (and VSIX) packages using a PKCS#11 module and
OpenSSL.  It produces an OPC digital signature that is compatible with the
signatures created by the C# `OpenVsixSignTool`.

## Requirements

* **OpenSSL 3.x** with the PKCS#11 engine support.  On Debian/Ubuntu:
  ```
  apt install libssl-dev libengine-pkcs11-openssl
  ```
* A PKCS#11 module (`.so`) for your hardware token or software HSM (e.g.
  OpenSC: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`).

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
  --pkcs11-key   "pkcs11:token=MyToken;type=private;object=MyCert" \
  [--file-digest sha256] \
  [--force] \
  path/to/package.hlkx
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--pkcs11-module` | Path to the PKCS#11 shared library | *(required)* |
| `--pkcs11-cert` | PKCS#11 URI or key ID for the certificate | *(required)* |
| `--pkcs11-key` | PKCS#11 URI or key ID for the private key | *(required)* |
| `--file-digest` | Hash algorithm (`sha1`, `sha256`, `sha384`, `sha512`) | `sha256` |
| `--force` / `-f` | Overwrite an existing signature | off |

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
   * The canonical `<SignedInfo>` bytes are signed with RSA PKCS#1 v1.5 via the
     PKCS#11 key.
5. The signature XML is written to
   `package/services/digital-signature/xml-signature/<uuid>.psdsxs`.
6. The DER-encoded certificate is written to
   `package/services/digital-signature/certificate/<serial>.cer`.
7. The updated package is written back to disk atomically.
