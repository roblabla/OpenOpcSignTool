//! Load a certificate and sign data using a PKCS#11 token via the `cryptoki` crate.
//!
//! This replaces the previous OpenSSL ENGINE-based implementation with a pure
//! Rust, safe API that talks directly to the PKCS#11 library.

use crate::xml_sig::DigestAlgorithm;
use anyhow::{bail, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass},
    session::UserType,
    types::AuthPin,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the `object=` component from a PKCS#11 URI, or return `id` as-is.
///
/// PKCS#11 URIs (RFC 7512) look like:
/// `pkcs11:token=MyToken;object=MyCert;type=cert`
/// Plain labels (e.g. `"MyCert"`) are accepted unchanged.
fn extract_label(id: &str) -> &str {
    if let Some(rest) = id.strip_prefix("pkcs11:") {
        for part in rest.split(';') {
            if let Some(val) = part.strip_prefix("object=") {
                return val;
            }
        }
        // URI present but no object= component – fall through to return full id.
    }
    id
}

/// Map a `DigestAlgorithm` to the combined RSA PKCS#1 v1.5 + hash PKCS#11 mechanism.
fn rsa_pkcs1_mechanism(digest_alg: DigestAlgorithm) -> Mechanism<'static> {
    match digest_alg {
        DigestAlgorithm::Sha1 => Mechanism::Sha1RsaPkcs,
        DigestAlgorithm::Sha256 => Mechanism::Sha256RsaPkcs,
        DigestAlgorithm::Sha384 => Mechanism::Sha384RsaPkcs,
        DigestAlgorithm::Sha512 => Mechanism::Sha512RsaPkcs,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Load the DER-encoded bytes of a certificate from the PKCS#11 token.
///
/// * `module`  – path to the PKCS#11 shared library.
/// * `cert_id` – PKCS#11 URI (RFC 7512) or plain label of the certificate object.
/// * `pin`     – optional user PIN for logging in; pass `None` if the token
///               does not require authentication.
pub fn load_certificate_der(module: &str, cert_id: &str, pin: Option<&str>) -> Result<Vec<u8>> {
    let label = extract_label(cert_id);

    let pkcs11 = Pkcs11::new(module).context("Failed to load PKCS#11 module")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("Failed to initialize PKCS#11")?;

    let slots = pkcs11
        .get_slots_with_initialized_token()
        .context("Failed to get PKCS#11 slots")?;

    if slots.is_empty() {
        bail!("No initialized PKCS#11 token found");
    }

    for slot in slots {
        let session = pkcs11
            .open_ro_session(slot)
            .context("Failed to open PKCS#11 session")?;

        if let Some(p) = pin {
            session
                .login(UserType::User, Some(&AuthPin::new(Box::from(p))))
                .context("PKCS#11 login failed")?;
        }

        let search = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&search)
            .context("PKCS#11 find_objects failed")?;

        for handle in handles {
            let attrs = session
                .get_attributes(handle, &[AttributeType::Value])
                .context("PKCS#11 get_attributes failed")?;
            for attr in attrs {
                if let Attribute::Value(der) = attr {
                    if !der.is_empty() {
                        return Ok(der);
                    }
                }
            }
        }
    }

    bail!("Certificate '{}' not found on any PKCS#11 slot", cert_id)
}

/// Sign `data` with the private key identified by `key_id` on the PKCS#11 token.
///
/// Uses the combined hash-and-sign RSA PKCS#1 v1.5 mechanism (e.g.
/// `CKM_SHA256_RSA_PKCS`) so the hash is computed on the token.
///
/// * `module`     – path to the PKCS#11 shared library.
/// * `key_id`     – PKCS#11 URI (RFC 7512) or plain label of the private key.
/// * `digest_alg` – selects the hash algorithm embedded in the mechanism.
/// * `pin`        – optional user PIN; pass `None` if the token does not require it.
/// * `data`       – the raw bytes to sign (the canonical `<SignedInfo>` XML).
pub fn pkcs11_sign(
    module: &str,
    key_id: &str,
    digest_alg: DigestAlgorithm,
    pin: Option<&str>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let label = extract_label(key_id);
    let mechanism = rsa_pkcs1_mechanism(digest_alg);

    let pkcs11 = Pkcs11::new(module).context("Failed to load PKCS#11 module")?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .context("Failed to initialize PKCS#11")?;

    let slots = pkcs11
        .get_slots_with_initialized_token()
        .context("Failed to get PKCS#11 slots")?;

    if slots.is_empty() {
        bail!("No initialized PKCS#11 token found");
    }

    for slot in slots {
        // Signing may require a read-write session on some tokens.
        let session = pkcs11
            .open_rw_session(slot)
            .context("Failed to open PKCS#11 session")?;

        if let Some(p) = pin {
            session
                .login(UserType::User, Some(&AuthPin::new(Box::from(p))))
                .context("PKCS#11 login failed")?;
        }

        let search = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&search)
            .context("PKCS#11 find_objects failed")?;

        if let Some(&key_handle) = handles.first() {
            let sig = session
                .sign(&mechanism, key_handle, data)
                .context("PKCS#11 sign failed")?;
            return Ok(sig);
        }
    }

    bail!("Private key '{}' not found on any PKCS#11 slot", key_id)
}
