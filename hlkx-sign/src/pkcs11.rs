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
// PKCS#11 URI parsing helpers (RFC 7512)
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed view of the fields we care about in a PKCS#11 URI.
///
/// PKCS#11 URIs look like:
/// `pkcs11:token=MyToken;object=MyCert;type=cert;pin-value=1234`
/// Plain labels (e.g. `"MyCert"`) are accepted and treated as `object=` only.
struct Pkcs11Uri<'a> {
    /// `object=` – the `CKA_LABEL` of the object to look up.
    pub object: &'a str,
    /// `token=` – if present, only slots whose token label matches are used.
    pub token: Option<&'a str>,
    /// `pin-value=` – if present, used to authenticate to the token.
    pub pin_value: Option<&'a str>,
}

impl<'a> Pkcs11Uri<'a> {
    /// Parse a PKCS#11 URI string, or treat a plain string as an object label.
    fn parse(id: &'a str) -> Self {
        if let Some(rest) = id.strip_prefix("pkcs11:") {
            let mut object: Option<&str> = None;
            let mut token: Option<&str> = None;
            let mut pin_value: Option<&str> = None;
            for part in rest.split(';') {
                if let Some(v) = part.strip_prefix("object=") {
                    object = Some(v);
                } else if let Some(v) = part.strip_prefix("token=") {
                    token = Some(v);
                } else if let Some(v) = part.strip_prefix("pin-value=") {
                    pin_value = Some(v);
                }
            }
            Pkcs11Uri {
                object: object.unwrap_or(""),
                token,
                pin_value,
            }
        } else {
            // Plain label – no token filter, no embedded PIN.
            Pkcs11Uri {
                object: id,
                token: None,
                pin_value: None,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize a PKCS#11 context from the shared library at `module`.
fn init_pkcs11(module: &str) -> Result<(Pkcs11, Vec<cryptoki::slot::Slot>)> {
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
    Ok((pkcs11, slots))
}

/// Return `true` if the token in `slot` has a label that matches `wanted`.
///
/// The PKCS#11 `CK_TOKEN_INFO.label` field is a fixed-width 32-byte space-padded
/// string. `TokenInfo::label()` trims that padding, so we compare the trimmed value.
fn token_label_matches(pkcs11: &Pkcs11, slot: cryptoki::slot::Slot, wanted: &str) -> bool {
    match pkcs11.get_token_info(slot) {
        Ok(info) => info.label().trim() == wanted.trim(),
        Err(_) => false,
    }
}

/// Optionally log in to a session with the given PIN.
fn maybe_login(session: &cryptoki::session::Session, pin: Option<&str>) -> Result<()> {
    if let Some(p) = pin {
        session
            .login(UserType::User, Some(&AuthPin::new(Box::from(p))))
            .context("PKCS#11 login failed")?;
    }
    Ok(())
}

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
///               If the URI contains a `token=` component only matching tokens are
///               searched.  A `pin-value=` component in the URI is used to log in.
pub fn load_certificate_der(module: &str, cert_id: &str) -> Result<Vec<u8>> {
    let uri = Pkcs11Uri::parse(cert_id);
    let (pkcs11, slots) = init_pkcs11(module)?;

    for slot in slots {
        // Skip this slot if the token label does not match the URI's token= field.
        if let Some(wanted) = uri.token {
            if !token_label_matches(&pkcs11, slot, wanted) {
                continue;
            }
        }

        let session = pkcs11
            .open_ro_session(slot)
            .context("Failed to open PKCS#11 session")?;
        maybe_login(&session, uri.pin_value)?;

        let search = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(uri.object.as_bytes().to_vec()),
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
///                  If the URI contains a `token=` component only matching tokens
///                  are searched.  A `pin-value=` component is used to log in.
/// * `digest_alg` – selects the hash algorithm embedded in the mechanism.
/// * `data`       – the raw bytes to sign (the canonical `<SignedInfo>` XML).
pub fn pkcs11_sign(
    module: &str,
    key_id: &str,
    digest_alg: DigestAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>> {
    let uri = Pkcs11Uri::parse(key_id);
    let mechanism = rsa_pkcs1_mechanism(digest_alg);
    let (pkcs11, slots) = init_pkcs11(module)?;

    for slot in slots {
        // Skip this slot if the token label does not match the URI's token= field.
        if let Some(wanted) = uri.token {
            if !token_label_matches(&pkcs11, slot, wanted) {
                continue;
            }
        }

        // Signing may require a read-write session on some tokens.
        let session = pkcs11
            .open_rw_session(slot)
            .context("Failed to open PKCS#11 session")?;
        maybe_login(&session, uri.pin_value)?;

        let search = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(uri.object.as_bytes().to_vec()),
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::Pkcs11Uri;

    #[test]
    fn parses_full_uri() {
        let uri = Pkcs11Uri::parse(
            "pkcs11:token=MyToken;object=MyCert;type=cert;pin-value=secret",
        );
        assert_eq!(uri.object, "MyCert");
        assert_eq!(uri.token, Some("MyToken"));
        assert_eq!(uri.pin_value, Some("secret"));
    }

    #[test]
    fn parses_uri_without_optional_fields() {
        let uri = Pkcs11Uri::parse("pkcs11:object=SomeCert");
        assert_eq!(uri.object, "SomeCert");
        assert_eq!(uri.token, None);
        assert_eq!(uri.pin_value, None);
    }

    #[test]
    fn parses_plain_label() {
        let uri = Pkcs11Uri::parse("MyLabel");
        assert_eq!(uri.object, "MyLabel");
        assert_eq!(uri.token, None);
        assert_eq!(uri.pin_value, None);
    }

    #[test]
    fn parses_uri_with_token_and_pin_no_object() {
        // Edge case: URI with token= and pin-value= but no object=.
        let uri = Pkcs11Uri::parse("pkcs11:token=Tok;pin-value=1234");
        assert_eq!(uri.object, "");
        assert_eq!(uri.token, Some("Tok"));
        assert_eq!(uri.pin_value, Some("1234"));
    }
}
