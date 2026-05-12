//! RFC 3161 timestamp request/response handling.
//!
//! Builds a minimal `TimeStampReq`, POSTs it to a Time Stamping Authority (TSA),
//! and returns the raw DER bytes of the `TimeStampToken` (a CMS ContentInfo) that
//! can be base64-encoded and embedded into the XML signature.
//!
//! Reference: RFC 3161 §2.4

use crate::xml_sig::DigestAlgorithm;
use anyhow::{bail, Context, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Minimal DER encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a DER TLV (Tag, Length, Value) triplet.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = Vec::with_capacity(3 + len);
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        // Values > 64 KiB are not expected in a timestamp request/response.
        panic!("DER value too long: {} bytes (maximum 65535)", len);
    }
    out.extend_from_slice(value);
    out
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x30, contents)
}

/// Encode a positive integer, adding a leading zero byte when the high bit is set.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.first().copied().unwrap_or(0) >= 0x80 {
        let mut padded = vec![0x00];
        padded.extend_from_slice(bytes);
        der_tlv(0x02, &padded)
    } else {
        der_tlv(0x02, bytes)
    }
}

fn der_octet_string(value: &[u8]) -> Vec<u8> {
    der_tlv(0x04, value)
}

fn der_oid(encoded_oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, encoded_oid)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_bool_true() -> Vec<u8> {
    // DER requires 0xFF for TRUE.
    vec![0x01, 0x01, 0xFF]
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash OID encoding (pre-computed per-algorithm)
// ─────────────────────────────────────────────────────────────────────────────

/// Return the pre-encoded OID bytes (the content of a DER OID TLV, without tag/len).
fn hash_oid_bytes(digest_alg: DigestAlgorithm) -> &'static [u8] {
    match digest_alg {
        // id-sha1  1.3.14.3.2.26
        DigestAlgorithm::Sha1 => &[0x2B, 0x0E, 0x03, 0x02, 0x1A],
        // id-sha256  2.16.840.1.101.3.4.2.1
        DigestAlgorithm::Sha256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        // id-sha384  2.16.840.1.101.3.4.2.2
        DigestAlgorithm::Sha384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        // id-sha512  2.16.840.1.101.3.4.2.3
        DigestAlgorithm::Sha512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimeStampReq encoder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the DER-encoded `TimeStampReq` for the given `digest` of `content`.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///    version         INTEGER { v1(1) },
///    messageImprint  MessageImprint,
///    nonce           INTEGER OPTIONAL,
///    certReq         BOOLEAN DEFAULT FALSE,
/// }
/// MessageImprint ::= SEQUENCE {
///    hashAlgorithm   AlgorithmIdentifier,
///    hashedMessage   OCTET STRING
/// }
/// ```
fn encode_timestamp_req(digest: &[u8], digest_alg: DigestAlgorithm, nonce: u64) -> Vec<u8> {
    // AlgorithmIdentifier { algorithm OID, parameters NULL }
    let alg_oid = der_oid(hash_oid_bytes(digest_alg));
    let alg_id = der_sequence(&[alg_oid, der_null()].concat());

    // MessageImprint { AlgorithmIdentifier, OCTET STRING(digest) }
    let msg_imprint = der_sequence(&[alg_id, der_octet_string(digest)].concat());

    // version INTEGER 1
    let version = der_integer(&[0x01]);

    // nonce INTEGER (8 random bytes, big-endian)
    let nonce_bytes = nonce.to_be_bytes();
    let nonce_der = der_integer(&nonce_bytes);

    // certReq BOOLEAN TRUE
    let cert_req = der_bool_true();

    // TimeStampReq SEQUENCE
    der_sequence(
        &[version, msg_imprint, nonce_der, cert_req].concat(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// TimeStampResp decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Skip one complete DER TLV in `bytes` and return the remainder.
fn der_skip(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.is_empty() {
        bail!("unexpected end of DER data");
    }
    // tag (we skip it)
    let (_, rest) = bytes.split_at(1);
    // length
    let (len, rest) = der_decode_length(rest)?;
    if rest.len() < len {
        bail!("DER TLV truncated: need {} bytes, have {}", len, rest.len());
    }
    Ok(&rest[len..])
}

/// Decode a DER length field and return `(length, remaining_bytes)`.
fn der_decode_length(bytes: &[u8]) -> Result<(usize, &[u8])> {
    if bytes.is_empty() {
        bail!("unexpected end of DER length field");
    }
    let first = bytes[0];
    if first < 0x80 {
        return Ok((first as usize, &bytes[1..]));
    }
    let n_bytes = (first & 0x7F) as usize;
    if n_bytes == 0 {
        bail!("DER indefinite length encoding is not supported");
    }
    if bytes.len() < 1 + n_bytes {
        bail!("DER length encoding truncated");
    }
    let mut len: usize = 0;
    for &b in &bytes[1..1 + n_bytes] {
        len = (len << 8) | b as usize;
    }
    Ok((len, &bytes[1 + n_bytes..]))
}

/// Unwrap the content of a SEQUENCE (the bytes inside the outer SEQUENCE TLV).
fn der_unwrap_sequence(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.is_empty() || bytes[0] != 0x30 {
        bail!("expected DER SEQUENCE (0x30), got {:02X}", bytes.first().copied().unwrap_or(0));
    }
    let (len, rest) = der_decode_length(&bytes[1..])?;
    if rest.len() < len {
        bail!("DER SEQUENCE truncated");
    }
    Ok(&rest[..len])
}

/// Decode a DER INTEGER into a small value (for PKI status check).
fn der_read_integer(bytes: &[u8]) -> Result<(i64, &[u8])> {
    if bytes.is_empty() || bytes[0] != 0x02 {
        bail!("expected DER INTEGER (0x02), got {:02X}", bytes.first().copied().unwrap_or(0));
    }
    let (len, rest) = der_decode_length(&bytes[1..])?;
    if rest.len() < len {
        bail!("DER INTEGER truncated");
    }
    let int_bytes = &rest[..len];
    // Convert up to 8 bytes to i64 (sign-extending from MSB).
    if len > 8 {
        bail!("DER INTEGER too large for i64");
    }
    let mut val: i64 = if int_bytes[0] >= 0x80 { -1 } else { 0 };
    for &b in int_bytes {
        val = (val << 8) | b as i64;
    }
    Ok((val, &rest[len..]))
}

/// Parse a `TimeStampResp` and return the raw DER bytes of the `TimeStampToken`.
///
/// ```text
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  TimeStampToken OPTIONAL
/// }
/// PKIStatusInfo ::= SEQUENCE {
///     status  PKIStatus,   -- INTEGER
///     ...
/// }
/// PKIStatus ::= INTEGER { granted(0), grantedWithMods(1), rejection(2), ... }
/// ```
fn decode_timestamp_response(resp: &[u8]) -> Result<Vec<u8>> {
    // Unwrap outer SEQUENCE
    let outer = der_unwrap_sequence(resp)?;

    // First element: PKIStatusInfo (a SEQUENCE)
    let pki_status_bytes = der_unwrap_sequence(outer)?;
    // First element of PKIStatusInfo: status INTEGER
    let (status, _) = der_read_integer(pki_status_bytes)?;
    if status != 0 && status != 1 {
        bail!(
            "TSA returned non-success status: {} (0=granted, 1=grantedWithMods, 2=rejection, …)",
            status
        );
    }

    // Skip the PKIStatusInfo TLV to reach the TimeStampToken
    let after_status = der_skip(outer)?;
    if after_status.is_empty() {
        bail!("TSA response did not include a TimeStampToken");
    }

    // The TimeStampToken is a ContentInfo starting here; return its full DER.
    // We wrap it back into a complete DER value (it already is one).
    Ok(after_status.to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Request a RFC 3161 timestamp for `signature_value` from the TSA at `url`.
///
/// * `url`          – HTTP(S) URL of the Time Stamping Authority.
/// * `signature_value` – raw bytes of the `<SignatureValue>` element (decoded from
///                       base64). The TSA will timestamp a hash of these bytes.
/// * `digest_alg`   – hash algorithm to use in the timestamp request.
///
/// Returns the raw DER bytes of the `TimeStampToken` (CMS ContentInfo), suitable
/// for base64-encoding and embedding in the XML signature.
pub fn request_timestamp(
    url: &str,
    signature_value: &[u8],
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>> {
    // Hash the signature value.
    let digest = digest_alg.hash(signature_value);

    // Generate a random 64-bit nonce.  Clear the MSB to ensure the value
    // encodes as a positive DER INTEGER (some TSAs reject negative nonces).
    let nonce: u64 = {
        let bytes: [u8; 8] = uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap();
        u64::from_be_bytes(bytes) & !(1u64 << 63)
    };

    let ts_req = encode_timestamp_req(&digest, digest_alg, nonce);

    // POST the request to the TSA.
    let response = ureq::post(url)
        .content_type("application/timestamp-query")
        .send(&ts_req)
        .context("HTTP request to TSA failed")?;

    let status = response.status();
    if status != 200 {
        bail!("TSA returned HTTP {}", status);
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !content_type.contains("timestamp-reply") && !content_type.contains("octet-stream") {
        // Some TSAs return a slightly different content type; just warn.
        eprintln!(
            "warning: unexpected TSA response content-type: {}",
            content_type
        );
    }

    let resp_bytes = response
        .into_body()
        .read_to_vec()
        .context("Failed to read TSA response body")?;

    let token = decode_timestamp_response(&resp_bytes)
        .context("Failed to parse TSA response")?;

    Ok(token)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test: ensure the DER TLV helper emits correct bytes for
    // short, 1-byte-extended, and 2-byte-extended lengths.
    #[test]
    fn test_der_tlv_lengths() {
        let short = der_tlv(0x04, &[0xAA; 10]);
        assert_eq!(&short[..2], &[0x04, 0x0A]);

        let medium = der_tlv(0x04, &[0xBB; 200]);
        assert_eq!(&medium[..3], &[0x04, 0x81, 0xC8]);

        let large = der_tlv(0x04, &[0xCC; 300]);
        assert_eq!(&large[..4], &[0x04, 0x82, 0x01, 0x2C]);
    }

    // Check integer sign-extension: high-bit bytes must get a leading zero.
    #[test]
    fn test_der_integer_sign_extension() {
        // 0xFF has high bit set → should be prefixed with 0x00
        let enc = der_integer(&[0xFF]);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0xFF]);

        // 0x01 does not have high bit set → no prefix
        let enc2 = der_integer(&[0x01]);
        assert_eq!(enc2, vec![0x02, 0x01, 0x01]);
    }
}
