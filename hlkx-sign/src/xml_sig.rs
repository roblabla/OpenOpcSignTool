//! Build the XML digital signature document for an OPC package.
//!
//! The output matches the structure produced by the C# OpenVsixSignTool, which
//! follows the OPC digital signature specification (ECMA-376 Part 2 §13).

use crate::c14n::c14n_dsig_element_under_signature;
use crate::debug_log;
use crate::opc::xml_escape_attr;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, FixedOffset};
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (URIs)
// ─────────────────────────────────────────────────────────────────────────────

const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_OPC_DSIG: &str =
    "http://schemas.openxmlformats.org/package/2006/digital-signature";

pub(crate) const C14N_URL: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
#[allow(dead_code)]
const C14N_WITH_COMMENTS_URL: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub(crate) const REL_TRANSFORM_URL: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

pub(crate) const RSA_SHA1_URL: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub(crate) const RSA_SHA256_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub(crate) const RSA_SHA384_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub(crate) const RSA_SHA512_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

pub(crate) const SHA1_URL: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub(crate) const SHA256_URL: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub(crate) const SHA384_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub(crate) const SHA512_URL: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

// ─────────────────────────────────────────────────────────────────────────────
// Digest algorithm selector
// ─────────────────────────────────────────────────────────────────────────────

/// Supported file-digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha1" => Some(Self::Sha1),
            "sha256" | "" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The XML DSig URI for this hash algorithm.
    pub fn xml_uri(&self) -> &'static str {
        match self {
            Self::Sha1 => SHA1_URL,
            Self::Sha256 => SHA256_URL,
            Self::Sha384 => SHA384_URL,
            Self::Sha512 => SHA512_URL,
        }
    }

    /// The XML DSig URI for the RSA+hash signature algorithm.
    pub fn rsa_sig_uri(&self) -> &'static str {
        match self {
            Self::Sha1 => RSA_SHA1_URL,
            Self::Sha256 => RSA_SHA256_URL,
            Self::Sha384 => RSA_SHA384_URL,
            Self::Sha512 => RSA_SHA512_URL,
        }
    }

    /// Compute a digest over `data` and return the bytes.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut h = sha1::Sha1::new();
                Sha1Digest::update(&mut h, data);
                Sha1Digest::finalize(h).to_vec()
            }
            Self::Sha256 => {
                let mut h = sha2::Sha256::new();
                Sha2Digest::update(&mut h, data);
                Sha2Digest::finalize(h).to_vec()
            }
            Self::Sha384 => {
                let mut h = sha2::Sha384::new();
                Sha2Digest::update(&mut h, data);
                Sha2Digest::finalize(h).to_vec()
            }
            Self::Sha512 => {
                let mut h = sha2::Sha512::new();
                Sha2Digest::update(&mut h, data);
                Sha2Digest::finalize(h).to_vec()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Part digest entry
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the Manifest, representing a hashed part (or part view).
#[derive(Debug, Clone)]
pub struct PartDigest {
    /// The Reference URI, e.g. `"/_rels/.rels?ContentType=..."`.
    pub uri: String,
    /// Base64-encoded digest.
    pub digest_b64: String,
    /// Hash algorithm URI.
    pub hash_uri: String,
    /// Optional transform list: each entry is the transform Algorithm URI.
    pub transforms: Vec<TransformInfo>,
}

/// Describes a single transform in a `<Transforms>` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformInfo {
    /// `<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`
    C14n,
    /// The OPC relationships transform with a list of relationship types to include.
    RelationshipTransform { source_types: Vec<String> },
}

// ─────────────────────────────────────────────────────────────────────────────
// XML signature builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the complete XML digital signature document.
///
/// Returns the UTF-8 bytes that should be written to the `.psdsxs` part.
///
/// Note: the certificate is stored in a separate `.cer` part linked via a
/// relationship; it is not embedded in the KeyInfo element (the C# reference
/// implementation leaves KeyInfo commented out).
///
/// `signer` is a closure that accepts the canonical `<SignedInfo>` bytes and
/// returns the RSA PKCS#1 v1.5 signature bytes.
///
/// Returns the UTF-8 signature document and the raw `SignatureValue` bytes that
/// were signed (needed for RFC 3161 timestamping).
pub fn build_signature_xml(
    digests: &[PartDigest],
    digest_alg: DigestAlgorithm,
    signing_time: DateTime<FixedOffset>,
    signer: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // ── 1. Build the <Object> element (canonical bytes for hashing, serialized
    //        bytes for the on-disk .psdsxs matching the C# XmlTextWriter output).
    let (object_canonical, object_document) =
        build_object_xml(digests, signing_time)?;

    // ── 2. Hash the canonical <Object> ──────────────────────────────────
    let object_hash = digest_alg.hash(&object_canonical);
    let object_hash_b64 = B64.encode(&object_hash);
    // #region agent log
    debug_log::log(
        "D",
        "xml_sig.rs:build_signature_xml",
        "object canonical digest",
        &format!(
            r#"{{"object_hash_b64":"{}","canonical_len":{},"document_len":{}}}"#,
            object_hash_b64,
            object_canonical.len(),
            object_document.len()
        ),
    );
    // #endregion

    // ── 3. Build the canonical <SignedInfo> and sign it ──────────────────
    let signed_info_xml =
        build_signed_info_xml(&object_hash_b64, digest_alg)?;

    // Sign the canonical SignedInfo bytes.
    let sig_bytes = signer(&signed_info_xml)?;
    let sig_b64 = B64.encode(&sig_bytes);

    // ── 4. Assemble the full <Signature> document ─────────────────────────
    // The final file has an XML declaration.
    let mut doc = Vec::new();
    doc.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>");

    // <Signature> root.
    doc.extend_from_slice(b"<Signature Id=\"SignatureIdValue\" xmlns=\"");
    doc.extend_from_slice(NS_DSIG.as_bytes());
    doc.extend_from_slice(b"\">");

    // Embed the canonical SignedInfo content (everything inside <SignedInfo>…).
    // We already have the full element bytes; strip the outer tags and re-wrap
    // is fragile, so instead we re-build from components.
    doc.extend_from_slice(&build_signed_info_inner(
        &object_hash_b64,
        digest_alg,
    ));

    // <SignatureValue>
    doc.extend_from_slice(b"<SignatureValue>");
    doc.extend_from_slice(sig_b64.as_bytes());
    doc.extend_from_slice(b"</SignatureValue>");

    // <Object> – serialized like .NET XmlTextWriter (self-closing empty tags,
    // no redundant xmlns on Object because it inherits from <Signature>).
    doc.extend_from_slice(&object_document);

    doc.extend_from_slice(b"</Signature>");

    Ok((doc, sig_bytes))
}

/// Append a timestamp `<Object>` to an existing signature document without
/// re-signing, matching `OpcPackageTimestampBuilder.ApplyTimestamp` in the C#
/// tool (timestamp the existing `SignatureValue`, then add the token).
pub fn append_timestamp_object(mut sig_xml: Vec<u8>, token: &[u8]) -> Result<Vec<u8>> {
    let close = b"</Signature>";
    let pos = sig_xml
        .windows(close.len())
        .rposition(|w| w == close)
        .context("signature document missing </Signature>")?;
    let token_b64 = B64.encode(token);
    let mut insert = Vec::new();
    insert.extend_from_slice(b"<Object><TimeStamp Id=\"idSignatureTimestamp\" xmlns=\"");
    insert.extend_from_slice(NS_OPC_DSIG.as_bytes());
    insert.extend_from_slice(
        b"\"><Comment>Timestamp got from the time stamp server</Comment><EncodedTime>",
    );
    insert.extend_from_slice(token_b64.as_bytes());
    insert.extend_from_slice(b"</EncodedTime></TimeStamp></Object>");
    sig_xml.splice(pos..pos, insert.iter().copied());
    Ok(sig_xml)
}

// ─────────────────────────────────────────────────────────────────────────────
// <Object> builder
// ─────────────────────────────────────────────────────────────────────────────

/// Append an empty element using either C14N expanded form or .NET-style ` />`.
fn push_empty_element(xml: &mut String, name: &str, attrs: &str, self_closing: bool) {
    if self_closing {
        xml.push('<');
        xml.push_str(name);
        xml.push_str(attrs);
        xml.push_str(" />");
    } else {
        xml.push('<');
        xml.push_str(name);
        xml.push_str(attrs);
        xml.push_str("></");
        xml.push_str(name);
        xml.push('>');
    }
}

/// Build `<Object Id="idPackageObject">` for hashing (C14N) and for the final
/// `.psdsxs` document (self-closing empty tags, no redundant xmlns on Object).
fn build_object_xml(
    digests: &[PartDigest],
    signing_time: DateTime<FixedOffset>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let inner = build_object_content(digests, signing_time, false);
    let canonical = c14n_dsig_element_under_signature(&inner, "Object")?;
    let document = build_object_content(digests, signing_time, true).into_bytes();
    Ok((canonical, document))
}

/// Serialize `<Object Id="idPackageObject">…</Object>` without a redundant
/// default-namespace declaration (inherits from `<Signature>` in the final file).
fn build_object_content(
    digests: &[PartDigest],
    signing_time: DateTime<FixedOffset>,
    self_closing: bool,
) -> String {
    let mut xml = String::new();
    xml.push_str("<Object Id=\"idPackageObject\">");

    xml.push_str("<Manifest xmlns:opc=\"");
    xml.push_str(NS_OPC_DSIG);
    xml.push_str("\">");

    for d in digests {
        xml.push_str("<Reference URI=\"");
        xml.push_str(&xml_escape_attr(&d.uri));
        xml.push_str("\">");

        if !d.transforms.is_empty() {
            xml.push_str("<Transforms>");
            for t in &d.transforms {
                match t {
                    TransformInfo::C14n => {
                        push_empty_element(
                            &mut xml,
                            "Transform",
                            &format!(" Algorithm=\"{C14N_URL}\""),
                            self_closing,
                        );
                    }
                    TransformInfo::RelationshipTransform { source_types } => {
                        // #region agent log
                        debug_log::log(
                            "G",
                            "xml_sig.rs:build_object_content",
                            "relationship transform selectors",
                            &format!(
                                r#"{{"selector_count":{},"unique_count":{}}}"#,
                                source_types.len(),
                                source_types
                                    .iter()
                                    .collect::<std::collections::HashSet<_>>()
                                    .len()
                            ),
                        );
                        // #endregion
                        xml.push_str("<Transform Algorithm=\"");
                        xml.push_str(REL_TRANSFORM_URL);
                        xml.push_str("\">");
                        for st in source_types {
                            push_empty_element(
                                &mut xml,
                                "opc:RelationshipsGroupReference",
                                &format!(" SourceType=\"{}\"", xml_escape_attr(st)),
                                self_closing,
                            );
                        }
                        xml.push_str("</Transform>");
                        push_empty_element(
                            &mut xml,
                            "Transform",
                            &format!(" Algorithm=\"{C14N_URL}\""),
                            self_closing,
                        );
                    }
                }
            }
            xml.push_str("</Transforms>");
        }

        push_empty_element(
            &mut xml,
            "DigestMethod",
            &format!(" Algorithm=\"{}\"", xml_escape_attr(&d.hash_uri)),
            self_closing,
        );

        xml.push_str("<DigestValue>");
        xml.push_str(&d.digest_b64);
        xml.push_str("</DigestValue>");

        xml.push_str("</Reference>");
    }

    xml.push_str("</Manifest>");

    xml.push_str("<SignatureProperties>");
    xml.push_str("<SignatureProperty Id=\"idSignatureTime\" Target=\"#SignatureIdValue\">");
    xml.push_str("<SignatureTime xmlns=\"");
    xml.push_str(NS_OPC_DSIG);
    xml.push_str("\">");
    xml.push_str("<Format>YYYY-MM-DDThh:mm:ss.sTZD</Format>");
    xml.push_str("<Value>");
    xml.push_str(&signing_time.format("%Y-%m-%dT%H:%M:%S.0%:z").to_string());
    xml.push_str("</Value>");
    xml.push_str("</SignatureTime>");
    xml.push_str("</SignatureProperty>");
    xml.push_str("</SignatureProperties>");

    xml.push_str("</Object>");
    xml
}

// ─────────────────────────────────────────────────────────────────────────────
// <SignedInfo> builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the canonical `<SignedInfo>` bytes (used both for hashing/signing and
/// for embedding in the final document).
pub(crate) fn build_signed_info_xml(
    object_hash_b64: &str,
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let inner = build_signed_info_inner_str(object_hash_b64, digest_alg, false);
    let element = format!("<SignedInfo>{inner}</SignedInfo>");
    // Canonicalize with the same parent context as in the final `.psdsxs` so the
    // signed bytes match what Microsoft derives from `<Signature><SignedInfo>…`.
    let canonical = c14n_dsig_element_under_signature(&element, "SignedInfo")?;
    // #region agent log
    debug_log::log(
        "E",
        "xml_sig.rs:build_signed_info_xml",
        "signedinfo canonical len",
        &format!(r#"{{"canonical_len":{},"has_xmlns_on_si":{}}}"#, canonical.len(), std::str::from_utf8(&canonical).unwrap_or("").contains("SignedInfo xmlns")),
    );
    // #endregion
    Ok(canonical)
}

/// Build `<SignedInfo>` for embedding in the final document (self-closing empty
/// elements, matching .NET XmlTextWriter output).
fn build_signed_info_inner(object_hash_b64: &str, digest_alg: DigestAlgorithm) -> Vec<u8> {
    let inner = build_signed_info_inner_str(object_hash_b64, digest_alg, true);
    format!("<SignedInfo>{inner}</SignedInfo>").into_bytes()
}

fn build_signed_info_inner_str(
    object_hash_b64: &str,
    digest_alg: DigestAlgorithm,
    self_closing: bool,
) -> String {
    let mut s = String::new();
    push_empty_element(
        &mut s,
        "CanonicalizationMethod",
        &format!(" Algorithm=\"{C14N_URL}\""),
        self_closing,
    );
    push_empty_element(
        &mut s,
        "SignatureMethod",
        &format!(" Algorithm=\"{}\"", digest_alg.rsa_sig_uri()),
        self_closing,
    );
    // Attribute order matches XmlSignatureBuilder: URI before Type.
    s.push_str("<Reference URI=\"#idPackageObject\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\">");
    push_empty_element(
        &mut s,
        "DigestMethod",
        &format!(" Algorithm=\"{}\"", digest_alg.xml_uri()),
        self_closing,
    );
    s.push_str("<DigestValue>");
    s.push_str(object_hash_b64);
    s.push_str("</DigestValue>");
    s.push_str("</Reference>");
    s
}
