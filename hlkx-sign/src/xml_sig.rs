//! Build the XML digital signature document for an OPC package.
//!
//! The output matches the structure produced by the C# OpenVsixSignTool, which
//! follows the OPC digital signature specification (ECMA-376 Part 2 §13).

use crate::c14n::c14n;
use crate::opc::xml_escape_attr;
use anyhow::Result;
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

const C14N_URL: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
#[allow(dead_code)]
const C14N_WITH_COMMENTS_URL: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const REL_TRANSFORM_URL: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

const RSA_SHA1_URL: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const RSA_SHA512_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

const SHA1_URL: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256_URL: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384_URL: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512_URL: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

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
#[derive(Debug, Clone)]
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
/// `timestamp_token` is the optional DER-encoded CMS token returned by a TSA.
/// When present it is base64-encoded and embedded as a second `<Object>` element
/// matching the format produced by the C# `OpcPackageTimestampBuilder`.
pub fn build_signature_xml(
    digests: &[PartDigest],
    digest_alg: DigestAlgorithm,
    signing_time: DateTime<FixedOffset>,
    signer: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
    timestamp_token: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // ── 1. Build the <Object> element in C14N form ───────────────────────
    let object_xml = build_object_xml(digests, digest_alg, signing_time)?;

    // ── 2. Hash the canonical <Object> ──────────────────────────────────
    let object_hash = digest_alg.hash(&object_xml);
    let object_hash_b64 = B64.encode(&object_hash);

    // ── 3. Build the canonical <SignedInfo> and sign it ──────────────────
    let signed_info_xml =
        build_signed_info_xml(&object_hash_b64, digest_alg)?;

    // Sign the canonical SignedInfo bytes.
    let sig_bytes = signer(&signed_info_xml)?;
    let sig_b64 = B64.encode(&sig_bytes);

    // ── 4. Assemble the full <Signature> document ─────────────────────────
    // The final file has an XML declaration.
    let mut doc = Vec::new();
    doc.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");

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

    // <Object> (already built in canonical form but the final document is not
    // canonicalised – it just embeds the same content).
    doc.extend_from_slice(&object_xml);

    // Optional timestamp <Object>, matching the C# OpcPackageTimestampBuilder output:
    //
    //   <Object xmlns="http://www.w3.org/2000/09/xmldsig#">
    //     <mdssi:TimeStamp Id="idSignatureTimestamp"
    //         xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature">
    //       <mdssi:Comment>Timestamp got from the time stamp server</mdssi:Comment>
    //       <mdssi:EncodedTime>BASE64</mdssi:EncodedTime>
    //     </mdssi:TimeStamp>
    //   </Object>
    if let Some(token) = timestamp_token {
        let token_b64 = B64.encode(token);
        doc.extend_from_slice(b"<Object>");
        doc.extend_from_slice(b"<mdssi:TimeStamp Id=\"idSignatureTimestamp\" xmlns:mdssi=\"");
        doc.extend_from_slice(NS_OPC_DSIG.as_bytes());
        doc.extend_from_slice(b"\">");
        doc.extend_from_slice(b"<mdssi:Comment>Timestamp got from the time stamp server</mdssi:Comment>");
        doc.extend_from_slice(b"<mdssi:EncodedTime>");
        doc.extend_from_slice(token_b64.as_bytes());
        doc.extend_from_slice(b"</mdssi:EncodedTime>");
        doc.extend_from_slice(b"</mdssi:TimeStamp>");
        doc.extend_from_slice(b"</Object>");
    }

    doc.extend_from_slice(b"</Signature>");

    Ok((doc, sig_bytes))
}

// ─────────────────────────────────────────────────────────────────────────────
// <Object> builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the `<Object Id="idPackageObject">` XML element in C14N-compatible
/// form (i.e. what we produce here *is* the canonical form we hash).
fn build_object_xml(
    digests: &[PartDigest],
    _digest_alg: DigestAlgorithm,
    signing_time: DateTime<FixedOffset>,
) -> Result<Vec<u8>> {
    let mut xml = String::new();
    xml.push_str("<Object Id=\"idPackageObject\" xmlns=\"");
    xml.push_str(NS_DSIG);
    xml.push_str("\">");

    // ── <Manifest> ───────────────────────────────────────────────────────
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
                        xml.push_str("<Transform Algorithm=\"");
                        xml.push_str(C14N_URL);
                        xml.push_str("\"></Transform>");
                    }
                    TransformInfo::RelationshipTransform { source_types } => {
                        xml.push_str("<Transform Algorithm=\"");
                        xml.push_str(REL_TRANSFORM_URL);
                        xml.push_str("\">");
                        for st in source_types {
                            xml.push_str("<opc:RelationshipsGroupReference SourceType=\"");
                            xml.push_str(&xml_escape_attr(st));
                            xml.push_str("\"></opc:RelationshipsGroupReference>");
                        }
                        xml.push_str("</Transform>");
                        // C14N is always appended after the RelationshipTransform.
                        xml.push_str("<Transform Algorithm=\"");
                        xml.push_str(C14N_URL);
                        xml.push_str("\"></Transform>");
                    }
                }
            }
            xml.push_str("</Transforms>");
        }

        xml.push_str("<DigestMethod Algorithm=\"");
        xml.push_str(&d.hash_uri);
        xml.push_str("\"></DigestMethod>");

        xml.push_str("<DigestValue>");
        xml.push_str(&d.digest_b64);
        xml.push_str("</DigestValue>");

        xml.push_str("</Reference>");
    }

    xml.push_str("</Manifest>");

    // ── <SignatureProperties> ─────────────────────────────────────────────
    xml.push_str("<SignatureProperties>");
    xml.push_str("<SignatureProperty Id=\"idSignatureTime\" Target=\"#SignatureIdValue\">");
    xml.push_str("<SignatureTime xmlns=\"");
    xml.push_str(NS_OPC_DSIG);
    xml.push_str("\">");
    xml.push_str("<Format>YYYY-MM-DDThh:mm:ss.sTZD</Format>");
    xml.push_str("<Value>");
    // Format matching the C# code: "yyyy-MM-ddTHH:mm:ss.fzzz"
    xml.push_str(&signing_time.format("%Y-%m-%dT%H:%M:%S%.1f%:z").to_string());
    xml.push_str("</Value>");
    xml.push_str("</SignatureTime>");
    xml.push_str("</SignatureProperty>");
    xml.push_str("</SignatureProperties>");

    xml.push_str("</Object>");

    // C14N of this element (it is already in C14N-compatible form, but run
    // through c14n() to ensure correct namespace handling and empty-element
    // expansion).
    let canonical = c14n(xml.as_bytes())?;
    Ok(canonical)
}

// ─────────────────────────────────────────────────────────────────────────────
// <SignedInfo> builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build the canonical `<SignedInfo>` bytes (used both for hashing/signing and
/// for embedding in the final document).
fn build_signed_info_xml(
    object_hash_b64: &str,
    digest_alg: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let xml = build_signed_info_inner_str(object_hash_b64, digest_alg);
    let full = format!("<SignedInfo xmlns=\"{}\">{}</SignedInfo>", NS_DSIG, xml);
    c14n(full.as_bytes())
}

/// Build the inner content of `<SignedInfo>` (without the outer `<SignedInfo>`
/// tags) as a string, ready for embedding in the final document.
fn build_signed_info_inner(object_hash_b64: &str, digest_alg: DigestAlgorithm) -> Vec<u8> {
    let inner = build_signed_info_inner_str(object_hash_b64, digest_alg);
    format!("<SignedInfo>{}</SignedInfo>", inner).into_bytes()
}

fn build_signed_info_inner_str(object_hash_b64: &str, digest_alg: DigestAlgorithm) -> String {
    let mut s = String::new();
    // <CanonicalizationMethod>
    s.push_str("<CanonicalizationMethod Algorithm=\"");
    s.push_str(C14N_URL);
    s.push_str("\"></CanonicalizationMethod>");
    // <SignatureMethod>
    s.push_str("<SignatureMethod Algorithm=\"");
    s.push_str(digest_alg.rsa_sig_uri());
    s.push_str("\"></SignatureMethod>");
    // <Reference> to the Object element.
    s.push_str(
        "<Reference Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#idPackageObject\">",
    );
    s.push_str("<DigestMethod Algorithm=\"");
    s.push_str(digest_alg.xml_uri());
    s.push_str("\"></DigestMethod>");
    s.push_str("<DigestValue>");
    s.push_str(object_hash_b64);
    s.push_str("</DigestValue>");
    s.push_str("</Reference>");
    s
}
