//! Top-level signing orchestration.
//!
//! Implements the same logic as the C# `OpcPackageSignatureBuilder.Sign` and
//! `OpcSignatureManifest.Build` methods:
//!
//!  1. Collect all parts that need to be signed.
//!  2. Compute digests (two for `_rels/.rels`, one for everything else).
//!  3. Build the XML digital signature.
//!  4. Write the signature, certificate, and updated relationship/content-type
//!     files back into the package.

use crate::c14n::c14n;
use crate::opc::{
    entry_to_uri, rels_path_for_part, serialize_rels, OpcPackage, OpcRelationship,
    MIME_DS_CERTIFICATE, MIME_DS_ORIGIN, MIME_DS_SIGNATURE, MIME_RELS, REL_DS_CERTIFICATE,
    REL_DS_ORIGIN, REL_DS_SIGNATURE,
};
use crate::timestamp;
use crate::xml_sig::{build_signature_xml, DigestAlgorithm, PartDigest, TransformInfo};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Local;
use der::Decode;
use uuid::Uuid;
use x509_cert::Certificate;

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Optional RFC 3161 timestamp configuration.
pub struct TimestampConfig<'a> {
    /// URL of the Time Stamping Authority.
    pub url: &'a str,
    /// Hash algorithm to use in the timestamp request (defaults to SHA-256 if
    /// no explicit selection is made by the caller).
    pub digest_alg: DigestAlgorithm,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry-point
// ─────────────────────────────────────────────────────────────────────────────

/// Sign the OPC package at `pkg`.
///
/// * `certificate_der` – DER-encoded signing certificate (embedded in the package).
/// * `signer`          – closure that signs the canonical `<SignedInfo>` bytes with
///                       RSA PKCS#1 v1.5 and returns the raw signature bytes.
/// * `digest_alg`      – hash algorithm for file digests and the signature.
/// * `timestamp`       – optional RFC 3161 timestamp configuration; when present,
///                       the signature value is timestamped and the token embedded.
/// * `force`           – overwrite an existing signature if one is present.
pub fn sign(
    pkg: &mut OpcPackage,
    certificate_der: &[u8],
    signer: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
    digest_alg: DigestAlgorithm,
    timestamp: Option<&TimestampConfig<'_>>,
    force: bool,
) -> Result<()> {
    if pkg.has_signatures() && !force {
        bail!("The package is already signed. Use --force to overwrite.");
    }

    // ── Step 1: Choose file names for the new signature artefacts ─────────
    let sig_filename = format!("{}.psdsxs", Uuid::new_v4().as_simple());
    let cert_filename = cert_der_filename(certificate_der)?;

    let origin_part_path = "package/services/digital-signature/origin.psdsor";
    let sig_part_path = format!(
        "package/services/digital-signature/xml-signature/{}",
        sig_filename
    );
    let cert_part_path = format!(
        "package/services/digital-signature/certificate/{}",
        cert_filename
    );

    // ── Step 2: Create origin, signature-placeholder, and certificate parts ─
    // Origin part (empty content).
    pkg.set_part(origin_part_path, vec![]);

    // Package-level relationship → origin.
    let origin_target = format!("/{}", origin_part_path);
    let rel_id = OpcPackage::new_rel_id(&pkg.pkg_rels);
    pkg.pkg_rels.push(OpcRelationship::new(
        rel_id,
        REL_DS_ORIGIN,
        &origin_target,
    ));

    // Flush `_rels/.rels` to the entries map now so the digest is computed on
    // the updated version (same order as the C# code: flush before digests).
    let rels_bytes = serialize_rels(&pkg.pkg_rels);
    pkg.entries.insert(crate::opc::GLOBAL_RELS.to_string(), rels_bytes);

    // Signature part (placeholder – written later).
    pkg.set_part(&sig_part_path, vec![]);

    // Origin → signature relationship.
    let origin_rels_path = rels_path_for_part(origin_part_path);
    let origin_rels = pkg
        .entries
        .get(origin_rels_path.as_str())
        .cloned()
        .unwrap_or_default();
    let mut origin_rel_list = if origin_rels.is_empty() {
        vec![]
    } else {
        crate::opc::parse_rels(&origin_rels)?
    };
    let sig_rel_id = OpcPackage::new_rel_id(&origin_rel_list);
    origin_rel_list.push(OpcRelationship::new(
        sig_rel_id,
        REL_DS_SIGNATURE,
        &format!("/{}", sig_part_path),
    ));
    pkg.entries.insert(origin_rels_path, serialize_rels(&origin_rel_list));

    // Certificate part (DER bytes).
    pkg.set_part(&cert_part_path, certificate_der.to_vec());

    // Signature → certificate relationship.
    let sig_rels_path = rels_path_for_part(&sig_part_path);
    let cert_rel_id = OpcPackage::new_rel_id(&[]);
    let cert_rels = vec![OpcRelationship::new(
        cert_rel_id,
        REL_DS_CERTIFICATE,
        &format!("/{}", cert_part_path),
    )];
    pkg.entries.insert(sig_rels_path, serialize_rels(&cert_rels));

    // ── Step 3: Ensure required content types exist ───────────────────────
    pkg.ensure_content_type("rels", MIME_RELS);
    pkg.ensure_content_type("psdsor", MIME_DS_ORIGIN);
    pkg.ensure_content_type("psdsxs", MIME_DS_SIGNATURE);
    pkg.ensure_content_type("cer", MIME_DS_CERTIFICATE);

    // ── Step 4: Collect the parts to sign ────────────────────────────────
    // Same logic as VSIXSignatureBuilderPreset: all parts that are not
    // themselves digital-signature XML files.
    let mut parts_to_sign: Vec<String> = pkg
        .entries
        .keys()
        .filter(|p| should_sign_part(p))
        .cloned()
        .collect();
    parts_to_sign.sort();

    // ── Step 5: Compute digests ────────────────────────────────────────────
    let mut all_digests: Vec<PartDigest> = Vec::new();

    for part_path in &parts_to_sign {
        let data = pkg.entries.get(part_path.as_str()).cloned().unwrap_or_default();
        let mime = pkg.content_type_for_extension(
            std::path::Path::new(part_path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or(""),
        ).to_string();

        if part_path == crate::opc::GLOBAL_RELS {
            // Two digest entries for _rels/.rels (mirrors OpcSignatureManifest.Build).
            let digests = digest_rels_part(part_path, &data, &mime, digest_alg, pkg)?;
            all_digests.extend(digests);
        } else {
            // Regular part: simple hash of raw bytes.
            let hash = digest_alg.hash(&data);
            let uri = format!("{}?ContentType={}", entry_to_uri(part_path), mime);
            all_digests.push(PartDigest {
                uri,
                digest_b64: B64.encode(&hash),
                hash_uri: digest_alg.xml_uri().to_string(),
                transforms: vec![],
            });
        }
    }

    // Sort by URI (case-insensitive, matching the C# sort).
    all_digests.sort_by(|a, b| a.uri.to_lowercase().cmp(&b.uri.to_lowercase()));

    // ── Step 6: Build the XML signature ───────────────────────────────────
    let signing_time = Local::now().fixed_offset();

    // First build without timestamp token so we can get the signature value.
    let (mut sig_xml, sig_bytes) = build_signature_xml(
        &all_digests,
        digest_alg,
        signing_time,
        signer,
        None, // no timestamp yet – we need sig_bytes first
    )?;

    // ── Optional Step 6b: Request timestamp and re-build with token ────────
    if let Some(ts) = timestamp {
        eprintln!("Requesting RFC 3161 timestamp...");
        let token = timestamp::request_timestamp(ts.url, &sig_bytes, ts.digest_alg)
            .context("Timestamp request failed")?;

        // Re-build the XML signature with the timestamp token embedded.
        (sig_xml, _) = build_signature_xml(
            &all_digests,
            digest_alg,
            signing_time,
            signer,
            Some(&token),
        )?;
    }

    // ── Step 7: Write the signature into the package ──────────────────────
    pkg.set_part(&sig_part_path, sig_xml);

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Determine whether a ZIP entry path should be included in the signature.
/// Excludes:
///   - `[Content_Types].xml`
///   - existing digital-signature parts (origin, signatures, certificates)
///   - relationship files that belong to signature parts
fn should_sign_part(path: &str) -> bool {
    if path.eq_ignore_ascii_case(crate::opc::CONTENT_TYPES_XML) {
        return false;
    }
    // Exclude the digital-signature infrastructure itself.
    let ds_prefix = "package/services/digital-signature/";
    if path.starts_with(ds_prefix) {
        return false;
    }
    // Exclude relationship files that live inside the ds hierarchy.
    // (e.g. "package/services/digital-signature/_rels/origin.psdsor.rels")
    if path.contains("/digital-signature/") {
        return false;
    }
    true
}

/// Compute the two digest entries required for a `_rels/*.rels` part.
///
/// Entry 1: C14N of the raw XML bytes.
/// Entry 2: C14N of a filtered relationships document (the OPC
///          RelationshipTransform), excluding the origin relationship.
fn digest_rels_part(
    part_path: &str,
    raw_xml: &[u8],
    mime: &str,
    digest_alg: DigestAlgorithm,
    pkg: &OpcPackage,
) -> Result<Vec<PartDigest>> {
    let uri = format!("{}?ContentType={}", entry_to_uri(part_path), mime);

    // ── Entry 1: C14N of the raw XML ──────────────────────────────────────
    let c14n_raw = c14n(raw_xml)?;
    let hash1 = digest_alg.hash(&c14n_raw);

    // ── Entry 2: RelationshipTransform + C14N ─────────────────────────────
    // Build a sorted filtered relationships document.
    // Filtering: exclude the origin relationship (same logic as C# code,
    // which excludes relationships whose Target is the origin file URI).
    // In practice, for _rels/.rels the origin relationship is the one with
    // Type = REL_DS_ORIGIN.
    let all_rels = &pkg.pkg_rels;
    let mut filtered: Vec<&OpcRelationship> = all_rels
        .iter()
        .filter(|r| r.rel_type != REL_DS_ORIGIN)
        .collect();
    // Sort by Id.
    filtered.sort_by(|a, b| a.id.cmp(&b.id));

    // Serialize in the form used by InternalRelationshipCollection:
    // each Relationship has TargetMode="Internal".
    let filtered_xml = build_filtered_rels_xml(&filtered);
    let c14n_filtered = c14n(filtered_xml.as_bytes())?;
    let hash2 = digest_alg.hash(&c14n_filtered);

    // Collect the relationship types for the RelationshipsGroupReference elements.
    let source_types: Vec<String> = {
        let mut types: Vec<String> =
            filtered.iter().map(|r| r.rel_type.clone()).collect();
        types.dedup();
        types
    };

    Ok(vec![
        // Entry 1 – C14N transform only.
        PartDigest {
            uri: uri.clone(),
            digest_b64: B64.encode(&hash1),
            hash_uri: digest_alg.xml_uri().to_string(),
            transforms: vec![TransformInfo::C14n],
        },
        // Entry 2 – RelationshipTransform + C14N.
        PartDigest {
            uri,
            digest_b64: B64.encode(&hash2),
            hash_uri: digest_alg.xml_uri().to_string(),
            transforms: vec![TransformInfo::RelationshipTransform { source_types }],
        },
    ])
}

/// Build the XML document used as input to the RelationshipTransform.
/// Matches the output of `InternalRelationshipCollection.WriteRelationshipsAsXml`
/// with `alwaysWriteTargetModeAttribute = true`.
fn build_filtered_rels_xml(rels: &[&OpcRelationship]) -> String {
    use crate::opc::xml_escape_attr;
    let mut s = String::new();
    s.push_str("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
    for r in rels {
        s.push_str("<Relationship");
        s.push_str(" Id=\"");
        s.push_str(&xml_escape_attr(&r.id));
        s.push_str("\" Target=\"");
        s.push_str(&xml_escape_attr(&r.target));
        s.push_str("\" TargetMode=\"Internal\" Type=\"");
        s.push_str(&xml_escape_attr(&r.rel_type));
        s.push_str("\" />");
    }
    s.push_str("</Relationships>");
    s
}

/// Compute the certificate file name: serial number bytes reversed, hex-encoded.
/// Matches the C# `ByteArrayToReverseString(certificate.GetSerialNumber())`.
fn cert_der_filename(cert_der: &[u8]) -> Result<String> {
    // Parse the DER certificate to extract the serial number.
    let cert = Certificate::from_der(cert_der)
        .context("Failed to parse certificate DER")?;
    // serial_number().as_bytes() returns the big-endian integer content bytes.
    let bytes = cert.tbs_certificate.serial_number.as_bytes();
    let reversed: Vec<u8> = bytes.iter().rev().copied().collect();
    let hex_str = hex::encode_upper(&reversed);
    Ok(format!("{}.cer", hex_str))
}
