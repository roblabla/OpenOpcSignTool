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
use crate::debug_log;
use crate::opc::{
    entry_to_uri, is_digital_signature_origin_target,
    rels_path_for_part, serialize_rels, OpcPackage, OpcRelationship, MIME_DS_CERTIFICATE,
    MIME_DS_ORIGIN, MIME_DS_SIGNATURE, MIME_RELS, REL_DS_CERTIFICATE, REL_DS_ORIGIN,
    REL_DS_SIGNATURE,
};
use std::collections::{BTreeMap, HashSet};
use crate::timestamp;
use crate::xml_sig::{
    append_timestamp_object, build_signature_xml, DigestAlgorithm, PartDigest, TransformInfo,
};
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
        let mime = pkg.content_type_for_part(part_path).to_string();

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
    // #region agent log
    {
        let sample: Vec<_> = parts_to_sign
            .iter()
            .take(3)
            .map(|p| {
                format!(
                    "{{\"part\":\"{}\",\"content_type\":\"{}\"}}",
                    p,
                    pkg.content_type_for_part(p)
                )
            })
            .collect();
        debug_log::log(
            "I",
            "signing.rs:sign",
            "resolved part content types",
            &format!(r#"{{"sample":{sample:?}}}"#),
        );
    }
    debug_log::log(
        "A",
        "signing.rs:sign",
        "digest manifest summary",
        &format!(
            r#"{{"digest_count":{},"uris":{:?}}}"#,
            all_digests.len(),
            all_digests.iter().map(|d| &d.uri).collect::<Vec<_>>()
        ),
    );
    // #endregion

    // ── Step 6: Build the XML signature ───────────────────────────────────
    let signing_time = Local::now().fixed_offset();

    let (mut sig_xml, sig_bytes) = build_signature_xml(
        &all_digests,
        digest_alg,
        signing_time,
        signer,
    )?;

    // ── Optional Step 6b: RFC 3161 timestamp (C# timestamps the existing
    //     SignatureValue; it does NOT re-sign the package).
    if let Some(ts) = timestamp {
        eprintln!("Requesting RFC 3161 timestamp...");
        let token = timestamp::request_timestamp(ts.url, &sig_bytes, ts.digest_alg)
            .context("Timestamp request failed")?;

        let sig_b64_before = B64.encode(&sig_bytes);
        sig_xml = append_timestamp_object(sig_xml, &token)?;
        let sig_xml_str = std::str::from_utf8(&sig_xml).unwrap_or("");
        let sig_b64_after = sig_xml_str
            .split("<SignatureValue>")
            .nth(1)
            .and_then(|s| s.split('<').next())
            .unwrap_or("");
        // #region agent log
        debug_log::log(
            "F",
            "signing.rs:sign",
            "timestamp append preserves signaturevalue",
            &format!(
                r#"{{"sig_unchanged":{},"sig_len":{}}}"#,
                sig_b64_before == sig_b64_after,
                sig_bytes.len()
            ),
        );
        // #endregion
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
pub(crate) fn should_sign_part(path: &str) -> bool {
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
pub(crate) fn digest_rels_part(
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
    // #region agent log
    debug_log::log(
        "B",
        "signing.rs:digest_rels_part",
        "rels c14n digest",
        &format!(
            r#"{{"hash1_b64":"{}","c14n_len":{},"raw_len":{}}}"#,
            B64.encode(&hash1),
            c14n_raw.len(),
            raw_xml.len()
        ),
    );
    // #endregion

    // ── Entry 2: RelationshipTransform + C14N ─────────────────────────────
    // Build a sorted filtered relationships document (mirrors
    // `OpcSignatureManifest.GetRelationships`: exclude origin by Target URI,
    // dedupe by Id, sort by Id).
    let filtered = filtered_package_relationships(pkg);
    let filtered_refs: Vec<&OpcRelationship> = filtered.iter().collect();

    // Serialize in the form used by InternalRelationshipCollection:
    // each Relationship has TargetMode="Internal".
    let filtered_xml = build_filtered_rels_xml(&filtered_refs);
    let c14n_filtered = c14n(filtered_xml.as_bytes())?;
    let hash2 = digest_alg.hash(&c14n_filtered);

    // One RelationshipsGroupReference per distinct SourceType (first-seen order when
    // relationships are sorted by Id). Duplicate selectors are redundant for the
    // RelationshipTransform and are omitted in Microsoft-accepted HLKX signatures.
    let source_types = unique_relationship_source_types(&filtered_refs);
    // #region agent log
    debug_log::log(
        "C",
        "signing.rs:digest_rels_part",
        "filtered rels digest",
        &format!(
            r#"{{"hash2_b64":"{}","filtered_count":{},"source_type_count":{},"unique_source_types":{},"filtered_xml_len":{}}}"#,
            B64.encode(&hash2),
            filtered.len(),
            filtered_refs.len(),
            source_types.len(),
            filtered_xml.len()
        ),
    );
    // #endregion

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
            transforms: vec![
                TransformInfo::RelationshipTransform { source_types },
                TransformInfo::C14n,
            ],
        },
    ])
}

/// Distinct relationship `Type` values in first-seen order (relationships sorted by Id).
pub(crate) fn unique_relationship_source_types(rels: &[&OpcRelationship]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in rels {
        if seen.insert(r.rel_type.as_str()) {
            out.push(r.rel_type.clone());
        }
    }
    out
}

/// Relationships to include in the RelationshipTransform digest, matching
/// `OpcSignatureManifest.GetRelationships`.
pub(crate) fn filtered_package_relationships(pkg: &OpcPackage) -> Vec<OpcRelationship> {
    let mut by_id: BTreeMap<String, OpcRelationship> = BTreeMap::new();
    for rel in &pkg.pkg_rels {
        if is_digital_signature_origin_target(&rel.target) {
            continue;
        }
        by_id.entry(rel.id.clone()).or_insert_with(|| rel.clone());
    }
    by_id.into_values().collect()
}

/// Build the XML document used as input to the RelationshipTransform.
/// Matches the output of `InternalRelationshipCollection.WriteRelationshipsAsXml`
/// with `alwaysWriteTargetModeAttribute = true` (attribute order: Type, Target,
/// TargetMode, Id).
pub(crate) fn build_filtered_rels_xml(rels: &[&OpcRelationship]) -> String {
    use crate::opc::xml_escape_attr;
    let mut s = String::new();
    s.push_str("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
    for r in rels {
        s.push_str("<Relationship");
        s.push_str(" Type=\"");
        s.push_str(&xml_escape_attr(&r.rel_type));
        s.push_str("\" Target=\"");
        s.push_str(&xml_escape_attr(&r.target));
        s.push_str("\" TargetMode=\"Internal\" Id=\"");
        s.push_str(&xml_escape_attr(&r.id));
        s.push_str("\" />");
    }
    s.push_str("</Relationships>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opc::{
        is_digital_signature_origin_target, normalize_relationship_target, parse_rels,
        DS_ORIGIN_PART_PATH, DS_ORIGIN_PART_URI, MIME_OCTET,
    };
    use std::collections::HashMap;

    #[test]
    fn default_mime_matches_csharp() {
        assert_eq!(MIME_OCTET, "application/octet");
    }

    #[test]
    fn origin_target_normalization() {
        assert_eq!(
            normalize_relationship_target(DS_ORIGIN_PART_URI),
            DS_ORIGIN_PART_PATH
        );
        assert_eq!(
            normalize_relationship_target(DS_ORIGIN_PART_PATH),
            DS_ORIGIN_PART_PATH
        );
        assert!(is_digital_signature_origin_target(DS_ORIGIN_PART_URI));
        assert!(is_digital_signature_origin_target(DS_ORIGIN_PART_PATH));
        assert!(!is_digital_signature_origin_target("/hck/data/foo"));
    }

    /// Verify canonical SignedInfo from on-disk psdsxs matches signing-time c14n.
    #[test]
    fn append_timestamp_preserves_signature_value() {
        use crate::xml_sig::append_timestamp_object;
        let sig_xml = b"<?xml version=\"1.0\"?><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignatureValue>QUJD</SignatureValue></Signature>".to_vec();
        let out = append_timestamp_object(sig_xml, b"fake-token").unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("<TimeStamp"));
        assert_eq!(s.matches("<SignatureValue>QUJD</SignatureValue>").count(), 1);
    }

    #[test]
    fn write_canon_si_for_openssl() {
        const PSDSXS: &str = "/private/tmp/hlelam/new2/package/services/digital-signature/xml-signature/430b3e8ff3144058ab4245fcf8dae1f9.psdsxs";
        if !std::path::Path::new(PSDSXS).exists() {
            return;
        }
        let psdsxs = std::fs::read_to_string(PSDSXS).unwrap();
        let si_start = psdsxs.find("<SignedInfo>").unwrap();
        let si_end = psdsxs.find("</SignedInfo>").unwrap() + "</SignedInfo>".len();
        let wrapped = format!(
            "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{}</Signature>",
            &psdsxs[si_start..si_end]
        );
        let canon = c14n(wrapped.as_bytes()).unwrap();
        let s = std::str::from_utf8(&canon).unwrap();
        let start = s.find("<SignedInfo").unwrap();
        let end = s.find("</SignedInfo>").unwrap() + "</SignedInfo>".len();
        std::fs::write("/tmp/canon_si.bin", &canon[start..end]).unwrap();
        let sig_b64 = psdsxs.split("<SignatureValue>").nth(1).unwrap().split('<').next().unwrap();
        std::fs::write("/tmp/sig.bin", base64::engine::general_purpose::STANDARD.decode(sig_b64).unwrap()).unwrap();
        eprintln!("wrote /tmp/canon_si.bin ({} bytes) and /tmp/sig.bin", end - start);
    }

    #[test]
    fn verify_new_package_signed_info_canonicalization() {
        const PSDSXS: &str = "/private/tmp/hlelam/new2/package/services/digital-signature/xml-signature/430b3e8ff3144058ab4245fcf8dae1f9.psdsxs";
        if !std::path::Path::new(PSDSXS).exists() {
            return;
        }
        let psdsxs = std::fs::read_to_string(PSDSXS).unwrap();
        let object_hash_b64 = psdsxs
            .split("URI=\"#idPackageObject\"")
            .nth(1)
            .and_then(|s| s.split("<DigestValue>").nth(1))
            .and_then(|s| s.split('<').next())
            .unwrap();
        let from_file = {
            let si_start = psdsxs.find("<SignedInfo>").unwrap();
            let si_end =
                psdsxs[si_start..].find("</SignedInfo>").unwrap() + "</SignedInfo>".len() + si_start;
            let signed_info_doc = &psdsxs[si_start..si_end];
            let wrapped = format!(
                "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{signed_info_doc}</Signature>"
            );
            let canon_full = c14n(wrapped.as_bytes()).unwrap();
            let canon_str = std::str::from_utf8(&canon_full).unwrap();
            let start = canon_str.find("<SignedInfo").unwrap();
            let end = canon_str.find("</SignedInfo>").unwrap() + "</SignedInfo>".len();
            canon_full[start..end].to_vec()
        };
        let at_sign_time =
            crate::xml_sig::build_signed_info_xml(object_hash_b64, DigestAlgorithm::Sha256).unwrap();
        eprintln!("canon from file len: {}", from_file.len());
        eprintln!("canon at sign len: {}", at_sign_time.len());
        if from_file != at_sign_time {
            let fs = std::str::from_utf8(&from_file).unwrap();
            let ss = std::str::from_utf8(&at_sign_time).unwrap();
            for (i, (a, b)) in fs.bytes().zip(ss.bytes()).enumerate() {
                if a != b {
                    eprintln!("first diff at {i}: file={a:02x} sign={b:02x}");
                    eprintln!("file context: {:?}", &fs[i.saturating_sub(20)..(i + 40).min(fs.len())]);
                    eprintln!("sign context: {:?}", &ss[i.saturating_sub(20)..(i + 40).min(ss.len())]);
                    break;
                }
            }
        }
        assert_eq!(from_file, at_sign_time, "SignedInfo canonical form mismatch");
    }

    /// Verify canonical Object digest in SignedInfo matches our c14n.
    #[test]
    fn verify_new_package_object_digest() {
        const PSDSXS: &str = "/private/tmp/hlelam/new2/package/services/digital-signature/xml-signature/430b3e8ff3144058ab4245fcf8dae1f9.psdsxs";
        if !std::path::Path::new(PSDSXS).exists() {
            return;
        }
        let psdsxs = std::fs::read_to_string(PSDSXS).unwrap();
        let expected = psdsxs
            .split("URI=\"#idPackageObject\"")
            .nth(1)
            .and_then(|s| s.split("<DigestValue>").nth(1))
            .and_then(|s| s.split('<').next())
            .unwrap();
        let start = psdsxs.find("<Object Id=\"idPackageObject\">").unwrap();
        let end = psdsxs[start..].find("</Object>").unwrap() + "</Object>".len() + start;
        let object_inner = &psdsxs[start..end];
        let wrapped = format!(
            "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{object_inner}</Signature>"
        );
        let canon_full = c14n(wrapped.as_bytes()).unwrap();
        let canon_str = std::str::from_utf8(&canon_full).unwrap();
        let obj_start = canon_str.find("<Object").unwrap();
        let obj_end = canon_str.find("</Object>").unwrap() + "</Object>".len();
        let canon_object = &canon_full[obj_start..obj_end];
        let computed = B64.encode(DigestAlgorithm::Sha256.hash(canon_object));
        eprintln!("expected object digest: {expected}");
        eprintln!("computed object digest: {computed}");
        assert_eq!(expected, computed);
    }

    /// Verify manifest digests in `/private/tmp/hlelam/new` match our algorithms.
    #[test]
    fn verify_new_package_manifest_digests() {
        const PKG: &str = "/private/tmp/hlelam/new2";
        const PSDSXS: &str = "/private/tmp/hlelam/new2/package/services/digital-signature/xml-signature/430b3e8ff3144058ab4245fcf8dae1f9.psdsxs";
        if !std::path::Path::new(PSDSXS).exists() {
            eprintln!("skip verify_new_package_manifest_digests: package not present");
            return;
        }
        let psdsxs = std::fs::read_to_string(PSDSXS).unwrap();
        let manifest_rels: Vec<(&str, &str)> = psdsxs
            .split("<Reference URI=\"")
            .skip(1)
            .filter_map(|chunk| {
                let uri = chunk.split('"').next()?;
                if uri.starts_with('#') {
                    return None;
                }
                let dv = chunk.split("<DigestValue>").nth(1)?.split('<').next()?;
                Some((uri, dv))
            })
            .collect();

        let rels_raw = std::fs::read(format!("{PKG}/_rels/.rels")).unwrap();
        let c14n_rels = c14n(&rels_raw).unwrap();
        let hash_rels = B64.encode(DigestAlgorithm::Sha256.hash(&c14n_rels));

        let pkg_rels = parse_rels(&rels_raw).unwrap();
        let pkg = OpcPackage {
            path: std::path::PathBuf::from(PKG),
            entries: HashMap::new(),
            content_types: vec![],
            pkg_rels,
        };
        let filtered = filtered_package_relationships(&pkg);
        let filtered_refs: Vec<&OpcRelationship> = filtered.iter().collect();
        let filtered_xml = build_filtered_rels_xml(&filtered_refs);
        let c14n_filt = c14n(filtered_xml.as_bytes()).unwrap();
        let hash_filt = B64.encode(DigestAlgorithm::Sha256.hash(&c14n_filt));

        let mut mismatches = Vec::new();
        for (uri, expected) in &manifest_rels {
            if uri.contains("_rels/.rels") {
                continue;
            }
            let path = uri.split('?').next().unwrap().trim_start_matches('/');
            let full = format!("{PKG}/{path}");
            if !std::path::Path::new(&full).exists() {
                continue;
            }
            let raw = std::fs::read(&full).unwrap();
            let computed = B64.encode(DigestAlgorithm::Sha256.hash(&raw));
            if computed != *expected {
                mismatches.push(format!("{path}: expected {expected} got {computed}"));
            }
        }

        eprintln!("manifest rels entries: {}", manifest_rels.len());
        eprintln!("c14n _rels/.rels: {hash_rels}");
        eprintln!("c14n filtered rels: {hash_filt}");
        for (uri, dv) in &manifest_rels {
            if uri.contains("_rels/.rels") {
                eprintln!("manifest _rels digest in file: {dv}");
            }
        }
        // Find both _rels digests in manifest
        let rels_digests: Vec<&str> = manifest_rels
            .iter()
            .filter(|(u, _)| u.contains("_rels/.rels"))
            .map(|(_, d)| *d)
            .collect();
        eprintln!("manifest _rels digests: {:?}", rels_digests);
        eprintln!("computed c14n raw rels matches first? {}", rels_digests.first() == Some(&hash_rels.as_str()));
        eprintln!("computed filtered matches second? {}", rels_digests.get(1) == Some(&hash_filt.as_str()));

        assert!(
            mismatches.is_empty(),
            "raw part digest mismatches: {mismatches:?}"
        );
        assert_eq!(rels_digests.first(), Some(&hash_rels.as_str()));
        assert_eq!(rels_digests.get(1), Some(&hash_filt.as_str()));
    }

    #[test]
    fn unique_source_types_dedupes_telemetry() {
        let rels = vec![
            OpcRelationship::new("r1", "http://example.com/telemetry", "/a"),
            OpcRelationship::new("r2", "http://example.com/coredata", "/b"),
            OpcRelationship::new("r3", "http://example.com/telemetry", "/c"),
        ];
        let refs: Vec<&OpcRelationship> = rels.iter().collect();
        let types = unique_relationship_source_types(&refs);
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], "http://example.com/telemetry");
        assert_eq!(types[1], "http://example.com/coredata");
    }

    #[test]
    fn filtered_rels_exclude_origin_by_target() {
        let pkg = OpcPackage {
            path: std::path::PathBuf::from("test.hlkx"),
            entries: HashMap::new(),
            content_types: vec![],
            pkg_rels: vec![
                OpcRelationship::new("r1", REL_DS_ORIGIN, DS_ORIGIN_PART_PATH),
                OpcRelationship::new("r2", "http://example.com/other", "/part.bin"),
            ],
        };
        let filtered = filtered_package_relationships(&pkg);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "r2");
    }
}

/// Compute the certificate file name: serial number bytes, hex-encoded.
fn cert_der_filename(cert_der: &[u8]) -> Result<String> {
    // Parse the DER certificate to extract the serial number.
    let cert = Certificate::from_der(cert_der)
        .context("Failed to parse certificate DER")?;
    let bytes = cert.tbs_certificate.serial_number.as_bytes();
    // Don't reverse the hex. C# had some broken code that appeared to reverse
    // it, but actually doesn't.
    let hex_str = hex::encode_upper(bytes);
    Ok(format!("{}.cer", hex_str))
}
