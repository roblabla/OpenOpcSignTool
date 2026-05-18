//! Verify OPC package digital signatures.
//!
//! Checks that embedded XML signatures are cryptographically valid (RSA PKCS#1
//! v1.5 over the canonical `<SignedInfo>`) and that every manifest digest
//! matches the current package contents.  No certificate chain or trust-anchor
//! validation is performed.

use crate::c14n::{c14n, c14n_dsig_element_committed};
use crate::opc::{
    entry_to_uri, normalize_relationship_target, parse_rels, rels_path_for_part, OpcPackage,
    OpcRelationship, GLOBAL_RELS, REL_DS_CERTIFICATE, REL_DS_ORIGIN, REL_DS_SIGNATURE,
};
use crate::signing::{build_filtered_rels_xml, digest_rels_part, filtered_package_relationships};
use crate::xml_sig::{DigestAlgorithm, TransformInfo, C14N_URL, REL_TRANSFORM_URL};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use signature::Verifier;
use std::collections::HashSet;
use x509_cert::Certificate;

/// Verify all digital signatures in `pkg`.
pub fn verify(pkg: &OpcPackage) -> Result<()> {
    if !pkg.has_signatures() {
        bail!("The package is not signed.");
    }

    let sigs = discover_signatures(pkg)?;
    if sigs.is_empty() {
        bail!("No signature parts found in the package.");
    }

    for (sig_path, cert_path) in sigs {
        eprintln!("Verifying signature: {sig_path}");
        let sig_xml = pkg
            .entries
            .get(&sig_path)
            .with_context(|| format!("signature part missing: {sig_path}"))?;
        let cert_der = pkg
            .entries
            .get(&cert_path)
            .with_context(|| format!("certificate part missing: {cert_path}"))?;

        verify_signature_xml(pkg, sig_xml, cert_der)
            .with_context(|| format!("signature verification failed for {sig_path}"))?;
    }

    Ok(())
}

/// Locate `(signature_part, certificate_part)` pairs via OPC relationships.
fn discover_signatures(pkg: &OpcPackage) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();

    for origin_rel in pkg.pkg_rels.iter().filter(|r| r.rel_type == REL_DS_ORIGIN) {
        let origin_path = normalize_relationship_target(&origin_rel.target);
        let origin_path = origin_path.trim_start_matches('/').to_string();

        let origin_rels_path = rels_path_for_part(&origin_path);
        let origin_rels_bytes = pkg
            .entries
            .get(&origin_rels_path)
            .with_context(|| format!("missing origin relationships: {origin_rels_path}"))?;
        let origin_rels = parse_rels(origin_rels_bytes)?;

        for sig_rel in origin_rels.iter().filter(|r| r.rel_type == REL_DS_SIGNATURE) {
            let sig_path = normalize_relationship_target(&sig_rel.target);
            let sig_path = sig_path.trim_start_matches('/').to_string();

            let sig_rels_path = rels_path_for_part(&sig_path);
            let sig_rels_bytes = pkg.entries.get(&sig_rels_path).with_context(|| {
                format!("missing signature relationships: {sig_rels_path}")
            })?;
            let sig_rels = parse_rels(sig_rels_bytes)?;

            for cert_rel in sig_rels.iter().filter(|r| r.rel_type == REL_DS_CERTIFICATE) {
                let cert_path = normalize_relationship_target(&cert_rel.target);
                let cert_path = cert_path.trim_start_matches('/').to_string();
                out.push((sig_path.clone(), cert_path));
            }
        }
    }

    Ok(out)
}

fn verify_signature_xml(pkg: &OpcPackage, sig_xml: &[u8], cert_der: &[u8]) -> Result<()> {
    let parsed = parse_signature_document(sig_xml)?;

    // ── 1. RSA signature over canonical SignedInfo ─────────────────────────
    let digest_alg = digest_alg_from_signature_method(&parsed.signature_method)?;
    let public_key = rsa_public_key_from_cert(cert_der)?;
    verify_signed_info_signature(
        digest_alg,
        &public_key,
        &parsed.signed_info_xml,
        &parsed.signature_value,
    )?;

    // ── 2. SignedInfo digest of the package Object ────────────────────────
    let object_hash = B64.encode(digest_alg.hash(&c14n_dsig_element_committed(&parsed.object_xml)?));
    if object_hash != parsed.object_digest_b64 {
        bail!(
            "SignedInfo Object digest mismatch (expected {}, got {})",
            parsed.object_digest_b64,
            object_hash
        );
    }

    // ── 3. Manifest part digests ──────────────────────────────────────────
    verify_manifest(pkg, &parsed.manifest_refs)?;

    Ok(())
}

struct ParsedSignature {
    signature_method: String,
    signature_value: Vec<u8>,
    signed_info_xml: String,
    object_digest_b64: String,
    object_xml: String,
    manifest_refs: Vec<ManifestReference>,
}

struct ManifestReference {
    uri: String,
    digest_b64: String,
    hash_uri: String,
    transforms: Vec<TransformInfo>,
}

fn parse_signature_document(sig_xml: &[u8]) -> Result<ParsedSignature> {
    let xml = std::str::from_utf8(sig_xml).context("signature is not valid UTF-8")?;

    let signature_value_b64 = extract_element_text(xml, "SignatureValue")?;
    let signature_value = B64
        .decode(signature_value_b64.trim())
        .context("invalid SignatureValue base64")?;

    let signature_method = extract_signature_method_algorithm(xml)?;

    let signed_info_start = xml
        .find("<SignedInfo")
        .context("missing <SignedInfo>")?;
    let signed_info_end = xml[signed_info_start..]
        .find("</SignedInfo>")
        .context("missing </SignedInfo>")?
        + "</SignedInfo>".len()
        + signed_info_start;
    let signed_info_xml = xml[signed_info_start..signed_info_end].to_string();

    let object_digest_b64 = extract_object_digest_value(xml)?;

    let object_start = xml
        .find("<Object Id=\"idPackageObject\">")
        .or_else(|| xml.find("<Object Id='idPackageObject'>"))
        .context("missing idPackageObject")?;
    let object_end = xml[object_start..]
        .find("</Object>")
        .context("missing </Object>")?
        + "</Object>".len()
        + object_start;
    let object_xml = xml[object_start..object_end].to_string();

    let manifest_refs = parse_manifest_references(&object_xml)?;

    Ok(ParsedSignature {
        signature_method,
        signature_value,
        signed_info_xml,
        object_digest_b64,
        object_xml,
        manifest_refs,
    })
}

fn extract_signature_method_algorithm(xml: &str) -> Result<String> {
    let si = xml
        .find("<SignedInfo")
        .context("missing <SignedInfo>")?;
    let chunk = &xml[si..];
    let sm = chunk
        .find("<SignatureMethod")
        .context("missing <SignatureMethod>")?;
    let attrs = &chunk[sm..];
    let algorithm = attrs
        .split("Algorithm=\"")
        .nth(1)
        .or_else(|| attrs.split("Algorithm='").nth(1))
        .context("SignatureMethod missing Algorithm")?
        .split(['\"', '\''])
        .next()
        .context("SignatureMethod Algorithm empty")?;
    Ok(algorithm.to_string())
}

fn extract_object_digest_value(xml: &str) -> Result<String> {
    let si = xml
        .find("<SignedInfo")
        .context("missing <SignedInfo>")?;
    let chunk = &xml[si..];
    let ref_pos = chunk
        .find("URI=\"#idPackageObject\"")
        .context("SignedInfo missing reference to idPackageObject")?;
    let after = &chunk[ref_pos..];
    extract_element_text(after, "DigestValue")
}

fn extract_element_text(xml: &str, local_name: &str) -> Result<String> {
    let open = format!("<{local_name}>");
    let close = format!("</{local_name}>");
    let start = xml
        .find(&open)
        .with_context(|| format!("missing <{local_name}>"))?;
    let inner_start = start + open.len();
    let end = xml[inner_start..]
        .find(&close)
        .with_context(|| format!("missing </{local_name}>"))?
        + inner_start;
    Ok(xml[inner_start..end].to_string())
}

fn parse_manifest_references(object_xml: &str) -> Result<Vec<ManifestReference>> {
    let mut refs = Vec::new();
    for chunk in object_xml.split("<Reference URI=\"").skip(1) {
        let uri = chunk
            .split('"')
            .next()
            .context("manifest Reference missing URI")?
            .to_string();

        let digest_b64 = chunk
            .split("<DigestValue>")
            .nth(1)
            .and_then(|s| s.split('<').next())
            .context("manifest Reference missing DigestValue")?
            .to_string();

        let hash_uri = chunk
            .split("DigestMethod")
            .nth(1)
            .and_then(|s| s.split("Algorithm=\"").nth(1))
            .or_else(|| chunk.split("DigestMethod").nth(1).and_then(|s| s.split("Algorithm='").nth(1)))
            .and_then(|s| s.split(['\"', '\'']).next())
            .context("manifest Reference missing DigestMethod")?
            .to_string();

        let transforms = parse_transforms(chunk)?;
        refs.push(ManifestReference {
            uri,
            digest_b64,
            hash_uri,
            transforms,
        });
    }
    Ok(refs)
}

fn parse_transforms(ref_chunk: &str) -> Result<Vec<TransformInfo>> {
    let transforms_start = match ref_chunk.find("<Transforms>") {
        Some(i) => i,
        None => return Ok(vec![]),
    };
    let transforms_end = ref_chunk[transforms_start..]
        .find("</Transforms>")
        .map(|i| i + transforms_start + "</Transforms>".len())
        .unwrap_or(ref_chunk.len());
    let block = &ref_chunk[transforms_start..transforms_end];

    let mut out = Vec::new();
    for part in block.split("<Transform").skip(1) {
        let algorithm = part
            .split("Algorithm=\"")
            .nth(1)
            .or_else(|| part.split("Algorithm='").nth(1))
            .and_then(|s| s.split(['\"', '\'']).next())
            .unwrap_or("");

        if algorithm == C14N_URL {
            out.push(TransformInfo::C14n);
        } else if algorithm == REL_TRANSFORM_URL {
            let mut source_types = Vec::new();
            for selector in part.split("opc:RelationshipsGroupReference").skip(1) {
                let st = selector
                    .split("SourceType=\"")
                    .nth(1)
                    .or_else(|| selector.split("SourceType='").nth(1))
                    .and_then(|s| s.split(['\"', '\'']).next());
                if let Some(st) = st {
                    source_types.push(st.to_string());
                }
            }
            out.push(TransformInfo::RelationshipTransform { source_types });
        }
    }
    Ok(out)
}

fn digest_alg_from_signature_method(uri: &str) -> Result<DigestAlgorithm> {
    match uri {
        crate::xml_sig::RSA_SHA1_URL => Ok(DigestAlgorithm::Sha1),
        crate::xml_sig::RSA_SHA256_URL => Ok(DigestAlgorithm::Sha256),
        crate::xml_sig::RSA_SHA384_URL => Ok(DigestAlgorithm::Sha384),
        crate::xml_sig::RSA_SHA512_URL => Ok(DigestAlgorithm::Sha512),
        other => bail!("unsupported SignatureMethod: {other}"),
    }
}

fn digest_alg_from_hash_uri(uri: &str) -> Result<DigestAlgorithm> {
    match uri {
        crate::xml_sig::SHA1_URL => Ok(DigestAlgorithm::Sha1),
        crate::xml_sig::SHA256_URL => Ok(DigestAlgorithm::Sha256),
        crate::xml_sig::SHA384_URL => Ok(DigestAlgorithm::Sha384),
        crate::xml_sig::SHA512_URL => Ok(DigestAlgorithm::Sha512),
        other => bail!("unsupported DigestMethod: {other}"),
    }
}

fn rsa_public_key_from_cert(cert_der: &[u8]) -> Result<RsaPublicKey> {
    let cert = Certificate::from_der(cert_der).context("failed to parse certificate DER")?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    RsaPublicKey::from_public_key_der(&spki.to_der()?).context("certificate is not an RSA key")
}

fn verify_signed_info_signature(
    digest_alg: DigestAlgorithm,
    public_key: &RsaPublicKey,
    signed_info_xml: &str,
    signature: &[u8],
) -> Result<()> {
    let canonical = c14n_dsig_element_committed(signed_info_xml)?;
    verify_signed_info_canonical(digest_alg, public_key, &canonical, signature)
}

fn verify_signed_info_canonical(
    digest_alg: DigestAlgorithm,
    public_key: &RsaPublicKey,
    signed_info_canonical: &[u8],
    signature: &[u8],
) -> Result<()> {
    let sig = Signature::try_from(signature).context("invalid RSA signature length")?;

    let result = match digest_alg {
        DigestAlgorithm::Sha1 => {
            VerifyingKey::<sha1::Sha1>::new(public_key.clone()).verify(signed_info_canonical, &sig)
        }
        DigestAlgorithm::Sha256 => VerifyingKey::<sha2::Sha256>::new(public_key.clone())
            .verify(signed_info_canonical, &sig),
        DigestAlgorithm::Sha384 => VerifyingKey::<sha2::Sha384>::new(public_key.clone())
            .verify(signed_info_canonical, &sig),
        DigestAlgorithm::Sha512 => VerifyingKey::<sha2::Sha512>::new(public_key.clone())
            .verify(signed_info_canonical, &sig),
    };

    result.map_err(|_| anyhow::anyhow!("RSA signature over SignedInfo is invalid"))
}

fn verify_manifest(pkg: &OpcPackage, refs: &[ManifestReference]) -> Result<()> {
    for reference in refs {
        let digest_alg = digest_alg_from_hash_uri(&reference.hash_uri)?;

        let part_path = manifest_uri_to_part_path(&reference.uri)?;
        if part_path == GLOBAL_RELS {
            let raw = pkg
                .entries
                .get(&part_path)
                .with_context(|| format!("signed part not found: {part_path}"))?;

            let computed_digests = digest_rels_part(
                &part_path,
                raw,
                pkg.content_type_for_part(&part_path),
                digest_alg,
                pkg,
            )?;

            let matched = computed_digests
                .iter()
                .any(|d| d.digest_b64 == reference.digest_b64);

            if !matched {
                bail!(
                    "digest mismatch for {}: no computed digest matches {}",
                    reference.uri,
                    reference.digest_b64
                );
            }
            continue;
        }

        let computed_b64 = compute_part_digest(pkg, reference, digest_alg)?;
        if computed_b64 != reference.digest_b64 {
            bail!(
                "digest mismatch for {}: expected {}, got {}",
                reference.uri,
                reference.digest_b64,
                computed_b64
            );
        }
    }

    verify_signed_parts_covered(pkg, refs)?;
    Ok(())
}

/// Every signable part must appear in the manifest (by URI without query).
fn verify_signed_parts_covered(pkg: &OpcPackage, refs: &[ManifestReference]) -> Result<()> {
    let manifest_uris: HashSet<String> = refs
        .iter()
        .map(|r| r.uri.split('?').next().unwrap_or(&r.uri).to_lowercase())
        .collect();

    let mut missing = Vec::new();
    for part_path in pkg.entries.keys() {
        if !crate::signing::should_sign_part(part_path) {
            continue;
        }
        let uri = entry_to_uri(part_path).to_lowercase();
        if !manifest_uris.contains(&uri) {
            missing.push(part_path.clone());
        }
    }

    if !missing.is_empty() {
        bail!(
            "package contains unsigned parts not listed in the signature manifest: {missing:?}"
        );
    }

    Ok(())
}

fn manifest_uri_to_part_path(uri: &str) -> Result<String> {
    let path = uri.split('?').next().context("empty manifest URI")?;
    Ok(path.trim_start_matches('/').to_string())
}

fn compute_part_digest(
    pkg: &OpcPackage,
    reference: &ManifestReference,
    digest_alg: DigestAlgorithm,
) -> Result<String> {
    let part_path = manifest_uri_to_part_path(&reference.uri)?;
    let data = pkg
        .entries
        .get(&part_path)
        .with_context(|| format!("signed part not found: {part_path}"))?;

    let digest_bytes = match reference.transforms.as_slice() {
        [] => digest_alg.hash(data),
        [TransformInfo::C14n] => {
            let canon = c14n(data)?;
            digest_alg.hash(&canon)
        }
        [TransformInfo::RelationshipTransform { source_types }, TransformInfo::C14n] => {
            let filtered = filtered_package_relationships(pkg);
            let filtered_refs: Vec<&OpcRelationship> = filtered.iter().collect();
            let filtered_xml = build_filtered_rels_xml_for_types(&filtered_refs, source_types);
            let canon = c14n(filtered_xml.as_bytes())?;
            digest_alg.hash(&canon)
        }
        other => bail!("unsupported transform chain for {}: {:?}", reference.uri, other),
    };

    Ok(B64.encode(&digest_bytes))
}

/// Build filtered relationships XML using manifest `SourceType` selectors (order preserved).
fn build_filtered_rels_xml_for_types(
    rels: &[&OpcRelationship],
    source_types: &[String],
) -> String {
    let allowed: HashSet<&str> = source_types.iter().map(String::as_str).collect();
    let filtered: Vec<&OpcRelationship> = rels
        .iter()
        .copied()
        .filter(|r| allowed.contains(r.rel_type.as_str()))
        .collect();
    build_filtered_rels_xml(&filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn manifest_uri_to_part_strips_query() {
        assert_eq!(
            manifest_uri_to_part_path("/_rels/.rels?ContentType=application/...")
                .unwrap(),
            "_rels/.rels"
        );
    }

    #[test]
    fn discover_requires_origin_relationship() {
        let pkg = OpcPackage {
            path: "test.hlkx".into(),
            entries: HashMap::new(),
            content_types: vec![],
            pkg_rels: vec![],
        };
        assert!(discover_signatures(&pkg).unwrap().is_empty());
    }
}
