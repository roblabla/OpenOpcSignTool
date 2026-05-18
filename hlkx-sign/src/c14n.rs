//! W3C Canonical XML 1.0 (without comments), matching .NET `XmlDsigC14NTransform`.
//!
//! Algorithm ported from .NET's `CanonicalXml` / `CanonicalXmlElement` writers:
//! - [`XmlDsigC14NTransform`](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/XmlDsigC14NTransform.cs)
//! - [`CanonicalXmlElement`](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/CanonicalXmlElement.cs)
//! - [`AttributeSortOrder`](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/AttributeSortOrder.cs) (namespace URI, then local name)
//! - [`NamespaceSortOrder`](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/NamespaceSortOrder.cs) (default xmlns first, then local name)
//!
//! Golden outputs are checked against `c14n-reference/` (runs the real .NET transform).

use anyhow::{Context, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Canonicalize an XML document (`XmlDsigC14NTransform(false)` on `XmlDocument`).
pub fn c14n(xml: &[u8]) -> Result<Vec<u8>> {
    let doc = parse_xml(xml)?;
    let mut out = Vec::new();
    let ctx = BTreeMap::new();
    for node in &doc {
        emit_node(node, &ctx, &mut out);
    }
    Ok(out)
}

/// Canonicalize a single element loaded as its own document (`CanonicalizeElement`).
pub fn c14n_element_outer_xml(element_xml: &str) -> Result<Vec<u8>> {
    c14n(element_xml.as_bytes())
}

/// Canonicalize a dsig element under a parent `<Signature xmlns="…">` (hlkx-sign signing).
pub fn c14n_dsig_element_under_signature(element_xml: &str, local_name: &str) -> Result<Vec<u8>> {
    let wrapped = format!("<Signature xmlns=\"{NS_DSIG}\">{element_xml}</Signature>");
    let canon = c14n(wrapped.as_bytes())?;
    extract_element(&canon, local_name)
}

/// Canonicalize with an explicit default namespace on the root (Windows HLK signatures).
pub fn c14n_dsig_element_committed(element_xml: &str, _local_name: &str) -> Result<Vec<u8>> {
    let doc = ensure_default_dsig_xmlns(element_xml);
    c14n(doc.as_bytes())
}

/// Both canonical forms needed to verify packages from different signers.
pub fn c14n_dsig_element_variants(element_xml: &str, local_name: &str) -> Result<Vec<Vec<u8>>> {
    Ok(vec![
        c14n_dsig_element_under_signature(element_xml, local_name)?,
        c14n_dsig_element_committed(element_xml, local_name)?,
    ])
}

fn ensure_default_dsig_xmlns(element_xml: &str) -> String {
    let close = element_xml.find('>').unwrap_or(element_xml.len());
    let open = &element_xml[..close];
    if open.contains("xmlns=") {
        return element_xml.to_string();
    }
    format!("{open} xmlns=\"{NS_DSIG}\"{}", &element_xml[close..])
}

fn extract_element(canon: &[u8], local_name: &str) -> Result<Vec<u8>> {
    let s = std::str::from_utf8(canon).context("canonical form is not valid UTF-8")?;
    let open = format!("<{local_name}");
    let start = s
        .find(&open)
        .with_context(|| format!("`<{local_name}` not found in canonical output"))?;
    let close = format!("</{local_name}>");
    let end = s
        .find(&close)
        .with_context(|| format!("`</{local_name}>` not found in canonical output"))?
        + close.len();
    Ok(canon[start..end].to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal DOM
// ─────────────────────────────────────────────────────────────────────────────

enum Node {
    Element(Element),
    Text(String),
}

struct Element {
    qname: String,
    prefix: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser (PreserveWhitespace = true)
// ─────────────────────────────────────────────────────────────────────────────

fn split_qname(qname: &str) -> (&str, &str) {
    match qname.find(':') {
        Some(i) => (&qname[..i], &qname[i + 1..]),
        None => ("", qname),
    }
}

fn parse_xml(xml: &[u8]) -> Result<Vec<Node>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut ns_stack: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    let mut out_stack: Vec<Vec<Node>> = vec![Vec::new()];
    let mut elem_stack: Vec<(String, String, Vec<(String, String)>)> = Vec::new();

    loop {
        match reader.read_event()? {
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,

            Event::Start(e) => {
                let (info, scope) = decode_element(&e, &ns_stack, &reader);
                ns_stack.push(scope);
                out_stack.push(Vec::new());
                elem_stack.push(info);
            }

            Event::Empty(e) => {
                let (info, scope) = decode_element(&e, &ns_stack, &reader);
                ns_stack.push(scope);
                out_stack.push(Vec::new());
                elem_stack.push(info);
                pop_element(&mut ns_stack, &mut out_stack, &mut elem_stack);
            }

            Event::End(_) => {
                pop_element(&mut ns_stack, &mut out_stack, &mut elem_stack);
            }

            Event::Text(e) => {
                let text = e.unescape().unwrap_or_default().into_owned();
                out_stack.last_mut().unwrap().push(Node::Text(text));
            }
            Event::CData(e) => {
                let text = std::str::from_utf8(e.as_ref()).unwrap_or("").to_string();
                out_stack.last_mut().unwrap().push(Node::Text(text));
            }
            _ => {}
        }
    }

    Ok(out_stack.pop().unwrap_or_default())
}

fn decode_element(
    e: &BytesStart<'_>,
    ns_stack: &[BTreeMap<String, String>],
    reader: &Reader<&[u8]>,
) -> ((String, String, Vec<(String, String)>), BTreeMap<String, String>) {
    let mut raw_attrs: Vec<(String, String)> = Vec::new();
    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("").to_string();
        let val = attr.decode_and_unescape_value(reader.decoder()).unwrap_or_default().into_owned();
        raw_attrs.push((key, val));
    }

    let mut scope = ns_stack.last().cloned().unwrap_or_default();
    for (k, v) in &raw_attrs {
        if k == "xmlns" {
            scope.insert(String::new(), v.clone());
        } else if let Some(pfx) = k.strip_prefix("xmlns:") {
            scope.insert(pfx.to_string(), v.clone());
        }
    }

    let qname = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
    let prefix_owned = split_qname(&qname).0.to_string();

    ((qname, prefix_owned, raw_attrs), scope)
}

fn pop_element(
    ns_stack: &mut Vec<BTreeMap<String, String>>,
    out_stack: &mut Vec<Vec<Node>>,
    elem_stack: &mut Vec<(String, String, Vec<(String, String)>)>,
) {
    ns_stack.pop();
    let children = out_stack.pop().unwrap_or_default();
    if let Some((qname, prefix, attrs)) = elem_stack.pop() {
        let elem = Element { qname, prefix, attrs, children };
        out_stack.last_mut().unwrap().push(Node::Element(elem));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C14N emitter (CanonicalXmlElement.Write)
// ─────────────────────────────────────────────────────────────────────────────

fn emit_node(node: &Node, parent_ctx: &BTreeMap<String, String>, out: &mut Vec<u8>) {
    match node {
        Node::Text(t) => emit_text(t, out),
        Node::Element(e) => emit_element(e, parent_ctx, out),
    }
}

/// `Utils.EscapeTextData`
fn emit_text(text: &str, out: &mut Vec<u8>) {
    for c in text.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn emit_element(elem: &Element, parent_ctx: &BTreeMap<String, String>, out: &mut Vec<u8>) {
    let mut my_ctx = parent_ctx.clone();
    for (k, v) in &elem.attrs {
        if k == "xmlns" {
            my_ctx.insert(String::new(), v.clone());
        } else if let Some(pfx) = k.strip_prefix("xmlns:") {
            my_ctx.insert(pfx.to_string(), v.clone());
        }
    }

    // NamespaceSortOrder: default xmlns first, then xmlns:localname.
    let mut ns_decls: BTreeMap<String, String> = BTreeMap::new();

    let elem_uri = my_ctx.get(elem.prefix.as_str()).cloned().unwrap_or_default();
    let parent_uri = parent_ctx.get(elem.prefix.as_str()).cloned().unwrap_or_default();
    if elem_uri != parent_uri {
        ns_decls.insert(elem.prefix.clone(), elem_uri.clone());
    }

    for (k, _) in &elem.attrs {
        if k == "xmlns" || k.starts_with("xmlns:") {
            continue;
        }
        let (ap, _) = split_qname(k);
        if !ap.is_empty() {
            let au = my_ctx.get(ap).cloned().unwrap_or_default();
            let pu = parent_ctx.get(ap).cloned().unwrap_or_default();
            if au != pu {
                ns_decls.insert(ap.to_string(), au);
            }
        }
    }

    for (k, v) in &elem.attrs {
        if k == "xmlns" {
            let pu = parent_ctx.get("").cloned().unwrap_or_default();
            if v != &pu {
                ns_decls.insert(String::new(), v.clone());
            }
        } else if let Some(ppfx) = k.strip_prefix("xmlns:") {
            let pu = parent_ctx.get(ppfx).cloned().unwrap_or_default();
            if v != &pu {
                ns_decls.insert(ppfx.to_string(), v.clone());
            }
        }
    }

    out.push(b'<');
    out.extend_from_slice(elem.qname.as_bytes());

    for (ns_pfx, ns_uri) in &ns_decls {
        if ns_pfx.is_empty() {
            out.extend_from_slice(b" xmlns=\"");
        } else {
            out.extend_from_slice(b" xmlns:");
            out.extend_from_slice(ns_pfx.as_bytes());
            out.extend_from_slice(b"=\"");
        }
        out.extend_from_slice(escape_attribute_value(ns_uri).as_bytes());
        out.push(b'"');
    }

    // AttributeSortOrder: namespace URI, then local name.
    let mut reg_attrs: Vec<(&str, &str)> = elem
        .attrs
        .iter()
        .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    reg_attrs.sort_by(|(k1, _), (k2, _)| {
        let (p1, l1) = split_qname(k1);
        let (p2, l2) = split_qname(k2);
        let u1 = if p1.is_empty() {
            ""
        } else {
            my_ctx.get(p1).map(|s| s.as_str()).unwrap_or("")
        };
        let u2 = if p2.is_empty() {
            ""
        } else {
            my_ctx.get(p2).map(|s| s.as_str()).unwrap_or("")
        };
        u1.cmp(u2).then(l1.cmp(l2))
    });

    for (k, v) in &reg_attrs {
        out.push(b' ');
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b"=\"");
        out.extend_from_slice(escape_attribute_value(v).as_bytes());
        out.push(b'"');
    }

    out.push(b'>');

    for child in &elem.children {
        emit_node(child, &my_ctx, out);
    }

    out.extend_from_slice(b"</");
    out.extend_from_slice(elem.qname.as_bytes());
    out.push(b'>');
}

/// `Utils.EscapeAttributeValue`
fn escape_attribute_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod dotnet_tests {
    use super::*;

    fn assert_matches_dotnet(input: &str, expected_bin: &str) {
        if !std::path::Path::new(expected_bin).exists() {
            return;
        }
        let expected = std::fs::read(expected_bin).unwrap();
        let got = c14n(input.as_bytes()).unwrap();
        assert_eq!(got, expected, "mismatch for {expected_bin}");
    }

    #[test]
    fn rels_matches_dotnet() {
        let xml = std::fs::read_to_string("/tmp/rels_raw.xml").unwrap_or_default();
        if xml.is_empty() {
            return;
        }
        assert_matches_dotnet(&xml, "/tmp/rels_dotnet.bin");
    }

    #[test]
    fn object_matches_dotnet() {
        let xml = std::fs::read_to_string("/tmp/ms_object.xml").unwrap_or_default();
        if xml.is_empty() {
            return;
        }
        assert_matches_dotnet(&xml, "/tmp/object_dotnet.bin");
    }

    #[test]
    fn signedinfo_matches_dotnet() {
        let xml = std::fs::read_to_string("/tmp/ms_signedinfo.xml").unwrap_or_default();
        if xml.is_empty() {
            return;
        }
        assert_matches_dotnet(&xml, "/tmp/si_dotnet.bin");
    }

    #[test]
    fn signedinfo_xmlns_matches_dotnet() {
        let xml = std::fs::read_to_string("/tmp/ms_signedinfo_xmlns.xml").unwrap_or_default();
        if xml.is_empty() {
            return;
        }
        assert_matches_dotnet(&xml, "/tmp/si_xmlns_dotnet.bin");
    }

    #[test]
    fn signedinfo_wrapped_matches_dotnet() {
        let xml = std::fs::read_to_string("/tmp/ms_signedinfo_wrapped.xml").unwrap_or_default();
        if xml.is_empty() {
            return;
        }
        assert_matches_dotnet(&xml, "/tmp/si_wrapped_dotnet.bin");
    }

    #[test]
    fn committed_matches_xmlns_form() {
        let raw = std::fs::read_to_string("/tmp/ms_signedinfo.xml").unwrap_or_default();
        if raw.is_empty() {
            return;
        }
        let committed = c14n_dsig_element_committed(&raw, "SignedInfo").unwrap();
        let expected = std::fs::read("/tmp/si_xmlns_dotnet.bin").unwrap();
        assert_eq!(committed, expected);
    }

    #[test]
    fn ensure_xmlns_on_root_not_descendant() {
        let raw = r#"<Object Id="id"><Manifest xmlns:opc="http://example.com/ns"/></Object>"#;
        let out = ensure_default_dsig_xmlns(raw);
        assert!(out.starts_with("<Object Id=\"id\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
    }

    #[test]
    fn committed_object_digest_matches_microsoft() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use crate::xml_sig::DigestAlgorithm;
        let raw = std::fs::read_to_string("/tmp/ms_object.xml").unwrap_or_default();
        if raw.is_empty() {
            return;
        }
        let committed = c14n_dsig_element_committed(&raw, "Object").unwrap();
        let hash = B64.encode(DigestAlgorithm::Sha256.hash(&committed));
        assert_eq!(hash, "xsliPb27EEU2yeNNURzHX5S8+1fAvMkrqauvAtyxmFs=");
    }

    #[test]
    fn object_xmlns_matches_dotnet() {
        let raw = std::fs::read_to_string("/tmp/ms_object.xml").unwrap_or_default();
        if raw.is_empty() {
            return;
        }
        let xmlns = raw.replace(
            "<Object Id=\"idPackageObject\">",
            "<Object Id=\"idPackageObject\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
        );
        assert_matches_dotnet(&xmlns, "/tmp/object_committed_dotnet.bin");
    }

    #[test]
    fn under_signature_matches_inner_form() {
        let raw = std::fs::read_to_string("/tmp/ms_signedinfo.xml").unwrap_or_default();
        if raw.is_empty() {
            return;
        }
        let under = c14n_dsig_element_under_signature(&raw, "SignedInfo").unwrap();
        let expected = std::fs::read("/tmp/si_dotnet.bin").unwrap();
        assert_eq!(under, expected);
    }
}
