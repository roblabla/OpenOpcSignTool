//! W3C Canonical XML 1.0 (without comments) implementation.
//!
//! Sufficient for the XML structures produced when signing OPC packages:
//!   - `_rels/*.rels` files
//!   - The `<Object>` element containing the signature manifest
//!   - The `<SignedInfo>` element

use anyhow::Result;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry-point
// ─────────────────────────────────────────────────────────────────────────────

/// Canonicalise XML bytes per W3C Canonical XML 1.0 (no XML declaration,
/// sorted attributes, namespace declarations before regular attributes,
/// expanded empty elements).
pub fn c14n(xml: &[u8]) -> Result<Vec<u8>> {
    let doc = parse_xml(xml)?;
    let mut out = Vec::new();
    let ctx = BTreeMap::new();
    for node in &doc {
        emit_node(node, &ctx, &mut out);
    }
    Ok(out)
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
    #[allow(dead_code)]
    ns_uri: String,
    prefix: String,
    /// All raw attributes including xmlns declarations.
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
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

    // Namespace scope stack: prefix → URI. "" = default namespace.
    let mut ns_stack: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    // Children stack: top = current element's children being collected.
    let mut out_stack: Vec<Vec<Node>> = vec![Vec::new()];
    // Pending element metadata: (qname, ns_uri, prefix, raw_attrs).
    let mut elem_stack: Vec<(String, String, String, Vec<(String, String)>)> = Vec::new();

    loop {
        match reader.read_event()? {
            // Strip declaration, comments and PIs (C14N without comments).
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
) -> ((String, String, String, Vec<(String, String)>), BTreeMap<String, String>) {
    let mut raw_attrs: Vec<(String, String)> = Vec::new();
    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("").to_string();
        let val = attr.decode_and_unescape_value(reader.decoder()).unwrap_or_default().into_owned();
        raw_attrs.push((key, val));
    }

    // Build new namespace scope.
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
    let ns_uri = if prefix_owned.is_empty() {
        scope.get("").cloned().unwrap_or_default()
    } else {
        scope.get(&prefix_owned).cloned().unwrap_or_default()
    };

    ((qname, ns_uri, prefix_owned, raw_attrs), scope)
}

fn pop_element(
    ns_stack: &mut Vec<BTreeMap<String, String>>,
    out_stack: &mut Vec<Vec<Node>>,
    elem_stack: &mut Vec<(String, String, String, Vec<(String, String)>)>,
) {
    ns_stack.pop();
    let children = out_stack.pop().unwrap_or_default();
    if let Some((qname, ns_uri, prefix, attrs)) = elem_stack.pop() {
        let elem = Element { qname, ns_uri, prefix, attrs, children };
        out_stack.last_mut().unwrap().push(Node::Element(elem));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C14N emitter
// ─────────────────────────────────────────────────────────────────────────────

fn emit_node(node: &Node, parent_ctx: &BTreeMap<String, String>, out: &mut Vec<u8>) {
    match node {
        Node::Text(t) => emit_text(t, out),
        Node::Element(e) => emit_element(e, parent_ctx, out),
    }
}

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
    // Build this element's namespace context by merging parent + own decls.
    let mut my_ctx = parent_ctx.clone();
    for (k, v) in &elem.attrs {
        if k == "xmlns" {
            my_ctx.insert(String::new(), v.clone());
        } else if let Some(pfx) = k.strip_prefix("xmlns:") {
            my_ctx.insert(pfx.to_string(), v.clone());
        }
    }

    // Determine which namespace declarations to emit.
    // C14N 1.0 (non-exclusive): emit a namespace node when its binding
    // differs from the parent context.
    let mut ns_decls: BTreeMap<String, String> = BTreeMap::new();

    // Check the element's own namespace.
    let pfx = &elem.prefix;
    let elem_uri = my_ctx.get(pfx.as_str()).cloned().unwrap_or_default();
    let parent_uri = parent_ctx.get(pfx.as_str()).cloned().unwrap_or_default();
    if elem_uri != parent_uri {
        ns_decls.insert(pfx.clone(), elem_uri.clone());
    }

    // Check attribute namespaces.
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

    // Propagate all xmlns declarations that changed relative to parent.
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

    // Start tag.
    out.push(b'<');
    out.extend_from_slice(elem.qname.as_bytes());

    // 1) Namespace declarations (BTreeMap order: "" first, then lexicographic).
    for (ns_pfx, ns_uri) in &ns_decls {
        if ns_pfx.is_empty() {
            out.extend_from_slice(b" xmlns=\"");
        } else {
            out.extend_from_slice(b" xmlns:");
            out.extend_from_slice(ns_pfx.as_bytes());
            out.extend_from_slice(b"=\"");
        }
        out.extend_from_slice(attr_escape(ns_uri).as_bytes());
        out.push(b'"');
    }

    // 2) Regular attributes sorted by (ns-URI, local-name).
    let mut reg_attrs: Vec<(&str, &str)> = elem
        .attrs
        .iter()
        .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    reg_attrs.sort_by(|(k1, _), (k2, _)| {
        let (p1, l1) = split_qname(k1);
        let (p2, l2) = split_qname(k2);
        // Namespace URI for attribute: only prefixed attributes have one.
        let u1 = if p1.is_empty() { "" } else { my_ctx.get(p1).map(|s| s.as_str()).unwrap_or("") };
        let u2 = if p2.is_empty() { "" } else { my_ctx.get(p2).map(|s| s.as_str()).unwrap_or("") };
        u1.cmp(u2).then(l1.cmp(l2))
    });

    for (k, v) in &reg_attrs {
        out.push(b' ');
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b"=\"");
        out.extend_from_slice(attr_escape(v).as_bytes());
        out.push(b'"');
    }

    out.push(b'>');

    // Children.
    for child in &elem.children {
        emit_node(child, &my_ctx, out);
    }

    // End tag.
    out.extend_from_slice(b"</");
    out.extend_from_slice(elem.qname.as_bytes());
    out.push(b'>');
}

fn attr_escape(s: &str) -> String {
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
