//! OPC (Open Packaging Conventions) package manipulation.
//!
//! An OPC package is a ZIP file with:
//!  - `[Content_Types].xml`  – maps file extensions / part names to MIME types
//!  - `_rels/.rels`          – package-level relationships
//!  - arbitrary parts (files)

use anyhow::Result;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use zip::ZipArchive;

// ─────────────────────────────────────────────────────────────────────────────
// Well-known strings
// ─────────────────────────────────────────────────────────────────────────────

pub const CONTENT_TYPES_XML: &str = "[Content_Types].xml";
pub const GLOBAL_RELS: &str = "_rels/.rels";

/// Well-known namespace for OPC relationships.
#[allow(dead_code)]
pub const NS_RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
/// Well-known namespace for OPC content types.
#[allow(dead_code)]
pub const NS_CONTENT_TYPES: &str =
    "http://schemas.openxmlformats.org/package/2006/content-types";

pub const REL_DS_ORIGIN: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
pub const REL_DS_SIGNATURE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
pub const REL_DS_CERTIFICATE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate";

pub const MIME_DS_ORIGIN: &str =
    "application/vnd.openxmlformats-package.digital-signature-origin";
pub const MIME_DS_SIGNATURE: &str =
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
pub const MIME_DS_CERTIFICATE: &str =
    "application/vnd.openxmlformats-package.digital-signature-certificate";
pub const MIME_RELS: &str =
    "application/vnd.openxmlformats-package.relationships+xml";
/// Default part content type when no `[Content_Types].xml` entry matches (matches
/// `OpcKnownMimeTypes.OctetString` in the C# tool).
pub const MIME_OCTET: &str = "application/octet";

/// Origin part URI used when filtering package relationships for signing (matches
/// `XTable.ID.OriginFileUri` / in-memory `OpcRelationship.Target` in the C# tool).
pub const DS_ORIGIN_PART_URI: &str =
    "package:///package/services/digital-signature/origin.psdsor";

/// `Target` attribute form written to `_rels/.rels` (matches `Uri.ToQualifiedPath()`).
pub const DS_ORIGIN_PART_PATH: &str = "/package/services/digital-signature/origin.psdsor";

/// Extension token used with `[Content_Types].xml` lookup, mirroring .NET
/// `Path.GetExtension(partPath)?.TrimStart('.')` on `OpcPart` paths.
///
/// Rust's [`std::path::Path::extension`] returns `None` for file names like
/// `.rels` (a leading dot before the extension), which would incorrectly fall
/// back to [`MIME_OCTET`] (`application/octet`) for `/_rels/.rels`.
pub fn extension_for_opc_content_type(part_path: &str) -> &str {
    let file = part_path.rsplit('/').next().unwrap_or(part_path);
    file.rfind('.').map(|i| &file[i + 1..]).unwrap_or("")
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcRelationship
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OpcRelationship {
    pub id: String,
    pub rel_type: String,
    pub target: String,
}

impl OpcRelationship {
    pub fn new(id: impl Into<String>, rel_type: impl Into<String>, target: impl Into<String>) -> Self {
        Self { id: id.into(), rel_type: rel_type.into(), target: target.into() }
    }
}

/// Decode a `_rels/*.rels` XML byte stream into a list of relationships.
pub fn parse_rels(xml: &[u8]) -> Result<Vec<OpcRelationship>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut rels = Vec::new();
    loop {
        match reader.read_event()? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => {
                if e.local_name().as_ref() == b"Relationship" {
                    let mut id = String::new();
                    let mut rel_type = String::new();
                    let mut target = String::new();
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.local_name().as_ref())?.to_string();
                        let val = attr.decode_and_unescape_value(reader.decoder())?.to_string();
                        match key.as_str() {
                            "Id" => id = val,
                            "Type" => rel_type = val,
                            "Target" => target = val,
                            _ => {}
                        }
                    }
                    rels.push(OpcRelationship::new(id, rel_type, target));
                }
            }
            _ => {}
        }
    }
    Ok(rels)
}

/// Serialize a list of relationships to a `_rels/*.rels` XML byte stream.
///
/// The output is NOT a C14N document; it is the normal on-disk form used by
/// OPC packages (UTF-8 with XML declaration).
pub fn serialize_rels(rels: &[OpcRelationship]) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>".to_vec();
    out.extend_from_slice(
        b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
    );
    // Sort by Id for determinism.
    let mut sorted: Vec<&OpcRelationship> = rels.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    for rel in &sorted {
        // Attribute order matches `OpcRelationships.ToXml` in the C# tool.
        out.extend_from_slice(b"<Relationship");
        write!(out, " Type=\"{}\"", xml_escape_attr(&rel.rel_type)).unwrap();
        write!(out, " Target=\"{}\"", xml_escape_attr(&rel.target)).unwrap();
        write!(out, " Id=\"{}\"", xml_escape_attr(&rel.id)).unwrap();
        out.extend_from_slice(b" />");
    }
    out.extend_from_slice(b"</Relationships>");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcContentType
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum OpcContentTypeEntry {
    Default { extension: String, content_type: String },
    Override { part_name: String, content_type: String },
}

pub fn parse_content_types(xml: &[u8]) -> Result<Vec<OpcContentTypeEntry>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut entries = Vec::new();
    loop {
        match reader.read_event()? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => {
                let lname = e.local_name();
                if lname.as_ref() == b"Default" {
                    let mut ext = String::new();
                    let mut ct = String::new();
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.local_name().as_ref())?.to_string();
                        let val = attr.decode_and_unescape_value(reader.decoder())?.to_string();
                        match key.as_str() {
                            "Extension" => ext = val,
                            "ContentType" => ct = val,
                            _ => {}
                        }
                    }
                    entries.push(OpcContentTypeEntry::Default {
                        extension: ext,
                        content_type: ct,
                    });
                } else if lname.as_ref() == b"Override" {
                    let mut part = String::new();
                    let mut ct = String::new();
                    for attr in e.attributes().flatten() {
                        let key = std::str::from_utf8(attr.key.local_name().as_ref())?.to_string();
                        let val = attr.decode_and_unescape_value(reader.decoder())?.to_string();
                        match key.as_str() {
                            "PartName" => part = val,
                            "ContentType" => ct = val,
                            _ => {}
                        }
                    }
                    entries.push(OpcContentTypeEntry::Override {
                        part_name: part,
                        content_type: ct,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(entries)
}

pub fn serialize_content_types(entries: &[OpcContentTypeEntry]) -> Vec<u8> {
    let mut out = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>".to_vec();
    out.extend_from_slice(b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
    for entry in entries {
        match entry {
            OpcContentTypeEntry::Default { extension, content_type } => {
                write!(
                    out,
                    "<Default ContentType=\"{}\" Extension=\"{}\" />",
                    xml_escape_attr(content_type),
                    xml_escape_attr(extension),
                ).unwrap();
            }
            OpcContentTypeEntry::Override { part_name, content_type } => {
                write!(
                    out,
                    "<Override ContentType=\"{}\" PartName=\"{}\" />",
                    xml_escape_attr(content_type),
                    xml_escape_attr(part_name),
                ).unwrap();
            }
        }
    }
    out.extend_from_slice(b"</Types>");
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// OpcPackage
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory representation of all ZIP entries, ready for modification before
/// writing the updated package back to disk.
pub struct OpcPackage {
    /// path of the original file (for writing back)
    pub path: std::path::PathBuf,
    /// All ZIP entries keyed by their path (e.g. `"_rels/.rels"`).
    pub entries: HashMap<String, Vec<u8>>,
    /// Parsed content types.
    pub content_types: Vec<OpcContentTypeEntry>,
    /// Package-level relationships.
    pub pkg_rels: Vec<OpcRelationship>,
}

impl OpcPackage {
    /// Read an HLKX/VSIX file into memory so parts can be modified and
    /// then written back with [`OpcPackage::save`].
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = std::fs::File::open(&path)?;
        let mut archive = ZipArchive::new(file)?;

        let mut entries: HashMap<String, Vec<u8>> = HashMap::new();
        let mut content_types = Vec::new();
        let mut pkg_rels = Vec::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;

            if name.eq_ignore_ascii_case(CONTENT_TYPES_XML) {
                content_types = parse_content_types(&buf)?;
                // keep raw bytes in entries too so we can rebuild later
            } else if name == GLOBAL_RELS {
                pkg_rels = parse_rels(&buf)?;
            }
            entries.insert(name, buf);
        }

        Ok(Self { path, entries, content_types, pkg_rels })
    }

    /// Return the raw bytes of a part (ZIP entry).
    #[allow(dead_code)]
    pub fn get_part(&self, name: &str) -> Option<&Vec<u8>> {
        self.entries.get(name)
    }

    /// Insert or replace a part's bytes.
    pub fn set_part(&mut self, name: impl Into<String>, data: Vec<u8>) {
        self.entries.insert(name.into(), data);
    }

    /// True if the package already contains a digital-signature origin file.
    pub fn has_signatures(&self) -> bool {
        self.pkg_rels
            .iter()
            .any(|r| r.rel_type == REL_DS_ORIGIN)
    }

    /// Look up the MIME content-type for a given file extension.
    /// Falls back to [`MIME_OCTET`] if not found.
    pub fn content_type_for_extension(&self, ext: &str) -> &str {
        for entry in &self.content_types {
            if let OpcContentTypeEntry::Default { extension, content_type } = entry {
                if extension.eq_ignore_ascii_case(ext) {
                    return content_type.as_str();
                }
            }
        }
        MIME_OCTET
    }

    /// Effective content type for a package part path (e.g. `hck/data/foo`).
    ///
    /// OPC `[Content_Types].xml` `Override` entries take precedence over
    /// `Default` extension rules. Microsoft validators resolve the
    /// `?ContentType=` query on manifest references this way.
    pub fn content_type_for_part(&self, part_path: &str) -> &str {
        let part_uri = entry_to_uri(part_path);
        for entry in &self.content_types {
            if let OpcContentTypeEntry::Override { part_name, content_type } = entry {
                if part_name.eq_ignore_ascii_case(&part_uri) {
                    return content_type.as_str();
                }
            }
        }
        self.content_type_for_extension(extension_for_opc_content_type(part_path))
    }

    /// Ensure that `<Default Extension="…" ContentType="…" />` exists.
    pub fn ensure_content_type(&mut self, extension: &str, mime: &str) {
        let already_there = self.content_types.iter().any(|e| match e {
            OpcContentTypeEntry::Default { extension: ext, .. } => {
                ext.eq_ignore_ascii_case(extension)
            }
            _ => false,
        });
        if !already_there {
            self.content_types.push(OpcContentTypeEntry::Default {
                extension: extension.to_string(),
                content_type: mime.to_string(),
            });
        }
    }

    /// Generate a unique relationship ID not already present in `rels`.
    pub fn new_rel_id(rels: &[OpcRelationship]) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Use a simple counter seeded with nanoseconds for uniqueness.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut counter = seed as u64;
        loop {
            counter = counter.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let id = format!("R{:016x}", counter);
            if !rels.iter().any(|r| r.id == id) {
                return id;
            }
        }
    }

    /// Write the modified package back to the original file.
    ///
    /// The procedure is: write a new ZIP to a temp file, then replace the
    /// original atomically (best-effort on Windows).
    pub fn save(&mut self) -> Result<()> {
        // Rebuild serialised forms of the mutable pieces.
        let ct_bytes = serialize_content_types(&self.content_types);
        let rels_bytes = serialize_rels(&self.pkg_rels);
        self.entries.insert(CONTENT_TYPES_XML.to_string(), ct_bytes);
        self.entries.insert(GLOBAL_RELS.to_string(), rels_bytes);

        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        let tmp = tempfile::NamedTempFile::new_in(dir)?;
        {
            let mut writer = zip::ZipWriter::new(tmp.as_file());
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            // Write every entry (sorted for determinism, content-types last).
            let mut names: Vec<&String> = self.entries.keys().collect();
            names.sort();
            for name in names {
                let data = &self.entries[name];
                writer.start_file(name, options)?;
                writer.write_all(data)?;
            }
            writer.finish()?;
        }
        tmp.persist(&self.path)?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return an XML attribute-safe version of `s` (escaping `&`, `<`, `>`, `"`).
pub fn xml_escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Derive the relationships file path for a given part path.
/// E.g. `"package/services/foo.psdsxs"` →
///      `"package/services/_rels/foo.psdsxs.rels"`.
pub fn rels_path_for_part(part_path: &str) -> String {
    match part_path.rfind('/') {
        Some(slash) => {
            let dir = &part_path[..slash];
            let file = &part_path[slash + 1..];
            format!("{}/_rels/{}.rels", dir, file)
        }
        None => format!("_rels/{}.rels", part_path),
    }
}

/// Normalize a relationship `Target` to a leading-slash package path.
pub fn normalize_relationship_target(target: &str) -> String {
    let t = target.trim();
    if let Some(rest) = t.strip_prefix("package:///") {
        if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        }
    } else if let Some(rest) = t.strip_prefix("package:/") {
        let rest = rest.trim_start_matches('/');
        format!("/{rest}")
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// True when `target` refers to the digital-signature origin part (matches
/// `OpcSignatureManifest.GetRelationships` in the C# implementation).
pub fn is_digital_signature_origin_target(target: &str) -> bool {
    normalize_relationship_target(target) == DS_ORIGIN_PART_PATH
}

/// Map a ZIP entry path to a URI-style path (e.g. `"/foo/bar.xml"`).
pub fn entry_to_uri(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

/// Read a ZIP entry from the archive by name, returning its bytes.
#[allow(dead_code)]
pub fn read_entry(zip_bytes: &[u8], name: &str) -> Result<Vec<u8>> {
    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor)?;
    let mut entry = archive.by_name(name)?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}
