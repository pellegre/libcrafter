//! Byte-preserving DNS name type and its wire codec/presentation helpers.

use core::str;

use crate::error::{CrafterError, Result};

use super::{
    DNS_MAX_LABEL_LEN, DNS_MAX_NAME_WIRE_LEN, DNS_NAME_POINTER_MASK, DNS_NAME_POINTER_TAG,
};

/// A DNS owner or target name preserved as wire labels.
///
/// DNS labels are byte sequences, not text (RFC 1035 Section 3.1). Most names
/// are text-compatible and round trip through the ergonomic trailing-dot string
/// API, but the wire format permits arbitrary octets in a label. `DnsName`
/// keeps the exact label bytes so non-text names are not silently lost, while
/// still exposing a stable presentation string.
///
/// The presentation string uses the RFC 1035 Section 5.1 master-file escaping
/// convention so non-text and special bytes survive a string round trip:
///
/// - bytes outside the printable ASCII range, and `.` or `\` inside a label,
///   are written as `\DDD` (a backslash followed by exactly three decimal
///   digits, the octet value), matching RFC 1035 Section 5.1 and RFC 4343
///   Section 2.1.
/// - printable ASCII bytes are written verbatim.
/// - the trailing dot terminates the name; the root name is `"."`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
    presentation: String,
}

impl DnsName {
    /// Build a name from raw wire labels (each label is a byte slice, the root
    /// label is the empty list).
    ///
    /// Returns an error when a label exceeds 63 bytes or the encoded name would
    /// exceed the 255-octet wire limit (RFC 1035 Section 2.3.4).
    pub fn from_labels<I, L>(labels: I) -> Result<Self>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let labels: Vec<Vec<u8>> = labels
            .into_iter()
            .map(|label| label.as_ref().to_vec())
            .collect();
        validate_labels(&labels)?;
        let presentation = labels_to_presentation(&labels);
        Ok(Self {
            labels,
            presentation,
        })
    }

    /// Parse a presentation-form name, honoring the RFC 1035 Section 5.1
    /// `\DDD` and `\X` escapes so non-text labels can be expressed as text.
    ///
    /// A trailing dot is accepted and canonical; a bare relative name is
    /// treated as fully qualified.
    pub fn parse(name: &str) -> Result<Self> {
        let labels = presentation_to_labels(name)?;
        validate_labels(&labels)?;
        let presentation = labels_to_presentation(&labels);
        Ok(Self {
            labels,
            presentation,
        })
    }

    /// The root name (`"."`).
    pub fn root() -> Self {
        Self {
            labels: Vec::new(),
            presentation: ".".to_string(),
        }
    }

    /// Stable presentation string in canonical trailing-dot form.
    ///
    /// Text-compatible names match the historical string form exactly;
    /// non-text labels use `\DDD` escapes.
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Exact wire-label bytes, in order. The root name yields an empty slice.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// True when every label is valid UTF-8 with no byte requiring an escape,
    /// so the presentation string is a faithful text rendering.
    pub fn is_text(&self) -> bool {
        self.labels.iter().all(|label| label_is_text(label))
    }

    pub(super) fn encoded_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| 1 + label.len())
            .sum::<usize>()
            + 1
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut wire_len = 1usize;
        for label in &self.labels {
            if label.is_empty() {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "empty label inside DNS name",
                ));
            }
            if label.len() > DNS_MAX_LABEL_LEN {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "label exceeds 63 bytes",
                ));
            }
            wire_len += 1 + label.len();
            if wire_len > DNS_MAX_NAME_WIRE_LEN {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "encoded name exceeds 255 bytes",
                ));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        Ok(())
    }
}

impl From<&str> for DnsName {
    /// Lossy convenience conversion used by builders. Falls back to the root
    /// name when the input cannot be parsed so infallible builder call sites
    /// keep compiling; use [`DnsName::parse`] when an error is meaningful.
    fn from(name: &str) -> Self {
        DnsName::parse(name).unwrap_or_else(|_| DnsName::root())
    }
}

impl From<String> for DnsName {
    fn from(name: String) -> Self {
        DnsName::from(name.as_str())
    }
}

/// Decode a DNS name from a full DNS message and byte offset.
///
/// The returned offset is the number of bytes consumed at the original offset,
/// so compressed names return the two-byte pointer length. The name is returned
/// in canonical trailing-dot presentation form; non-text labels are rendered
/// with `\DDD` escapes (RFC 1035 Section 5.1). Use [`decode_dns_name_typed`] to
/// recover the exact wire-label bytes.
pub fn decode_dns_name(message: &[u8], offset: usize) -> Result<(String, usize)> {
    let (name, used) = decode_dns_name_typed(message, offset)?;
    Ok((name.presentation().to_string(), used))
}

/// Decode a DNS name into a byte-preserving [`DnsName`].
///
/// Behaves like [`decode_dns_name`] but keeps the exact wire-label bytes, so
/// labels that are not valid UTF-8 round trip without loss. Compression
/// pointers are followed; cycles, reserved markers, out-of-range pointers,
/// truncated pointers, label-length overrun, and full-name length overrun all
/// return structured [`CrafterError`] values rather than panicking.
pub fn decode_dns_name_typed(message: &[u8], offset: usize) -> Result<(DnsName, usize)> {
    if offset >= message.len() {
        return Err(CrafterError::buffer_too_short(
            "dns.name",
            offset + 1,
            message.len(),
        ));
    }

    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut wire_len = 1usize;
    let mut cursor = offset;
    let mut consumed = None;
    let mut visited = Vec::new();

    loop {
        if cursor >= message.len() {
            return Err(CrafterError::buffer_too_short(
                "dns.name",
                cursor + 1,
                message.len(),
            ));
        }
        if visited.contains(&cursor) {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "compressed name pointer cycle",
            ));
        }
        visited.push(cursor);

        let length = message[cursor];
        match length & DNS_NAME_POINTER_MASK {
            0x00 => {
                if length == 0 {
                    let used = match consumed {
                        Some(consumed) => consumed,
                        None => cursor
                            .checked_add(1)
                            .and_then(|end| end.checked_sub(offset))
                            .ok_or_else(|| {
                                CrafterError::invalid_field_value(
                                    "dns.name",
                                    "name cursor moved before original offset",
                                )
                            })?,
                    };
                    let presentation = labels_to_presentation(&labels);
                    return Ok((
                        DnsName {
                            labels,
                            presentation,
                        },
                        used,
                    ));
                }

                let label_len = length as usize;
                if label_len > DNS_MAX_LABEL_LEN {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "label exceeds 63 bytes",
                    ));
                }
                let label_start = cursor + 1;
                let label_end = label_start + label_len;
                if label_end > message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.label",
                        label_end,
                        message.len(),
                    ));
                }
                wire_len += 1 + label_len;
                if wire_len > DNS_MAX_NAME_WIRE_LEN {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "decoded name exceeds 255 bytes",
                    ));
                }
                labels.push(message[label_start..label_end].to_vec());
                cursor = label_end;
            }
            DNS_NAME_POINTER_TAG => {
                if cursor + 1 >= message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.pointer",
                        cursor + 2,
                        message.len(),
                    ));
                }
                let pointer = (((length & 0x3f) as usize) << 8) | (message[cursor + 1] as usize);
                if pointer >= message.len() {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name.pointer",
                        "pointer offset is outside the DNS message",
                    ));
                }
                if consumed.is_none() {
                    consumed = Some(cursor + 2 - offset);
                }
                cursor = pointer;
            }
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "reserved label length marker",
                ))
            }
        }
    }
}

/// Validate decoded or constructed labels against the RFC 1035 length bounds:
/// each label is at most 63 octets (Section 2.3.4) and the encoded name is at
/// most 255 octets including the per-label length bytes and the root
/// terminator.
fn validate_labels(labels: &[Vec<u8>]) -> Result<()> {
    let mut wire_len = 1usize;
    for label in labels {
        if label.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "empty label inside DNS name",
            ));
        }
        if label.len() > DNS_MAX_LABEL_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "label exceeds 63 bytes",
            ));
        }
        wire_len += 1 + label.len();
        if wire_len > DNS_MAX_NAME_WIRE_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "encoded name exceeds 255 bytes",
            ));
        }
    }
    Ok(())
}

/// True when a label is valid UTF-8 and contains only bytes that render
/// verbatim in presentation form (printable ASCII other than `.` and `\`).
fn label_is_text(label: &[u8]) -> bool {
    str::from_utf8(label).is_ok() && label.iter().all(|&byte| byte_renders_verbatim(byte))
}

/// True when a byte is printable ASCII and is neither `.` nor `\`, so it needs
/// no RFC 1035 Section 5.1 escaping.
fn byte_renders_verbatim(byte: u8) -> bool {
    byte > 0x20 && byte < 0x7f && byte != b'.' && byte != b'\\'
}

/// Render wire labels into a canonical trailing-dot presentation string using
/// the RFC 1035 Section 5.1 escaping convention (`\DDD` for octets that do not
/// render verbatim, including `.` and `\` inside a label). The root name is
/// `"."`.
fn labels_to_presentation(labels: &[Vec<u8>]) -> String {
    if labels.is_empty() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in labels {
        for &byte in label {
            if byte_renders_verbatim(byte) {
                out.push(byte as char);
            } else {
                out.push('\\');
                out.push_str(&format!("{byte:03}"));
            }
        }
        out.push('.');
    }
    out
}

/// Parse a presentation-form name into wire labels, honoring the RFC 1035
/// Section 5.1 `\DDD` (decimal octet) and `\X` (literal character) escapes. An
/// empty input or `"."` is the root name. A trailing dot is canonical and
/// stripped before splitting; a bare relative name is accepted as fully
/// qualified.
fn presentation_to_labels(name: &str) -> Result<Vec<Vec<u8>>> {
    if name.is_empty() || name == "." {
        return Ok(Vec::new());
    }

    let bytes = name.as_bytes();
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut index = 0;
    let mut saw_label = false;

    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'.' => {
                if current.is_empty() {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "empty label inside DNS name",
                    ));
                }
                labels.push(core::mem::take(&mut current));
                saw_label = true;
                index += 1;
            }
            b'\\' => {
                let next = *bytes.get(index + 1).ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        "dns.name",
                        "trailing backslash escape in DNS name",
                    )
                })?;
                if next.is_ascii_digit() {
                    if index + 3 >= bytes.len() {
                        return Err(CrafterError::invalid_field_value(
                            "dns.name",
                            "incomplete \\DDD escape in DNS name",
                        ));
                    }
                    let digits = &bytes[index + 1..index + 4];
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return Err(CrafterError::invalid_field_value(
                            "dns.name",
                            "malformed \\DDD escape in DNS name",
                        ));
                    }
                    let value = (digits[0] - b'0') as u16 * 100
                        + (digits[1] - b'0') as u16 * 10
                        + (digits[2] - b'0') as u16;
                    let octet = u8::try_from(value).map_err(|_| {
                        CrafterError::invalid_field_value(
                            "dns.name",
                            "\\DDD escape exceeds 255 in DNS name",
                        )
                    })?;
                    current.push(octet);
                    index += 4;
                } else {
                    current.push(next);
                    index += 2;
                }
            }
            other => {
                current.push(other);
                index += 1;
            }
        }
    }

    if !current.is_empty() {
        labels.push(current);
    } else if !saw_label {
        // Input was non-empty but produced no labels (e.g. only a stray dot).
        return Err(CrafterError::invalid_field_value(
            "dns.name",
            "DNS name has no labels",
        ));
    }

    Ok(labels)
}

#[cfg(test)]
mod dns_name_decode {
    use super::{decode_dns_name, decode_dns_name_typed, DnsName, DNS_MAX_LABEL_LEN};

    #[test]
    fn rejects_truncated_names_and_pointers() {
        assert!(decode_dns_name(&[3, b'w'], 0).is_err());
        assert!(decode_dns_name(&[0xc0], 0).is_err());
        assert!(decode_dns_name(&[0xc0, 0x10], 0).is_err());
    }

    #[test]
    fn rejects_pointer_cycles_and_reserved_markers() {
        assert!(decode_dns_name(&[0xc0, 0x00], 0).is_err());
        assert!(decode_dns_name(&[0x40], 0).is_err());
    }

    #[test]
    fn decodes_root_name() {
        assert_eq!(decode_dns_name(&[0], 0).unwrap(), (".".to_string(), 1));
    }

    #[test]
    fn non_text_label_decodes_and_preserves_wire_bytes() {
        // A two-byte label that is not valid UTF-8 (0xff is never a UTF-8 lead
        // byte) must decode into the byte-preserving DnsName instead of failing
        // the way a UTF-8-only decoder would.
        let message = [2u8, 0x00, 0xff, 0];
        let (name, used) = decode_dns_name_typed(&message, 0).unwrap();

        assert_eq!(used, 4);
        assert_eq!(name.labels(), &[vec![0x00, 0xff]]);
        assert!(!name.is_text());
        // RFC 1035 Section 5.1 \DDD escaping renders the exact octet values.
        assert_eq!(name.presentation(), "\\000\\255.");
    }

    #[test]
    fn non_text_presentation_round_trips_through_parse() {
        // Decoding a non-text name to its presentation string and parsing that
        // string back must recover the identical wire labels.
        let message = [3u8, 0x80, b'a', 0x2e, 0];
        let (decoded, _) = decode_dns_name_typed(&message, 0).unwrap();
        let reparsed = DnsName::parse(decoded.presentation()).unwrap();

        assert_eq!(reparsed.labels(), decoded.labels());
        assert_eq!(reparsed.presentation(), decoded.presentation());
    }

    #[test]
    fn non_text_name_decode_and_encode_preserves_original_label_bytes() {
        // The exact wire-label bytes survive a decode then re-encode cycle.
        let original = [4u8, 0x00, 0x01, 0xfe, 0xff, 0];
        let (name, _) = decode_dns_name_typed(&original, 0).unwrap();

        let mut encoded = Vec::new();
        name.encode(&mut encoded).unwrap();
        assert_eq!(encoded, original);
    }

    #[test]
    fn label_at_63_octet_boundary_round_trips() {
        let label = vec![b'a'; DNS_MAX_LABEL_LEN];
        let mut wire = Vec::new();
        wire.push(DNS_MAX_LABEL_LEN as u8);
        wire.extend_from_slice(&label);
        wire.push(0);

        let (name, used) = decode_dns_name_typed(&wire, 0).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(name.labels(), &[label]);

        let mut encoded = Vec::new();
        name.encode(&mut encoded).unwrap();
        assert_eq!(encoded, wire);
    }

    #[test]
    fn full_name_length_overrun_is_rejected() {
        // Four 63-octet labels encode to 4 * 64 + 1 = 257 wire octets, past the
        // 255-octet full-name limit, and must error rather than panic.
        let label = vec![b'a'; DNS_MAX_LABEL_LEN];
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.push(DNS_MAX_LABEL_LEN as u8);
            wire.extend_from_slice(&label);
        }
        wire.push(0);

        assert!(decode_dns_name_typed(&wire, 0).is_err());
    }
}

#[cfg(test)]
mod dns_name_parse {
    use super::{decode_dns_name_typed, DnsName};

    #[test]
    fn parses_root_name_to_empty_labels() {
        // Both the canonical "." and the empty string are the root name with no
        // labels and a "." presentation.
        for input in [".", ""] {
            let name = DnsName::parse(input).unwrap();
            assert!(name.labels().is_empty());
            assert_eq!(name.presentation(), ".");
            assert!(name.is_text());
        }
        assert_eq!(DnsName::root(), DnsName::parse(".").unwrap());
    }

    #[test]
    fn trailing_dot_and_relative_names_parse_identically() {
        // A trailing dot is canonical; a bare relative name is treated as fully
        // qualified, so both forms yield the same wire labels.
        let with_dot = DnsName::parse("trailing.example.com.").unwrap();
        let relative = DnsName::parse("trailing.example.com").unwrap();

        assert_eq!(with_dot.labels(), relative.labels());
        assert_eq!(
            with_dot.labels(),
            &[b"trailing".to_vec(), b"example".to_vec(), b"com".to_vec()]
        );
        assert_eq!(with_dot.presentation(), "trailing.example.com.");
        assert!(with_dot.is_text());
    }

    #[test]
    fn escapes_for_literal_dot_and_backslash_parse_into_one_label() {
        // RFC 1035 Section 5.1 \. and \\ escapes keep a literal '.' (0x2e) and
        // '\' (0x5c) inside a single label instead of splitting on them.
        let name = DnsName::parse("lit\\046dot\\092slash.example.com.").unwrap();
        assert_eq!(
            name.labels(),
            &[
                b"lit.dot\\slash".to_vec(),
                b"example".to_vec(),
                b"com".to_vec()
            ]
        );
        // The label is text-compatible bytes that still need escaping, so the
        // presentation re-renders the special octets.
        assert_eq!(name.labels()[0], b"lit.dot\\slash");
        assert!(!name.is_text());

        // The \X (non-digit) escape form is equivalent for '.' and '\'.
        let alt = DnsName::parse("lit\\.dot\\\\slash.example.com.").unwrap();
        assert_eq!(alt.labels(), name.labels());
    }

    #[test]
    fn decimal_escapes_parse_into_exact_non_utf8_octets() {
        // \000 and \255 are the byte-preserving form of a non-text label; the
        // parsed wire bytes are exactly 0x00 and 0xff.
        let name = DnsName::parse("\\000\\255.example.com.").unwrap();
        assert_eq!(
            name.labels(),
            &[vec![0x00, 0xff], b"example".to_vec(), b"com".to_vec()]
        );
        assert!(!name.is_text());
        assert_eq!(name.presentation(), "\\000\\255.example.com.");
    }

    #[test]
    fn non_text_presentation_round_trips_parse_decode_encode() {
        // Parsing a non-UTF-8 presentation name and re-encoding it yields the
        // same wire image a decode of those bytes recovers, so parse and decode
        // agree on the exact label octets.
        let parsed = DnsName::parse("\\000\\255.example.com.").unwrap();
        let mut encoded = Vec::new();
        parsed.encode(&mut encoded).unwrap();

        let (decoded, used) = decode_dns_name_typed(&encoded, 0).unwrap();
        assert_eq!(used, encoded.len());
        assert_eq!(decoded.labels(), parsed.labels());
        assert_eq!(decoded.presentation(), parsed.presentation());
    }

    #[test]
    fn malformed_escapes_are_rejected_without_panic() {
        // A dangling backslash and an out-of-range \DDD escape both surface as
        // structured errors rather than panicking.
        assert!(DnsName::parse("bad\\").is_err());
        assert!(DnsName::parse("bad\\99.example.com.").is_err());
        assert!(DnsName::parse("\\300.example.com.").is_err());
    }
}
