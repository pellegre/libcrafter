//! BER TLV scaffolding for SNMP.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use crate::error::{CrafterError, Result};

pub(super) const BER_CLASS_MASK: u8 = 0xc0;
pub(super) const BER_CONSTRUCTED_MASK: u8 = 0x20;
pub(super) const BER_TAG_NUMBER_MASK: u8 = 0x1f;
pub(super) const BER_IDENTIFIER_LEN: usize = 1;
pub(super) const BER_LOW_TAG_NUMBER_MAX: u8 = BER_TAG_NUMBER_MASK - 1;
pub(super) const BER_LENGTH_SHORT_FORM_MAX: usize = 0x7f;
pub(super) const BER_LENGTH_LONG_FORM_FLAG: u8 = 0x80;
pub(super) const BER_LENGTH_LONG_FORM_OCTETS_MASK: u8 = 0x7f;
pub(super) const BER_LENGTH_FIELD_MIN_LEN: usize = 1;
pub(super) const BER_INTEGER_MIN_CONTENT_LEN: usize = 1;
pub(super) const BER_INTEGER_MAX_I64_CONTENT_LEN: usize = core::mem::size_of::<i64>();

pub(super) const BER_TAG_INTEGER: u8 = 2;
pub(super) const BER_TAG_OCTET_STRING: u8 = 4;
pub(super) const BER_TAG_NULL: u8 = 5;
pub(super) const BER_TAG_OBJECT_IDENTIFIER: u8 = 6;
pub(super) const BER_TAG_SEQUENCE: u8 = 16;

pub(super) const SNMP_APPLICATION_TAG_IP_ADDRESS: u8 = 0;
pub(super) const SNMP_APPLICATION_TAG_COUNTER32: u8 = 1;
pub(super) const SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32: u8 = 2;
pub(super) const SNMP_APPLICATION_TAG_TIME_TICKS: u8 = 3;
pub(super) const SNMP_APPLICATION_TAG_OPAQUE: u8 = 4;
pub(super) const SNMP_APPLICATION_TAG_COUNTER64: u8 = 6;

pub(super) const SNMP_CONTEXT_TAG_NO_SUCH_OBJECT: u8 = 0;
pub(super) const SNMP_CONTEXT_TAG_NO_SUCH_INSTANCE: u8 = 1;
pub(super) const SNMP_CONTEXT_TAG_END_OF_MIB_VIEW: u8 = 2;

pub(super) const SNMP_PDU_TAG_GET_REQUEST: u8 = 0;
pub(super) const SNMP_PDU_TAG_GET_NEXT_REQUEST: u8 = 1;
pub(super) const SNMP_PDU_TAG_RESPONSE: u8 = 2;
pub(super) const SNMP_PDU_TAG_SET_REQUEST: u8 = 3;
pub(super) const SNMP_PDU_TAG_TRAP: u8 = 4;
pub(super) const SNMP_PDU_TAG_GET_BULK_REQUEST: u8 = 5;
pub(super) const SNMP_PDU_TAG_INFORM_REQUEST: u8 = 6;
pub(super) const SNMP_PDU_TAG_TRAP_V2: u8 = 7;
pub(super) const SNMP_PDU_TAG_REPORT: u8 = 8;

/// BER identifier class bits used by SNMP TLVs.
///
/// The SNMP manifest records BER identifier handling through RFC 1157 Section
/// 3.2.2 and RFC 3417 Section 8. The enum intentionally models the raw BER
/// class space so unsupported but well-formed tags can stay inspectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BerClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl BerClass {
    pub(super) const fn from_identifier_octet(octet: u8) -> Self {
        match octet & BER_CLASS_MASK {
            0x00 => Self::Universal,
            0x40 => Self::Application,
            0x80 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }

    pub(super) const fn bits(self) -> u8 {
        match self {
            Self::Universal => 0x00,
            Self::Application => 0x40,
            Self::ContextSpecific => 0x80,
            Self::Private => 0xc0,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::Application => "application",
            Self::ContextSpecific => "context-specific",
            Self::Private => "private",
        }
    }
}

impl fmt::Display for BerClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Parsed metadata from an SNMP BER identifier octet.
///
/// This is not the full BER identifier codec. It records the single-octet
/// metadata shared by the later identifier, length, value, and PDU slices:
/// class, constructed bit, and low tag-number bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BerTag {
    class: BerClass,
    constructed: bool,
    number: u8,
}

impl BerTag {
    pub(super) const fn new(class: BerClass, constructed: bool, number: u8) -> Self {
        Self {
            class,
            constructed,
            number: number & BER_TAG_NUMBER_MASK,
        }
    }

    pub(super) const fn class(self) -> BerClass {
        self.class
    }

    pub(super) const fn is_constructed(self) -> bool {
        self.constructed
    }

    pub(super) const fn number(self) -> u8 {
        self.number
    }

    pub(super) const fn identifier_octet(self) -> u8 {
        self.class.bits()
            | if self.constructed {
                BER_CONSTRUCTED_MASK
            } else {
                0
            }
            | (self.number & BER_TAG_NUMBER_MASK)
    }

    pub(super) const fn from_identifier_octet(octet: u8) -> Self {
        Self {
            class: BerClass::from_identifier_octet(octet),
            constructed: octet & BER_CONSTRUCTED_MASK != 0,
            number: octet & BER_TAG_NUMBER_MASK,
        }
    }

    pub(super) fn label(self) -> String {
        if let Some(label) = self.known_label() {
            return label.to_string();
        }

        if self.constructed {
            format!("constructed-{}-{}", self.class.label(), self.number)
        } else {
            format!("{}-{}", self.class.label(), self.number)
        }
    }

    fn known_label(self) -> Option<&'static str> {
        match (self.class, self.constructed, self.number) {
            (BerClass::Universal, false, BER_TAG_INTEGER) => Some("integer"),
            (BerClass::Universal, false, BER_TAG_OCTET_STRING) => Some("octet-string"),
            (BerClass::Universal, false, BER_TAG_NULL) => Some("null"),
            (BerClass::Universal, false, BER_TAG_OBJECT_IDENTIFIER) => Some("object-identifier"),
            (BerClass::Universal, true, BER_TAG_SEQUENCE) => Some("sequence"),
            (BerClass::Application, false, SNMP_APPLICATION_TAG_IP_ADDRESS) => Some("ip-address"),
            (BerClass::Application, false, SNMP_APPLICATION_TAG_COUNTER32) => Some("counter32"),
            (BerClass::Application, false, SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32) => {
                Some("gauge32-or-unsigned32")
            }
            (BerClass::Application, false, SNMP_APPLICATION_TAG_TIME_TICKS) => Some("time-ticks"),
            (BerClass::Application, false, SNMP_APPLICATION_TAG_OPAQUE) => Some("opaque"),
            (BerClass::Application, false, SNMP_APPLICATION_TAG_COUNTER64) => Some("counter64"),
            (BerClass::ContextSpecific, false, SNMP_CONTEXT_TAG_NO_SUCH_OBJECT) => {
                Some("no-such-object")
            }
            (BerClass::ContextSpecific, false, SNMP_CONTEXT_TAG_NO_SUCH_INSTANCE) => {
                Some("no-such-instance")
            }
            (BerClass::ContextSpecific, false, SNMP_CONTEXT_TAG_END_OF_MIB_VIEW) => {
                Some("end-of-mib-view")
            }
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_GET_REQUEST) => Some("get-request"),
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_GET_NEXT_REQUEST) => {
                Some("get-next-request")
            }
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_RESPONSE) => Some("response"),
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_SET_REQUEST) => Some("set-request"),
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_TRAP) => Some("trap"),
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_GET_BULK_REQUEST) => {
                Some("get-bulk-request")
            }
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_INFORM_REQUEST) => {
                Some("inform-request")
            }
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_TRAP_V2) => Some("snmpv2-trap"),
            (BerClass::ContextSpecific, true, SNMP_PDU_TAG_REPORT) => Some("report"),
            _ => None,
        }
    }
}

impl fmt::Display for BerTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

pub(super) fn decode_identifier(bytes: &[u8]) -> Result<(BerTag, &[u8])> {
    let Some((&octet, rest)) = bytes.split_first() else {
        return Err(truncated_identifier(bytes.len()));
    };

    let tag = BerTag::from_identifier_octet(octet);
    if tag.number() > BER_LOW_TAG_NUMBER_MAX {
        return Err(invalid_ber_field(
            "snmp.ber.identifier",
            "high-tag-number form is not supported for SNMP",
        ));
    }

    Ok((tag, rest))
}

pub(super) fn encode_identifier(tag: BerTag, out: &mut Vec<u8>) -> Result<()> {
    out.push(encode_identifier_octet(tag)?);
    Ok(())
}

pub(super) fn encode_identifier_octet(tag: BerTag) -> Result<u8> {
    if tag.number() > BER_LOW_TAG_NUMBER_MAX {
        return Err(invalid_ber_field(
            "snmp.ber.identifier",
            "high-tag-number form is not supported for SNMP",
        ));
    }

    Ok(tag.identifier_octet())
}

pub(super) fn parse_identifier_octet(bytes: &[u8]) -> Result<(BerTag, &[u8])> {
    decode_identifier(bytes)
}

pub(super) fn decode_length(bytes: &[u8]) -> Result<(usize, &[u8])> {
    let Some((&first, rest)) = bytes.split_first() else {
        return Err(truncated_length(bytes.len()));
    };

    if first & BER_LENGTH_LONG_FORM_FLAG == 0 {
        return Ok((usize::from(first), rest));
    }

    let length_octets = usize::from(first & BER_LENGTH_LONG_FORM_OCTETS_MASK);
    if length_octets == 0 {
        return Err(invalid_ber_field(
            "snmp.ber.length",
            "indefinite length is not valid for SNMP",
        ));
    }

    let required = BER_LENGTH_FIELD_MIN_LEN + length_octets;
    if bytes.len() < required {
        return Err(truncated_ber("snmp.ber.length", required, bytes.len()));
    }

    let mut length = 0usize;
    for octet in &rest[..length_octets] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*octet)))
            .ok_or_else(|| invalid_ber_field("snmp.ber.length", "length exceeds supported size"))?;
    }

    Ok((length, &rest[length_octets..]))
}

pub(super) fn encode_length(length: usize, out: &mut Vec<u8>) -> Result<()> {
    if length <= BER_LENGTH_SHORT_FORM_MAX {
        out.push(length as u8);
        return Ok(());
    }

    let octets = length.to_be_bytes();
    let first_non_zero = octets
        .iter()
        .position(|octet| *octet != 0)
        .unwrap_or(octets.len() - 1);
    let encoded = &octets[first_non_zero..];

    out.push(BER_LENGTH_LONG_FORM_FLAG | encoded.len() as u8);
    out.extend_from_slice(encoded);
    Ok(())
}

pub(super) fn decode_integer(bytes: &[u8]) -> Result<(i64, &[u8])> {
    let (tag, rest) = decode_identifier(bytes)?;
    if tag != BerTag::new(BerClass::Universal, false, BER_TAG_INTEGER) {
        return Err(invalid_ber_field(
            "snmp.ber.integer",
            "expected universal primitive INTEGER",
        ));
    }

    let (length, rest) = decode_length(rest)?;
    if rest.len() < length {
        let prefix_len = bytes.len() - rest.len();
        let required = prefix_len.checked_add(length).ok_or_else(|| {
            invalid_ber_field("snmp.ber.integer", "integer length exceeds supported size")
        })?;
        return Err(truncated_ber("snmp.ber.integer", required, bytes.len()));
    }

    let (content, rest) = rest.split_at(length);
    Ok((decode_integer_content(content)?, rest))
}

pub(super) fn encode_integer(value: i64, out: &mut Vec<u8>) -> Result<()> {
    let mut content = Vec::with_capacity(BER_INTEGER_MAX_I64_CONTENT_LEN);
    encode_integer_content(value, &mut content);

    encode_identifier(
        BerTag::new(BerClass::Universal, false, BER_TAG_INTEGER),
        out,
    )?;
    encode_length(content.len(), out)?;
    out.extend_from_slice(&content);
    Ok(())
}

pub(super) fn decode_integer_content(content: &[u8]) -> Result<i64> {
    if content.len() < BER_INTEGER_MIN_CONTENT_LEN {
        return Err(invalid_ber_field(
            "snmp.ber.integer",
            "integer requires at least one content octet",
        ));
    }

    if content.len() > BER_INTEGER_MAX_I64_CONTENT_LEN {
        return Err(invalid_ber_field(
            "snmp.ber.integer",
            "integer exceeds supported i64 width",
        ));
    }

    let mut value = 0u64;
    for octet in content {
        value = (value << 8) | u64::from(*octet);
    }

    let shift = (BER_INTEGER_MAX_I64_CONTENT_LEN - content.len()) * 8;
    Ok(((value << shift) as i64) >> shift)
}

pub(super) fn encode_integer_content(value: i64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let mut start = 0;

    if value >= 0 {
        while start < bytes.len() - 1 && bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0 {
            start += 1;
        }
    } else {
        while start < bytes.len() - 1 && bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }

    out.extend_from_slice(&bytes[start..]);
}

pub(super) fn truncated_identifier(available: usize) -> CrafterError {
    CrafterError::buffer_too_short("snmp.ber.identifier", BER_IDENTIFIER_LEN, available)
}

pub(super) fn truncated_length(available: usize) -> CrafterError {
    CrafterError::buffer_too_short("snmp.ber.length", BER_LENGTH_FIELD_MIN_LEN, available)
}

pub(super) fn truncated_ber(
    context: &'static str,
    required: usize,
    available: usize,
) -> CrafterError {
    CrafterError::buffer_too_short(context, required, available)
}

pub(super) fn invalid_ber_field(field: &'static str, reason: &'static str) -> CrafterError {
    CrafterError::invalid_field_value(field, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_ber_tag_parses_identifier_metadata() {
        let (tag, rest) = parse_identifier_octet(&[0x30, 0xaa]).expect("sequence tag");

        assert_eq!(tag.class(), BerClass::Universal);
        assert!(tag.is_constructed());
        assert_eq!(tag.number(), BER_TAG_SEQUENCE);
        assert_eq!(tag.identifier_octet(), 0x30);
        assert_eq!(rest, &[0xaa]);

        let application = BerTag::from_identifier_octet(0x41);
        assert_eq!(application.class(), BerClass::Application);
        assert!(!application.is_constructed());
        assert_eq!(application.number(), SNMP_APPLICATION_TAG_COUNTER32);
    }

    #[test]
    fn snmp_ber_tag_display_labels_source_backed_tags() {
        let cases = [
            (0x02, "integer"),
            (0x04, "octet-string"),
            (0x05, "null"),
            (0x06, "object-identifier"),
            (0x30, "sequence"),
            (0x40, "ip-address"),
            (0x41, "counter32"),
            (0x42, "gauge32-or-unsigned32"),
            (0x43, "time-ticks"),
            (0x44, "opaque"),
            (0x46, "counter64"),
            (0x80, "no-such-object"),
            (0x81, "no-such-instance"),
            (0x82, "end-of-mib-view"),
            (0xa0, "get-request"),
            (0xa1, "get-next-request"),
            (0xa2, "response"),
            (0xa3, "set-request"),
            (0xa4, "trap"),
            (0xa5, "get-bulk-request"),
            (0xa6, "inform-request"),
            (0xa7, "snmpv2-trap"),
            (0xa8, "report"),
        ];

        for (octet, label) in cases {
            let tag = BerTag::from_identifier_octet(octet);
            assert_eq!(tag.label(), label, "0x{octet:02x}");
            assert_eq!(tag.to_string(), label, "0x{octet:02x}");
        }
    }

    #[test]
    fn snmp_ber_tag_display_labels_unknown_tags_without_rejecting_them() {
        assert_eq!(
            BerTag::new(BerClass::Application, false, 30).to_string(),
            "application-30"
        );
        assert_eq!(
            BerTag::new(BerClass::ContextSpecific, true, 17).to_string(),
            "constructed-context-specific-17"
        );
        assert_eq!(
            BerTag::new(BerClass::Private, false, 3).to_string(),
            "private-3"
        );
    }

    #[test]
    fn snmp_ber_tag_errors_use_crafter_error_surface() {
        assert_eq!(
            parse_identifier_octet(&[]),
            Err(CrafterError::buffer_too_short("snmp.ber.identifier", 1, 0))
        );
        assert_eq!(
            truncated_ber("snmp.ber.length", 2, 1),
            CrafterError::buffer_too_short("snmp.ber.length", 2, 1)
        );
        assert_eq!(
            invalid_ber_field("snmp.ber.length", "indefinite length is not valid for SNMP"),
            CrafterError::invalid_field_value(
                "snmp.ber.length",
                "indefinite length is not valid for SNMP"
            )
        );
    }

    #[test]
    fn snmp_ber_length_boundary_lengths_decode_and_encode() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x81, 0x80]),
            (255, &[0x81, 0xff]),
            (256, &[0x82, 0x01, 0x00]),
            (65_535, &[0x82, 0xff, 0xff]),
        ];

        for (length, encoded) in cases {
            let mut bytes = encoded.to_vec();
            bytes.push(0xaa);

            let (decoded, rest) = decode_length(&bytes).expect("BER length");
            assert_eq!(decoded, *length, "decode {encoded:02x?}");
            assert_eq!(rest, &[0xaa], "decode rest {encoded:02x?}");

            let mut out = Vec::new();
            encode_length(*length, &mut out).expect("encode BER length");
            assert_eq!(&out, encoded, "encode {length}");
        }
    }

    #[test]
    fn snmp_ber_length_long_form_decodes_and_encodes_multi_octet_lengths() {
        let bytes = [0x83, 0x01, 0x00, 0x00, 0xbb];
        let (length, rest) = decode_length(&bytes).expect("long-form length");

        assert_eq!(length, 65_536);
        assert_eq!(rest, &[0xbb]);

        let mut out = Vec::new();
        encode_length(length, &mut out).expect("encode long-form length");
        assert_eq!(out, [0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn snmp_ber_length_non_minimal_long_form_decode_is_accepted() {
        let cases: &[(usize, &[u8], &[u8])] = &[
            (0, &[0x81, 0x00, 0xcc], &[0xcc]),
            (127, &[0x81, 0x7f, 0xcc], &[0xcc]),
            (128, &[0x82, 0x00, 0x80, 0xcc], &[0xcc]),
            (256, &[0x84, 0x00, 0x00, 0x01, 0x00, 0xcc], &[0xcc]),
        ];

        for (expected, bytes, expected_rest) in cases {
            let (length, rest) = decode_length(bytes).expect("non-minimal BER length");
            assert_eq!(length, *expected, "decode {bytes:02x?}");
            assert_eq!(rest, *expected_rest, "decode rest {bytes:02x?}");
        }

        let mut minimal = Vec::new();
        encode_length(127, &mut minimal).expect("minimal encoding");
        assert_eq!(minimal, [0x7f]);
    }

    #[test]
    fn snmp_ber_length_indefinite_form_is_rejected_for_snmp() {
        assert_eq!(
            decode_length(&[0x80, 0x00, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.length",
                "indefinite length is not valid for SNMP"
            ))
        );
    }

    #[test]
    fn snmp_ber_length_truncation_reports_required_and_available() {
        assert_eq!(
            decode_length(&[]),
            Err(CrafterError::buffer_too_short("snmp.ber.length", 1, 0))
        );
        assert_eq!(
            decode_length(&[0x82, 0x01]),
            Err(CrafterError::buffer_too_short("snmp.ber.length", 3, 2))
        );
    }

    #[test]
    fn snmp_ber_length_overflow_returns_invalid_field() {
        let length_octets = core::mem::size_of::<usize>() + 1;
        assert!(length_octets <= usize::from(BER_LENGTH_LONG_FORM_OCTETS_MASK));

        let mut bytes = Vec::with_capacity(BER_LENGTH_FIELD_MIN_LEN + length_octets);
        bytes.push(BER_LENGTH_LONG_FORM_FLAG | length_octets as u8);
        bytes.push(0x01);
        bytes.extend(core::iter::repeat(0).take(length_octets - 1));

        assert_eq!(
            decode_length(&bytes),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.length",
                "length exceeds supported size"
            ))
        );
    }

    #[test]
    fn snmp_ber_length_emission_is_bounded_to_native_usize_width() {
        let mut encoded = Vec::new();
        encode_length(usize::MAX, &mut encoded).expect("encode usize max");

        assert_eq!(
            usize::from(encoded[0] & BER_LENGTH_LONG_FORM_OCTETS_MASK),
            core::mem::size_of::<usize>()
        );
        assert_eq!(&encoded[1..], &usize::MAX.to_be_bytes());

        let (decoded, rest) = decode_length(&encoded).expect("decode usize max");
        assert_eq!(decoded, usize::MAX);
        assert!(rest.is_empty());
    }

    #[test]
    fn snmp_ber_identifier_decodes_universal_application_and_context_specific_tags() {
        let cases = [
            (
                0x02,
                BerTag::new(BerClass::Universal, false, BER_TAG_INTEGER),
                "integer",
            ),
            (
                0x30,
                BerTag::new(BerClass::Universal, true, BER_TAG_SEQUENCE),
                "sequence",
            ),
            (
                0x40,
                BerTag::new(
                    BerClass::Application,
                    false,
                    SNMP_APPLICATION_TAG_IP_ADDRESS,
                ),
                "ip-address",
            ),
            (
                0x82,
                BerTag::new(
                    BerClass::ContextSpecific,
                    false,
                    SNMP_CONTEXT_TAG_END_OF_MIB_VIEW,
                ),
                "end-of-mib-view",
            ),
            (
                0xa5,
                BerTag::new(
                    BerClass::ContextSpecific,
                    true,
                    SNMP_PDU_TAG_GET_BULK_REQUEST,
                ),
                "get-bulk-request",
            ),
        ];

        for (octet, expected, label) in cases {
            let bytes = [octet, 0xaa];
            let (tag, rest) = decode_identifier(&bytes).expect("identifier");

            assert_eq!(tag, expected, "0x{octet:02x}");
            assert_eq!(tag.label(), label, "0x{octet:02x}");
            assert_eq!(rest, &[0xaa], "0x{octet:02x}");
        }
    }

    #[test]
    fn snmp_ber_identifier_encodes_single_octet_tags() {
        let cases = [
            (BerTag::new(BerClass::Universal, false, BER_TAG_NULL), 0x05),
            (
                BerTag::new(BerClass::Universal, true, BER_TAG_SEQUENCE),
                0x30,
            ),
            (
                BerTag::new(BerClass::Application, false, SNMP_APPLICATION_TAG_COUNTER64),
                0x46,
            ),
            (
                BerTag::new(BerClass::ContextSpecific, true, SNMP_PDU_TAG_REPORT),
                0xa8,
            ),
        ];

        let mut encoded = Vec::new();
        for (tag, octet) in cases {
            assert_eq!(
                encode_identifier_octet(tag).expect("identifier octet"),
                octet
            );
            encode_identifier(tag, &mut encoded).expect("identifier");
        }

        assert_eq!(encoded, [0x05, 0x30, 0x46, 0xa8]);
    }

    #[test]
    fn snmp_ber_identifier_preserves_unknown_low_tag_numbers_and_private_class() {
        let unknown_application = decode_identifier(&[0x5e]).expect("application tag").0;
        assert_eq!(unknown_application.class(), BerClass::Application);
        assert!(!unknown_application.is_constructed());
        assert_eq!(unknown_application.number(), 30);
        assert_eq!(unknown_application.to_string(), "application-30");
        assert_eq!(
            encode_identifier_octet(unknown_application).expect("application tag"),
            0x5e
        );

        let unknown_private = decode_identifier(&[0xea]).expect("private tag").0;
        assert_eq!(unknown_private.class(), BerClass::Private);
        assert!(unknown_private.is_constructed());
        assert_eq!(unknown_private.number(), 10);
        assert_eq!(unknown_private.to_string(), "constructed-private-10");
        assert_eq!(
            encode_identifier_octet(unknown_private).expect("private tag"),
            0xea
        );
    }

    #[test]
    fn snmp_ber_identifier_errors_on_missing_bytes() {
        assert_eq!(
            decode_identifier(&[]),
            Err(CrafterError::buffer_too_short(
                "snmp.ber.identifier",
                BER_IDENTIFIER_LEN,
                0
            ))
        );
    }

    #[test]
    fn snmp_ber_identifier_keeps_high_tag_number_form_out_of_scope() {
        assert_eq!(
            decode_identifier(&[0x1f]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.identifier",
                "high-tag-number form is not supported for SNMP"
            ))
        );
        assert_eq!(
            encode_identifier_octet(BerTag::new(BerClass::Private, false, BER_TAG_NUMBER_MASK)),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.identifier",
                "high-tag-number form is not supported for SNMP"
            ))
        );
    }

    #[test]
    fn snmp_ber_integer_decodes_positive_negative_and_zero_content() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x00, 0x80]),
            (255, &[0x00, 0xff]),
            (256, &[0x01, 0x00]),
            (-1, &[0xff]),
            (-128, &[0x80]),
            (-129, &[0xff, 0x7f]),
            (i64::MAX, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            (i64::MIN, &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ];

        for (expected, content) in cases {
            assert_eq!(
                decode_integer_content(content).expect("BER INTEGER content"),
                *expected,
                "{content:02x?}"
            );
        }
    }

    #[test]
    fn snmp_ber_integer_encodes_minimal_two_complement_content() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x00, 0x80]),
            (255, &[0x00, 0xff]),
            (256, &[0x01, 0x00]),
            (-1, &[0xff]),
            (-128, &[0x80]),
            (-129, &[0xff, 0x7f]),
            (i64::MAX, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            (i64::MIN, &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ];

        for (value, expected) in cases {
            let mut encoded = Vec::new();
            encode_integer_content(*value, &mut encoded);
            assert_eq!(&encoded, expected, "{value}");
        }
    }

    #[test]
    fn snmp_ber_integer_tlv_encodes_minimal_lengths_and_decodes_rest() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (127, &[0x02, 0x01, 0x7f]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xff, 0x7f]),
        ];

        for (value, expected) in cases {
            let mut encoded = Vec::new();
            encode_integer(*value, &mut encoded).expect("encode BER INTEGER");
            assert_eq!(&encoded, expected, "{value}");

            encoded.push(0xaa);
            let (decoded, rest) = decode_integer(&encoded).expect("decode BER INTEGER");
            assert_eq!(decoded, *value, "{value}");
            assert_eq!(rest, &[0xaa], "{value}");
        }
    }

    #[test]
    fn snmp_ber_integer_decodes_non_minimal_content_without_rewriting_it() {
        assert_eq!(
            decode_integer_content(&[0x00, 0x7f]).expect("non-minimal positive"),
            127
        );
        assert_eq!(
            decode_integer_content(&[0xff, 0x80]).expect("non-minimal negative"),
            -128
        );
    }

    #[test]
    fn snmp_ber_integer_truncated_integer_buffers_report_required_and_available() {
        assert_eq!(
            decode_integer(&[0x02, 0x02, 0x01]),
            Err(CrafterError::buffer_too_short("snmp.ber.integer", 4, 3))
        );
        assert_eq!(
            decode_integer_content(&[]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.integer",
                "integer requires at least one content octet"
            ))
        );
    }

    #[test]
    fn snmp_ber_integer_rejects_wrong_tag_and_unsupported_width() {
        assert_eq!(
            decode_integer(&[0x04, 0x01, 0x00]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.integer",
                "expected universal primitive INTEGER"
            ))
        );
        assert_eq!(
            decode_integer_content(&[0x00; BER_INTEGER_MAX_I64_CONTENT_LEN + 1]),
            Err(CrafterError::invalid_field_value(
                "snmp.ber.integer",
                "integer exceeds supported i64 width"
            ))
        );
    }
}
