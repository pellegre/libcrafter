//! BER TLV scaffolding for SNMP.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use crate::error::{CrafterError, Result};

pub(super) const BER_CLASS_MASK: u8 = 0xc0;
pub(super) const BER_CONSTRUCTED_MASK: u8 = 0x20;
pub(super) const BER_TAG_NUMBER_MASK: u8 = 0x1f;

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

pub(super) fn parse_identifier_octet(bytes: &[u8]) -> Result<(BerTag, &[u8])> {
    let Some((&octet, rest)) = bytes.split_first() else {
        return Err(truncated_identifier(bytes.len()));
    };

    Ok((BerTag::from_identifier_octet(octet), rest))
}

pub(super) fn truncated_identifier(available: usize) -> CrafterError {
    CrafterError::buffer_too_short("snmp.ber.identifier", 1, available)
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
}
