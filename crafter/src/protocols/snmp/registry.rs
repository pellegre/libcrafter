//! SNMP registry metadata.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`; this module does not register
//! UDP dispatch or expose payload detection.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use super::{ber, constants};

/// Source-backed assignment status for an SNMP PDU tag number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnmpPduTagStatus {
    /// Assigned by the manifest-backed SNMP PDU sources.
    Assigned,
    /// Not assigned by the manifest-backed SNMP PDU sources.
    Unknown,
}

impl SnmpPduTagStatus {
    /// Stable lowercase status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SnmpPduTagStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One source-backed SNMP PDU tag metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnmpPduTagMeta {
    /// Low-tag-number value from the context-specific BER identifier.
    pub tag_number: u8,
    /// Stable short name, or `"unknown-pdu"` for unassigned tags.
    pub name: &'static str,
    /// Assignment status from the manifest-backed PDU matrix.
    pub status: SnmpPduTagStatus,
}

/// Return source-backed metadata for an SNMP PDU tag number.
///
/// Source: RFC 1157 Sections 4.1.2 through 4.1.6 and RFC 3416 Section 3.
pub const fn snmp_pdu_tag_meta(tag_number: u8) -> SnmpPduTagMeta {
    let (name, status) = match tag_number {
        constants::SNMP_PDU_TAG_GET_REQUEST => ("get-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_GET_NEXT_REQUEST => {
            ("get-next-request", SnmpPduTagStatus::Assigned)
        }
        constants::SNMP_PDU_TAG_RESPONSE => ("response", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_SET_REQUEST => ("set-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_TRAP => ("trap", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_GET_BULK_REQUEST => {
            ("get-bulk-request", SnmpPduTagStatus::Assigned)
        }
        constants::SNMP_PDU_TAG_INFORM_REQUEST => ("inform-request", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_TRAP_V2 => ("snmpv2-trap", SnmpPduTagStatus::Assigned),
        constants::SNMP_PDU_TAG_REPORT => ("report", SnmpPduTagStatus::Assigned),
        _ => ("unknown-pdu", SnmpPduTagStatus::Unknown),
    };

    SnmpPduTagMeta {
        tag_number,
        name,
        status,
    }
}

/// Return the source-backed PDU name for an assigned tag number.
pub const fn snmp_pdu_tag_name(tag_number: u8) -> Option<&'static str> {
    let meta = snmp_pdu_tag_meta(tag_number);
    match meta.status {
        SnmpPduTagStatus::Assigned => Some(meta.name),
        SnmpPduTagStatus::Unknown => None,
    }
}

/// Return the source-backed assignment status for a PDU tag number.
pub const fn snmp_pdu_tag_status(tag_number: u8) -> SnmpPduTagStatus {
    snmp_pdu_tag_meta(tag_number).status
}

pub(super) fn pdu_tag_label(tag_number: u8) -> String {
    snmp_pdu_tag_name(tag_number)
        .map(str::to_string)
        .unwrap_or_else(|| format!("pdu-{tag_number}"))
}

pub(super) fn application_tag_name(tag_number: u8) -> Option<&'static str> {
    match tag_number {
        ber::SNMP_APPLICATION_TAG_IP_ADDRESS => Some("ip-address"),
        ber::SNMP_APPLICATION_TAG_COUNTER32 => Some("counter32"),
        ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32 => Some("gauge32-or-unsigned32"),
        ber::SNMP_APPLICATION_TAG_TIME_TICKS => Some("time-ticks"),
        ber::SNMP_APPLICATION_TAG_OPAQUE => Some("opaque"),
        ber::SNMP_APPLICATION_TAG_COUNTER64 => Some("counter64"),
        _ => None,
    }
}

pub(super) fn application_tag_label(tag_number: u8, constructed: bool) -> String {
    if !constructed {
        if let Some(name) = application_tag_name(tag_number) {
            return name.to_string();
        }
    }

    if constructed {
        format!("constructed-application-{tag_number}")
    } else {
        format!("application-{tag_number}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_pdu_tags_registry_names_source_backed_tags_and_unknowns() {
        let cases = [
            (constants::SNMP_PDU_TAG_GET_REQUEST, "get-request"),
            (constants::SNMP_PDU_TAG_GET_NEXT_REQUEST, "get-next-request"),
            (constants::SNMP_PDU_TAG_RESPONSE, "response"),
            (constants::SNMP_PDU_TAG_SET_REQUEST, "set-request"),
            (constants::SNMP_PDU_TAG_TRAP, "trap"),
            (constants::SNMP_PDU_TAG_GET_BULK_REQUEST, "get-bulk-request"),
            (constants::SNMP_PDU_TAG_INFORM_REQUEST, "inform-request"),
            (constants::SNMP_PDU_TAG_TRAP_V2, "snmpv2-trap"),
            (constants::SNMP_PDU_TAG_REPORT, "report"),
        ];

        for (tag, name) in cases {
            let meta = snmp_pdu_tag_meta(tag);
            assert_eq!(meta.tag_number, tag);
            assert_eq!(meta.name, name);
            assert_eq!(meta.status, SnmpPduTagStatus::Assigned);
            assert_eq!(snmp_pdu_tag_name(tag), Some(name));
            assert_eq!(snmp_pdu_tag_status(tag), SnmpPduTagStatus::Assigned);
            assert_eq!(pdu_tag_label(tag), name);
        }

        let unknown = snmp_pdu_tag_meta(9);
        assert_eq!(unknown.name, "unknown-pdu");
        assert_eq!(unknown.status, SnmpPduTagStatus::Unknown);
        assert_eq!(snmp_pdu_tag_name(9), None);
        assert_eq!(snmp_pdu_tag_status(9), SnmpPduTagStatus::Unknown);
        assert_eq!(pdu_tag_label(9), "pdu-9");
        assert_eq!(SnmpPduTagStatus::Assigned.label(), "assigned");
        assert_eq!(SnmpPduTagStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn snmp_application_values_registry_labels_source_backed_tags_and_unknowns() {
        let cases = [
            (ber::SNMP_APPLICATION_TAG_IP_ADDRESS, "ip-address"),
            (ber::SNMP_APPLICATION_TAG_COUNTER32, "counter32"),
            (
                ber::SNMP_APPLICATION_TAG_GAUGE32_OR_UNSIGNED32,
                "gauge32-or-unsigned32",
            ),
            (ber::SNMP_APPLICATION_TAG_TIME_TICKS, "time-ticks"),
            (ber::SNMP_APPLICATION_TAG_OPAQUE, "opaque"),
            (ber::SNMP_APPLICATION_TAG_COUNTER64, "counter64"),
        ];

        for (tag, label) in cases {
            assert_eq!(application_tag_name(tag), Some(label));
            assert_eq!(application_tag_label(tag, false), label);
        }

        assert_eq!(application_tag_name(5), None);
        assert_eq!(application_tag_label(5, false), "application-5");
        assert_eq!(application_tag_label(5, true), "constructed-application-5");
        assert_eq!(
            application_tag_label(ber::SNMP_APPLICATION_TAG_IP_ADDRESS, true),
            "constructed-application-0"
        );
    }
}
