use super::constants::*;
use super::operation::ArpOperation;

/// Short label for a known ARP hardware type, or `None` for unknown values.
///
/// This is a data-only lookup over the source-backed hardware-type codepoints
/// (IANA registry arp-parameters-2, `target/arp-rfc/scope.md`). It never blocks
/// or rewrites any value: unknown numeric hardware types simply return `None`
/// and remain usable through [`crate::protocols::link::Arp::hardware_type`].
/// Mirrors the [`ArpOperation::label`] shape so summaries and generated tools
/// can recognize a hardware type without narrowing the packet model.
pub fn arp_hardware_type_label(hardware_type: u16) -> Option<&'static str> {
    match hardware_type {
        ARP_HRD_ETHERNET => Some("ethernet"),
        ARP_HRD_IEEE_802 => Some("ieee-802"),
        ARP_HRD_FIBRE_CHANNEL => Some("fibre-channel"),
        ARP_HRD_ATM => Some("atm"),
        ARP_HRD_MAPOS => Some("mapos"),
        ARP_HRD_INFINIBAND => Some("infiniband"),
        _ => None,
    }
}

/// Short label for a known ARP protocol type, or `None` for unknown values.
///
/// This is a data-only lookup over the source-backed protocol-type codepoints.
/// The ARP protocol-type field shares the EtherType space (IANA registry
/// arp-parameters-3, administered per RFC 5342), and that sub-registry returned
/// no records of its own in the manifest build, so the only source-backed known
/// value is the IPv4 default ([`ARP_PRO_IPV4`] = [`super::super::ETHERTYPE_IPV4`])
/// (`target/arp-rfc/scope.md`, assumption 3). It never blocks or rewrites any
/// value: unknown numeric protocol types simply return `None` and remain usable
/// through [`crate::protocols::link::Arp::protocol_type`]. Mirrors the
/// [`arp_hardware_type_label`] shape so summaries and generated tools can
/// recognize a protocol type without narrowing the packet model.
pub fn arp_protocol_type_label(protocol_type: u16) -> Option<&'static str> {
    match protocol_type {
        ARP_PRO_IPV4 => Some("ipv4"),
        _ => None,
    }
}

pub(in crate::protocols::link) fn operation_summary(operation: u16) -> String {
    match ArpOperation::from_opcode(operation) {
        Some(named) => named.label().to_string(),
        None => operation.to_string(),
    }
}

/// Inspection rendering for the ARP operation: known operations show their
/// source-backed label alongside the raw opcode so unknown numeric values stay
/// visible (e.g. `reply (2)`, `1024`).
pub(in crate::protocols::link) fn operation_inspection(operation: u16) -> String {
    match ArpOperation::from_opcode(operation) {
        Some(named) => format!("{} ({operation})", named.label()),
        None => operation.to_string(),
    }
}

/// Inspection rendering for the ARP hardware type: known IANA hardware types
/// show their label next to the raw codepoint, unknown values render as a bare
/// hex codepoint so nonstandard hardware types stay inspectable.
pub(in crate::protocols::link) fn hardware_type_inspection(hardware_type: u16) -> String {
    match arp_hardware_type_label(hardware_type) {
        Some(label) => format!("{label} (0x{hardware_type:04x})"),
        None => format!("0x{hardware_type:04x}"),
    }
}

/// Inspection rendering for the ARP protocol type, mirroring
/// [`hardware_type_inspection`].
pub(in crate::protocols::link) fn protocol_type_inspection(protocol_type: u16) -> String {
    match arp_protocol_type_label(protocol_type) {
        Some(label) => format!("{label} (0x{protocol_type:04x})"),
        None => format!("0x{protocol_type:04x}"),
    }
}
