//! SNMP constants.
//!
//! Source-gated by `docs/snmp-rfc-manifest.md`.

/// SNMP message UDP port.
///
/// Source: IANA Service Name and Transport Protocol Port Number Registry row
/// `snmp`/UDP, and RFC 3417 Section 3 for the preferred UDP/IPv4 mapping.
pub const SNMP_PORT: u16 = 161;

/// SNMP notification/trap UDP port.
///
/// Source: IANA Service Name and Transport Protocol Port Number Registry row
/// `snmptrap`/UDP.
pub const SNMP_TRAP_PORT: u16 = 162;

/// GetRequest-PDU context-specific tag number.
///
/// Source: RFC 1157 Section 4.1.2 and RFC 3416 Section 3.
pub const SNMP_PDU_TAG_GET_REQUEST: u8 = 0;

/// GetNextRequest-PDU context-specific tag number.
///
/// Source: RFC 1157 Section 4.1.3 and RFC 3416 Section 3.
pub const SNMP_PDU_TAG_GET_NEXT_REQUEST: u8 = 1;

/// Response/GetResponse PDU context-specific tag number.
///
/// Source: RFC 1157 Section 4.1.4 and RFC 3416 Section 3.
pub const SNMP_PDU_TAG_RESPONSE: u8 = 2;

/// SetRequest-PDU context-specific tag number.
///
/// Source: RFC 1157 Section 4.1.5 and RFC 3416 Section 3.
pub const SNMP_PDU_TAG_SET_REQUEST: u8 = 3;

/// SNMPv1 Trap-PDU context-specific tag number.
///
/// Source: RFC 1157 Section 4.1.6.
pub const SNMP_PDU_TAG_TRAP: u8 = 4;

/// GetBulkRequest-PDU context-specific tag number.
///
/// Source: RFC 3416 Section 3 and Section 4.2.3.
pub const SNMP_PDU_TAG_GET_BULK_REQUEST: u8 = 5;

/// InformRequest-PDU context-specific tag number.
///
/// Source: RFC 3416 Section 3 and Section 4.2.7.
pub const SNMP_PDU_TAG_INFORM_REQUEST: u8 = 6;

/// SNMPv2-Trap-PDU context-specific tag number.
///
/// Source: RFC 3416 Section 3 and Section 4.2.6.
pub const SNMP_PDU_TAG_TRAP_V2: u8 = 7;

/// Report-PDU context-specific tag number.
///
/// Source: RFC 3416 Section 3; usage is supplied by administrative framework
/// sources such as RFC 3412.
pub const SNMP_PDU_TAG_REPORT: u8 = 8;
