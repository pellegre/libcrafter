//! IGMP constants and wire-level codepoints.
//!
//! Values are sourced from the reviewed handoff in
//! `.agents/docs/igmp-codepoints.md`; length and default-field constants cite
//! the RFC sections named there.

/// IPv4 Protocol number for IGMP. RFC 9776 section 4.
pub const IPPROTO_IGMP: u8 = 2;

/// Fixed IGMP v1/v2/base header length, in octets.
/// RFC 1112 / RFC 2236 / RFC 9776 section 4.
pub const IGMP_FIXED_HEADER_LEN: usize = 8;
/// Compatibility name for the fixed IGMP header length.
pub const IGMP_HEADER_LEN: usize = IGMP_FIXED_HEADER_LEN;
/// Minimum IGMPv3 Membership Query length, in octets. RFC 9776 section 4.1.
pub const IGMP_V3_QUERY_MIN_LEN: usize = 12;
/// IGMPv3 Membership Report header length before group records, in octets.
/// RFC 9776 section 4.2.
pub const IGMP_V3_REPORT_HEADER_LEN: usize = 8;
/// IGMPv3 Group Record header length before source addresses, in octets.
/// RFC 9776 section 4.2.
pub const IGMP_V3_GROUP_RECORD_HEADER_LEN: usize = 8;
/// IGMP/MLD extension TLV header length, in octets. RFC 9279 section 3.
pub const IGMP_EXTENSION_HEADER_LEN: usize = 4;

/// Reserved IGMP Type value. IANA IGMP Type Numbers registry.
pub const IGMP_TYPE_RESERVED: u8 = 0x00;
/// First obsolete reserved IGMP Type value. IANA IGMP Type Numbers registry.
pub const IGMP_TYPE_OBSOLETE_RESERVED_FIRST: u8 = 0x01;
/// Last obsolete reserved IGMP Type value. IANA IGMP Type Numbers registry.
pub const IGMP_TYPE_OBSOLETE_RESERVED_LAST: u8 = 0x08;
/// First currently unassigned IGMP Type value. IANA IGMP Type Numbers registry.
pub const IGMP_TYPE_UNASSIGNED_FIRST: u8 = 0x09;
/// Last currently unassigned IGMP Type value. IANA IGMP Type Numbers registry.
pub const IGMP_TYPE_UNASSIGNED_LAST: u8 = 0x10;
/// IGMP Membership Query. RFC 1112, updated by RFC 9776 behavior.
pub const IGMP_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
/// IGMPv1 Membership Report. RFC 1112.
pub const IGMP_TYPE_V1_MEMBERSHIP_REPORT: u8 = 0x12;
/// DVMRP registered IGMP Type value. Typed DVMRP behavior is out of scope here.
pub const IGMP_TYPE_DVMRP: u8 = 0x13;
/// PIM version 1 registered IGMP Type value. Typed PIM behavior is out of scope here.
pub const IGMP_TYPE_PIM_V1: u8 = 0x14;
/// Cisco Trace Messages registered IGMP Type value.
pub const IGMP_TYPE_CISCO_TRACE_MESSAGES: u8 = 0x15;
/// IGMPv2 Membership Report. RFC 2236.
pub const IGMP_TYPE_V2_MEMBERSHIP_REPORT: u8 = 0x16;
/// IGMPv2 Leave Group. RFC 2236.
pub const IGMP_TYPE_V2_LEAVE_GROUP: u8 = 0x17;
/// Multicast Traceroute Response registered IGMP Type value.
pub const IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE: u8 = 0x1e;
/// Multicast Traceroute registered IGMP Type value.
pub const IGMP_TYPE_MULTICAST_TRACEROUTE: u8 = 0x1f;
/// IGMPv3 Membership Report. RFC 9776.
pub const IGMP_TYPE_V3_MEMBERSHIP_REPORT: u8 = 0x22;
/// Multicast Router Advertisement. RFC 4286.
pub const IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT: u8 = 0x30;
/// Multicast Router Solicitation. RFC 4286.
pub const IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION: u8 = 0x31;
/// Multicast Router Termination. RFC 4286.
pub const IGMP_TYPE_MULTICAST_ROUTER_TERMINATION: u8 = 0x32;
/// First IGMP Type value reserved for experimentation. RFC 9778 / IANA.
pub const IGMP_TYPE_EXPERIMENTAL_FIRST: u8 = 0xf0;
/// Last IGMP Type value reserved for experimentation. RFC 9778 / IANA.
pub const IGMP_TYPE_EXPERIMENTAL_LAST: u8 = 0xff;

/// Membership Query Code value for IGMPv1. IANA Code Fields registry.
pub const IGMP_QUERY_CODE_V1: u8 = 0;
/// First Membership Query Code value carrying v2-or-later Max Response Time.
/// IANA Code Fields registry.
pub const IGMP_QUERY_CODE_MAX_RESPONSE_FIRST: u8 = 1;
/// Last Membership Query Code value carrying v2-or-later Max Response Time.
/// IANA Code Fields registry.
pub const IGMP_QUERY_CODE_MAX_RESPONSE_LAST: u8 = u8::MAX;

/// Default zero-valued Code or Reserved octet when a format has no registered
/// Code value. RFC 9776 sections 4.1 and 4.2 / IANA Code Fields registry.
pub const IGMP_DEFAULT_CODE: u8 = 0;
/// Default checksum field value before checksum calculation. RFC 9776 section 4.
pub const IGMP_DEFAULT_CHECKSUM: u16 = 0;
/// Default zero-valued reserved byte. RFC 9776 sections 4.1 and 4.2.
pub const IGMP_DEFAULT_RESERVED_U8: u8 = 0;
/// Default zero-valued reserved or flags field. RFC 9776 section 4.2.
pub const IGMP_DEFAULT_RESERVED_U16: u16 = 0;
/// Default source-count value for query and group-record builders.
pub const IGMP_DEFAULT_SOURCE_COUNT: u16 = 0;
/// Default group-record count for IGMPv3 reports.
pub const IGMP_DEFAULT_GROUP_RECORD_COUNT: u16 = 0;
/// Default auxiliary-data length in 32-bit words. RFC 9776 section 4.2.11.
pub const IGMP_DEFAULT_AUX_DATA_LEN: u8 = 0;
/// Default IGMPv3 Query Flags field: no flags set.
pub const IGMP_DEFAULT_QUERY_FLAGS: u8 = 0;
/// Default IGMPv3 Report Flags field: no flags set.
pub const IGMP_DEFAULT_REPORT_FLAGS: u16 = 0;
/// Default extension value length for an empty extension TLV.
pub const IGMP_DEFAULT_EXTENSION_LENGTH: u16 = 0;

/// IGMPv3 record type MODE_IS_INCLUDE. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_MODE_IS_INCLUDE: u8 = 1;
/// IGMPv3 record type MODE_IS_EXCLUDE. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_MODE_IS_EXCLUDE: u8 = 2;
/// IGMPv3 record type CHANGE_TO_INCLUDE_MODE. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE: u8 = 3;
/// IGMPv3 record type CHANGE_TO_EXCLUDE_MODE. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE: u8 = 4;
/// IGMPv3 record type ALLOW_NEW_SOURCES. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES: u8 = 5;
/// IGMPv3 record type BLOCK_OLD_SOURCES. RFC 9776 section 4.2.13.
pub const IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES: u8 = 6;

/// No-op IGMP/MLD extension type. RFC 9279 section 4.
pub const IGMP_EXTENSION_TYPE_NOOP: u16 = 0;
/// First unassigned registry-managed IGMP/MLD extension type. RFC 9279 / IANA.
pub const IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST: u16 = 1;
/// Last unassigned registry-managed IGMP/MLD extension type. RFC 9279 / IANA.
pub const IGMP_EXTENSION_TYPE_UNASSIGNED_LAST: u16 = 65_533;
/// First experimental IGMP/MLD extension type. RFC 9279 / IANA.
pub const IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST: u16 = 65_534;
/// Last experimental IGMP/MLD extension type. RFC 9279 / IANA.
pub const IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST: u16 = u16::MAX;

/// IGMPv3 Query extension flag mask for the wire octet containing Flags/S/QRV.
/// RFC 9279 section 3.3 places the E flag in the high-order wire bit.
pub const IGMP_V3_QUERY_FLAG_EXTENSION: u8 = 0x80;
/// Mask for registry-managed IGMPv3 Query flag bits.
pub const IGMP_V3_QUERY_FLAGS_MASK: u8 = 0xf0;
/// Mask for currently unassigned IGMPv3 Query flag bits.
pub const IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK: u8 = 0x70;
/// IGMPv3 Report extension flag mask for the 16-bit Flags field.
/// RFC 9279 section 3.4 places the E flag in the high-order wire bit.
pub const IGMP_V3_REPORT_FLAG_EXTENSION: u16 = 0x8000;
/// Mask for registry-managed IGMPv3 Report flag bits.
pub const IGMP_V3_REPORT_FLAGS_MASK: u16 = u16::MAX;
/// Mask for currently unassigned IGMPv3 Report flag bits.
pub const IGMP_V3_REPORT_FLAGS_UNASSIGNED_MASK: u16 = 0x7fff;

const IGMP_V3_TIMER_CODE_FLOATING_BIT: u8 = 0x80;
const IGMP_V3_TIMER_CODE_EXP_MASK: u8 = 0x70;
const IGMP_V3_TIMER_CODE_MANT_MASK: u8 = 0x0f;
const IGMP_V3_TIMER_CODE_LINEAR_LIMIT: u32 = 128;

/// Largest time value representable by the IGMPv3 timer-code format.
pub(crate) const IGMP_V3_TIMER_CODE_MAX_UNITS: u32 = 31_744;

/// Decode the RFC 9776 IGMPv3 Max Resp Code / QQIC floating timer format.
///
/// The caller supplies the units: Max Resp Code units are tenths of seconds,
/// while QQIC units are seconds.
pub(crate) fn igmp_v3_timer_code_units(code: u8) -> u32 {
    if code < IGMP_V3_TIMER_CODE_FLOATING_BIT {
        return u32::from(code);
    }

    let exp = (code & IGMP_V3_TIMER_CODE_EXP_MASK) >> 4;
    let mant = code & IGMP_V3_TIMER_CODE_MANT_MASK;
    u32::from(mant | 0x10) << (u32::from(exp) + 3)
}

/// Encode the nearest representable IGMPv3 timer code not greater than `units`.
///
/// RFC 9776 recommends using the exact value when possible, otherwise the next
/// lower representable value for configured Max Resp Code timers. QQIC uses the
/// same wire representation, so this helper applies the same floor behavior.
pub(crate) fn igmp_v3_timer_code_from_units_floor(units: u32) -> u8 {
    if units < IGMP_V3_TIMER_CODE_LINEAR_LIMIT {
        return units as u8;
    }

    let target = units.min(IGMP_V3_TIMER_CODE_MAX_UNITS);
    let mut encoded = IGMP_V3_TIMER_CODE_FLOATING_BIT;
    for code in IGMP_V3_TIMER_CODE_FLOATING_BIT..=u8::MAX {
        let value = igmp_v3_timer_code_units(code);
        if value > target {
            break;
        }
        encoded = code;
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn igmp_constants_match_reviewed_codepoints() {
        assert_eq!(IPPROTO_IGMP, 2);
        assert_eq!(IGMP_FIXED_HEADER_LEN, 8);
        assert_eq!(IGMP_HEADER_LEN, IGMP_FIXED_HEADER_LEN);
        assert_eq!(IGMP_V3_QUERY_MIN_LEN, 12);
        assert_eq!(IGMP_V3_REPORT_HEADER_LEN, 8);
        assert_eq!(IGMP_V3_GROUP_RECORD_HEADER_LEN, 8);
        assert_eq!(IGMP_EXTENSION_HEADER_LEN, 4);

        assert_eq!(IGMP_TYPE_RESERVED, 0x00);
        assert_eq!(IGMP_TYPE_OBSOLETE_RESERVED_FIRST, 0x01);
        assert_eq!(IGMP_TYPE_OBSOLETE_RESERVED_LAST, 0x08);
        assert_eq!(IGMP_TYPE_UNASSIGNED_FIRST, 0x09);
        assert_eq!(IGMP_TYPE_UNASSIGNED_LAST, 0x10);
        assert_eq!(IGMP_TYPE_MEMBERSHIP_QUERY, 0x11);
        assert_eq!(IGMP_TYPE_V1_MEMBERSHIP_REPORT, 0x12);
        assert_eq!(IGMP_TYPE_DVMRP, 0x13);
        assert_eq!(IGMP_TYPE_PIM_V1, 0x14);
        assert_eq!(IGMP_TYPE_CISCO_TRACE_MESSAGES, 0x15);
        assert_eq!(IGMP_TYPE_V2_MEMBERSHIP_REPORT, 0x16);
        assert_eq!(IGMP_TYPE_V2_LEAVE_GROUP, 0x17);
        assert_eq!(IGMP_TYPE_MULTICAST_TRACEROUTE_RESPONSE, 0x1e);
        assert_eq!(IGMP_TYPE_MULTICAST_TRACEROUTE, 0x1f);
        assert_eq!(IGMP_TYPE_V3_MEMBERSHIP_REPORT, 0x22);
        assert_eq!(IGMP_TYPE_MULTICAST_ROUTER_ADVERTISEMENT, 0x30);
        assert_eq!(IGMP_TYPE_MULTICAST_ROUTER_SOLICITATION, 0x31);
        assert_eq!(IGMP_TYPE_MULTICAST_ROUTER_TERMINATION, 0x32);
        assert_eq!(IGMP_TYPE_EXPERIMENTAL_FIRST, 0xf0);
        assert_eq!(IGMP_TYPE_EXPERIMENTAL_LAST, 0xff);

        assert_eq!(IGMP_QUERY_CODE_V1, 0);
        assert_eq!(IGMP_QUERY_CODE_MAX_RESPONSE_FIRST, 1);
        assert_eq!(IGMP_QUERY_CODE_MAX_RESPONSE_LAST, 255);

        assert_eq!(IGMP_DEFAULT_CODE, 0);
        assert_eq!(IGMP_DEFAULT_CHECKSUM, 0);
        assert_eq!(IGMP_DEFAULT_RESERVED_U8, 0);
        assert_eq!(IGMP_DEFAULT_RESERVED_U16, 0);
        assert_eq!(IGMP_DEFAULT_SOURCE_COUNT, 0);
        assert_eq!(IGMP_DEFAULT_GROUP_RECORD_COUNT, 0);
        assert_eq!(IGMP_DEFAULT_AUX_DATA_LEN, 0);
        assert_eq!(IGMP_DEFAULT_QUERY_FLAGS, 0);
        assert_eq!(IGMP_DEFAULT_REPORT_FLAGS, 0);
        assert_eq!(IGMP_DEFAULT_EXTENSION_LENGTH, 0);

        assert_eq!(IGMP_RECORD_TYPE_MODE_IS_INCLUDE, 1);
        assert_eq!(IGMP_RECORD_TYPE_MODE_IS_EXCLUDE, 2);
        assert_eq!(IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE, 3);
        assert_eq!(IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE, 4);
        assert_eq!(IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES, 5);
        assert_eq!(IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES, 6);

        assert_eq!(IGMP_EXTENSION_TYPE_NOOP, 0);
        assert_eq!(IGMP_EXTENSION_TYPE_UNASSIGNED_FIRST, 1);
        assert_eq!(IGMP_EXTENSION_TYPE_UNASSIGNED_LAST, 65_533);
        assert_eq!(IGMP_EXTENSION_TYPE_EXPERIMENTAL_FIRST, 65_534);
        assert_eq!(IGMP_EXTENSION_TYPE_EXPERIMENTAL_LAST, 65_535);

        assert_eq!(IGMP_V3_QUERY_FLAG_EXTENSION, 0x80);
        assert_eq!(IGMP_V3_QUERY_FLAGS_MASK, 0xf0);
        assert_eq!(IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK, 0x70);
        assert_eq!(IGMP_V3_REPORT_FLAG_EXTENSION, 0x8000);
        assert_eq!(IGMP_V3_REPORT_FLAGS_MASK, 0xffff);
        assert_eq!(IGMP_V3_REPORT_FLAGS_UNASSIGNED_MASK, 0x7fff);
    }
}
